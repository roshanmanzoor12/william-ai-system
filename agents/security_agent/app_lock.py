"""
agents/security_agent/app_lock.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Locks sensitive apps behind verification.

The AppLock class provides a production-ready application access-control layer
for William/Jarvis. It can protect dashboards, applications, integrations,
tools, agent capabilities, finance areas, browser sessions, system controls,
administrative panels, and other sensitive resources.

Architecture connections
------------------------
Master Agent / Agent Router:
    The public run() method accepts structured tasks and routes supported
    app-lock actions.

Security Agent:
    AppLock is part of the Security Agent and enforces lock policy, permissions,
    verification requirements, failed-attempt protection, cooldowns, and
    security approvals.

Verification Agent:
    Successful and failed security operations prepare structured verification
    payloads through _prepare_verification_payload().

Memory Agent:
    Useful non-secret security context can be prepared through
    _prepare_memory_payload(). Raw credentials, verification codes, biometric
    data, secrets, and private tokens are never included.

Dashboard / FastAPI:
    All public methods return JSON-compatible dictionaries with:
        success
        message
        data
        error
        metadata

Agent Registry / Agent Loader:
    get_registry_metadata() and health_check() expose stable integration
    interfaces.

SaaS isolation:
    Every app registration, lock policy, challenge, unlock grant, audit event,
    and access decision is scoped by both user_id and workspace_id.

Security principles
-------------------
1. Deny by default.
2. Never trust client-provided verification status.
3. Never store raw passwords, PINs, OTP codes, biometric templates, or secrets.
4. Bind temporary unlock grants to user/workspace and optionally device,
   session, IP, role, and actor agent.
5. Expire challenges and grants automatically.
6. Apply cooldowns after repeated failures.
7. Require Security Agent approval for sensitive policy or bulk operations.
8. Keep the file import-safe if future William modules do not exist yet.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union


# ============================================================================
# Optional imports and safe fallbacks
# ============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe BaseAgent fallback.

        The real William BaseAgent can replace this automatically when it
        becomes available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback audit: %s", payload)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_AGENT_NAME = "AppLock"
DEFAULT_AGENT_ID = "security_agent.app_lock"

DEFAULT_STORAGE_DIR = Path("data/security_agent/app_lock")
DEFAULT_STORAGE_FILE = "app_lock.json"

DEFAULT_CHALLENGE_TTL_SECONDS = 300
DEFAULT_UNLOCK_TTL_SECONDS = 900
DEFAULT_MAX_FAILED_ATTEMPTS = 5
DEFAULT_COOLDOWN_SECONDS = 900
DEFAULT_MAX_UNLOCK_TTL_SECONDS = 86_400

SUPPORTED_VERIFICATION_METHODS: Set[str] = {
    "password",
    "pin",
    "otp",
    "totp",
    "email_otp",
    "sms_otp",
    "biometric",
    "passkey",
    "security_key",
    "device_approval",
    "admin_approval",
    "security_agent",
    "multi_factor",
    "custom",
}

SUPPORTED_RISK_LEVELS: Set[str] = {
    "low",
    "medium",
    "high",
    "critical",
}

SUPPORTED_APP_TYPES: Set[str] = {
    "application",
    "dashboard",
    "integration",
    "agent",
    "tool",
    "system",
    "finance",
    "browser",
    "call",
    "message",
    "workflow",
    "file_manager",
    "admin_panel",
    "api",
    "custom",
}

SENSITIVE_ACTIONS: Set[str] = {
    "register_app",
    "update_app",
    "remove_app",
    "set_lock_policy",
    "disable_lock",
    "force_unlock",
    "revoke_all_unlocks",
    "lock_all_apps",
    "export_configuration",
    "import_configuration",
    "purge_workspace_data",
}

SAFE_PERMISSION_ADMIN = "app_lock:admin"
SAFE_PERMISSION_BYPASS = "app_lock:bypass"
SAFE_PERMISSION_FORCE_UNLOCK = "app_lock:force_unlock"


# ============================================================================
# Data models
# ============================================================================

@dataclass
class AppLockContext:
    """
    SaaS and request context for an AppLock operation.
    """

    user_id: str
    workspace_id: str
    actor_agent: str = DEFAULT_AGENT_ID
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtectedApp:
    """
    Registered application or resource protected by AppLock.
    """

    app_id: str
    app_name: str
    app_type: str
    user_id: str
    workspace_id: str
    description: Optional[str] = None
    resource_identifier: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: AppLock.utcnow())
    updated_at: str = field(default_factory=lambda: AppLock.utcnow())


@dataclass
class AppLockPolicy:
    """
    Lock policy attached to a protected application.
    """

    policy_id: str
    app_id: str
    user_id: str
    workspace_id: str
    enabled: bool = True
    verification_required: bool = True
    verification_methods: List[str] = field(
        default_factory=lambda: ["security_agent"]
    )
    required_verification_count: int = 1
    unlock_ttl_seconds: int = DEFAULT_UNLOCK_TTL_SECONDS
    challenge_ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS
    max_failed_attempts: int = DEFAULT_MAX_FAILED_ATTEMPTS
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS
    allowed_roles: List[str] = field(default_factory=list)
    allowed_permissions: List[str] = field(default_factory=list)
    blocked_roles: List[str] = field(default_factory=list)
    bind_to_session: bool = True
    bind_to_device: bool = True
    bind_to_ip: bool = False
    relock_on_risk_change: bool = True
    relock_on_device_change: bool = True
    require_security_approval: bool = False
    minimum_risk_level_for_extra_verification: str = "high"
    high_risk_verification_methods: List[str] = field(
        default_factory=lambda: ["multi_factor"]
    )
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: AppLock.utcnow())
    updated_at: str = field(default_factory=lambda: AppLock.utcnow())


@dataclass
class VerificationChallenge:
    """
    Short-lived verification challenge.

    The challenge stores only identifiers and metadata. It never stores a raw
    password, PIN, OTP, biometric template, or other credential.
    """

    challenge_id: str
    app_id: str
    user_id: str
    workspace_id: str
    verification_methods: List[str]
    required_verification_count: int
    nonce_hash: str
    status: str = "pending"
    attempts: int = 0
    successful_methods: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address_hash: Optional[str] = None
    actor_agent: Optional[str] = None
    risk_level: str = "low"
    expires_at: str = ""
    created_at: str = field(default_factory=lambda: AppLock.utcnow())
    completed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnlockGrant:
    """
    Temporary authorization allowing access to a protected app.
    """

    grant_id: str
    app_id: str
    user_id: str
    workspace_id: str
    challenge_id: Optional[str]
    verification_methods: List[str]
    issued_at: str
    expires_at: str
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address_hash: Optional[str] = None
    actor_agent: Optional[str] = None
    risk_level_at_issue: str = "low"
    revoked: bool = False
    revoked_at: Optional[str] = None
    revoke_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureState:
    """
    Failed verification state for one app and SaaS scope.
    """

    app_id: str
    user_id: str
    workspace_id: str
    failed_attempts: int = 0
    cooldown_until: Optional[str] = None
    last_failed_at: Optional[str] = None
    updated_at: str = field(default_factory=lambda: AppLock.utcnow())


# ============================================================================
# AppLock
# ============================================================================

class AppLock(BaseAgent):
    """
    Locks sensitive applications behind verification.

    AppLock does not directly authenticate passwords, PINs, OTPs, biometrics,
    passkeys, or security keys. Instead, it delegates credential validation to
    an injected verification callback or the future Verification/Security Agent.

    This separation prevents raw credentials from entering the application-lock
    persistence layer.
    """

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR,
        storage_file: str = DEFAULT_STORAGE_FILE,
        autosave: bool = True,
        verification_callback: Optional[
            Callable[[Dict[str, Any]], Dict[str, Any]]
        ] = None,
        security_approval_callback: Optional[
            Callable[[Dict[str, Any]], Dict[str, Any]]
        ] = None,
        risk_callback: Optional[
            Callable[[Dict[str, Any]], Dict[str, Any]]
        ] = None,
        event_callback: Optional[
            Callable[[str, Dict[str, Any]], None]
        ] = None,
        audit_callback: Optional[
            Callable[[Dict[str, Any]], None]
        ] = None,
        logger: Optional[logging.Logger] = None,
        allow_test_verification: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=DEFAULT_AGENT_NAME,
            agent_id=DEFAULT_AGENT_ID,
            **kwargs,
        )

        self.agent_name = DEFAULT_AGENT_NAME
        self.agent_id = DEFAULT_AGENT_ID

        self.storage_dir = Path(storage_dir)
        self.storage_file = storage_file
        self.storage_path = self.storage_dir / self.storage_file
        self.autosave = bool(autosave)

        self.verification_callback = verification_callback
        self.security_approval_callback = security_approval_callback
        self.risk_callback = risk_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.allow_test_verification = bool(allow_test_verification)

        self.logger = logger or logging.getLogger(self.agent_name)
        self._lock = threading.RLock()

        self._apps: Dict[str, ProtectedApp] = {}
        self._policies: Dict[str, AppLockPolicy] = {}
        self._challenges: Dict[str, VerificationChallenge] = {}
        self._grants: Dict[str, UnlockGrant] = {}
        self._failures: Dict[str, FailureState] = {}

        self._load_from_disk()
        self._cleanup_expired_records()

    # ========================================================================
    # General utilities
    # ========================================================================

    @staticmethod
    def utcnow() -> str:
        """Return a timezone-aware UTC ISO timestamp."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
        """Safely parse an ISO datetime."""
        if not value:
            return None

        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _future_time(seconds: int) -> str:
        """Return an ISO timestamp a number of seconds in the future."""
        return (
            datetime.now(timezone.utc) + timedelta(seconds=max(0, seconds))
        ).isoformat()

    @staticmethod
    def _normalize(value: Any) -> str:
        """Normalize a string-like value."""
        return str(value or "").strip().lower()

    @staticmethod
    def _new_id(prefix: str) -> str:
        """Generate a readable unique identifier."""
        return f"{prefix}_{uuid.uuid4().hex}"

    @staticmethod
    def _hash_sensitive_value(value: Optional[str]) -> Optional[str]:
        """
        Hash an IP address or other context value before persistence.

        This is not used for passwords or credentials. Credential verification
        must happen in the verification callback.
        """
        if not value:
            return None

        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _constant_time_equal(left: str, right: str) -> bool:
        """Compare strings using constant-time comparison."""
        return hmac.compare_digest(str(left), str(right))

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Any] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a William/Jarvis-compatible structured result."""
        return {
            "success": bool(success),
            "message": str(message),
            "data": data if data is not None else {},
            "error": None if error is None else str(error),
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured error response."""
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error or message,
            metadata=metadata or {},
        )

    def _context_from_kwargs(
        self,
        user_id: str,
        workspace_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AppLockContext:
        """Build a normalized operation context."""
        return AppLockContext(
            user_id=str(user_id or "").strip(),
            workspace_id=str(workspace_id or "").strip(),
            actor_agent=str(actor_agent or DEFAULT_AGENT_ID).strip(),
            request_id=str(request_id or uuid.uuid4()),
            role=str(role).strip() if role is not None else None,
            permissions=[
                str(permission).strip()
                for permission in (permissions or [])
                if str(permission).strip()
            ],
            session_id=str(session_id).strip() if session_id else None,
            device_id=str(device_id).strip() if device_id else None,
            ip_address=str(ip_address).strip() if ip_address else None,
            user_agent=str(user_agent).strip() if user_agent else None,
            metadata=dict(metadata or {}),
        )

    @staticmethod
    def _app_to_dict(app: ProtectedApp) -> Dict[str, Any]:
        return asdict(app)

    @staticmethod
    def _policy_to_dict(policy: AppLockPolicy) -> Dict[str, Any]:
        return asdict(policy)

    @staticmethod
    def _challenge_to_dict(
        challenge: VerificationChallenge,
    ) -> Dict[str, Any]:
        data = asdict(challenge)

        # Internal nonce fingerprints should not be exposed to callers.
        data.pop("nonce_hash", None)
        return data

    @staticmethod
    def _grant_to_dict(grant: UnlockGrant) -> Dict[str, Any]:
        return asdict(grant)

    @staticmethod
    def _failure_to_dict(failure: FailureState) -> Dict[str, Any]:
        return asdict(failure)

    # ========================================================================
    # Required compatibility hooks
    # ========================================================================

    def _validate_task_context(
        self,
        context: Union[AppLockContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate mandatory SaaS isolation context.
        """
        try:
            if isinstance(context, dict):
                user_id = str(context.get("user_id", "")).strip()
                workspace_id = str(
                    context.get("workspace_id", "")
                ).strip()
                request_id = str(
                    context.get("request_id") or uuid.uuid4()
                )
            else:
                user_id = str(context.user_id).strip()
                workspace_id = str(context.workspace_id).strip()
                request_id = str(context.request_id or uuid.uuid4())

            if not user_id:
                return self._error_result(
                    "Missing required user_id for AppLock operation.",
                    metadata={"request_id": request_id},
                )

            if not workspace_id:
                return self._error_result(
                    "Missing required workspace_id for AppLock operation.",
                    metadata={
                        "request_id": request_id,
                        "user_id": user_id,
                    },
                )

            return self._safe_result(
                message="AppLock task context validated.",
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "request_id": request_id,
                },
                metadata={"request_id": request_id},
            )
        except Exception as exc:
            self.logger.exception("AppLock context validation failed.")
            return self._error_result(
                "AppLock context validation failed.",
                exc,
            )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Return whether an action needs explicit Security Agent approval.
        """
        normalized_action = self._normalize(action)
        payload = payload or {}

        if normalized_action in SENSITIVE_ACTIONS:
            return True

        if payload.get("force_security_check") is True:
            return True

        if payload.get("risk_level") == "critical":
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: AppLockContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from the Security Agent.

        Safe default:
            Sensitive actions are denied unless an approval callback grants
            them or the caller holds app_lock:admin.
        """
        payload = dict(payload or {})

        if not self._requires_security_check(action, payload):
            return self._safe_result(
                message="Security approval not required.",
                data={
                    "approved": True,
                    "approval_type": "not_required",
                },
                metadata={"request_id": context.request_id},
            )

        approval_request = {
            "approval_type": "app_lock_security_action",
            "action": action,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_agent": context.actor_agent,
            "request_id": context.request_id,
            "role": context.role,
            "permissions": list(context.permissions),
            "payload": payload,
            "requested_at": self.utcnow(),
        }

        try:
            if self.security_approval_callback:
                response = self.security_approval_callback(
                    approval_request
                )

                if not isinstance(response, dict):
                    return self._error_result(
                        "Security approval callback returned an invalid result.",
                        metadata={"request_id": context.request_id},
                    )

                approved = bool(response.get("approved", False))

                return self._safe_result(
                    success=approved,
                    message=(
                        "Security approval granted."
                        if approved
                        else "Security approval denied."
                    ),
                    data=response,
                    error=(
                        None
                        if approved
                        else response.get(
                            "reason",
                            "Denied by Security Agent.",
                        )
                    ),
                    metadata={"request_id": context.request_id},
                )

            has_admin_permission = (
                SAFE_PERMISSION_ADMIN in context.permissions
            )

            return self._safe_result(
                success=has_admin_permission,
                message=(
                    "Security approval granted by administrative permission."
                    if has_admin_permission
                    else "Security approval is required."
                ),
                data={
                    "approved": has_admin_permission,
                    "approval_type": "permission_fallback",
                    "required_permission": SAFE_PERMISSION_ADMIN,
                },
                error=(
                    None
                    if has_admin_permission
                    else "No Security Agent approval callback is configured."
                ),
                metadata={"request_id": context.request_id},
            )
        except Exception as exc:
            self.logger.exception(
                "AppLock security approval request failed."
            )
            return self._error_result(
                "AppLock security approval request failed.",
                exc,
                metadata={"request_id": context.request_id},
            )

    def _prepare_verification_payload(
        self,
        action: str,
        context: AppLockContext,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent-compatible payload.
        """
        return {
            "verification_type": "app_lock_action",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_agent": context.actor_agent,
            "request_id": context.request_id,
            "result_data": result_data or {},
            "checks": {
                "saas_context_present": bool(
                    context.user_id and context.workspace_id
                ),
                "workspace_isolated": True,
                "credentials_not_persisted": True,
                "structured_result": True,
                "deny_by_default": True,
            },
            "created_at": self.utcnow(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: AppLockContext,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a safe Memory Agent payload.

        Never place credentials, OTPs, PINs, biometric data, raw IP addresses,
        challenge nonces, or secret tokens in this payload.
        """
        safe_data = dict(data or {})

        for sensitive_key in {
            "password",
            "pin",
            "otp",
            "totp",
            "credential",
            "credentials",
            "secret",
            "token",
            "nonce",
            "raw_response",
            "ip_address",
            "biometric",
        }:
            safe_data.pop(sensitive_key, None)

        return {
            "memory_type": "security_app_lock_event",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": action,
            "summary": summary,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_agent": context.actor_agent,
            "request_id": context.request_id,
            "data": safe_data,
            "created_at": self.utcnow(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """Emit an AppLock event to the Agent Registry or dashboard."""
        try:
            safe_payload = dict(payload or {})
            safe_payload.setdefault("agent_id", self.agent_id)
            safe_payload.setdefault("agent_name", self.agent_name)
            safe_payload.setdefault("timestamp", self.utcnow())

            if self.event_callback:
                self.event_callback(event_name, safe_payload)
                return

            try:
                super().emit_event(event_name, safe_payload)
                return
            except Exception:
                self.logger.debug(
                    "AppLock event: %s %s",
                    event_name,
                    safe_payload,
                )
        except Exception:
            self.logger.exception("Failed to emit AppLock event.")

    def _log_audit_event(
        self,
        action: str,
        context: AppLockContext,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """Emit an audit record without storing raw credentials."""
        try:
            safe_details = dict(details or {})

            for sensitive_key in {
                "password",
                "pin",
                "otp",
                "totp",
                "credential",
                "secret",
                "token",
                "nonce",
                "verification_data",
                "ip_address",
            }:
                safe_details.pop(sensitive_key, None)

            payload = {
                "event_type": "app_lock_audit",
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "action": action,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "actor_agent": context.actor_agent,
                "request_id": context.request_id,
                "role": context.role,
                "session_id": context.session_id,
                "device_id": context.device_id,
                "success": bool(success),
                "error": error,
                "details": safe_details,
                "timestamp": self.utcnow(),
            }

            if self.audit_callback:
                self.audit_callback(payload)
                return

            try:
                super().log_audit(payload)
                return
            except Exception:
                self.logger.info("AppLock audit: %s", payload)
        except Exception:
            self.logger.exception("Failed to log AppLock audit event.")

    # ========================================================================
    # Persistence
    # ========================================================================

    def _ensure_storage_dir(self) -> None:
        """Create the AppLock storage directory."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _load_from_disk(self) -> None:
        """Load AppLock state from JSON storage."""
        with self._lock:
            try:
                self._ensure_storage_dir()

                if not self.storage_path.exists():
                    return

                with self.storage_path.open(
                    "r",
                    encoding="utf-8",
                ) as file:
                    raw = json.load(file)

                self._apps = {
                    app_id: ProtectedApp(**app_data)
                    for app_id, app_data in raw.get("apps", {}).items()
                    if isinstance(app_data, dict)
                }

                self._policies = {
                    app_id: AppLockPolicy(**policy_data)
                    for app_id, policy_data in raw.get(
                        "policies",
                        {},
                    ).items()
                    if isinstance(policy_data, dict)
                }

                self._challenges = {
                    challenge_id: VerificationChallenge(**challenge_data)
                    for challenge_id, challenge_data in raw.get(
                        "challenges",
                        {},
                    ).items()
                    if isinstance(challenge_data, dict)
                }

                self._grants = {
                    grant_id: UnlockGrant(**grant_data)
                    for grant_id, grant_data in raw.get(
                        "grants",
                        {},
                    ).items()
                    if isinstance(grant_data, dict)
                }

                self._failures = {
                    failure_key: FailureState(**failure_data)
                    for failure_key, failure_data in raw.get(
                        "failures",
                        {},
                    ).items()
                    if isinstance(failure_data, dict)
                }

                self.logger.info(
                    "AppLock state loaded: %s apps, %s policies, "
                    "%s challenges, %s grants.",
                    len(self._apps),
                    len(self._policies),
                    len(self._challenges),
                    len(self._grants),
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to load AppLock state: %s",
                    exc,
                )

                # Deny-by-default behavior is preserved because empty state
                # does not create any active unlock grant.
                self._apps = {}
                self._policies = {}
                self._challenges = {}
                self._grants = {}
                self._failures = {}

    def save(self) -> Dict[str, Any]:
        """Persist AppLock state using an atomic JSON replacement."""
        with self._lock:
            try:
                self._ensure_storage_dir()

                payload = {
                    "metadata": {
                        "agent_id": self.agent_id,
                        "agent_name": self.agent_name,
                        "saved_at": self.utcnow(),
                        "app_count": len(self._apps),
                        "policy_count": len(self._policies),
                        "challenge_count": len(self._challenges),
                        "grant_count": len(self._grants),
                    },
                    "apps": {
                        app_id: asdict(app)
                        for app_id, app in self._apps.items()
                    },
                    "policies": {
                        app_id: asdict(policy)
                        for app_id, policy in self._policies.items()
                    },
                    "challenges": {
                        challenge_id: asdict(challenge)
                        for challenge_id, challenge
                        in self._challenges.items()
                    },
                    "grants": {
                        grant_id: asdict(grant)
                        for grant_id, grant in self._grants.items()
                    },
                    "failures": {
                        failure_key: asdict(failure)
                        for failure_key, failure
                        in self._failures.items()
                    },
                }

                temporary_path = self.storage_path.with_suffix(".tmp")

                with temporary_path.open(
                    "w",
                    encoding="utf-8",
                ) as file:
                    json.dump(
                        payload,
                        file,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )

                os.replace(temporary_path, self.storage_path)

                return self._safe_result(
                    message="AppLock state saved successfully.",
                    data={
                        "storage_path": str(self.storage_path),
                        "app_count": len(self._apps),
                        "policy_count": len(self._policies),
                        "challenge_count": len(self._challenges),
                        "grant_count": len(self._grants),
                    },
                )
            except Exception as exc:
                self.logger.exception("Failed to save AppLock state.")
                return self._error_result(
                    "Failed to save AppLock state.",
                    exc,
                )

    def _autosave(self) -> None:
        """Persist state when autosave is enabled."""
        if not self.autosave:
            return

        result = self.save()

        if not result.get("success"):
            self.logger.warning(
                "AppLock autosave failed: %s",
                result.get("error"),
            )

    # ========================================================================
    # Validation and scope helpers
    # ========================================================================

    def _normalize_app_type(self, app_type: str) -> str:
        normalized = self._normalize(app_type) or "custom"
        return (
            normalized
            if normalized in SUPPORTED_APP_TYPES
            else "custom"
        )

    def _normalize_verification_methods(
        self,
        methods: Optional[Iterable[str]],
    ) -> List[str]:
        normalized: List[str] = []

        for method in methods or []:
            clean_method = self._normalize(method)

            if not clean_method:
                continue

            if clean_method not in SUPPORTED_VERIFICATION_METHODS:
                clean_method = "custom"

            if clean_method not in normalized:
                normalized.append(clean_method)

        return normalized or ["security_agent"]

    def _normalize_risk_level(self, risk_level: Any) -> str:
        normalized = self._normalize(risk_level) or "low"
        return (
            normalized
            if normalized in SUPPORTED_RISK_LEVELS
            else "low"
        )

    @staticmethod
    def _risk_rank(risk_level: str) -> int:
        return {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }.get(risk_level, 1)

    def _app_visible(
        self,
        app: ProtectedApp,
        context: AppLockContext,
    ) -> bool:
        return (
            app.user_id == context.user_id
            and app.workspace_id == context.workspace_id
            and app.is_active
        )

    def _policy_visible(
        self,
        policy: AppLockPolicy,
        context: AppLockContext,
    ) -> bool:
        return (
            policy.user_id == context.user_id
            and policy.workspace_id == context.workspace_id
        )

    def _challenge_visible(
        self,
        challenge: VerificationChallenge,
        context: AppLockContext,
    ) -> bool:
        return (
            challenge.user_id == context.user_id
            and challenge.workspace_id == context.workspace_id
        )

    def _grant_visible(
        self,
        grant: UnlockGrant,
        context: AppLockContext,
    ) -> bool:
        return (
            grant.user_id == context.user_id
            and grant.workspace_id == context.workspace_id
        )

    def _get_app_or_error(
        self,
        app_id: str,
        context: AppLockContext,
    ) -> Tuple[Optional[ProtectedApp], Optional[Dict[str, Any]]]:
        app = self._apps.get(app_id)

        if not app or not self._app_visible(app, context):
            return None, self._error_result(
                "Protected app was not found in this user/workspace scope.",
                metadata={
                    "app_id": app_id,
                    "request_id": context.request_id,
                },
            )

        return app, None

    def _get_policy_or_error(
        self,
        app_id: str,
        context: AppLockContext,
    ) -> Tuple[Optional[AppLockPolicy], Optional[Dict[str, Any]]]:
        policy = self._policies.get(app_id)

        if not policy or not self._policy_visible(policy, context):
            return None, self._error_result(
                "App lock policy was not found in this user/workspace scope.",
                metadata={
                    "app_id": app_id,
                    "request_id": context.request_id,
                },
            )

        return policy, None

    def _failure_key(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
    ) -> str:
        raw = f"{user_id}:{workspace_id}:{app_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _is_expired(self, value: Optional[str]) -> bool:
        parsed = self._parse_datetime(value)

        if parsed is None:
            return True

        return datetime.now(timezone.utc) >= parsed

    def _cleanup_expired_records(self) -> None:
        """
        Mark expired challenges and grants.

        Records are retained for audit continuity but are no longer valid.
        """
        with self._lock:
            changed = False

            for challenge in self._challenges.values():
                if (
                    challenge.status == "pending"
                    and self._is_expired(challenge.expires_at)
                ):
                    challenge.status = "expired"
                    changed = True

            for grant in self._grants.values():
                if (
                    not grant.revoked
                    and self._is_expired(grant.expires_at)
                ):
                    grant.revoked = True
                    grant.revoked_at = self.utcnow()
                    grant.revoke_reason = "expired"
                    changed = True

            if changed:
                self._autosave()

    def _check_cooldown(
        self,
        app_id: str,
        context: AppLockContext,
    ) -> Dict[str, Any]:
        failure_key = self._failure_key(
            context.user_id,
            context.workspace_id,
            app_id,
        )
        failure = self._failures.get(failure_key)

        if not failure or not failure.cooldown_until:
            return self._safe_result(
                message="No verification cooldown is active.",
                data={"cooldown_active": False},
                metadata={"request_id": context.request_id},
            )

        cooldown_time = self._parse_datetime(failure.cooldown_until)

        if (
            cooldown_time is not None
            and datetime.now(timezone.utc) < cooldown_time
        ):
            return self._safe_result(
                success=False,
                message="Verification is temporarily blocked.",
                data={
                    "cooldown_active": True,
                    "cooldown_until": failure.cooldown_until,
                    "failed_attempts": failure.failed_attempts,
                },
                error="Too many failed verification attempts.",
                metadata={"request_id": context.request_id},
            )

        failure.cooldown_until = None
        failure.failed_attempts = 0
        failure.updated_at = self.utcnow()
        self._autosave()

        return self._safe_result(
            message="Verification cooldown has expired.",
            data={"cooldown_active": False},
            metadata={"request_id": context.request_id},
        )

    def _record_verification_failure(
        self,
        app_id: str,
        context: AppLockContext,
        policy: AppLockPolicy,
    ) -> FailureState:
        failure_key = self._failure_key(
            context.user_id,
            context.workspace_id,
            app_id,
        )

        failure = self._failures.get(failure_key)

        if failure is None:
            failure = FailureState(
                app_id=app_id,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
            )

        failure.failed_attempts += 1
        failure.last_failed_at = self.utcnow()
        failure.updated_at = self.utcnow()

        if failure.failed_attempts >= policy.max_failed_attempts:
            failure.cooldown_until = self._future_time(
                policy.cooldown_seconds
            )

        self._failures[failure_key] = failure
        return failure

    def _clear_verification_failures(
        self,
        app_id: str,
        context: AppLockContext,
    ) -> None:
        failure_key = self._failure_key(
            context.user_id,
            context.workspace_id,
            app_id,
        )

        if failure_key in self._failures:
            self._failures[failure_key] = FailureState(
                app_id=app_id,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
            )

    def _evaluate_role_and_permission(
        self,
        policy: AppLockPolicy,
        context: AppLockContext,
    ) -> Dict[str, Any]:
        """
        Evaluate role and permission constraints before verification.
        """
        role = context.role or ""
        caller_permissions = set(context.permissions)

        if role and role in policy.blocked_roles:
            return self._error_result(
                "The current role is blocked from this application.",
                metadata={
                    "role": role,
                    "request_id": context.request_id,
                },
            )

        if policy.allowed_roles:
            if not role or role not in policy.allowed_roles:
                return self._error_result(
                    "The current role is not allowed to access this application.",
                    metadata={
                        "role": role,
                        "allowed_roles": list(policy.allowed_roles),
                        "request_id": context.request_id,
                    },
                )

        if policy.allowed_permissions:
            missing_permissions = [
                permission
                for permission in policy.allowed_permissions
                if permission not in caller_permissions
            ]

            if missing_permissions:
                return self._error_result(
                    "Required application permissions are missing.",
                    metadata={
                        "missing_permissions": missing_permissions,
                        "request_id": context.request_id,
                    },
                )

        return self._safe_result(
            message="Role and permission requirements passed.",
            data={"authorized": True},
            metadata={"request_id": context.request_id},
        )

    def _evaluate_risk(
        self,
        app: ProtectedApp,
        policy: AppLockPolicy,
        context: AppLockContext,
        supplied_risk_level: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate access risk through the Risk Engine callback when available.
        """
        risk_level = self._normalize_risk_level(
            supplied_risk_level or context.metadata.get("risk_level")
        )
        reasons: List[str] = []

        request_payload = {
            "assessment_type": "app_lock_access",
            "app_id": app.app_id,
            "app_name": app.app_name,
            "app_type": app.app_type,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_agent": context.actor_agent,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "device_id": context.device_id,
            "ip_address_hash": self._hash_sensitive_value(
                context.ip_address
            ),
            "user_agent_hash": self._hash_sensitive_value(
                context.user_agent
            ),
            "supplied_risk_level": risk_level,
            "metadata": dict(context.metadata),
            "timestamp": self.utcnow(),
        }

        try:
            if self.risk_callback:
                response = self.risk_callback(request_payload)

                if isinstance(response, dict):
                    risk_level = self._normalize_risk_level(
                        response.get("risk_level", risk_level)
                    )
                    reasons = [
                        str(reason)
                        for reason in response.get("reasons", [])
                    ]

            extra_verification_required = (
                self._risk_rank(risk_level)
                >= self._risk_rank(
                    policy.minimum_risk_level_for_extra_verification
                )
            )

            return self._safe_result(
                message="Application access risk evaluated.",
                data={
                    "risk_level": risk_level,
                    "reasons": reasons,
                    "extra_verification_required": (
                        extra_verification_required
                    ),
                },
                metadata={"request_id": context.request_id},
            )
        except Exception as exc:
            self.logger.exception("AppLock risk evaluation failed.")

            # Fail safely. An unavailable risk engine produces high risk.
            return self._safe_result(
                message="Risk evaluation failed; high-risk controls applied.",
                data={
                    "risk_level": "high",
                    "reasons": ["risk_engine_unavailable"],
                    "extra_verification_required": True,
                },
                metadata={
                    "request_id": context.request_id,
                    "risk_error": str(exc),
                },
            )

    # ========================================================================
    # App registration and policy management
    # ========================================================================

    def register_app(
        self,
        user_id: str,
        workspace_id: str,
        app_name: str,
        app_type: str = "application",
        description: Optional[str] = None,
        resource_identifier: Optional[str] = None,
        tags: Optional[List[str]] = None,
        app_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        create_default_policy: bool = True,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a sensitive application or resource."""
        context = self._context_from_kwargs(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_agent=actor_agent,
            request_id=request_id,
            role=role,
            permissions=permissions,
            session_id=session_id,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        clean_name = str(app_name or "").strip()

        if not clean_name:
            return self._error_result(
                "app_name is required.",
                metadata={"request_id": context.request_id},
            )

        approval = self._request_security_approval(
            "register_app",
            context,
            {
                "app_name": clean_name,
                "app_type": app_type,
                "resource_identifier": resource_identifier,
            },
        )

        if not approval["success"]:
            return approval

        with self._lock:
            try:
                normalized_app_id = (
                    str(app_id).strip()
                    if app_id
                    else self._new_id("app")
                )

                existing_app = self._apps.get(normalized_app_id)

                if existing_app and existing_app.is_active:
                    if (
                        existing_app.user_id != context.user_id
                        or existing_app.workspace_id
                        != context.workspace_id
                    ):
                        return self._error_result(
                            "app_id already exists in another SaaS scope.",
                            metadata={
                                "app_id": normalized_app_id,
                                "request_id": context.request_id,
                            },
                        )

                    return self._error_result(
                        "app_id is already registered.",
                        metadata={
                            "app_id": normalized_app_id,
                            "request_id": context.request_id,
                        },
                    )

                now = self.utcnow()

                app = ProtectedApp(
                    app_id=normalized_app_id,
                    app_name=clean_name,
                    app_type=self._normalize_app_type(app_type),
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    description=(
                        str(description).strip()
                        if description
                        else None
                    ),
                    resource_identifier=(
                        str(resource_identifier).strip()
                        if resource_identifier
                        else None
                    ),
                    tags=[
                        str(tag).strip()
                        for tag in (tags or [])
                        if str(tag).strip()
                    ],
                    metadata=dict(metadata or {}),
                    is_active=True,
                    created_by=context.actor_agent,
                    updated_by=context.actor_agent,
                    created_at=now,
                    updated_at=now,
                )

                self._apps[app.app_id] = app

                policy: Optional[AppLockPolicy] = None

                if create_default_policy:
                    policy = AppLockPolicy(
                        policy_id=self._new_id("policy"),
                        app_id=app.app_id,
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        created_by=context.actor_agent,
                        updated_by=context.actor_agent,
                    )
                    self._policies[app.app_id] = policy

                self._autosave()

                app_data = self._app_to_dict(app)
                policy_data = (
                    self._policy_to_dict(policy)
                    if policy is not None
                    else None
                )

                verification_payload = (
                    self._prepare_verification_payload(
                        "register_app",
                        context,
                        {
                            "app_id": app.app_id,
                            "policy_created": policy is not None,
                        },
                    )
                )

                memory_payload = self._prepare_memory_payload(
                    "register_app",
                    context,
                    f"Registered protected app: {app.app_name}",
                    {
                        "app_id": app.app_id,
                        "app_name": app.app_name,
                        "app_type": app.app_type,
                    },
                )

                self._emit_agent_event(
                    "security.app_lock.app_registered",
                    {
                        "app": app_data,
                        "policy": policy_data,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "register_app",
                    context,
                    {
                        "app_id": app.app_id,
                        "app_name": app.app_name,
                        "app_type": app.app_type,
                    },
                )

                return self._safe_result(
                    message="Protected application registered successfully.",
                    data={
                        "app": app_data,
                        "policy": policy_data,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to register protected application."
                )
                self._log_audit_event(
                    "register_app",
                    context,
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to register protected application.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def update_app(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        app_name: Optional[str] = None,
        app_type: Optional[str] = None,
        description: Optional[str] = None,
        resource_identifier: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a protected application registration."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "update_app",
            context,
            {"app_id": app_id},
        )

        if not approval["success"]:
            return approval

        with self._lock:
            try:
                app, error = self._get_app_or_error(app_id, context)

                if error:
                    return error

                assert app is not None

                if app_name is not None:
                    clean_name = str(app_name).strip()

                    if not clean_name:
                        return self._error_result(
                            "app_name cannot be empty.",
                            metadata={
                                "app_id": app_id,
                                "request_id": context.request_id,
                            },
                        )

                    app.app_name = clean_name

                if app_type is not None:
                    app.app_type = self._normalize_app_type(app_type)

                if description is not None:
                    app.description = str(description).strip() or None

                if resource_identifier is not None:
                    app.resource_identifier = (
                        str(resource_identifier).strip() or None
                    )

                if tags is not None:
                    app.tags = [
                        str(tag).strip()
                        for tag in tags
                        if str(tag).strip()
                    ]

                if metadata is not None:
                    app.metadata = dict(metadata)

                app.updated_by = context.actor_agent
                app.updated_at = self.utcnow()

                self._autosave()

                app_data = self._app_to_dict(app)

                self._emit_agent_event(
                    "security.app_lock.app_updated",
                    {
                        "app": app_data,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "update_app",
                    context,
                    {"app_id": app_id},
                )

                return self._safe_result(
                    message="Protected application updated successfully.",
                    data={
                        "app": app_data,
                        "verification_payload": (
                            self._prepare_verification_payload(
                                "update_app",
                                context,
                                {"app_id": app_id},
                            )
                        ),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to update protected application."
                )
                self._log_audit_event(
                    "update_app",
                    context,
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to update protected application.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def set_lock_policy(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        enabled: bool = True,
        verification_required: bool = True,
        verification_methods: Optional[List[str]] = None,
        required_verification_count: int = 1,
        unlock_ttl_seconds: int = DEFAULT_UNLOCK_TTL_SECONDS,
        challenge_ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS,
        max_failed_attempts: int = DEFAULT_MAX_FAILED_ATTEMPTS,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
        allowed_roles: Optional[List[str]] = None,
        allowed_permissions: Optional[List[str]] = None,
        blocked_roles: Optional[List[str]] = None,
        bind_to_session: bool = True,
        bind_to_device: bool = True,
        bind_to_ip: bool = False,
        relock_on_risk_change: bool = True,
        relock_on_device_change: bool = True,
        require_security_approval: bool = False,
        minimum_risk_level_for_extra_verification: str = "high",
        high_risk_verification_methods: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or replace an application's lock policy."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "set_lock_policy",
            context,
            {
                "app_id": app_id,
                "enabled": enabled,
                "verification_required": verification_required,
            },
        )

        if not approval["success"]:
            return approval

        with self._lock:
            try:
                app, error = self._get_app_or_error(app_id, context)

                if error:
                    return error

                assert app is not None

                normalized_methods = (
                    self._normalize_verification_methods(
                        verification_methods
                    )
                )
                normalized_high_risk_methods = (
                    self._normalize_verification_methods(
                        high_risk_verification_methods
                        or ["multi_factor"]
                    )
                )

                clean_required_count = max(
                    1,
                    min(
                        int(required_verification_count),
                        len(normalized_methods),
                    ),
                )

                clean_unlock_ttl = max(
                    30,
                    min(
                        int(unlock_ttl_seconds),
                        DEFAULT_MAX_UNLOCK_TTL_SECONDS,
                    ),
                )

                clean_challenge_ttl = max(
                    30,
                    min(int(challenge_ttl_seconds), 3600),
                )

                clean_max_attempts = max(
                    1,
                    min(int(max_failed_attempts), 50),
                )

                clean_cooldown = max(
                    30,
                    min(int(cooldown_seconds), 86_400),
                )

                existing_policy = self._policies.get(app_id)
                now = self.utcnow()

                policy = AppLockPolicy(
                    policy_id=(
                        existing_policy.policy_id
                        if existing_policy
                        else self._new_id("policy")
                    ),
                    app_id=app_id,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    enabled=bool(enabled),
                    verification_required=bool(
                        verification_required
                    ),
                    verification_methods=normalized_methods,
                    required_verification_count=clean_required_count,
                    unlock_ttl_seconds=clean_unlock_ttl,
                    challenge_ttl_seconds=clean_challenge_ttl,
                    max_failed_attempts=clean_max_attempts,
                    cooldown_seconds=clean_cooldown,
                    allowed_roles=[
                        str(item).strip()
                        for item in (allowed_roles or [])
                        if str(item).strip()
                    ],
                    allowed_permissions=[
                        str(item).strip()
                        for item in (allowed_permissions or [])
                        if str(item).strip()
                    ],
                    blocked_roles=[
                        str(item).strip()
                        for item in (blocked_roles or [])
                        if str(item).strip()
                    ],
                    bind_to_session=bool(bind_to_session),
                    bind_to_device=bool(bind_to_device),
                    bind_to_ip=bool(bind_to_ip),
                    relock_on_risk_change=bool(
                        relock_on_risk_change
                    ),
                    relock_on_device_change=bool(
                        relock_on_device_change
                    ),
                    require_security_approval=bool(
                        require_security_approval
                    ),
                    minimum_risk_level_for_extra_verification=(
                        self._normalize_risk_level(
                            minimum_risk_level_for_extra_verification
                        )
                    ),
                    high_risk_verification_methods=(
                        normalized_high_risk_methods
                    ),
                    metadata=dict(metadata or {}),
                    created_by=(
                        existing_policy.created_by
                        if existing_policy
                        else context.actor_agent
                    ),
                    updated_by=context.actor_agent,
                    created_at=(
                        existing_policy.created_at
                        if existing_policy
                        else now
                    ),
                    updated_at=now,
                )

                self._policies[app_id] = policy

                # Policy changes invalidate previous grants.
                revoked_count = self._revoke_grants_internal(
                    context=context,
                    app_id=app_id,
                    reason="lock_policy_updated",
                )

                self._autosave()

                policy_data = self._policy_to_dict(policy)

                self._emit_agent_event(
                    "security.app_lock.policy_updated",
                    {
                        "app_id": app_id,
                        "policy": policy_data,
                        "revoked_grants": revoked_count,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "set_lock_policy",
                    context,
                    {
                        "app_id": app_id,
                        "enabled": policy.enabled,
                        "verification_required": (
                            policy.verification_required
                        ),
                        "revoked_grants": revoked_count,
                    },
                )

                return self._safe_result(
                    message="Application lock policy saved successfully.",
                    data={
                        "app": self._app_to_dict(app),
                        "policy": policy_data,
                        "revoked_grants": revoked_count,
                        "verification_payload": (
                            self._prepare_verification_payload(
                                "set_lock_policy",
                                context,
                                {
                                    "app_id": app_id,
                                    "policy_id": policy.policy_id,
                                    "revoked_grants": revoked_count,
                                },
                            )
                        ),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to save application lock policy."
                )
                self._log_audit_event(
                    "set_lock_policy",
                    context,
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to save application lock policy.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def get_app(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return one protected app and its policy."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            app, error = self._get_app_or_error(app_id, context)

            if error:
                return error

            policy = self._policies.get(app_id)

            return self._safe_result(
                message="Protected application retrieved.",
                data={
                    "app": self._app_to_dict(app),  # type: ignore[arg-type]
                    "policy": (
                        self._policy_to_dict(policy)
                        if policy
                        and self._policy_visible(policy, context)
                        else None
                    ),
                },
                metadata={"request_id": context.request_id},
            )

    def list_apps(
        self,
        user_id: str,
        workspace_id: str,
        app_type: Optional[str] = None,
        search: Optional[str] = None,
        locked_only: bool = False,
        limit: int = 100,
        offset: int = 0,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List protected apps inside one SaaS scope."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        clean_type = (
            self._normalize_app_type(app_type)
            if app_type
            else None
        )
        clean_search = self._normalize(search)

        with self._lock:
            try:
                records: List[Dict[str, Any]] = []

                for app in self._apps.values():
                    if not self._app_visible(app, context):
                        continue

                    if clean_type and app.app_type != clean_type:
                        continue

                    policy = self._policies.get(app.app_id)

                    if locked_only and (
                        policy is None
                        or not policy.enabled
                        or not policy.verification_required
                    ):
                        continue

                    if clean_search:
                        haystack = " ".join(
                            [
                                app.app_id,
                                app.app_name,
                                app.app_type,
                                app.description or "",
                                app.resource_identifier or "",
                                " ".join(app.tags),
                                json.dumps(
                                    app.metadata,
                                    ensure_ascii=False,
                                    default=str,
                                ),
                            ]
                        ).lower()

                        if clean_search not in haystack:
                            continue

                    records.append(
                        {
                            "app": self._app_to_dict(app),
                            "policy": (
                                self._policy_to_dict(policy)
                                if policy
                                and self._policy_visible(
                                    policy,
                                    context,
                                )
                                else None
                            ),
                        }
                    )

                records.sort(
                    key=lambda item: item["app"]["updated_at"],
                    reverse=True,
                )

                total = len(records)
                clean_offset = max(0, int(offset))
                clean_limit = max(1, min(int(limit), 500))

                return self._safe_result(
                    message="Protected applications listed successfully.",
                    data={
                        "apps": records[
                            clean_offset:
                            clean_offset + clean_limit
                        ],
                        "total": total,
                        "limit": clean_limit,
                        "offset": clean_offset,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to list protected applications."
                )
                return self._error_result(
                    "Failed to list protected applications.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def remove_app(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        soft_delete: bool = True,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remove a protected app registration."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "remove_app",
            context,
            {
                "app_id": app_id,
                "soft_delete": soft_delete,
            },
        )

        if not approval["success"]:
            return approval

        with self._lock:
            try:
                app, error = self._get_app_or_error(app_id, context)

                if error:
                    return error

                assert app is not None

                revoked_count = self._revoke_grants_internal(
                    context,
                    app_id,
                    "app_removed",
                )

                for challenge in self._challenges.values():
                    if (
                        challenge.app_id == app_id
                        and self._challenge_visible(
                            challenge,
                            context,
                        )
                        and challenge.status == "pending"
                    ):
                        challenge.status = "cancelled"

                if soft_delete:
                    app.is_active = False
                    app.updated_by = context.actor_agent
                    app.updated_at = self.utcnow()

                    policy = self._policies.get(app_id)
                    if policy:
                        policy.enabled = False
                        policy.updated_by = context.actor_agent
                        policy.updated_at = self.utcnow()
                else:
                    self._apps.pop(app_id, None)
                    self._policies.pop(app_id, None)

                self._autosave()

                self._emit_agent_event(
                    "security.app_lock.app_removed",
                    {
                        "app_id": app_id,
                        "soft_delete": soft_delete,
                        "revoked_grants": revoked_count,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "remove_app",
                    context,
                    {
                        "app_id": app_id,
                        "soft_delete": soft_delete,
                        "revoked_grants": revoked_count,
                    },
                )

                return self._safe_result(
                    message="Protected application removed successfully.",
                    data={
                        "app_id": app_id,
                        "soft_delete": soft_delete,
                        "revoked_grants": revoked_count,
                        "verification_payload": (
                            self._prepare_verification_payload(
                                "remove_app",
                                context,
                                {
                                    "app_id": app_id,
                                    "soft_delete": soft_delete,
                                },
                            )
                        ),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to remove protected application."
                )
                self._log_audit_event(
                    "remove_app",
                    context,
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to remove protected application.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    # ========================================================================
    # Verification challenges
    # ========================================================================

    def create_verification_challenge(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        requested_methods: Optional[List[str]] = None,
        risk_level: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a short-lived verification challenge.

        A random nonce is returned once to the caller. Only its SHA-256
        fingerprint is persisted.
        """
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                self._cleanup_expired_records()

                app, app_error = self._get_app_or_error(
                    app_id,
                    context,
                )
                if app_error:
                    return app_error

                policy, policy_error = self._get_policy_or_error(
                    app_id,
                    context,
                )
                if policy_error:
                    return policy_error

                assert app is not None
                assert policy is not None

                if not policy.enabled:
                    return self._safe_result(
                        message="App lock policy is disabled.",
                        data={
                            "challenge_required": False,
                            "app_id": app_id,
                        },
                        metadata={"request_id": context.request_id},
                    )

                authorization = self._evaluate_role_and_permission(
                    policy,
                    context,
                )
                if not authorization["success"]:
                    self._log_audit_event(
                        "create_verification_challenge",
                        context,
                        {
                            "app_id": app_id,
                            "reason": "authorization_failed",
                        },
                        success=False,
                        error=authorization.get("error"),
                    )
                    return authorization

                cooldown = self._check_cooldown(app_id, context)
                if not cooldown["success"]:
                    self._log_audit_event(
                        "create_verification_challenge",
                        context,
                        {
                            "app_id": app_id,
                            "reason": "cooldown_active",
                        },
                        success=False,
                        error=cooldown.get("error"),
                    )
                    return cooldown

                risk_result = self._evaluate_risk(
                    app,
                    policy,
                    context,
                    supplied_risk_level=risk_level,
                )

                evaluated_risk = risk_result["data"]["risk_level"]
                extra_verification = risk_result["data"][
                    "extra_verification_required"
                ]

                methods = self._normalize_verification_methods(
                    requested_methods
                    or policy.verification_methods
                )

                # A caller may request only methods already authorized by policy.
                unauthorized_methods = [
                    method
                    for method in methods
                    if method not in policy.verification_methods
                    and method
                    not in policy.high_risk_verification_methods
                ]

                if unauthorized_methods:
                    return self._error_result(
                        "One or more requested verification methods are not "
                        "allowed by the application policy.",
                        metadata={
                            "unauthorized_methods": unauthorized_methods,
                            "request_id": context.request_id,
                        },
                    )

                required_count = policy.required_verification_count

                if extra_verification:
                    for method in policy.high_risk_verification_methods:
                        if method not in methods:
                            methods.append(method)

                    required_count = min(
                        len(methods),
                        max(required_count + 1, 2),
                    )

                if policy.require_security_approval:
                    if "security_agent" not in methods:
                        methods.append("security_agent")
                    required_count = min(
                        len(methods),
                        max(required_count, 1),
                    )

                nonce = secrets.token_urlsafe(32)
                nonce_hash = hashlib.sha256(
                    nonce.encode("utf-8")
                ).hexdigest()

                challenge = VerificationChallenge(
                    challenge_id=self._new_id("challenge"),
                    app_id=app_id,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    verification_methods=methods,
                    required_verification_count=required_count,
                    nonce_hash=nonce_hash,
                    status="pending",
                    attempts=0,
                    successful_methods=[],
                    session_id=context.session_id,
                    device_id=context.device_id,
                    ip_address_hash=self._hash_sensitive_value(
                        context.ip_address
                    ),
                    actor_agent=context.actor_agent,
                    risk_level=evaluated_risk,
                    expires_at=self._future_time(
                        policy.challenge_ttl_seconds
                    ),
                    metadata=dict(metadata or {}),
                )

                self._challenges[
                    challenge.challenge_id
                ] = challenge

                self._autosave()

                challenge_data = self._challenge_to_dict(challenge)

                self._emit_agent_event(
                    "security.app_lock.challenge_created",
                    {
                        "challenge": challenge_data,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "create_verification_challenge",
                    context,
                    {
                        "app_id": app_id,
                        "challenge_id": challenge.challenge_id,
                        "verification_methods": methods,
                        "required_verification_count": required_count,
                        "risk_level": evaluated_risk,
                    },
                )

                return self._safe_result(
                    message="Verification challenge created.",
                    data={
                        "app": self._app_to_dict(app),
                        "challenge": challenge_data,
                        "challenge_nonce": nonce,
                        "risk": risk_result["data"],
                    },
                    metadata={
                        "request_id": context.request_id,
                        "security_notice": (
                            "The challenge nonce is returned once and is not "
                            "stored in plaintext."
                        ),
                    },
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to create AppLock verification challenge."
                )
                self._log_audit_event(
                    "create_verification_challenge",
                    context,
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to create verification challenge.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def complete_verification(
        self,
        user_id: str,
        workspace_id: str,
        challenge_id: str,
        challenge_nonce: str,
        verification_method: str,
        verification_data: Optional[Dict[str, Any]] = None,
        risk_level: Optional[str] = None,
        unlock_ttl_seconds: Optional[int] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Complete one verification step.

        verification_data is passed to the verification callback but is never
        persisted, returned, emitted, logged, or added to memory.
        """
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        method = self._normalize(verification_method)

        if method not in SUPPORTED_VERIFICATION_METHODS:
            return self._error_result(
                "Unsupported verification method.",
                metadata={
                    "verification_method": method,
                    "request_id": context.request_id,
                },
            )

        with self._lock:
            try:
                self._cleanup_expired_records()

                challenge = self._challenges.get(challenge_id)

                if (
                    not challenge
                    or not self._challenge_visible(
                        challenge,
                        context,
                    )
                ):
                    return self._error_result(
                        "Verification challenge was not found in this scope.",
                        metadata={
                            "challenge_id": challenge_id,
                            "request_id": context.request_id,
                        },
                    )

                if challenge.status != "pending":
                    return self._error_result(
                        "Verification challenge is not pending.",
                        metadata={
                            "challenge_id": challenge_id,
                            "challenge_status": challenge.status,
                            "request_id": context.request_id,
                        },
                    )

                if self._is_expired(challenge.expires_at):
                    challenge.status = "expired"
                    self._autosave()

                    return self._error_result(
                        "Verification challenge has expired.",
                        metadata={
                            "challenge_id": challenge_id,
                            "request_id": context.request_id,
                        },
                    )

                app, app_error = self._get_app_or_error(
                    challenge.app_id,
                    context,
                )
                if app_error:
                    return app_error

                policy, policy_error = self._get_policy_or_error(
                    challenge.app_id,
                    context,
                )
                if policy_error:
                    return policy_error

                assert app is not None
                assert policy is not None

                cooldown = self._check_cooldown(
                    challenge.app_id,
                    context,
                )
                if not cooldown["success"]:
                    return cooldown

                supplied_nonce_hash = hashlib.sha256(
                    str(challenge_nonce).encode("utf-8")
                ).hexdigest()

                if not self._constant_time_equal(
                    supplied_nonce_hash,
                    challenge.nonce_hash,
                ):
                    challenge.attempts += 1

                    failure = self._record_verification_failure(
                        challenge.app_id,
                        context,
                        policy,
                    )

                    if (
                        failure.failed_attempts
                        >= policy.max_failed_attempts
                    ):
                        challenge.status = "blocked"

                    self._autosave()

                    self._log_audit_event(
                        "complete_verification",
                        context,
                        {
                            "app_id": challenge.app_id,
                            "challenge_id": challenge_id,
                            "verification_method": method,
                            "reason": "invalid_challenge_nonce",
                            "failed_attempts": (
                                failure.failed_attempts
                            ),
                        },
                        success=False,
                        error="Invalid challenge nonce.",
                    )

                    return self._error_result(
                        "Verification challenge validation failed.",
                        error="Invalid challenge nonce.",
                        metadata={
                            "challenge_id": challenge_id,
                            "failed_attempts": failure.failed_attempts,
                            "cooldown_until": failure.cooldown_until,
                            "request_id": context.request_id,
                        },
                    )

                if method not in challenge.verification_methods:
                    return self._error_result(
                        "Verification method is not allowed for this challenge.",
                        metadata={
                            "verification_method": method,
                            "allowed_methods": list(
                                challenge.verification_methods
                            ),
                            "request_id": context.request_id,
                        },
                    )

                if method in challenge.successful_methods:
                    return self._safe_result(
                        message="This verification method was already completed.",
                        data={
                            "challenge": (
                                self._challenge_to_dict(challenge)
                            ),
                            "unlock_granted": False,
                        },
                        metadata={"request_id": context.request_id},
                    )

                callback_payload = {
                    "verification_type": "app_lock",
                    "challenge_id": challenge.challenge_id,
                    "app_id": challenge.app_id,
                    "app_name": app.app_name,
                    "verification_method": method,
                    "verification_data": verification_data or {},
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "actor_agent": context.actor_agent,
                    "request_id": context.request_id,
                    "session_id": context.session_id,
                    "device_id": context.device_id,
                    "ip_address_hash": self._hash_sensitive_value(
                        context.ip_address
                    ),
                    "risk_level": self._normalize_risk_level(
                        risk_level or challenge.risk_level
                    ),
                    "timestamp": self.utcnow(),
                }

                verified = False
                verification_reference: Optional[str] = None
                verification_message = "Verification denied."

                if self.verification_callback:
                    callback_result = self.verification_callback(
                        callback_payload
                    )

                    if not isinstance(callback_result, dict):
                        raise ValueError(
                            "Verification callback must return a dictionary."
                        )

                    verified = bool(
                        callback_result.get("verified", False)
                    )
                    verification_reference = callback_result.get(
                        "verification_reference"
                    )
                    verification_message = str(
                        callback_result.get(
                            "message",
                            (
                                "Verification completed."
                                if verified
                                else "Verification denied."
                            ),
                        )
                    )
                elif (
                    self.allow_test_verification
                    and method == "custom"
                    and bool(
                        (verification_data or {}).get(
                            "test_verified",
                            False,
                        )
                    )
                ):
                    verified = True
                    verification_reference = "test_verification"
                    verification_message = (
                        "Test verification completed."
                    )
                else:
                    verification_message = (
                        "No verification provider is configured."
                    )

                challenge.attempts += 1

                if not verified:
                    failure = self._record_verification_failure(
                        challenge.app_id,
                        context,
                        policy,
                    )

                    if (
                        failure.failed_attempts
                        >= policy.max_failed_attempts
                    ):
                        challenge.status = "blocked"

                    self._autosave()

                    self._emit_agent_event(
                        "security.app_lock.verification_failed",
                        {
                            "app_id": challenge.app_id,
                            "challenge_id": challenge.challenge_id,
                            "verification_method": method,
                            "failed_attempts": (
                                failure.failed_attempts
                            ),
                            "cooldown_until": (
                                failure.cooldown_until
                            ),
                            "request_id": context.request_id,
                        },
                    )

                    self._log_audit_event(
                        "complete_verification",
                        context,
                        {
                            "app_id": challenge.app_id,
                            "challenge_id": challenge.challenge_id,
                            "verification_method": method,
                            "failed_attempts": (
                                failure.failed_attempts
                            ),
                            "cooldown_until": (
                                failure.cooldown_until
                            ),
                        },
                        success=False,
                        error=verification_message,
                    )

                    return self._error_result(
                        "Application verification failed.",
                        error=verification_message,
                        metadata={
                            "challenge_id": challenge.challenge_id,
                            "failed_attempts": (
                                failure.failed_attempts
                            ),
                            "cooldown_until": (
                                failure.cooldown_until
                            ),
                            "request_id": context.request_id,
                        },
                    )

                challenge.successful_methods.append(method)

                completed_count = len(
                    set(challenge.successful_methods)
                )
                verification_complete = (
                    completed_count
                    >= challenge.required_verification_count
                )

                if not verification_complete:
                    self._autosave()

                    self._log_audit_event(
                        "complete_verification_step",
                        context,
                        {
                            "app_id": challenge.app_id,
                            "challenge_id": challenge.challenge_id,
                            "verification_method": method,
                            "completed_count": completed_count,
                            "required_count": (
                                challenge.required_verification_count
                            ),
                        },
                    )

                    return self._safe_result(
                        message=(
                            "Verification step completed. Additional "
                            "verification is required."
                        ),
                        data={
                            "challenge": (
                                self._challenge_to_dict(challenge)
                            ),
                            "completed_verification_count": (
                                completed_count
                            ),
                            "required_verification_count": (
                                challenge.required_verification_count
                            ),
                            "remaining_verification_count": max(
                                0,
                                challenge.required_verification_count
                                - completed_count,
                            ),
                            "unlock_granted": False,
                        },
                        metadata={"request_id": context.request_id},
                    )

                if policy.require_security_approval:
                    approval = self._request_security_approval(
                        "force_unlock",
                        context,
                        {
                            "app_id": challenge.app_id,
                            "challenge_id": challenge.challenge_id,
                            "risk_level": challenge.risk_level,
                        },
                    )

                    if not approval["success"]:
                        challenge.status = "approval_denied"
                        self._autosave()
                        return approval

                challenge.status = "completed"
                challenge.completed_at = self.utcnow()

                self._clear_verification_failures(
                    challenge.app_id,
                    context,
                )

                ttl = (
                    int(unlock_ttl_seconds)
                    if unlock_ttl_seconds is not None
                    else policy.unlock_ttl_seconds
                )
                ttl = max(
                    30,
                    min(
                        ttl,
                        policy.unlock_ttl_seconds,
                        DEFAULT_MAX_UNLOCK_TTL_SECONDS,
                    ),
                )

                grant = UnlockGrant(
                    grant_id=self._new_id("grant"),
                    app_id=challenge.app_id,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    challenge_id=challenge.challenge_id,
                    verification_methods=list(
                        challenge.successful_methods
                    ),
                    issued_at=self.utcnow(),
                    expires_at=self._future_time(ttl),
                    session_id=(
                        context.session_id
                        if policy.bind_to_session
                        else None
                    ),
                    device_id=(
                        context.device_id
                        if policy.bind_to_device
                        else None
                    ),
                    ip_address_hash=(
                        self._hash_sensitive_value(
                            context.ip_address
                        )
                        if policy.bind_to_ip
                        else None
                    ),
                    actor_agent=context.actor_agent,
                    risk_level_at_issue=challenge.risk_level,
                    metadata={
                        "verification_reference": (
                            verification_reference
                        )
                    },
                )

                self._grants[grant.grant_id] = grant
                self._autosave()

                grant_data = self._grant_to_dict(grant)

                verification_payload = (
                    self._prepare_verification_payload(
                        "complete_verification",
                        context,
                        {
                            "app_id": challenge.app_id,
                            "challenge_id": challenge.challenge_id,
                            "grant_id": grant.grant_id,
                            "verification_methods": list(
                                challenge.successful_methods
                            ),
                        },
                    )
                )

                memory_payload = self._prepare_memory_payload(
                    "complete_verification",
                    context,
                    f"Temporary access granted for {app.app_name}.",
                    {
                        "app_id": app.app_id,
                        "app_name": app.app_name,
                        "grant_id": grant.grant_id,
                        "expires_at": grant.expires_at,
                        "verification_methods": list(
                            challenge.successful_methods
                        ),
                    },
                )

                self._emit_agent_event(
                    "security.app_lock.app_unlocked",
                    {
                        "app_id": app.app_id,
                        "grant": grant_data,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "complete_verification",
                    context,
                    {
                        "app_id": app.app_id,
                        "challenge_id": challenge.challenge_id,
                        "grant_id": grant.grant_id,
                        "verification_methods": list(
                            challenge.successful_methods
                        ),
                        "expires_at": grant.expires_at,
                    },
                )

                return self._safe_result(
                    message="Application verification completed successfully.",
                    data={
                        "app": self._app_to_dict(app),
                        "challenge": (
                            self._challenge_to_dict(challenge)
                        ),
                        "unlock_grant": grant_data,
                        "unlock_granted": True,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to complete AppLock verification."
                )
                self._log_audit_event(
                    "complete_verification",
                    context,
                    {
                        "challenge_id": challenge_id,
                        "verification_method": method,
                    },
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to complete application verification.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    # ========================================================================
    # Access decisions and unlock grants
    # ========================================================================

    def check_access(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        risk_level: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether the current context may access a protected application.

        This method only returns an authorization decision. It does not launch,
        open, click, call, message, pay, browse, or execute the app.
        """
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                self._cleanup_expired_records()

                app, app_error = self._get_app_or_error(
                    app_id,
                    context,
                )
                if app_error:
                    return app_error

                policy, policy_error = self._get_policy_or_error(
                    app_id,
                    context,
                )
                if policy_error:
                    return policy_error

                assert app is not None
                assert policy is not None

                authorization = self._evaluate_role_and_permission(
                    policy,
                    context,
                )

                if not authorization["success"]:
                    self._log_audit_event(
                        "check_access",
                        context,
                        {
                            "app_id": app_id,
                            "access_granted": False,
                            "reason": "role_or_permission_denied",
                        },
                        success=False,
                        error=authorization.get("error"),
                    )
                    return authorization

                if SAFE_PERMISSION_BYPASS in context.permissions:
                    self._log_audit_event(
                        "check_access",
                        context,
                        {
                            "app_id": app_id,
                            "access_granted": True,
                            "reason": "authorized_bypass_permission",
                        },
                    )

                    return self._safe_result(
                        message="Application access granted by bypass permission.",
                        data={
                            "access_granted": True,
                            "app": self._app_to_dict(app),
                            "reason": "bypass_permission",
                            "verification_required": False,
                        },
                        metadata={"request_id": context.request_id},
                    )

                if not policy.enabled:
                    return self._safe_result(
                        message="Application access granted because locking is disabled.",
                        data={
                            "access_granted": True,
                            "app": self._app_to_dict(app),
                            "reason": "lock_disabled",
                            "verification_required": False,
                        },
                        metadata={"request_id": context.request_id},
                    )

                if not policy.verification_required:
                    return self._safe_result(
                        message="Application access granted by policy.",
                        data={
                            "access_granted": True,
                            "app": self._app_to_dict(app),
                            "reason": "verification_not_required",
                            "verification_required": False,
                        },
                        metadata={"request_id": context.request_id},
                    )

                cooldown = self._check_cooldown(app_id, context)
                if not cooldown["success"]:
                    return self._safe_result(
                        success=False,
                        message="Application access is temporarily locked.",
                        data={
                            "access_granted": False,
                            "verification_required": True,
                            "cooldown": cooldown["data"],
                        },
                        error=cooldown.get("error"),
                        metadata={"request_id": context.request_id},
                    )

                risk_result = self._evaluate_risk(
                    app,
                    policy,
                    context,
                    supplied_risk_level=risk_level,
                )

                current_risk = risk_result["data"]["risk_level"]
                current_ip_hash = self._hash_sensitive_value(
                    context.ip_address
                )

                valid_grant: Optional[UnlockGrant] = None
                invalidation_reasons: List[str] = []

                for grant in sorted(
                    self._grants.values(),
                    key=lambda item: item.issued_at,
                    reverse=True,
                ):
                    if not self._grant_visible(grant, context):
                        continue

                    if grant.app_id != app_id:
                        continue

                    if grant.revoked or self._is_expired(
                        grant.expires_at
                    ):
                        continue

                    if (
                        policy.bind_to_session
                        and grant.session_id != context.session_id
                    ):
                        invalidation_reasons.append(
                            "session_binding_mismatch"
                        )
                        continue

                    if (
                        policy.bind_to_device
                        and grant.device_id != context.device_id
                    ):
                        invalidation_reasons.append(
                            "device_binding_mismatch"
                        )

                        if policy.relock_on_device_change:
                            grant.revoked = True
                            grant.revoked_at = self.utcnow()
                            grant.revoke_reason = (
                                "device_binding_mismatch"
                            )
                        continue

                    if (
                        policy.bind_to_ip
                        and grant.ip_address_hash
                        != current_ip_hash
                    ):
                        invalidation_reasons.append(
                            "ip_binding_mismatch"
                        )
                        continue

                    if (
                        policy.relock_on_risk_change
                        and self._risk_rank(current_risk)
                        > self._risk_rank(
                            grant.risk_level_at_issue
                        )
                    ):
                        invalidation_reasons.append(
                            "risk_level_increased"
                        )
                        grant.revoked = True
                        grant.revoked_at = self.utcnow()
                        grant.revoke_reason = (
                            "risk_level_increased"
                        )
                        continue

                    valid_grant = grant
                    break

                self._autosave()

                if valid_grant:
                    self._log_audit_event(
                        "check_access",
                        context,
                        {
                            "app_id": app_id,
                            "access_granted": True,
                            "grant_id": valid_grant.grant_id,
                            "risk_level": current_risk,
                        },
                    )

                    return self._safe_result(
                        message="Application access granted.",
                        data={
                            "access_granted": True,
                            "verification_required": False,
                            "app": self._app_to_dict(app),
                            "policy": self._policy_to_dict(policy),
                            "unlock_grant": (
                                self._grant_to_dict(valid_grant)
                            ),
                            "risk": risk_result["data"],
                            "reason": "valid_unlock_grant",
                        },
                        metadata={"request_id": context.request_id},
                    )

                self._log_audit_event(
                    "check_access",
                    context,
                    {
                        "app_id": app_id,
                        "access_granted": False,
                        "reason": "verification_required",
                        "grant_invalidation_reasons": list(
                            set(invalidation_reasons)
                        ),
                        "risk_level": current_risk,
                    },
                    success=False,
                    error="Application verification is required.",
                )

                return self._safe_result(
                    success=False,
                    message="Application is locked.",
                    data={
                        "access_granted": False,
                        "verification_required": True,
                        "app": self._app_to_dict(app),
                        "policy": self._policy_to_dict(policy),
                        "required_verification_methods": (
                            policy.verification_methods
                        ),
                        "required_verification_count": (
                            policy.required_verification_count
                        ),
                        "risk": risk_result["data"],
                        "grant_invalidation_reasons": list(
                            set(invalidation_reasons)
                        ),
                    },
                    error="Verification is required before access.",
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception(
                    "Failed to evaluate application access."
                )
                self._log_audit_event(
                    "check_access",
                    context,
                    {"app_id": app_id},
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to evaluate application access.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def lock_app(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        reason: str = "manual_lock",
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Immediately revoke all active grants for one app."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                app, error = self._get_app_or_error(app_id, context)

                if error:
                    return error

                revoked_count = self._revoke_grants_internal(
                    context,
                    app_id,
                    reason,
                )

                for challenge in self._challenges.values():
                    if (
                        challenge.app_id == app_id
                        and self._challenge_visible(
                            challenge,
                            context,
                        )
                        and challenge.status == "pending"
                    ):
                        challenge.status = "cancelled"

                self._autosave()

                self._emit_agent_event(
                    "security.app_lock.app_locked",
                    {
                        "app_id": app_id,
                        "reason": reason,
                        "revoked_grants": revoked_count,
                        "request_id": context.request_id,
                    },
                )

                self._log_audit_event(
                    "lock_app",
                    context,
                    {
                        "app_id": app_id,
                        "reason": reason,
                        "revoked_grants": revoked_count,
                    },
                )

                return self._safe_result(
                    message="Application locked successfully.",
                    data={
                        "app": self._app_to_dict(app),  # type: ignore[arg-type]
                        "revoked_grants": revoked_count,
                        "reason": reason,
                        "verification_payload": (
                            self._prepare_verification_payload(
                                "lock_app",
                                context,
                                {
                                    "app_id": app_id,
                                    "revoked_grants": revoked_count,
                                },
                            )
                        ),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to lock application.")
                self._log_audit_event(
                    "lock_app",
                    context,
                    {"app_id": app_id},
                    success=False,
                    error=str(exc),
                )
                return self._error_result(
                    "Failed to lock application.",
                    exc,
                    metadata={"request_id": context.request_id},
                )

    def revoke_unlock(
        self,
        user_id: str,
        workspace_id: str,
        grant_id: str,
        reason: str = "manual_revoke",
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Revoke one temporary unlock grant."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            grant = self._grants.get(grant_id)

            if (
                not grant
                or not self._grant_visible(grant, context)
            ):
                return self._error_result(
                    "Unlock grant was not found in this scope.",
                    metadata={
                        "grant_id": grant_id,
                        "request_id": context.request_id,
                    },
                )

            if not grant.revoked:
                grant.revoked = True
                grant.revoked_at = self.utcnow()
                grant.revoke_reason = str(reason or "manual_revoke")
                self._autosave()

            self._emit_agent_event(
                "security.app_lock.unlock_revoked",
                {
                    "grant_id": grant_id,
                    "app_id": grant.app_id,
                    "reason": grant.revoke_reason,
                    "request_id": context.request_id,
                },
            )

            self._log_audit_event(
                "revoke_unlock",
                context,
                {
                    "grant_id": grant_id,
                    "app_id": grant.app_id,
                    "reason": grant.revoke_reason,
                },
            )

            return self._safe_result(
                message="Application unlock grant revoked.",
                data={
                    "unlock_grant": self._grant_to_dict(grant),
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "revoke_unlock",
                            context,
                            {
                                "grant_id": grant_id,
                                "app_id": grant.app_id,
                            },
                        )
                    ),
                },
                metadata={"request_id": context.request_id},
            )

    def _revoke_grants_internal(
        self,
        context: AppLockContext,
        app_id: Optional[str],
        reason: str,
    ) -> int:
        """Revoke grants inside the already-validated SaaS scope."""
        revoked_count = 0

        for grant in self._grants.values():
            if not self._grant_visible(grant, context):
                continue

            if app_id is not None and grant.app_id != app_id:
                continue

            if grant.revoked:
                continue

            grant.revoked = True
            grant.revoked_at = self.utcnow()
            grant.revoke_reason = str(reason or "revoked")
            revoked_count += 1

        return revoked_count

    def revoke_all_unlocks(
        self,
        user_id: str,
        workspace_id: str,
        reason: str = "workspace_unlocks_revoked",
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Revoke all active app unlocks in one user/workspace scope."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "revoke_all_unlocks",
            context,
            {"reason": reason},
        )

        if not approval["success"]:
            return approval

        with self._lock:
            revoked_count = self._revoke_grants_internal(
                context,
                app_id=None,
                reason=reason,
            )

            self._autosave()

            self._emit_agent_event(
                "security.app_lock.all_unlocks_revoked",
                {
                    "revoked_grants": revoked_count,
                    "reason": reason,
                    "request_id": context.request_id,
                },
            )

            self._log_audit_event(
                "revoke_all_unlocks",
                context,
                {
                    "revoked_grants": revoked_count,
                    "reason": reason,
                },
            )

            return self._safe_result(
                message="All application unlocks were revoked.",
                data={
                    "revoked_grants": revoked_count,
                    "reason": reason,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "revoke_all_unlocks",
                            context,
                            {
                                "revoked_grants": revoked_count,
                            },
                        )
                    ),
                },
                metadata={"request_id": context.request_id},
            )

    def lock_all_apps(
        self,
        user_id: str,
        workspace_id: str,
        reason: str = "workspace_lock",
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Immediately lock all registered apps in one SaaS scope."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "lock_all_apps",
            context,
            {"reason": reason},
        )

        if not approval["success"]:
            return approval

        with self._lock:
            revoked_count = self._revoke_grants_internal(
                context,
                app_id=None,
                reason=reason,
            )

            cancelled_challenges = 0

            for challenge in self._challenges.values():
                if (
                    self._challenge_visible(challenge, context)
                    and challenge.status == "pending"
                ):
                    challenge.status = "cancelled"
                    cancelled_challenges += 1

            self._autosave()

            self._emit_agent_event(
                "security.app_lock.workspace_locked",
                {
                    "revoked_grants": revoked_count,
                    "cancelled_challenges": cancelled_challenges,
                    "reason": reason,
                    "request_id": context.request_id,
                },
            )

            self._log_audit_event(
                "lock_all_apps",
                context,
                {
                    "revoked_grants": revoked_count,
                    "cancelled_challenges": cancelled_challenges,
                    "reason": reason,
                },
            )

            return self._safe_result(
                message="All protected applications were locked.",
                data={
                    "revoked_grants": revoked_count,
                    "cancelled_challenges": cancelled_challenges,
                    "reason": reason,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "lock_all_apps",
                            context,
                            {
                                "revoked_grants": revoked_count,
                                "cancelled_challenges": (
                                    cancelled_challenges
                                ),
                            },
                        )
                    ),
                },
                metadata={"request_id": context.request_id},
            )

    # ========================================================================
    # Dashboard and status methods
    # ========================================================================

    def get_app_status(
        self,
        user_id: str,
        workspace_id: str,
        app_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return dashboard-ready app lock status."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
            role,
            permissions,
            session_id,
            device_id,
            ip_address,
            user_agent,
            metadata,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            self._cleanup_expired_records()

            app, error = self._get_app_or_error(app_id, context)
            if error:
                return error

            policy = self._policies.get(app_id)

            active_grants = [
                self._grant_to_dict(grant)
                for grant in self._grants.values()
                if self._grant_visible(grant, context)
                and grant.app_id == app_id
                and not grant.revoked
                and not self._is_expired(grant.expires_at)
            ]

            pending_challenges = [
                self._challenge_to_dict(challenge)
                for challenge in self._challenges.values()
                if self._challenge_visible(challenge, context)
                and challenge.app_id == app_id
                and challenge.status == "pending"
                and not self._is_expired(challenge.expires_at)
            ]

            failure = self._failures.get(
                self._failure_key(
                    context.user_id,
                    context.workspace_id,
                    app_id,
                )
            )

            return self._safe_result(
                message="Application lock status retrieved.",
                data={
                    "app": self._app_to_dict(app),  # type: ignore[arg-type]
                    "policy": (
                        self._policy_to_dict(policy)
                        if policy
                        else None
                    ),
                    "is_locked": (
                        bool(
                            policy
                            and policy.enabled
                            and policy.verification_required
                        )
                        and not active_grants
                    ),
                    "active_unlock_grants": active_grants,
                    "pending_challenges": pending_challenges,
                    "failure_state": (
                        self._failure_to_dict(failure)
                        if failure
                        else None
                    ),
                },
                metadata={"request_id": context.request_id},
            )

    def get_workspace_summary(
        self,
        user_id: str,
        workspace_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return dashboard analytics for one SaaS scope."""
        context = self._context_from_kwargs(
            user_id,
            workspace_id,
            actor_agent,
            request_id,
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            self._cleanup_expired_records()

            apps = [
                app
                for app in self._apps.values()
                if self._app_visible(app, context)
            ]

            policies = [
                policy
                for policy in self._policies.values()
                if self._policy_visible(policy, context)
            ]

            active_grants = [
                grant
                for grant in self._grants.values()
                if self._grant_visible(grant, context)
                and not grant.revoked
                and not self._is_expired(grant.expires_at)
            ]

            pending_challenges = [
                challenge
                for challenge in self._challenges.values()
                if self._challenge_visible(challenge, context)
                and challenge.status == "pending"
                and not self._is_expired(challenge.expires_at)
            ]

            cooldowns = [
                failure
                for failure in self._failures.values()
                if failure.user_id == context.user_id
                and failure.workspace_id == context.workspace_id
                and failure.cooldown_until
                and not self._is_expired(failure.cooldown_until)
            ]

            app_type_counts: Dict[str, int] = {}
            locked_app_count = 0

            for app in apps:
                app_type_counts[app.app_type] = (
                    app_type_counts.get(app.app_type, 0) + 1
                )

                policy = self._policies.get(app.app_id)
                has_active_grant = any(
                    grant.app_id == app.app_id
                    for grant in active_grants
                )

                if (
                    policy
                    and policy.enabled
                    and policy.verification_required
                    and not has_active_grant
                ):
                    locked_app_count += 1

            return self._safe_result(
                message="AppLock workspace summary generated.",
                data={
                    "protected_app_count": len(apps),
                    "enabled_policy_count": len(
                        [
                            policy
                            for policy in policies
                            if policy.enabled
                        ]
                    ),
                    "locked_app_count": locked_app_count,
                    "temporarily_unlocked_app_count": len(
                        {grant.app_id for grant in active_grants}
                    ),
                    "active_grant_count": len(active_grants),
                    "pending_challenge_count": len(
                        pending_challenges
                    ),
                    "active_cooldown_count": len(cooldowns),
                    "app_counts_by_type": app_type_counts,
                    "recent_apps": [
                        self._app_to_dict(app)
                        for app in sorted(
                            apps,
                            key=lambda item: item.updated_at,
                            reverse=True,
                        )[:10]
                    ],
                },
                metadata={"request_id": context.request_id},
            )

    # ========================================================================
    # Master Agent / Router entry point
    # ========================================================================

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic Agent Router entry point.

        Expected format:
            {
                "action": "check_access",
                "user_id": "user_1",
                "workspace_id": "workspace_1",
                "actor_agent": "master_agent",
                "payload": {
                    "app_id": "app_x"
                }
            }
        """
        if not isinstance(task, dict):
            return self._error_result(
                "AppLock task must be a dictionary."
            )

        action = self._normalize(task.get("action"))
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(
                "AppLock task payload must be a dictionary."
            )

        common: Dict[str, Any] = {
            "user_id": str(task.get("user_id", "")).strip(),
            "workspace_id": str(
                task.get("workspace_id", "")
            ).strip(),
            "actor_agent": str(
                task.get("actor_agent") or DEFAULT_AGENT_ID
            ),
            "request_id": str(
                task.get("request_id") or uuid.uuid4()
            ),
            "role": task.get("role"),
            "permissions": task.get("permissions") or [],
            "session_id": task.get("session_id"),
            "device_id": task.get("device_id"),
            "ip_address": task.get("ip_address"),
            "user_agent": task.get("user_agent"),
            "metadata": task.get("metadata") or {},
        }

        try:
            if action == "register_app":
                return self.register_app(**common, **payload)

            if action == "update_app":
                return self.update_app(**common, **payload)

            if action == "set_lock_policy":
                return self.set_lock_policy(**common, **payload)

            if action == "remove_app":
                return self.remove_app(**common, **payload)

            if action == "create_verification_challenge":
                return self.create_verification_challenge(
                    **common,
                    **payload,
                )

            if action == "complete_verification":
                return self.complete_verification(
                    **common,
                    **payload,
                )

            if action == "check_access":
                return self.check_access(**common, **payload)

            if action == "lock_app":
                return self.lock_app(**common, **payload)

            if action == "revoke_unlock":
                return self.revoke_unlock(**common, **payload)

            if action == "revoke_all_unlocks":
                return self.revoke_all_unlocks(
                    **common,
                    **payload,
                )

            if action == "lock_all_apps":
                return self.lock_all_apps(**common, **payload)

            if action == "get_app_status":
                return self.get_app_status(**common, **payload)

            # Read-only methods do not accept every extended context argument.
            if action == "get_app":
                return self.get_app(
                    user_id=common["user_id"],
                    workspace_id=common["workspace_id"],
                    actor_agent=common["actor_agent"],
                    request_id=common["request_id"],
                    **payload,
                )

            if action == "list_apps":
                return self.list_apps(
                    user_id=common["user_id"],
                    workspace_id=common["workspace_id"],
                    actor_agent=common["actor_agent"],
                    request_id=common["request_id"],
                    **payload,
                )

            if action == "get_workspace_summary":
                return self.get_workspace_summary(
                    user_id=common["user_id"],
                    workspace_id=common["workspace_id"],
                    actor_agent=common["actor_agent"],
                    request_id=common["request_id"],
                )

            if action == "save":
                return self.save()

            return self._error_result(
                "Unsupported AppLock action.",
                error=f"Unsupported action: {action}",
                metadata={
                    "request_id": common["request_id"],
                    "supported_actions": self.supported_actions(),
                },
            )
        except TypeError as exc:
            self.logger.exception(
                "Invalid AppLock payload for action %s.",
                action,
            )
            return self._error_result(
                "Invalid AppLock task payload.",
                exc,
                metadata={
                    "action": action,
                    "request_id": common["request_id"],
                },
            )
        except Exception as exc:
            self.logger.exception("AppLock run operation failed.")
            return self._error_result(
                "AppLock run operation failed.",
                exc,
                metadata={
                    "action": action,
                    "request_id": common["request_id"],
                },
            )

    def supported_actions(self) -> List[str]:
        """Return Master Agent and Registry-compatible actions."""
        return [
            "register_app",
            "update_app",
            "set_lock_policy",
            "get_app",
            "list_apps",
            "remove_app",
            "create_verification_challenge",
            "complete_verification",
            "check_access",
            "lock_app",
            "revoke_unlock",
            "revoke_all_unlocks",
            "lock_all_apps",
            "get_app_status",
            "get_workspace_summary",
            "save",
        ]

    # ========================================================================
    # Registry and health
    # ========================================================================

    def health_check(self) -> Dict[str, Any]:
        """Return AppLock health information."""
        with self._lock:
            try:
                self._cleanup_expired_records()

                return self._safe_result(
                    message="AppLock is healthy.",
                    data={
                        "agent_id": self.agent_id,
                        "agent_name": self.agent_name,
                        "storage_path": str(self.storage_path),
                        "autosave": self.autosave,
                        "verification_callback_configured": bool(
                            self.verification_callback
                        ),
                        "security_callback_configured": bool(
                            self.security_approval_callback
                        ),
                        "risk_callback_configured": bool(
                            self.risk_callback
                        ),
                        "allow_test_verification": (
                            self.allow_test_verification
                        ),
                        "registered_app_count": len(self._apps),
                        "policy_count": len(self._policies),
                        "challenge_count": len(self._challenges),
                        "grant_count": len(self._grants),
                        "supported_actions": (
                            self.supported_actions()
                        ),
                    },
                )
            except Exception as exc:
                return self._error_result(
                    "AppLock health check failed.",
                    exc,
                )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry-compatible metadata."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "module": "Security Agent",
            "file_path": "agents/security_agent/app_lock.py",
            "class_name": "AppLock",
            "purpose": "Locks sensitive apps behind verification.",
            "requires_user_id": True,
            "requires_workspace_id": True,
            "deny_by_default": True,
            "credentials_persisted": False,
            "security_sensitive_actions": sorted(
                SENSITIVE_ACTIONS
            ),
            "supported_verification_methods": sorted(
                SUPPORTED_VERIFICATION_METHODS
            ),
            "supported_app_types": sorted(
                SUPPORTED_APP_TYPES
            ),
            "supported_actions": self.supported_actions(),
            "safe_to_import": True,
            "created_for": (
                "William / Jarvis Multi-Agent AI SaaS System "
                "by Digital Promotix"
            ),
        }


__all__ = [
    "AppLock",
    "AppLockContext",
    "ProtectedApp",
    "AppLockPolicy",
    "VerificationChallenge",
    "UnlockGrant",
    "FailureState",
]