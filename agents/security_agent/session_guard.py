"""
agents/security_agent/session_guard.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Security Agent - Session Guard

Purpose:
    Session timeout, re-authentication, unknown device/session protection.

This file provides a production-level, import-safe helper/agent class named
SessionGuard. It is responsible for protecting SaaS sessions per user/workspace,
including:
    - Creating and tracking secure session records.
    - Validating active sessions.
    - Enforcing idle timeout.
    - Enforcing absolute session lifetime.
    - Requiring re-authentication for stale or risky sessions.
    - Detecting unknown devices.
    - Tracking trusted devices.
    - Blocking suspicious sessions/devices.
    - Revoking sessions.
    - Preparing verification payloads.
    - Preparing memory payloads.
    - Emitting audit and agent events.
    - Returning William-compatible structured dict results.

Design goals:
    - Import-safe even if the rest of William/Jarvis is not generated yet.
    - No hardcoded secrets.
    - No real destructive system actions.
    - No real biometric checks.
    - No real external network calls.
    - Safe defaults.
    - SaaS isolation by user_id + workspace_id.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent, Security Agent, Memory Agent, Verification Agent, and
      Dashboard/API integration.

Security notes:
    This module does NOT authenticate passwords or biometrics itself. It only
    tracks session state and returns whether a session is allowed, expired,
    re-auth required, unknown-device blocked/reviewed, or revoked.

    Real authentication should be handled by the future auth service or
    biometric_gate.py. Real permission decisions should also pass through
    permission_checker.py where needed.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Union


# =============================================================================
# Optional BaseAgent compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis BaseAgent can replace this automatically when
        agents/base_agent.py exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_version = kwargs.get("agent_version", "1.0.0")
            self.logger = logging.getLogger(self.agent_name)

        def health_check(self) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent is active.",
                "data": {
                    "agent_name": self.agent_name,
                    "agent_version": self.agent_version,
                },
                "error": None,
                "metadata": {
                    "fallback_base_agent": True,
                    "timestamp": _utc_now_iso(),
                },
            }


# =============================================================================
# Constants
# =============================================================================

DEFAULT_IDLE_TIMEOUT_SECONDS = 60 * 30
DEFAULT_ABSOLUTE_TIMEOUT_SECONDS = 60 * 60 * 12
DEFAULT_REAUTH_INTERVAL_SECONDS = 60 * 60 * 2
DEFAULT_HIGH_RISK_REAUTH_INTERVAL_SECONDS = 60 * 15
DEFAULT_UNKNOWN_DEVICE_POLICY = "reauth_required"
DEFAULT_AUDIT_LOG_LIMIT = 5000
DEFAULT_EVENT_LOG_LIMIT = 5000
DEFAULT_SESSION_LIMIT_PER_SCOPE = 100
DEFAULT_TRUSTED_DEVICE_LIMIT_PER_SCOPE = 50
DEFAULT_BLOCKED_DEVICE_LIMIT_PER_SCOPE = 200
DEFAULT_PAYLOAD_MAX_DEPTH = 8
DEFAULT_STRING_MAX_LENGTH = 5000
DEFAULT_MAX_FAILED_REAUTH_ATTEMPTS = 5
DEFAULT_FAILED_REAUTH_LOCK_SECONDS = 60 * 15

SESSION_STATUS_ACTIVE = "active"
SESSION_STATUS_EXPIRED = "expired"
SESSION_STATUS_REAUTH_REQUIRED = "reauth_required"
SESSION_STATUS_REVOKED = "revoked"
SESSION_STATUS_BLOCKED = "blocked"
SESSION_STATUS_UNKNOWN_DEVICE = "unknown_device"
SESSION_STATUS_LOCKED = "locked"

VALID_SESSION_STATUSES = {
    SESSION_STATUS_ACTIVE,
    SESSION_STATUS_EXPIRED,
    SESSION_STATUS_REAUTH_REQUIRED,
    SESSION_STATUS_REVOKED,
    SESSION_STATUS_BLOCKED,
    SESSION_STATUS_UNKNOWN_DEVICE,
    SESSION_STATUS_LOCKED,
}

UNKNOWN_DEVICE_POLICIES = {
    "allow",
    "reauth_required",
    "biometric_required",
    "block",
    "review",
}

RISK_LEVELS = {
    "minimal": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "client_secret",
    "cookie",
    "session_cookie",
    "biometric_template",
    "fingerprint_template",
    "face_template",
    "voiceprint",
}

SENSITIVE_ACTION_PATTERNS = (
    r"\bpayment\b",
    r"\btransfer\b",
    r"\bwithdraw\b",
    r"\brefund\b",
    r"\bdelete\b",
    r"\bdrop\b",
    r"\btruncate\b",
    r"\bexport\b",
    r"\bcredential\b",
    r"\bpassword\b",
    r"\bsecret\b",
    r"\btoken\b",
    r"\badmin\b",
    r"\brole\b",
    r"\bpermission\b",
    r"\bdeploy\b",
    r"\bproduction\b",
    r"\bsend_email\b",
    r"\bcall\b",
    r"\bsystem_execute\b",
    r"\bbrowser_submit\b",
    r"\bdisable_security\b",
)

SAFE_DEVICE_TYPES = {
    "desktop",
    "laptop",
    "mobile",
    "tablet",
    "server",
    "browser",
    "unknown",
}


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _unix_now() -> float:
    """Return current Unix timestamp."""
    return time.time()


def _safe_uuid(prefix: str = "session") -> str:
    """Generate a safe prefixed UUID."""
    clean_prefix = re.sub(r"[^A-Za-z0-9_-]", "", str(prefix or "session"))[:32]
    if not clean_prefix:
        clean_prefix = "session"
    return f"{clean_prefix}_{uuid.uuid4().hex}"


def _safe_json(value: Any) -> str:
    """Serialize safely to JSON string."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return str(value)


def _stable_hash(value: Any) -> str:
    """Return stable SHA-256 hash for JSON-safe data."""
    return hashlib.sha256(_safe_json(value).encode("utf-8")).hexdigest()


def _deepcopy_safe(value: Any) -> Any:
    """Best effort deep copy."""
    try:
        return copy.deepcopy(value)
    except Exception:
        try:
            return json.loads(json.dumps(value, default=str))
        except Exception:
            return str(value)


def _truncate_string(value: str, max_length: int = DEFAULT_STRING_MAX_LENGTH) -> str:
    """Safely truncate long strings."""
    if len(value) <= max_length:
        return value
    return value[:max_length] + "...[truncated]"


def _normalize_identifier(value: Any, field_name: str) -> str:
    """
    Normalize SaaS identifiers.

    Allowed:
        letters, numbers, underscore, dash, dot, colon, at sign
    """
    if value is None:
        raise ValueError(f"{field_name} is required.")

    normalized = str(value).strip()

    if not normalized:
        raise ValueError(f"{field_name} cannot be empty.")

    if len(normalized) > 256:
        raise ValueError(f"{field_name} cannot exceed 256 characters.")

    if not re.fullmatch(r"[A-Za-z0-9_.:@\-]+", normalized):
        raise ValueError(
            f"{field_name} contains invalid characters. "
            "Allowed: letters, numbers, underscore, dash, dot, colon, and @."
        )

    return normalized


def _normalize_optional_identifier(value: Any, field_name: str) -> Optional[str]:
    """Normalize optional identifier."""
    if value is None:
        return None
    return _normalize_identifier(value, field_name)


def _normalize_ip(ip_address: Optional[Any]) -> Optional[str]:
    """Normalize and validate IP address where possible."""
    if ip_address is None:
        return None

    raw = str(ip_address).strip()
    if not raw:
        return None

    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return _truncate_string(raw, 128)


def _normalize_user_agent(user_agent: Optional[Any]) -> Optional[str]:
    """Normalize browser/app user agent."""
    if user_agent is None:
        return None

    clean = str(user_agent).strip()
    if not clean:
        return None

    return _truncate_string(clean, 1000)


def _normalize_device_type(device_type: Optional[Any]) -> str:
    """Normalize device type."""
    clean = str(device_type or "unknown").strip().lower()
    clean = re.sub(r"[^a-z0-9_-]", "_", clean)
    if clean not in SAFE_DEVICE_TYPES:
        return "unknown"
    return clean


def _normalize_risk_level(risk_level: Optional[Any]) -> str:
    """Normalize risk level."""
    clean = str(risk_level or "low").strip().lower()
    if clean not in RISK_LEVELS:
        raise ValueError(f"Invalid risk_level '{clean}'. Allowed: {sorted(RISK_LEVELS)}")
    return clean


def _coerce_mapping(value: Optional[Mapping[str, Any]], field_name: str) -> Dict[str, Any]:
    """Coerce optional mapping to dict."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a dictionary/mapping.")
    return dict(value)


def _fingerprint_device(
    device_id: Optional[str],
    user_agent: Optional[str],
    ip_address: Optional[str],
    device_type: str,
    platform: Optional[str],
) -> str:
    """
    Create a stable privacy-safe device fingerprint.

    This is not a real hardware fingerprint. It is only a deterministic hash
    of provided metadata for session comparison.
    """
    payload = {
        "device_id": device_id or "",
        "user_agent": user_agent or "",
        "ip_address": ip_address or "",
        "device_type": device_type or "unknown",
        "platform": platform or "",
    }
    return "devfp_" + _stable_hash(payload)[:32]


# =============================================================================
# Enums and data models
# =============================================================================

class SessionDecision(str, Enum):
    """Final session guard decision."""

    ALLOW = "allow"
    REAUTH_REQUIRED = "reauth_required"
    BIOMETRIC_REQUIRED = "biometric_required"
    BLOCK = "block"
    REVIEW = "review"


class SessionReason(str, Enum):
    """Reason codes for session decisions."""

    SESSION_VALID = "session_valid"
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_EXPIRED_IDLE = "session_expired_idle"
    SESSION_EXPIRED_ABSOLUTE = "session_expired_absolute"
    SESSION_REVOKED = "session_revoked"
    SESSION_BLOCKED = "session_blocked"
    SESSION_LOCKED = "session_locked"
    REAUTH_INTERVAL_EXPIRED = "reauth_interval_expired"
    HIGH_RISK_REAUTH_REQUIRED = "high_risk_reauth_required"
    BIOMETRIC_REQUIRED = "biometric_required"
    UNKNOWN_DEVICE = "unknown_device"
    BLOCKED_DEVICE = "blocked_device"
    DEVICE_MISMATCH = "device_mismatch"
    IP_CHANGED = "ip_changed"
    USER_AGENT_CHANGED = "user_agent_changed"
    SENSITIVE_ACTION_REAUTH = "sensitive_action_reauth"
    FAILED_REAUTH_LOCKED = "failed_reauth_locked"
    EMERGENCY_LOCK = "emergency_lock"


@dataclass
class SessionGuardConfig:
    """
    Configuration for SessionGuard.

    unknown_device_policy:
        allow | reauth_required | biometric_required | block | review
    """

    idle_timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS
    absolute_timeout_seconds: int = DEFAULT_ABSOLUTE_TIMEOUT_SECONDS
    reauth_interval_seconds: int = DEFAULT_REAUTH_INTERVAL_SECONDS
    high_risk_reauth_interval_seconds: int = DEFAULT_HIGH_RISK_REAUTH_INTERVAL_SECONDS

    unknown_device_policy: str = DEFAULT_UNKNOWN_DEVICE_POLICY

    require_reauth_for_sensitive_actions: bool = True
    require_biometric_for_critical_risk: bool = True
    require_reauth_on_ip_change: bool = True
    require_reauth_on_user_agent_change: bool = True
    block_known_bad_devices: bool = True
    allow_trusted_devices: bool = True

    max_sessions_per_scope: int = DEFAULT_SESSION_LIMIT_PER_SCOPE
    max_trusted_devices_per_scope: int = DEFAULT_TRUSTED_DEVICE_LIMIT_PER_SCOPE
    max_blocked_devices_per_scope: int = DEFAULT_BLOCKED_DEVICE_LIMIT_PER_SCOPE

    max_failed_reauth_attempts: int = DEFAULT_MAX_FAILED_REAUTH_ATTEMPTS
    failed_reauth_lock_seconds: int = DEFAULT_FAILED_REAUTH_LOCK_SECONDS

    audit_log_limit: int = DEFAULT_AUDIT_LOG_LIMIT
    event_log_limit: int = DEFAULT_EVENT_LOG_LIMIT

    payload_max_depth: int = DEFAULT_PAYLOAD_MAX_DEPTH
    string_max_length: int = DEFAULT_STRING_MAX_LENGTH
    redact_sensitive_values: bool = True

    auto_cleanup_expired_sessions: bool = True
    fail_closed: bool = True


@dataclass
class DeviceRecord:
    """Trusted or blocked device record."""

    device_fingerprint: str
    device_id: Optional[str] = None
    device_type: str = "unknown"
    platform: Optional[str] = None
    user_agent_hash: Optional[str] = None
    ip_address_hash: Optional[str] = None
    label: Optional[str] = None
    trust_level: str = "trusted"
    status: str = "trusted"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    last_seen_at: Optional[str] = None


@dataclass
class SessionRecord:
    """Tracked SaaS session."""

    session_id: str
    user_id: str
    workspace_id: str

    status: str = SESSION_STATUS_ACTIVE

    device_fingerprint: str = ""
    device_id: Optional[str] = None
    device_type: str = "unknown"
    platform: Optional[str] = None

    ip_address: Optional[str] = None
    ip_address_hash: Optional[str] = None
    user_agent: Optional[str] = None
    user_agent_hash: Optional[str] = None

    source: str = "unknown"
    risk_level: str = "low"
    risk_score: float = 0.0

    created_at: str = field(default_factory=_utc_now_iso)
    created_at_unix: float = field(default_factory=_unix_now)

    last_activity_at: str = field(default_factory=_utc_now_iso)
    last_activity_unix: float = field(default_factory=_unix_now)

    last_reauth_at: Optional[str] = None
    last_reauth_unix: Optional[float] = None

    last_biometric_at: Optional[str] = None
    last_biometric_unix: Optional[float] = None

    expires_at: Optional[str] = None
    expires_at_unix: Optional[float] = None

    revoked_at: Optional[str] = None
    blocked_at: Optional[str] = None
    locked_until_unix: Optional[float] = None

    failed_reauth_attempts: int = 0

    unknown_device: bool = False
    trusted_device: bool = False
    blocked_device: bool = False

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionEvaluation:
    """Internal session evaluation result."""

    decision: str
    reason: str
    status: str

    allowed: bool = False
    reauth_required: bool = False
    biometric_required: bool = False
    blocked: bool = False
    review_required: bool = False

    risk_level: str = "low"
    risk_score: float = 0.0

    unknown_device: bool = False
    trusted_device: bool = False
    blocked_device: bool = False

    session_age_seconds: Optional[float] = None
    idle_seconds: Optional[float] = None
    seconds_until_idle_timeout: Optional[float] = None
    seconds_until_absolute_timeout: Optional[float] = None
    seconds_until_reauth_required: Optional[float] = None

    warnings: List[str] = field(default_factory=list)
    trace: List[Dict[str, Any]] = field(default_factory=list)


# =============================================================================
# SessionGuard
# =============================================================================

class SessionGuard(BaseAgent):
    """
    Security Agent helper for session timeout, re-authentication, and
    unknown-device/session protection.

    Main public methods:
        - create_session()
        - validate_session()
        - touch_session()
        - mark_reauthenticated()
        - mark_biometric_verified()
        - revoke_session()
        - block_session()
        - trust_device()
        - block_device()
        - list_sessions()
        - get_session()
        - cleanup_expired_sessions()
        - get_audit_events()
        - get_agent_events()
        - health_check()

    Decision output:
        - allow
        - reauth_required
        - biometric_required
        - block
        - review
    """

    def __init__(
        self,
        config: Optional[Union[SessionGuardConfig, Mapping[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "SessionGuard",
        agent_version: str = "1.0.0",
    ) -> None:
        """Initialize SessionGuard."""
        try:
            super().__init__(agent_name=agent_name, agent_version=agent_version)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_version = agent_version
        self.logger = logger or logging.getLogger("william.security_agent.session_guard")

        if isinstance(config, SessionGuardConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = SessionGuardConfig(**dict(config))
        else:
            self.config = SessionGuardConfig()

        self._validate_config()

        self._lock = threading.RLock()

        # Scope key = (user_id, workspace_id)
        self._sessions: Dict[Tuple[str, str], Dict[str, SessionRecord]] = {}
        self._trusted_devices: Dict[Tuple[str, str], Dict[str, DeviceRecord]] = {}
        self._blocked_devices: Dict[Tuple[str, str], Dict[str, DeviceRecord]] = {}

        self._audit_events: Deque[Dict[str, Any]] = deque(maxlen=self.config.audit_log_limit)
        self._agent_events: Deque[Dict[str, Any]] = deque(maxlen=self.config.event_log_limit)

        self._emit_agent_event(
            event_type="session_guard_initialized",
            user_id=None,
            workspace_id=None,
            session_id=None,
            data={
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
                "idle_timeout_seconds": self.config.idle_timeout_seconds,
                "absolute_timeout_seconds": self.config.absolute_timeout_seconds,
                "unknown_device_policy": self.config.unknown_device_policy,
            },
        )

    # =========================================================================
    # Config and compatibility hooks
    # =========================================================================

    def _validate_config(self) -> None:
        """Validate SessionGuard config."""
        if self.config.idle_timeout_seconds < 60:
            raise ValueError("idle_timeout_seconds must be >= 60.")

        if self.config.absolute_timeout_seconds < self.config.idle_timeout_seconds:
            raise ValueError("absolute_timeout_seconds must be >= idle_timeout_seconds.")

        if self.config.reauth_interval_seconds < 60:
            raise ValueError("reauth_interval_seconds must be >= 60.")

        if self.config.high_risk_reauth_interval_seconds < 60:
            raise ValueError("high_risk_reauth_interval_seconds must be >= 60.")

        if self.config.unknown_device_policy not in UNKNOWN_DEVICE_POLICIES:
            raise ValueError(
                f"unknown_device_policy must be one of {sorted(UNKNOWN_DEVICE_POLICIES)}."
            )

        if self.config.max_sessions_per_scope < 1:
            raise ValueError("max_sessions_per_scope must be >= 1.")

        if self.config.max_trusted_devices_per_scope < 1:
            raise ValueError("max_trusted_devices_per_scope must be >= 1.")

        if self.config.max_blocked_devices_per_scope < 1:
            raise ValueError("max_blocked_devices_per_scope must be >= 1.")

        if self.config.max_failed_reauth_attempts < 1:
            raise ValueError("max_failed_reauth_attempts must be >= 1.")

        if self.config.failed_reauth_lock_seconds < 60:
            raise ValueError("failed_reauth_lock_seconds must be >= 60.")

        if self.config.audit_log_limit < 10:
            raise ValueError("audit_log_limit must be >= 10.")

        if self.config.event_log_limit < 10:
            raise ValueError("event_log_limit must be >= 10.")

        if self.config.payload_max_depth < 1:
            raise ValueError("payload_max_depth must be >= 1.")

        if self.config.string_max_length < 100:
            raise ValueError("string_max_length must be >= 100.")

    def _validate_task_context(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Optional[Any] = None,
        require_session_id: bool = False,
    ) -> Dict[str, Optional[str]]:
        """
        Validate SaaS task context.

        Required compatibility hook.
        """
        normalized_user_id = _normalize_identifier(user_id, "user_id")
        normalized_workspace_id = _normalize_identifier(workspace_id, "workspace_id")
        normalized_session_id = None

        if session_id is not None:
            normalized_session_id = _normalize_identifier(session_id, "session_id")
        elif require_session_id:
            raise ValueError("session_id is required.")

        return {
            "user_id": normalized_user_id,
            "workspace_id": normalized_workspace_id,
            "session_id": normalized_session_id,
        }

    def _requires_security_check(
        self,
        action: str,
        risk_level: str = "low",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether the current session action should pass through
        Security Agent permission flow.
        """
        normalized_risk = _normalize_risk_level(risk_level)
        normalized_action = str(action or "").strip().lower()

        if normalized_risk in {"medium", "high", "critical"}:
            return True

        if any(re.search(pattern, normalized_action, re.IGNORECASE) for pattern in SENSITIVE_ACTION_PATTERNS):
            return True

        if metadata:
            serialized = _safe_json(metadata).lower()
            if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in SENSITIVE_ACTION_PATTERNS):
                return True

        return False

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        session_id: Optional[str],
        action: str,
        reason: str,
        required_method: str = "reauthentication",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval request.

        This does not approve or execute anything.
        """
        request = {
            "approval_request_id": _safe_uuid("session_security_approval"),
            "requested_by_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "action": action,
            "reason": reason,
            "required_method": required_method,
            "status": "pending",
            "metadata": self._sanitize_payload(metadata or {}),
            "created_at": _utc_now_iso(),
        }

        self._log_audit_event(
            action="session_security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            details=request,
            level="warning",
        )

        self._emit_agent_event(
            event_type="session_security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            data=request,
        )

        return request

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        session_id: Optional[str],
        action: str,
        evaluation: Optional[SessionEvaluation] = None,
        before: Optional[Mapping[str, Any]] = None,
        after: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required compatibility hook.
        """
        return {
            "verification_id": _safe_uuid("session_verify"),
            "source_agent": self.agent_name,
            "verification_type": "session_guard",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "action": action,
            "decision": evaluation.decision if evaluation else None,
            "reason": evaluation.reason if evaluation else None,
            "status": evaluation.status if evaluation else None,
            "risk_level": evaluation.risk_level if evaluation else None,
            "risk_score": evaluation.risk_score if evaluation else None,
            "before": self._sanitize_payload(before or {}),
            "after": self._sanitize_payload(after or {}),
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        session_id: Optional[str],
        memory_type: str,
        content: Mapping[str, Any],
        importance: str = "security",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Required compatibility hook.
        """
        return {
            "memory_id": _safe_uuid("session_memory"),
            "source_agent": self.agent_name,
            "memory_type": memory_type,
            "importance": importance,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "content": self._sanitize_payload(content),
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        session_id: Optional[str],
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit internal agent event for Dashboard/API or future event bus.

        Required compatibility hook.
        """
        event = {
            "event_id": _safe_uuid("session_event"),
            "event_type": str(event_type),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "data": self._sanitize_payload(data or {}),
            "created_at": _utc_now_iso(),
        }

        with self._lock:
            self._agent_events.append(event)

        return event

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        session_id: Optional[str],
        details: Optional[Mapping[str, Any]] = None,
        level: str = "info",
    ) -> Dict[str, Any]:
        """
        Add security audit event.

        Required compatibility hook.
        """
        event = {
            "audit_id": _safe_uuid("session_audit"),
            "action": str(action),
            "level": str(level),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "details": self._sanitize_payload(details or {}),
            "created_at": _utc_now_iso(),
        }

        with self._lock:
            self._audit_events.append(event)

        if str(level).lower() in {"warning", "error", "critical"}:
            self.logger.warning("SessionGuard audit event: %s", _safe_json(event))
        else:
            self.logger.debug("SessionGuard audit event: %s", _safe_json(event))

        return event

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return William-compatible success result.

        Required compatibility hook.
        """
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return William-compatible error result.

        Required compatibility hook.
        """
        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error) if error is not None else message,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # =========================================================================
    # Sanitization
    # =========================================================================

    def _sanitize_payload(self, payload: Any, depth: int = 0, parent_key: str = "") -> Any:
        """Sanitize payloads before logs/events/storage."""
        if depth > self.config.payload_max_depth:
            return "[max_depth_reached]"

        if self.config.redact_sensitive_values and parent_key.lower() in SENSITIVE_KEYS:
            return "[redacted]"

        if payload is None or isinstance(payload, (bool, int, float)):
            return payload

        if isinstance(payload, str):
            if self._looks_like_secret(payload):
                return "[redacted]"
            return _truncate_string(payload, self.config.string_max_length)

        if isinstance(payload, Mapping):
            output: Dict[str, Any] = {}
            for raw_key, raw_value in payload.items():
                key = _truncate_string(str(raw_key), 256)
                if self.config.redact_sensitive_values and key.lower() in SENSITIVE_KEYS:
                    output[key] = "[redacted]"
                else:
                    output[key] = self._sanitize_payload(raw_value, depth + 1, key)
            return output

        if isinstance(payload, (list, tuple, set)):
            return [
                self._sanitize_payload(item, depth + 1, parent_key)
                for item in list(payload)[:1000]
            ]

        return _truncate_string(str(payload), self.config.string_max_length)

    def _looks_like_secret(self, value: str) -> bool:
        """Detect obvious secret-like strings."""
        secret_patterns = (
            r"sk-[A-Za-z0-9_\-]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"AIza[0-9A-Za-z_\-]{20,}",
            r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}",
            r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+",
        )
        return any(re.search(pattern, value) for pattern in secret_patterns)

    # =========================================================================
    # Scope helpers
    # =========================================================================

    def _scope_key(self, user_id: str, workspace_id: str) -> Tuple[str, str]:
        """Build SaaS isolation scope key."""
        return user_id, workspace_id

    def _get_scope_sessions(self, user_id: str, workspace_id: str) -> Dict[str, SessionRecord]:
        """Get or create sessions dict for scope. Caller should hold lock."""
        scope = self._scope_key(user_id, workspace_id)
        if scope not in self._sessions:
            self._sessions[scope] = {}
        return self._sessions[scope]

    def _get_scope_trusted_devices(self, user_id: str, workspace_id: str) -> Dict[str, DeviceRecord]:
        """Get or create trusted devices dict for scope. Caller should hold lock."""
        scope = self._scope_key(user_id, workspace_id)
        if scope not in self._trusted_devices:
            self._trusted_devices[scope] = {}
        return self._trusted_devices[scope]

    def _get_scope_blocked_devices(self, user_id: str, workspace_id: str) -> Dict[str, DeviceRecord]:
        """Get or create blocked devices dict for scope. Caller should hold lock."""
        scope = self._scope_key(user_id, workspace_id)
        if scope not in self._blocked_devices:
            self._blocked_devices[scope] = {}
        return self._blocked_devices[scope]

    def _session_to_dict(self, session: SessionRecord, include_sensitive_runtime: bool = False) -> Dict[str, Any]:
        """Convert session to dict with safe redaction."""
        data = asdict(session)
        if not include_sensitive_runtime:
            data["ip_address"] = None
            data["user_agent"] = None
        return self._sanitize_payload(data)

    def _device_to_dict(self, device: DeviceRecord) -> Dict[str, Any]:
        """Convert device to safe dict."""
        return self._sanitize_payload(asdict(device))

    # =========================================================================
    # Device helpers
    # =========================================================================

    def _build_device_context(
        self,
        device_id: Optional[Any] = None,
        device_type: Optional[Any] = None,
        platform: Optional[Any] = None,
        user_agent: Optional[Any] = None,
        ip_address: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Build normalized device context."""
        normalized_device_id = _normalize_optional_identifier(device_id, "device_id")
        normalized_device_type = _normalize_device_type(device_type)
        normalized_platform = _truncate_string(str(platform).strip(), 128) if platform is not None and str(platform).strip() else None
        normalized_user_agent = _normalize_user_agent(user_agent)
        normalized_ip = _normalize_ip(ip_address)

        device_fingerprint = _fingerprint_device(
            device_id=normalized_device_id,
            user_agent=normalized_user_agent,
            ip_address=normalized_ip,
            device_type=normalized_device_type,
            platform=normalized_platform,
        )

        return {
            "device_id": normalized_device_id,
            "device_type": normalized_device_type,
            "platform": normalized_platform,
            "user_agent": normalized_user_agent,
            "ip_address": normalized_ip,
            "device_fingerprint": device_fingerprint,
            "user_agent_hash": _stable_hash(normalized_user_agent or "") if normalized_user_agent else None,
            "ip_address_hash": _stable_hash(normalized_ip or "") if normalized_ip else None,
        }

    def _is_device_trusted(self, user_id: str, workspace_id: str, device_fingerprint: str) -> bool:
        """Return whether device is trusted for user/workspace."""
        with self._lock:
            devices = self._trusted_devices.get((user_id, workspace_id), {})
            record = devices.get(device_fingerprint)
            return bool(record and record.status == "trusted")

    def _is_device_blocked(self, user_id: str, workspace_id: str, device_fingerprint: str) -> bool:
        """Return whether device is blocked for user/workspace."""
        with self._lock:
            devices = self._blocked_devices.get((user_id, workspace_id), {})
            record = devices.get(device_fingerprint)
            return bool(record and record.status == "blocked")

    # =========================================================================
    # Public session lifecycle
    # =========================================================================

    def create_session(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Optional[Any] = None,
        device_id: Optional[Any] = None,
        device_type: Optional[Any] = None,
        platform: Optional[Any] = None,
        user_agent: Optional[Any] = None,
        ip_address: Optional[Any] = None,
        source: str = "unknown",
        risk_level: str = "low",
        risk_score: float = 0.0,
        authenticated: bool = True,
        reauthenticated: bool = False,
        biometric_verified: bool = False,
        trust_device_on_create: bool = False,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create and track a new session.

        This does not authenticate credentials. It records a session after
        upstream authentication has succeeded.
        """
        try:
            self._maybe_cleanup_expired_sessions()

            ctx = self._validate_task_context(user_id, workspace_id)
            normalized_user_id = str(ctx["user_id"])
            normalized_workspace_id = str(ctx["workspace_id"])
            normalized_session_id = (
                _normalize_identifier(session_id, "session_id")
                if session_id is not None
                else _safe_uuid("sess")
            )

            device_context = self._build_device_context(
                device_id=device_id,
                device_type=device_type,
                platform=platform,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            normalized_risk_level = _normalize_risk_level(risk_level)
            normalized_risk_score = max(0.0, min(100.0, float(risk_score)))
            now = _unix_now()
            now_iso = _utc_now_iso()

            device_fingerprint = str(device_context["device_fingerprint"])
            blocked_device = self._is_device_blocked(
                normalized_user_id,
                normalized_workspace_id,
                device_fingerprint,
            )
            trusted_device = self._is_device_trusted(
                normalized_user_id,
                normalized_workspace_id,
                device_fingerprint,
            )
            unknown_device = not trusted_device

            status = SESSION_STATUS_ACTIVE
            if blocked_device and self.config.block_known_bad_devices:
                status = SESSION_STATUS_BLOCKED
            elif unknown_device and self.config.unknown_device_policy in {"reauth_required", "biometric_required", "review"}:
                status = SESSION_STATUS_UNKNOWN_DEVICE
            elif unknown_device and self.config.unknown_device_policy == "block":
                status = SESSION_STATUS_BLOCKED

            session = SessionRecord(
                session_id=normalized_session_id,
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                status=status,
                device_fingerprint=device_fingerprint,
                device_id=device_context["device_id"],
                device_type=device_context["device_type"],
                platform=device_context["platform"],
                ip_address=device_context["ip_address"],
                ip_address_hash=device_context["ip_address_hash"],
                user_agent=device_context["user_agent"],
                user_agent_hash=device_context["user_agent_hash"],
                source=_truncate_string(str(source or "unknown"), 128),
                risk_level=normalized_risk_level,
                risk_score=normalized_risk_score,
                created_at=now_iso,
                created_at_unix=now,
                last_activity_at=now_iso,
                last_activity_unix=now,
                last_reauth_at=now_iso if reauthenticated or authenticated else None,
                last_reauth_unix=now if reauthenticated or authenticated else None,
                last_biometric_at=now_iso if biometric_verified else None,
                last_biometric_unix=now if biometric_verified else None,
                expires_at=datetime.fromtimestamp(now + self.config.absolute_timeout_seconds, timezone.utc).isoformat(),
                expires_at_unix=now + self.config.absolute_timeout_seconds,
                unknown_device=unknown_device,
                trusted_device=trusted_device,
                blocked_device=blocked_device,
                metadata=self._sanitize_payload(_coerce_mapping(metadata, "metadata")),
            )

            if trust_device_on_create and not blocked_device:
                self.trust_device(
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                    device_id=device_context["device_id"],
                    device_type=device_context["device_type"],
                    platform=device_context["platform"],
                    user_agent=device_context["user_agent"],
                    ip_address=device_context["ip_address"],
                    label="Trusted during session creation",
                    metadata={"created_from_session_id": normalized_session_id},
                )
                session.trusted_device = True
                session.unknown_device = False
                if session.status == SESSION_STATUS_UNKNOWN_DEVICE:
                    session.status = SESSION_STATUS_ACTIVE

            with self._lock:
                sessions = self._get_scope_sessions(normalized_user_id, normalized_workspace_id)

                if len(sessions) >= self.config.max_sessions_per_scope and normalized_session_id not in sessions:
                    self._prune_oldest_session_locked(normalized_user_id, normalized_workspace_id)

                before = sessions.get(normalized_session_id)
                sessions[normalized_session_id] = session

            evaluation = self._evaluate_session(
                session=session,
                action="session.create",
                device_context=device_context,
                risk_level=normalized_risk_level,
                risk_score=normalized_risk_score,
                sensitive_action=False,
            )

            approval_request = self._approval_request_for_evaluation(session, evaluation, "session.create")

            session_payload = self._session_to_dict(session)

            self._log_audit_event(
                action="session_created",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={
                    "status": session.status,
                    "unknown_device": unknown_device,
                    "trusted_device": trusted_device,
                    "blocked_device": blocked_device,
                    "decision": evaluation.decision,
                    "source": session.source,
                },
                level="warning" if evaluation.decision != SessionDecision.ALLOW.value else "info",
            )

            self._emit_agent_event(
                event_type="session_created",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                data={
                    "status": session.status,
                    "decision": evaluation.decision,
                    "unknown_device": unknown_device,
                },
            )

            return self._safe_result(
                message="Session created and evaluated.",
                data={
                    "session": session_payload,
                    "decision": asdict(evaluation),
                    "approval_request": approval_request,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "create_session",
                        evaluation=evaluation,
                        before=self._session_to_dict(before) if before else None,
                        after=session_payload,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "security_session_created",
                        {
                            "session_id": normalized_session_id,
                            "status": session.status,
                            "decision": evaluation.decision,
                            "unknown_device": unknown_device,
                            "trusted_device": trusted_device,
                            "blocked_device": blocked_device,
                            "risk_level": normalized_risk_level,
                        },
                    ),
                },
                metadata={"session_id": normalized_session_id},
            )

        except Exception as exc:
            return self._handle_exception("Failed to create session.", exc)

    def validate_session(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        action: str = "session.validate",
        device_id: Optional[Any] = None,
        device_type: Optional[Any] = None,
        platform: Optional[Any] = None,
        user_agent: Optional[Any] = None,
        ip_address: Optional[Any] = None,
        risk_level: str = "low",
        risk_score: float = 0.0,
        sensitive_action: Optional[bool] = None,
        update_activity: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate whether a session is still safe.

        Returns decision:
            allow | reauth_required | biometric_required | block | review
        """
        try:
            self._maybe_cleanup_expired_sessions()

            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            normalized_user_id = str(ctx["user_id"])
            normalized_workspace_id = str(ctx["workspace_id"])
            normalized_session_id = str(ctx["session_id"])

            normalized_risk_level = _normalize_risk_level(risk_level)
            normalized_risk_score = max(0.0, min(100.0, float(risk_score)))

            normalized_action = _truncate_string(str(action or "session.validate").strip().lower(), 256)
            if not normalized_action:
                normalized_action = "session.validate"

            if sensitive_action is None:
                sensitive_action = self._requires_security_check(
                    normalized_action,
                    normalized_risk_level,
                    metadata=metadata,
                )

            device_context = self._build_device_context(
                device_id=device_id,
                device_type=device_type,
                platform=platform,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            with self._lock:
                session = self._sessions.get((normalized_user_id, normalized_workspace_id), {}).get(normalized_session_id)

                if not session:
                    evaluation = SessionEvaluation(
                        decision=SessionDecision.BLOCK.value,
                        reason=SessionReason.SESSION_NOT_FOUND.value,
                        status=SESSION_STATUS_BLOCKED,
                        allowed=False,
                        blocked=True,
                        risk_level=normalized_risk_level,
                        risk_score=normalized_risk_score,
                        trace=[{"step": "lookup", "found": False}],
                    )

                    approval_request = self._approval_request_for_missing_session(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        normalized_action,
                        evaluation,
                    )

                    self._log_audit_event(
                        action="session_validation_failed",
                        user_id=normalized_user_id,
                        workspace_id=normalized_workspace_id,
                        session_id=normalized_session_id,
                        details={
                            "reason": evaluation.reason,
                            "decision": evaluation.decision,
                        },
                        level="warning",
                    )

                    return self._safe_result(
                        message="Session validation failed: session not found.",
                        data={
                            "session": None,
                            "decision": asdict(evaluation),
                            "approval_request": approval_request,
                            "verification_payload": self._prepare_verification_payload(
                                normalized_user_id,
                                normalized_workspace_id,
                                normalized_session_id,
                                "validate_session",
                                evaluation=evaluation,
                            ),
                            "memory_payload": self._prepare_memory_payload(
                                normalized_user_id,
                                normalized_workspace_id,
                                normalized_session_id,
                                "security_session_validation_failed",
                                {
                                    "reason": evaluation.reason,
                                    "decision": evaluation.decision,
                                },
                                importance="critical",
                            ),
                        },
                    )

                before = self._session_to_dict(session)

                evaluation = self._evaluate_session(
                    session=session,
                    action=normalized_action,
                    device_context=device_context,
                    risk_level=normalized_risk_level,
                    risk_score=normalized_risk_score,
                    sensitive_action=bool(sensitive_action),
                )

                session.risk_level = normalized_risk_level
                session.risk_score = normalized_risk_score

                if evaluation.decision == SessionDecision.ALLOW.value and update_activity:
                    now = _unix_now()
                    session.last_activity_unix = now
                    session.last_activity_at = _utc_now_iso()
                    session.status = SESSION_STATUS_ACTIVE

                elif evaluation.decision == SessionDecision.REAUTH_REQUIRED.value:
                    session.status = SESSION_STATUS_REAUTH_REQUIRED

                elif evaluation.decision == SessionDecision.BIOMETRIC_REQUIRED.value:
                    session.status = SESSION_STATUS_REAUTH_REQUIRED

                elif evaluation.decision == SessionDecision.BLOCK.value:
                    if session.status not in {SESSION_STATUS_REVOKED, SESSION_STATUS_BLOCKED, SESSION_STATUS_LOCKED}:
                        session.status = SESSION_STATUS_BLOCKED if evaluation.reason in {
                            SessionReason.BLOCKED_DEVICE.value,
                            SessionReason.DEVICE_MISMATCH.value,
                        } else session.status

                elif evaluation.decision == SessionDecision.REVIEW.value:
                    session.status = SESSION_STATUS_UNKNOWN_DEVICE

                after = self._session_to_dict(session)

            approval_request = self._approval_request_for_evaluation(session, evaluation, normalized_action)

            level = "info"
            if evaluation.decision in {SessionDecision.REAUTH_REQUIRED.value, SessionDecision.BIOMETRIC_REQUIRED.value, SessionDecision.REVIEW.value}:
                level = "warning"
            elif evaluation.decision == SessionDecision.BLOCK.value:
                level = "critical"

            self._log_audit_event(
                action="session_validated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={
                    "action_checked": normalized_action,
                    "decision": evaluation.decision,
                    "reason": evaluation.reason,
                    "status": evaluation.status,
                    "risk_level": normalized_risk_level,
                    "sensitive_action": bool(sensitive_action),
                },
                level=level,
            )

            self._emit_agent_event(
                event_type="session_validated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                data={
                    "decision": evaluation.decision,
                    "reason": evaluation.reason,
                    "status": evaluation.status,
                },
            )

            return self._safe_result(
                message=f"Session decision: {evaluation.decision}.",
                data={
                    "session": after,
                    "decision": asdict(evaluation),
                    "approval_request": approval_request,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "validate_session",
                        evaluation=evaluation,
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "security_session_validated",
                        {
                            "action": normalized_action,
                            "decision": evaluation.decision,
                            "reason": evaluation.reason,
                            "status": evaluation.status,
                            "risk_level": normalized_risk_level,
                        },
                        importance="critical" if evaluation.decision == SessionDecision.BLOCK.value else "security",
                    ),
                },
                metadata={
                    "decision": evaluation.decision,
                    "session_id": normalized_session_id,
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to validate session.", exc)

    def touch_session(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update last activity timestamp for a session."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            session_id_str = str(ctx["session_id"])

            with self._lock:
                session = self._sessions.get((user_id_str, workspace_id_str), {}).get(session_id_str)

                if not session:
                    return self._safe_result(
                        message="Session not found. Activity was not updated.",
                        data={"updated": False, "session": None},
                    )

                before = self._session_to_dict(session)
                now = _unix_now()
                session.last_activity_unix = now
                session.last_activity_at = _utc_now_iso()

                if metadata:
                    session.metadata.update(self._sanitize_payload(_coerce_mapping(metadata, "metadata")))

                after = self._session_to_dict(session)

            self._log_audit_event(
                action="session_touched",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=session_id_str,
                details={"updated": True},
            )

            return self._safe_result(
                message="Session activity updated.",
                data={
                    "updated": True,
                    "session": after,
                    "verification_payload": self._prepare_verification_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "touch_session",
                        before=before,
                        after=after,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to touch session.", exc)

    def mark_reauthenticated(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        method: str = "password",
        success: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a session as re-authenticated or record failed attempt."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            session_id_str = str(ctx["session_id"])

            with self._lock:
                session = self._sessions.get((user_id_str, workspace_id_str), {}).get(session_id_str)

                if not session:
                    return self._safe_result(
                        message="Session not found. Re-authentication was not recorded.",
                        data={"updated": False, "session": None},
                    )

                before = self._session_to_dict(session)
                now = _unix_now()
                now_iso = _utc_now_iso()

                if success:
                    session.last_reauth_unix = now
                    session.last_reauth_at = now_iso
                    session.failed_reauth_attempts = 0
                    session.locked_until_unix = None
                    if session.status in {
                        SESSION_STATUS_REAUTH_REQUIRED,
                        SESSION_STATUS_UNKNOWN_DEVICE,
                        SESSION_STATUS_LOCKED,
                    }:
                        session.status = SESSION_STATUS_ACTIVE
                else:
                    session.failed_reauth_attempts += 1
                    if session.failed_reauth_attempts >= self.config.max_failed_reauth_attempts:
                        session.status = SESSION_STATUS_LOCKED
                        session.locked_until_unix = now + self.config.failed_reauth_lock_seconds

                if metadata:
                    session.metadata.setdefault("reauth_events", [])
                    session.metadata["reauth_events"].append(
                        self._sanitize_payload(
                            {
                                "method": method,
                                "success": bool(success),
                                "created_at": now_iso,
                                "metadata": metadata,
                            }
                        )
                    )

                after = self._session_to_dict(session)

            level = "info" if success else "warning"
            if not success and session.failed_reauth_attempts >= self.config.max_failed_reauth_attempts:
                level = "critical"

            self._log_audit_event(
                action="session_reauthentication_recorded",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=session_id_str,
                details={
                    "success": bool(success),
                    "method": method,
                    "failed_reauth_attempts": session.failed_reauth_attempts,
                    "status": session.status,
                },
                level=level,
            )

            return self._safe_result(
                message="Session re-authentication recorded.",
                data={
                    "updated": True,
                    "session": after,
                    "verification_payload": self._prepare_verification_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "mark_reauthenticated",
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "security_session_reauthentication",
                        {
                            "success": bool(success),
                            "method": method,
                            "status": session.status,
                        },
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to mark session re-authentication.", exc)

    def mark_biometric_verified(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        method: str = "device_biometric",
        success: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark biometric verification evidence for a session."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            session_id_str = str(ctx["session_id"])

            with self._lock:
                session = self._sessions.get((user_id_str, workspace_id_str), {}).get(session_id_str)

                if not session:
                    return self._safe_result(
                        message="Session not found. Biometric verification was not recorded.",
                        data={"updated": False, "session": None},
                    )

                before = self._session_to_dict(session)
                now = _unix_now()
                now_iso = _utc_now_iso()

                if success:
                    session.last_biometric_unix = now
                    session.last_biometric_at = now_iso
                    session.last_reauth_unix = now
                    session.last_reauth_at = now_iso
                    session.failed_reauth_attempts = 0
                    session.locked_until_unix = None
                    if session.status in {
                        SESSION_STATUS_REAUTH_REQUIRED,
                        SESSION_STATUS_UNKNOWN_DEVICE,
                        SESSION_STATUS_LOCKED,
                    }:
                        session.status = SESSION_STATUS_ACTIVE
                else:
                    session.failed_reauth_attempts += 1
                    if session.failed_reauth_attempts >= self.config.max_failed_reauth_attempts:
                        session.status = SESSION_STATUS_LOCKED
                        session.locked_until_unix = now + self.config.failed_reauth_lock_seconds

                if metadata:
                    session.metadata.setdefault("biometric_events", [])
                    session.metadata["biometric_events"].append(
                        self._sanitize_payload(
                            {
                                "method": method,
                                "success": bool(success),
                                "created_at": now_iso,
                                "metadata": metadata,
                            }
                        )
                    )

                after = self._session_to_dict(session)

            self._log_audit_event(
                action="session_biometric_verification_recorded",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=session_id_str,
                details={
                    "success": bool(success),
                    "method": method,
                    "status": session.status,
                },
                level="info" if success else "warning",
            )

            return self._safe_result(
                message="Session biometric verification recorded.",
                data={
                    "updated": True,
                    "session": after,
                    "verification_payload": self._prepare_verification_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "mark_biometric_verified",
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "security_session_biometric_verification",
                        {
                            "success": bool(success),
                            "method": method,
                            "status": session.status,
                        },
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to mark biometric verification.", exc)

    # =========================================================================
    # Session evaluation
    # =========================================================================

    def _evaluate_session(
        self,
        *,
        session: SessionRecord,
        action: str,
        device_context: Mapping[str, Any],
        risk_level: str,
        risk_score: float,
        sensitive_action: bool,
    ) -> SessionEvaluation:
        """Core session safety evaluation."""
        now = _unix_now()
        trace: List[Dict[str, Any]] = []
        warnings: List[str] = []

        session_age = max(0.0, now - session.created_at_unix)
        idle_seconds = max(0.0, now - session.last_activity_unix)

        seconds_until_idle = self.config.idle_timeout_seconds - idle_seconds
        seconds_until_absolute = (session.expires_at_unix or (session.created_at_unix + self.config.absolute_timeout_seconds)) - now

        last_reauth_unix = session.last_reauth_unix or session.created_at_unix
        reauth_interval = (
            self.config.high_risk_reauth_interval_seconds
            if risk_level in {"high", "critical"}
            else self.config.reauth_interval_seconds
        )
        seconds_since_reauth = now - last_reauth_unix
        seconds_until_reauth = reauth_interval - seconds_since_reauth

        base = {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "session_age_seconds": session_age,
            "idle_seconds": idle_seconds,
            "seconds_until_idle_timeout": max(0.0, seconds_until_idle),
            "seconds_until_absolute_timeout": max(0.0, seconds_until_absolute),
            "seconds_until_reauth_required": max(0.0, seconds_until_reauth),
            "unknown_device": session.unknown_device,
            "trusted_device": session.trusted_device,
            "blocked_device": session.blocked_device,
        }

        trace.append({"step": "session_timing", **base})

        if session.status == SESSION_STATUS_REVOKED:
            return SessionEvaluation(
                decision=SessionDecision.BLOCK.value,
                reason=SessionReason.SESSION_REVOKED.value,
                status=session.status,
                blocked=True,
                trace=trace,
                warnings=warnings,
                **base,
            )

        if session.status == SESSION_STATUS_BLOCKED:
            return SessionEvaluation(
                decision=SessionDecision.BLOCK.value,
                reason=SessionReason.SESSION_BLOCKED.value,
                status=session.status,
                blocked=True,
                trace=trace,
                warnings=warnings,
                **base,
            )

        if session.status == SESSION_STATUS_LOCKED:
            if session.locked_until_unix and session.locked_until_unix > now:
                return SessionEvaluation(
                    decision=SessionDecision.BLOCK.value,
                    reason=SessionReason.FAILED_REAUTH_LOCKED.value,
                    status=session.status,
                    blocked=True,
                    trace=trace + [{"step": "failed_reauth_lock", "locked_until_unix": session.locked_until_unix}],
                    warnings=warnings,
                    **base,
                )
            session.status = SESSION_STATUS_REAUTH_REQUIRED
            session.locked_until_unix = None

        if session.blocked_device or self._is_device_blocked(session.user_id, session.workspace_id, session.device_fingerprint):
            return SessionEvaluation(
                decision=SessionDecision.BLOCK.value,
                reason=SessionReason.BLOCKED_DEVICE.value,
                status=SESSION_STATUS_BLOCKED,
                blocked=True,
                blocked_device=True,
                trace=trace + [{"step": "blocked_device", "matched": True}],
                warnings=warnings,
                **{k: v for k, v in base.items() if k != "blocked_device"},
            )

        if idle_seconds >= self.config.idle_timeout_seconds:
            session.status = SESSION_STATUS_EXPIRED
            return SessionEvaluation(
                decision=SessionDecision.BLOCK.value,
                reason=SessionReason.SESSION_EXPIRED_IDLE.value,
                status=session.status,
                blocked=True,
                trace=trace + [{"step": "idle_timeout", "expired": True}],
                warnings=warnings,
                **base,
            )

        if seconds_until_absolute <= 0:
            session.status = SESSION_STATUS_EXPIRED
            return SessionEvaluation(
                decision=SessionDecision.BLOCK.value,
                reason=SessionReason.SESSION_EXPIRED_ABSOLUTE.value,
                status=session.status,
                blocked=True,
                trace=trace + [{"step": "absolute_timeout", "expired": True}],
                warnings=warnings,
                **base,
            )

        incoming_fingerprint = str(device_context.get("device_fingerprint") or "")
        if incoming_fingerprint and incoming_fingerprint != session.device_fingerprint:
            if self.config.require_reauth_on_user_agent_change or self.config.require_reauth_on_ip_change:
                return SessionEvaluation(
                    decision=SessionDecision.REAUTH_REQUIRED.value,
                    reason=SessionReason.DEVICE_MISMATCH.value,
                    status=SESSION_STATUS_REAUTH_REQUIRED,
                    reauth_required=True,
                    trace=trace + [
                        {
                            "step": "device_fingerprint_check",
                            "matched": False,
                            "stored_fingerprint": session.device_fingerprint,
                            "incoming_fingerprint": incoming_fingerprint,
                        }
                    ],
                    warnings=warnings + ["Device fingerprint changed during session."],
                    **base,
                )

        incoming_ip_hash = device_context.get("ip_address_hash")
        if (
            self.config.require_reauth_on_ip_change
            and incoming_ip_hash
            and session.ip_address_hash
            and incoming_ip_hash != session.ip_address_hash
        ):
            return SessionEvaluation(
                decision=SessionDecision.REAUTH_REQUIRED.value,
                reason=SessionReason.IP_CHANGED.value,
                status=SESSION_STATUS_REAUTH_REQUIRED,
                reauth_required=True,
                trace=trace + [{"step": "ip_change_check", "changed": True}],
                warnings=warnings + ["IP address changed during session."],
                **base,
            )

        incoming_user_agent_hash = device_context.get("user_agent_hash")
        if (
            self.config.require_reauth_on_user_agent_change
            and incoming_user_agent_hash
            and session.user_agent_hash
            and incoming_user_agent_hash != session.user_agent_hash
        ):
            return SessionEvaluation(
                decision=SessionDecision.REAUTH_REQUIRED.value,
                reason=SessionReason.USER_AGENT_CHANGED.value,
                status=SESSION_STATUS_REAUTH_REQUIRED,
                reauth_required=True,
                trace=trace + [{"step": "user_agent_change_check", "changed": True}],
                warnings=warnings + ["User agent changed during session."],
                **base,
            )

        if session.unknown_device and not session.trusted_device:
            if self.config.unknown_device_policy == "block":
                return SessionEvaluation(
                    decision=SessionDecision.BLOCK.value,
                    reason=SessionReason.UNKNOWN_DEVICE.value,
                    status=SESSION_STATUS_BLOCKED,
                    blocked=True,
                    trace=trace + [{"step": "unknown_device_policy", "policy": "block"}],
                    warnings=warnings,
                    **base,
                )

            if self.config.unknown_device_policy == "biometric_required":
                return SessionEvaluation(
                    decision=SessionDecision.BIOMETRIC_REQUIRED.value,
                    reason=SessionReason.UNKNOWN_DEVICE.value,
                    status=SESSION_STATUS_REAUTH_REQUIRED,
                    biometric_required=True,
                    trace=trace + [{"step": "unknown_device_policy", "policy": "biometric_required"}],
                    warnings=warnings,
                    **base,
                )

            if self.config.unknown_device_policy == "reauth_required":
                return SessionEvaluation(
                    decision=SessionDecision.REAUTH_REQUIRED.value,
                    reason=SessionReason.UNKNOWN_DEVICE.value,
                    status=SESSION_STATUS_REAUTH_REQUIRED,
                    reauth_required=True,
                    trace=trace + [{"step": "unknown_device_policy", "policy": "reauth_required"}],
                    warnings=warnings,
                    **base,
                )

            if self.config.unknown_device_policy == "review":
                return SessionEvaluation(
                    decision=SessionDecision.REVIEW.value,
                    reason=SessionReason.UNKNOWN_DEVICE.value,
                    status=SESSION_STATUS_UNKNOWN_DEVICE,
                    review_required=True,
                    trace=trace + [{"step": "unknown_device_policy", "policy": "review"}],
                    warnings=warnings,
                    **base,
                )

        if risk_level == "critical" and self.config.require_biometric_for_critical_risk:
            return SessionEvaluation(
                decision=SessionDecision.BIOMETRIC_REQUIRED.value,
                reason=SessionReason.BIOMETRIC_REQUIRED.value,
                status=SESSION_STATUS_REAUTH_REQUIRED,
                biometric_required=True,
                trace=trace + [{"step": "critical_risk", "biometric_required": True}],
                warnings=warnings,
                **base,
            )

        if risk_level in {"high", "critical"} and seconds_since_reauth >= self.config.high_risk_reauth_interval_seconds:
            return SessionEvaluation(
                decision=SessionDecision.REAUTH_REQUIRED.value,
                reason=SessionReason.HIGH_RISK_REAUTH_REQUIRED.value,
                status=SESSION_STATUS_REAUTH_REQUIRED,
                reauth_required=True,
                trace=trace + [{"step": "high_risk_reauth_interval", "expired": True}],
                warnings=warnings,
                **base,
            )

        if seconds_since_reauth >= self.config.reauth_interval_seconds:
            return SessionEvaluation(
                decision=SessionDecision.REAUTH_REQUIRED.value,
                reason=SessionReason.REAUTH_INTERVAL_EXPIRED.value,
                status=SESSION_STATUS_REAUTH_REQUIRED,
                reauth_required=True,
                trace=trace + [{"step": "reauth_interval", "expired": True}],
                warnings=warnings,
                **base,
            )

        if sensitive_action and self.config.require_reauth_for_sensitive_actions:
            if seconds_since_reauth >= min(self.config.reauth_interval_seconds, 900):
                return SessionEvaluation(
                    decision=SessionDecision.REAUTH_REQUIRED.value,
                    reason=SessionReason.SENSITIVE_ACTION_REAUTH.value,
                    status=SESSION_STATUS_REAUTH_REQUIRED,
                    reauth_required=True,
                    trace=trace + [{"step": "sensitive_action_reauth", "required": True}],
                    warnings=warnings,
                    **base,
                )

        return SessionEvaluation(
            decision=SessionDecision.ALLOW.value,
            reason=SessionReason.SESSION_VALID.value,
            status=SESSION_STATUS_ACTIVE,
            allowed=True,
            trace=trace + [{"step": "final", "allowed": True}],
            warnings=warnings,
            **base,
        )

    def _approval_request_for_evaluation(
        self,
        session: SessionRecord,
        evaluation: SessionEvaluation,
        action: str,
    ) -> Optional[Dict[str, Any]]:
        """Create approval request when needed."""
        if evaluation.decision == SessionDecision.REAUTH_REQUIRED.value:
            return self._request_security_approval(
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                session_id=session.session_id,
                action=action,
                reason=evaluation.reason,
                required_method="reauthentication",
                metadata={"decision": evaluation.decision, "risk_level": evaluation.risk_level},
            )

        if evaluation.decision == SessionDecision.BIOMETRIC_REQUIRED.value:
            return self._request_security_approval(
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                session_id=session.session_id,
                action=action,
                reason=evaluation.reason,
                required_method="biometric",
                metadata={"decision": evaluation.decision, "risk_level": evaluation.risk_level},
            )

        if evaluation.decision == SessionDecision.REVIEW.value:
            return self._request_security_approval(
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                session_id=session.session_id,
                action=action,
                reason=evaluation.reason,
                required_method="manual_review",
                metadata={"decision": evaluation.decision, "risk_level": evaluation.risk_level},
            )

        return None

    def _approval_request_for_missing_session(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
        action: str,
        evaluation: SessionEvaluation,
    ) -> Dict[str, Any]:
        """Create request payload for missing-session case."""
        return self._request_security_approval(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            action=action,
            reason=evaluation.reason,
            required_method="reauthentication",
            metadata={"decision": evaluation.decision},
        )

    # =========================================================================
    # Session revocation / blocking
    # =========================================================================

    def revoke_session(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        reason: str = "Session revoked by security policy.",
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Revoke a session. Confirmation/security approval is expected."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            session_id_str = str(ctx["session_id"])

            if not security_approved:
                approval = self._request_security_approval(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    session_id=session_id_str,
                    action="session.revoke",
                    reason="Revoking a session requires security approval.",
                    required_method="confirmation",
                    metadata={"requested_reason": reason},
                )
                return self._safe_result(
                    message="Security approval required before revoking session.",
                    data={
                        "revoked": False,
                        "approval_request": approval,
                    },
                )

            with self._lock:
                session = self._sessions.get((user_id_str, workspace_id_str), {}).get(session_id_str)
                if not session:
                    return self._safe_result(
                        message="Session not found. Nothing revoked.",
                        data={"revoked": False, "session": None},
                    )

                before = self._session_to_dict(session)
                session.status = SESSION_STATUS_REVOKED
                session.revoked_at = _utc_now_iso()
                session.metadata["revocation_reason"] = _truncate_string(str(reason), 1000)
                after = self._session_to_dict(session)

            self._log_audit_event(
                action="session_revoked",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=session_id_str,
                details={"reason": reason},
                level="warning",
            )

            return self._safe_result(
                message="Session revoked.",
                data={
                    "revoked": True,
                    "session": after,
                    "verification_payload": self._prepare_verification_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "revoke_session",
                        before=before,
                        after=after,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to revoke session.", exc)

    def block_session(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        reason: str = "Session blocked by security policy.",
        block_device_too: bool = False,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Block a session, optionally blocking its device fingerprint too."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            session_id_str = str(ctx["session_id"])

            if not security_approved:
                approval = self._request_security_approval(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    session_id=session_id_str,
                    action="session.block",
                    reason="Blocking a session requires security approval.",
                    required_method="confirmation",
                    metadata={"requested_reason": reason, "block_device_too": block_device_too},
                )
                return self._safe_result(
                    message="Security approval required before blocking session.",
                    data={
                        "blocked": False,
                        "approval_request": approval,
                    },
                )

            with self._lock:
                session = self._sessions.get((user_id_str, workspace_id_str), {}).get(session_id_str)
                if not session:
                    return self._safe_result(
                        message="Session not found. Nothing blocked.",
                        data={"blocked": False, "session": None},
                    )

                before = self._session_to_dict(session)
                session.status = SESSION_STATUS_BLOCKED
                session.blocked_at = _utc_now_iso()
                session.metadata["block_reason"] = _truncate_string(str(reason), 1000)

                if block_device_too:
                    self._block_device_locked(
                        user_id=user_id_str,
                        workspace_id=workspace_id_str,
                        device_fingerprint=session.device_fingerprint,
                        device_id=session.device_id,
                        device_type=session.device_type,
                        platform=session.platform,
                        user_agent_hash=session.user_agent_hash,
                        ip_address_hash=session.ip_address_hash,
                        reason=reason,
                    )
                    session.blocked_device = True

                after = self._session_to_dict(session)

            self._log_audit_event(
                action="session_blocked",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=session_id_str,
                details={"reason": reason, "block_device_too": block_device_too},
                level="critical",
            )

            return self._safe_result(
                message="Session blocked.",
                data={
                    "blocked": True,
                    "session": after,
                    "verification_payload": self._prepare_verification_payload(
                        user_id_str,
                        workspace_id_str,
                        session_id_str,
                        "block_session",
                        before=before,
                        after=after,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to block session.", exc)

    def revoke_all_sessions(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        except_session_id: Optional[Any] = None,
        reason: str = "All sessions revoked by security policy.",
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Revoke all sessions in a user/workspace scope."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            except_id = _normalize_identifier(except_session_id, "except_session_id") if except_session_id is not None else None

            if not security_approved:
                approval = self._request_security_approval(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    session_id=except_id,
                    action="session.revoke_all",
                    reason="Revoking all sessions requires security approval.",
                    required_method="biometric",
                    metadata={"requested_reason": reason, "except_session_id": except_id},
                )
                return self._safe_result(
                    message="Security approval required before revoking all sessions.",
                    data={"revoked_count": 0, "approval_request": approval},
                )

            revoked_count = 0
            with self._lock:
                sessions = self._sessions.get((user_id_str, workspace_id_str), {})
                for sid, session in sessions.items():
                    if except_id and sid == except_id:
                        continue
                    if session.status not in {SESSION_STATUS_REVOKED, SESSION_STATUS_BLOCKED}:
                        session.status = SESSION_STATUS_REVOKED
                        session.revoked_at = _utc_now_iso()
                        session.metadata["revocation_reason"] = _truncate_string(str(reason), 1000)
                        revoked_count += 1

            self._log_audit_event(
                action="all_sessions_revoked",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=except_id,
                details={"revoked_count": revoked_count, "reason": reason},
                level="critical",
            )

            return self._safe_result(
                message="All matching sessions revoked.",
                data={
                    "revoked_count": revoked_count,
                    "except_session_id": except_id,
                    "memory_payload": self._prepare_memory_payload(
                        user_id_str,
                        workspace_id_str,
                        except_id,
                        "security_all_sessions_revoked",
                        {"revoked_count": revoked_count, "reason": reason},
                        importance="critical",
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to revoke all sessions.", exc)

    # =========================================================================
    # Trusted / blocked device management
    # =========================================================================

    def trust_device(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        device_id: Optional[Any] = None,
        device_type: Optional[Any] = None,
        platform: Optional[Any] = None,
        user_agent: Optional[Any] = None,
        ip_address: Optional[Any] = None,
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Trust a device for a specific user/workspace."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])

            device_context = self._build_device_context(
                device_id=device_id,
                device_type=device_type,
                platform=platform,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            device = DeviceRecord(
                device_fingerprint=str(device_context["device_fingerprint"]),
                device_id=device_context["device_id"],
                device_type=device_context["device_type"],
                platform=device_context["platform"],
                user_agent_hash=device_context["user_agent_hash"],
                ip_address_hash=device_context["ip_address_hash"],
                label=_truncate_string(str(label), 256) if label else None,
                trust_level="trusted",
                status="trusted",
                metadata=self._sanitize_payload(_coerce_mapping(metadata, "metadata")),
                last_seen_at=_utc_now_iso(),
            )

            with self._lock:
                devices = self._get_scope_trusted_devices(user_id_str, workspace_id_str)

                if len(devices) >= self.config.max_trusted_devices_per_scope and device.device_fingerprint not in devices:
                    self._prune_oldest_device_locked(devices)

                devices[device.device_fingerprint] = device

                blocked = self._blocked_devices.get((user_id_str, workspace_id_str), {})
                blocked.pop(device.device_fingerprint, None)

                sessions = self._sessions.get((user_id_str, workspace_id_str), {})
                for session in sessions.values():
                    if session.device_fingerprint == device.device_fingerprint:
                        session.trusted_device = True
                        session.unknown_device = False
                        session.blocked_device = False
                        if session.status == SESSION_STATUS_UNKNOWN_DEVICE:
                            session.status = SESSION_STATUS_ACTIVE

            self._log_audit_event(
                action="device_trusted",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=None,
                details={"device_fingerprint": device.device_fingerprint, "label": device.label},
                level="warning",
            )

            return self._safe_result(
                message="Device trusted for user/workspace.",
                data={
                    "device": self._device_to_dict(device),
                    "memory_payload": self._prepare_memory_payload(
                        user_id_str,
                        workspace_id_str,
                        None,
                        "security_device_trusted",
                        {
                            "device_fingerprint": device.device_fingerprint,
                            "device_type": device.device_type,
                            "label": device.label,
                        },
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to trust device.", exc)

    def block_device(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        device_id: Optional[Any] = None,
        device_type: Optional[Any] = None,
        platform: Optional[Any] = None,
        user_agent: Optional[Any] = None,
        ip_address: Optional[Any] = None,
        reason: str = "Device blocked by security policy.",
        revoke_matching_sessions: bool = True,
        security_approved: bool = False,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Block a device for a specific user/workspace."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])

            if not security_approved:
                approval = self._request_security_approval(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    session_id=None,
                    action="device.block",
                    reason="Blocking a device requires security approval.",
                    required_method="confirmation",
                    metadata={"requested_reason": reason},
                )
                return self._safe_result(
                    message="Security approval required before blocking device.",
                    data={"blocked": False, "approval_request": approval},
                )

            device_context = self._build_device_context(
                device_id=device_id,
                device_type=device_type,
                platform=platform,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            device_fingerprint = str(device_context["device_fingerprint"])

            with self._lock:
                device = self._block_device_locked(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    device_fingerprint=device_fingerprint,
                    device_id=device_context["device_id"],
                    device_type=device_context["device_type"],
                    platform=device_context["platform"],
                    user_agent_hash=device_context["user_agent_hash"],
                    ip_address_hash=device_context["ip_address_hash"],
                    reason=reason,
                    metadata=metadata,
                )

                revoked_count = 0
                if revoke_matching_sessions:
                    sessions = self._sessions.get((user_id_str, workspace_id_str), {})
                    for session in sessions.values():
                        if session.device_fingerprint == device_fingerprint:
                            session.blocked_device = True
                            session.status = SESSION_STATUS_BLOCKED
                            session.blocked_at = _utc_now_iso()
                            session.metadata["device_block_reason"] = _truncate_string(str(reason), 1000)
                            revoked_count += 1
                else:
                    revoked_count = 0

            self._log_audit_event(
                action="device_blocked",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=None,
                details={
                    "device_fingerprint": device_fingerprint,
                    "reason": reason,
                    "revoke_matching_sessions": revoke_matching_sessions,
                    "revoked_count": revoked_count,
                },
                level="critical",
            )

            return self._safe_result(
                message="Device blocked for user/workspace.",
                data={
                    "blocked": True,
                    "device": self._device_to_dict(device),
                    "revoked_matching_sessions": revoked_count,
                    "memory_payload": self._prepare_memory_payload(
                        user_id_str,
                        workspace_id_str,
                        None,
                        "security_device_blocked",
                        {
                            "device_fingerprint": device_fingerprint,
                            "reason": reason,
                            "revoked_matching_sessions": revoked_count,
                        },
                        importance="critical",
                    ),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to block device.", exc)

    def _block_device_locked(
        self,
        *,
        user_id: str,
        workspace_id: str,
        device_fingerprint: str,
        device_id: Optional[str],
        device_type: str,
        platform: Optional[str],
        user_agent_hash: Optional[str],
        ip_address_hash: Optional[str],
        reason: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> DeviceRecord:
        """Block device. Caller should hold lock."""
        devices = self._get_scope_blocked_devices(user_id, workspace_id)

        if len(devices) >= self.config.max_blocked_devices_per_scope and device_fingerprint not in devices:
            self._prune_oldest_device_locked(devices)

        device = DeviceRecord(
            device_fingerprint=device_fingerprint,
            device_id=device_id,
            device_type=device_type,
            platform=platform,
            user_agent_hash=user_agent_hash,
            ip_address_hash=ip_address_hash,
            label="Blocked device",
            trust_level="blocked",
            status="blocked",
            metadata=self._sanitize_payload(
                {
                    "reason": reason,
                    **_coerce_mapping(metadata, "metadata"),
                }
            ),
            last_seen_at=_utc_now_iso(),
        )

        devices[device_fingerprint] = device

        trusted = self._trusted_devices.get((user_id, workspace_id), {})
        trusted.pop(device_fingerprint, None)

        return device

    def untrust_device(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        device_fingerprint: Any,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Remove device from trusted list."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            fingerprint = _normalize_identifier(device_fingerprint, "device_fingerprint")

            if not security_approved:
                approval = self._request_security_approval(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    session_id=None,
                    action="device.untrust",
                    reason="Removing a trusted device requires confirmation.",
                    required_method="confirmation",
                    metadata={"device_fingerprint": fingerprint},
                )
                return self._safe_result(
                    message="Security approval required before untrusting device.",
                    data={"removed": False, "approval_request": approval},
                )

            with self._lock:
                trusted = self._trusted_devices.get((user_id_str, workspace_id_str), {})
                removed = trusted.pop(fingerprint, None)

            self._log_audit_event(
                action="device_untrusted",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=None,
                details={"device_fingerprint": fingerprint, "removed": removed is not None},
                level="warning",
            )

            return self._safe_result(
                message="Trusted device removed." if removed else "Trusted device not found.",
                data={"removed": removed is not None, "device": self._device_to_dict(removed) if removed else None},
            )

        except Exception as exc:
            return self._error_result("Failed to untrust device.", exc)

    def unblock_device(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        device_fingerprint: Any,
        biometric_verified: bool = False,
    ) -> Dict[str, Any]:
        """Remove device from blocked list. Requires biometric flag."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            fingerprint = _normalize_identifier(device_fingerprint, "device_fingerprint")

            if not biometric_verified:
                approval = self._request_security_approval(
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    session_id=None,
                    action="device.unblock",
                    reason="Unblocking a device requires biometric verification.",
                    required_method="biometric",
                    metadata={"device_fingerprint": fingerprint},
                )
                return self._safe_result(
                    message="Biometric verification required before unblocking device.",
                    data={"removed": False, "approval_request": approval},
                )

            with self._lock:
                blocked = self._blocked_devices.get((user_id_str, workspace_id_str), {})
                removed = blocked.pop(fingerprint, None)

            self._log_audit_event(
                action="device_unblocked",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                session_id=None,
                details={"device_fingerprint": fingerprint, "removed": removed is not None},
                level="warning",
            )

            return self._safe_result(
                message="Blocked device removed." if removed else "Blocked device not found.",
                data={"removed": removed is not None, "device": self._device_to_dict(removed) if removed else None},
            )

        except Exception as exc:
            return self._error_result("Failed to unblock device.", exc)

    # =========================================================================
    # Read/list methods for Dashboard/API
    # =========================================================================

    def get_session(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        include_sensitive_runtime: bool = False,
    ) -> Dict[str, Any]:
        """Get one session by SaaS scope."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id, session_id, require_session_id=True)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            session_id_str = str(ctx["session_id"])

            with self._lock:
                session = self._sessions.get((user_id_str, workspace_id_str), {}).get(session_id_str)

            return self._safe_result(
                message="Session retrieved." if session else "Session not found.",
                data={
                    "exists": session is not None,
                    "session": self._session_to_dict(session, include_sensitive_runtime) if session else None,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get session.", exc)

    def list_sessions(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        status: Optional[str] = None,
        limit: int = 100,
        include_sensitive_runtime: bool = False,
    ) -> Dict[str, Any]:
        """List sessions for one user/workspace only."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])

            normalized_status = str(status).strip().lower() if status else None
            if normalized_status and normalized_status not in VALID_SESSION_STATUSES:
                raise ValueError(f"Invalid status filter. Allowed: {sorted(VALID_SESSION_STATUSES)}")

            safe_limit = max(1, min(int(limit), self.config.max_sessions_per_scope))

            with self._lock:
                sessions = list(self._sessions.get((user_id_str, workspace_id_str), {}).values())

            if normalized_status:
                sessions = [session for session in sessions if session.status == normalized_status]

            sessions.sort(key=lambda item: item.last_activity_unix, reverse=True)
            payload = [self._session_to_dict(session, include_sensitive_runtime) for session in sessions[:safe_limit]]

            return self._safe_result(
                message="Sessions listed.",
                data={
                    "sessions": payload,
                    "count": len(payload),
                    "user_id": user_id_str,
                    "workspace_id": workspace_id_str,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to list sessions.", exc)

    def list_trusted_devices(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List trusted devices for user/workspace."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            safe_limit = max(1, min(int(limit), self.config.max_trusted_devices_per_scope))

            with self._lock:
                devices = list(self._trusted_devices.get((user_id_str, workspace_id_str), {}).values())

            devices.sort(key=lambda item: item.updated_at, reverse=True)
            payload = [self._device_to_dict(device) for device in devices[:safe_limit]]

            return self._safe_result(
                message="Trusted devices listed.",
                data={"devices": payload, "count": len(payload)},
            )

        except Exception as exc:
            return self._error_result("Failed to list trusted devices.", exc)

    def list_blocked_devices(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List blocked devices for user/workspace."""
        try:
            ctx = self._validate_task_context(user_id, workspace_id)
            user_id_str = str(ctx["user_id"])
            workspace_id_str = str(ctx["workspace_id"])
            safe_limit = max(1, min(int(limit), self.config.max_blocked_devices_per_scope))

            with self._lock:
                devices = list(self._blocked_devices.get((user_id_str, workspace_id_str), {}).values())

            devices.sort(key=lambda item: item.updated_at, reverse=True)
            payload = [self._device_to_dict(device) for device in devices[:safe_limit]]

            return self._safe_result(
                message="Blocked devices listed.",
                data={"devices": payload, "count": len(payload)},
            )

        except Exception as exc:
            return self._error_result("Failed to list blocked devices.", exc)

    # =========================================================================
    # Cleanup and pruning
    # =========================================================================

    def _maybe_cleanup_expired_sessions(self) -> None:
        """Run cleanup if enabled."""
        if self.config.auto_cleanup_expired_sessions:
            self._cleanup_expired_sessions_locked()

    def _cleanup_expired_sessions_locked(self) -> int:
        """Mark expired sessions as expired. Safe to call without external lock."""
        now = _unix_now()
        count = 0

        with self._lock:
            for sessions in self._sessions.values():
                for session in sessions.values():
                    if session.status in {SESSION_STATUS_REVOKED, SESSION_STATUS_BLOCKED, SESSION_STATUS_EXPIRED}:
                        continue

                    idle_expired = now - session.last_activity_unix >= self.config.idle_timeout_seconds
                    absolute_expired = session.expires_at_unix is not None and session.expires_at_unix <= now

                    if idle_expired or absolute_expired:
                        session.status = SESSION_STATUS_EXPIRED
                        count += 1

        return count

    def cleanup_expired_sessions(self) -> Dict[str, Any]:
        """Public cleanup method for scheduler/dashboard."""
        try:
            count = self._cleanup_expired_sessions_locked()
            self._log_audit_event(
                action="expired_sessions_cleaned",
                user_id=None,
                workspace_id=None,
                session_id=None,
                details={"expired_count": count},
            )
            return self._safe_result(
                message="Expired sessions cleaned.",
                data={"expired_count": count},
            )
        except Exception as exc:
            return self._error_result("Failed to cleanup expired sessions.", exc)

    def _prune_oldest_session_locked(self, user_id: str, workspace_id: str) -> None:
        """Remove oldest session in a scope. Caller should hold lock."""
        sessions = self._sessions.get((user_id, workspace_id), {})
        if not sessions:
            return

        oldest_id = min(sessions.keys(), key=lambda sid: sessions[sid].last_activity_unix)
        removed = sessions.pop(oldest_id, None)

        if removed:
            self._log_audit_event(
                action="oldest_session_pruned",
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=oldest_id,
                details={"reason": "max_sessions_per_scope_reached"},
                level="warning",
            )

    def _prune_oldest_device_locked(self, devices: Dict[str, DeviceRecord]) -> None:
        """Remove oldest device record from dict. Caller should hold lock."""
        if not devices:
            return

        oldest_id = min(devices.keys(), key=lambda did: devices[did].updated_at)
        devices.pop(oldest_id, None)

    # =========================================================================
    # Audit, events, stats, health
    # =========================================================================

    def get_audit_events(
        self,
        *,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get audit events filtered by optional SaaS scope."""
        try:
            normalized_user_id = _normalize_identifier(user_id, "user_id") if user_id is not None else None
            normalized_workspace_id = _normalize_identifier(workspace_id, "workspace_id") if workspace_id is not None else None
            safe_limit = max(1, min(int(limit), self.config.audit_log_limit))

            with self._lock:
                events = list(self._audit_events)

            if normalized_user_id:
                events = [event for event in events if event.get("user_id") == normalized_user_id]
            if normalized_workspace_id:
                events = [event for event in events if event.get("workspace_id") == normalized_workspace_id]

            events = list(reversed(events))[:safe_limit]

            return self._safe_result(
                message="SessionGuard audit events retrieved.",
                data={"events": events, "count": len(events)},
            )

        except Exception as exc:
            return self._error_result("Failed to get audit events.", exc)

    def get_agent_events(
        self,
        *,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get agent events filtered by optional SaaS scope."""
        try:
            normalized_user_id = _normalize_identifier(user_id, "user_id") if user_id is not None else None
            normalized_workspace_id = _normalize_identifier(workspace_id, "workspace_id") if workspace_id is not None else None
            safe_limit = max(1, min(int(limit), self.config.event_log_limit))

            with self._lock:
                events = list(self._agent_events)

            if normalized_user_id:
                events = [event for event in events if event.get("user_id") == normalized_user_id]
            if normalized_workspace_id:
                events = [event for event in events if event.get("workspace_id") == normalized_workspace_id]

            events = list(reversed(events))[:safe_limit]

            return self._safe_result(
                message="SessionGuard agent events retrieved.",
                data={"events": events, "count": len(events)},
            )

        except Exception as exc:
            return self._error_result("Failed to get agent events.", exc)

    def get_stats(self) -> Dict[str, Any]:
        """Return SessionGuard dashboard stats."""
        try:
            with self._lock:
                session_count = sum(len(sessions) for sessions in self._sessions.values())
                trusted_device_count = sum(len(devices) for devices in self._trusted_devices.values())
                blocked_device_count = sum(len(devices) for devices in self._blocked_devices.values())

                status_counts = {status: 0 for status in sorted(VALID_SESSION_STATUSES)}
                for sessions in self._sessions.values():
                    for session in sessions.values():
                        status_counts[session.status] = status_counts.get(session.status, 0) + 1

                scope_count = len(self._sessions)

            return self._safe_result(
                message="SessionGuard stats retrieved.",
                data={
                    "scope_count": scope_count,
                    "session_count": session_count,
                    "trusted_device_count": trusted_device_count,
                    "blocked_device_count": blocked_device_count,
                    "status_counts": status_counts,
                    "audit_event_count": len(self._audit_events),
                    "agent_event_count": len(self._agent_events),
                    "config": {
                        "idle_timeout_seconds": self.config.idle_timeout_seconds,
                        "absolute_timeout_seconds": self.config.absolute_timeout_seconds,
                        "reauth_interval_seconds": self.config.reauth_interval_seconds,
                        "high_risk_reauth_interval_seconds": self.config.high_risk_reauth_interval_seconds,
                        "unknown_device_policy": self.config.unknown_device_policy,
                        "fail_closed": self.config.fail_closed,
                    },
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get SessionGuard stats.", exc)

    def get_capabilities(self) -> List[str]:
        """Return capabilities for Agent Registry and Master Agent."""
        return [
            "session_timeout_enforcement",
            "idle_timeout_detection",
            "absolute_session_expiry",
            "session_validation",
            "session_reauthentication_tracking",
            "biometric_verification_tracking",
            "unknown_device_detection",
            "trusted_device_management",
            "blocked_device_management",
            "device_fingerprint_comparison",
            "ip_change_detection",
            "user_agent_change_detection",
            "failed_reauth_lockout",
            "session_revocation",
            "session_blocking",
            "bulk_session_revocation",
            "saas_user_workspace_isolation",
            "security_approval_request_payloads",
            "verification_payload_preparation",
            "memory_payload_preparation",
            "audit_event_logging",
            "dashboard_session_stats",
        ]

    def health_check(self) -> Dict[str, Any]:
        """Health check for Agent Loader / Registry."""
        stats = self.get_stats()

        return self._safe_result(
            message="SessionGuard is healthy.",
            data={
                "healthy": True,
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
                "capabilities": self.get_capabilities(),
                "stats": stats.get("data", {}),
            },
            metadata={"component": "security_agent.session_guard"},
        )

    # =========================================================================
    # Error handling
    # =========================================================================

    def _handle_exception(self, message: str, exc: Exception) -> Dict[str, Any]:
        """Handle exceptions with fail-closed behavior."""
        self.logger.exception(message)

        if self.config.fail_closed:
            return self._safe_result(
                message=f"{message} Fail-closed session decision: block.",
                data={
                    "decision": {
                        "decision": SessionDecision.BLOCK.value,
                        "reason": "session_guard_internal_error",
                        "status": SESSION_STATUS_BLOCKED,
                        "allowed": False,
                        "blocked": True,
                        "internal_error": str(exc),
                    }
                },
                metadata={"fail_closed": True},
            )

        return self._error_result(message, exc)


# =============================================================================
# Factory
# =============================================================================

def create_session_guard(
    config: Optional[Union[SessionGuardConfig, Mapping[str, Any]]] = None,
    logger: Optional[logging.Logger] = None,
) -> SessionGuard:
    """
    Factory for Agent Loader / Agent Registry.
    """
    return SessionGuard(config=config, logger=logger)


# =============================================================================
# Manual smoke test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    guard = SessionGuard()

    created = guard.create_session(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        device_id="device_1",
        device_type="desktop",
        platform="windows",
        user_agent="Mozilla/5.0 Example",
        ip_address="127.0.0.1",
        source="dashboard",
        risk_level="low",
        authenticated=True,
        trust_device_on_create=True,
        metadata={"note": "manual smoke test"},
    )

    print("\n1. Create session")
    print(json.dumps(created, indent=2, default=str))

    print("\n2. Validate session")
    validated = guard.validate_session(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        action="browser.search",
        device_id="device_1",
        device_type="desktop",
        platform="windows",
        user_agent="Mozilla/5.0 Example",
        ip_address="127.0.0.1",
        risk_level="low",
    )
    print(json.dumps(validated, indent=2, default=str))

    print("\n3. Sensitive action validation")
    sensitive = guard.validate_session(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        action="finance.transfer",
        device_id="device_1",
        device_type="desktop",
        platform="windows",
        user_agent="Mozilla/5.0 Example",
        ip_address="127.0.0.1",
        risk_level="high",
        sensitive_action=True,
    )
    print(json.dumps(sensitive, indent=2, default=str))

    print("\n4. Mark biometric verified")
    biometric = guard.mark_biometric_verified(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        method="device_biometric",
        success=True,
    )
    print(json.dumps(biometric, indent=2, default=str))

    print("\n5. List sessions")
    print(
        json.dumps(
            guard.list_sessions(
                user_id="user_1",
                workspace_id="workspace_1",
            ),
            indent=2,
            default=str,
        )
    )

    print("\n6. Health check")
    print(json.dumps(guard.health_check(), indent=2, default=str))