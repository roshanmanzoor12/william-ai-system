"""
agents/security_agent/approval_manager.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Security Agent Component: ApprovalManager

Purpose:
    Creates user confirmation prompts and records approvals or denials for
    sensitive actions.

Security responsibilities:
    - Require explicit, scoped, expiring confirmation for protected actions.
    - Never mix approval requests between SaaS users or workspaces.
    - Prevent replay, duplicate decisions, and unauthorized approval attempts.
    - Record immutable-style decision history and audit-ready events.
    - Produce Verification Agent and Memory Agent compatible payloads.
    - Avoid directly executing the protected action.

Architecture integration:
    - Master Agent or any specialist agent asks Security Agent for approval.
    - Security Agent delegates confirmation lifecycle management here.
    - Dashboard/API presents the generated prompt to an authorized user.
    - User approval or denial is recorded through this class.
    - The calling agent verifies the resulting approval receipt before acting.
    - Verification Agent can validate the receipt and completed action.
    - Memory Agent may store only safe operational summaries, never raw secrets.
    - Agent Registry/Loader/Router can import this module before all other
      William modules exist because optional imports and fallbacks are included.

Important:
    This module does not execute system, browser, financial, message, call,
    payment, file, or destructive actions. It only manages approval state.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import inspect
import json
import logging
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
    runtime_checkable,
)


# =============================================================================
# Optional William/Jarvis imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Import-safe fallback for the William BaseAgent.

        The real BaseAgent may later provide registry metadata, lifecycle
        hooks, routing, tracing, permission context, and async execution.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": {
                    "code": "base_agent_not_available",
                    "details": None,
                },
                "metadata": {},
            }


try:
    from agents.security_agent.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


try:
    from agents.security_agent.permission_checker import PermissionChecker  # type: ignore
except Exception:  # pragma: no cover
    PermissionChecker = None  # type: ignore


try:
    from agents.security_agent.risk_engine import RiskEngine  # type: ignore
except Exception:  # pragma: no cover
    RiskEngine = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enumerations
# =============================================================================

class ApprovalStatus(str, Enum):
    """Lifecycle states for an approval request."""

    PENDING = "pending"
    PARTIALLY_APPROVED = "partially_approved"
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


class ApprovalDecision(str, Enum):
    """Supported user decisions."""

    APPROVE = "approve"
    DENY = "deny"


class RiskLevel(str, Enum):
    """Normalized risk levels used in prompts and policies."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalChannel(str, Enum):
    """Channels through which a confirmation may be presented."""

    DASHBOARD = "dashboard"
    WEB = "web"
    MOBILE = "mobile"
    VOICE = "voice"
    EMAIL = "email"
    API = "api"
    INTERNAL = "internal"


class ApprovalMode(str, Enum):
    """Approval policy mode."""

    SINGLE = "single"
    MULTI = "multi"
    UNANIMOUS = "unanimous"


class ActorType(str, Enum):
    """Types of entities that may create or decide approval requests."""

    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    ADMIN = "admin"
    UNKNOWN = "unknown"


# =============================================================================
# Data models
# =============================================================================

@dataclass(frozen=True)
class ApprovalManagerConfig:
    """
    Runtime configuration for ApprovalManager.

    Security-sensitive defaults are intentionally conservative.
    """

    default_expiry_seconds: int = 300
    minimum_expiry_seconds: int = 30
    maximum_expiry_seconds: int = 86_400
    critical_maximum_expiry_seconds: int = 300

    token_bytes: int = 32
    token_digest_algorithm: str = "sha256"

    default_required_approvals: int = 1
    maximum_required_approvals: int = 20
    maximum_pending_per_user_workspace: int = 500

    allow_creator_to_approve: bool = True
    allow_decision_without_token: bool = False
    require_reason_for_denial: bool = False
    require_reason_for_critical_approval: bool = True
    require_security_check_for_critical_creation: bool = True

    include_action_details_in_prompt: bool = True
    redact_sensitive_details: bool = True
    retain_decision_history: bool = True

    auto_expire_on_read: bool = True
    default_channel: str = ApprovalChannel.DASHBOARD.value

    idempotency_ttl_seconds: int = 86_400
    verification_receipt_ttl_seconds: int = 900

    module_version: str = "1.0.0"


@dataclass
class ApprovalPrompt:
    """User-facing confirmation prompt."""

    title: str
    message: str
    confirm_label: str = "Approve"
    deny_label: str = "Deny"
    warning: Optional[str] = None
    consequences: List[str] = field(default_factory=list)
    action_summary: str = ""
    expires_at: Optional[str] = None
    risk_level: str = RiskLevel.MEDIUM.value
    requires_reason: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalDecisionRecord:
    """Immutable-style record of one user decision attempt."""

    decision_id: str
    approval_id: str
    user_id: str
    workspace_id: str
    decision: str
    decided_by: str
    actor_type: str
    reason: Optional[str]
    decided_at: str
    channel: str
    request_ip_hash: Optional[str] = None
    user_agent_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalRequest:
    """
    Persistent approval request model.

    Raw confirmation tokens are never stored. Only token hashes are retained.
    """

    approval_id: str
    user_id: str
    workspace_id: str
    task_id: str
    action_id: str
    action_type: str
    action_summary: str
    action_details: Dict[str, Any]

    created_by: str
    created_by_type: str
    created_at: str
    updated_at: str
    expires_at: str

    status: str
    risk_level: str
    channel: str
    approval_mode: str

    required_approvals: int
    approved_by: List[str]
    denied_by: List[str]
    eligible_approver_ids: List[str]
    eligible_roles: List[str]

    prompt: Dict[str, Any]
    token_hash: Optional[str]
    token_salt: Optional[str]

    idempotency_key_hash: Optional[str]
    action_fingerprint: str

    decision_history: List[Dict[str, Any]]
    final_decision_id: Optional[str] = None
    final_decided_by: Optional[str] = None
    final_decided_at: Optional[str] = None
    final_reason: Optional[str] = None

    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalReceipt:
    """
    Receipt returned after an approval becomes effective.

    Calling agents should validate this receipt before performing the protected
    action. The receipt is scoped to the same user, workspace, task and action.
    """

    receipt_id: str
    approval_id: str
    user_id: str
    workspace_id: str
    task_id: str
    action_id: str
    action_type: str
    status: str
    approved_by: List[str]
    issued_at: str
    expires_at: str
    action_fingerprint: str
    receipt_signature: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Repository protocol and in-memory implementation
# =============================================================================

@runtime_checkable
class ApprovalRepository(Protocol):
    """
    Storage contract for database, Redis, document store, or in-memory adapters.

    All implementations must preserve user/workspace isolation.
    """

    def create(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new approval request."""

    def get(
        self,
        approval_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Read one request within tenant context."""

    def update(
        self,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace/update one request within tenant context."""

    def list(
        self,
        user_id: str,
        workspace_id: str,
        statuses: Optional[Sequence[str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List tenant-scoped approval requests."""

    def find_by_idempotency_hash(
        self,
        user_id: str,
        workspace_id: str,
        idempotency_key_hash: str,
    ) -> Optional[Dict[str, Any]]:
        """Find request by tenant-scoped idempotency hash."""


class InMemoryApprovalRepository:
    """
    Thread-safe in-memory repository.

    Intended for development, tests, single-process deployments, and fallback
    operation. Production deployments should inject a persistent repository.
    """

    def __init__(self) -> None:
        self._records: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._idempotency_index: Dict[Tuple[str, str, str], str] = {}
        self._lock = threading.RLock()

    def create(self, request: Dict[str, Any]) -> Dict[str, Any]:
        user_id = str(request["user_id"])
        workspace_id = str(request["workspace_id"])
        approval_id = str(request["approval_id"])
        key = (user_id, workspace_id, approval_id)

        with self._lock:
            if key in self._records:
                raise ValueError("approval_request_already_exists")

            stored = copy.deepcopy(request)
            self._records[key] = stored

            idempotency_hash = stored.get("idempotency_key_hash")
            if idempotency_hash:
                index_key = (user_id, workspace_id, str(idempotency_hash))
                self._idempotency_index[index_key] = approval_id

            return copy.deepcopy(stored)

    def get(
        self,
        approval_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[Dict[str, Any]]:
        key = (str(user_id), str(workspace_id), str(approval_id))

        with self._lock:
            record = self._records.get(key)
            return copy.deepcopy(record) if record is not None else None

    def update(
        self,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        key = (str(user_id), str(workspace_id), str(approval_id))

        with self._lock:
            if key not in self._records:
                raise KeyError("approval_request_not_found")

            if (
                str(request.get("user_id")) != str(user_id)
                or str(request.get("workspace_id")) != str(workspace_id)
                or str(request.get("approval_id")) != str(approval_id)
            ):
                raise ValueError("approval_repository_context_mismatch")

            stored = copy.deepcopy(request)
            self._records[key] = stored

            idempotency_hash = stored.get("idempotency_key_hash")
            if idempotency_hash:
                index_key = (
                    str(user_id),
                    str(workspace_id),
                    str(idempotency_hash),
                )
                self._idempotency_index[index_key] = str(approval_id)

            return copy.deepcopy(stored)

    def list(
        self,
        user_id: str,
        workspace_id: str,
        statuses: Optional[Sequence[str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        normalized_statuses = (
            {str(status).lower() for status in statuses}
            if statuses
            else None
        )

        with self._lock:
            records = [
                copy.deepcopy(record)
                for (record_user, record_workspace, _), record in self._records.items()
                if record_user == str(user_id)
                and record_workspace == str(workspace_id)
                and (
                    normalized_statuses is None
                    or str(record.get("status", "")).lower() in normalized_statuses
                )
            ]

        records.sort(
            key=lambda item: str(item.get("created_at", "")),
            reverse=True,
        )
        return records[offset: offset + limit]

    def find_by_idempotency_hash(
        self,
        user_id: str,
        workspace_id: str,
        idempotency_key_hash: str,
    ) -> Optional[Dict[str, Any]]:
        index_key = (
            str(user_id),
            str(workspace_id),
            str(idempotency_key_hash),
        )

        with self._lock:
            approval_id = self._idempotency_index.get(index_key)
            if not approval_id:
                return None

            record = self._records.get(
                (str(user_id), str(workspace_id), approval_id)
            )
            return copy.deepcopy(record) if record else None


# =============================================================================
# ApprovalManager
# =============================================================================

class ApprovalManager(BaseAgent):
    """
    Creates confirmation prompts and records approval or denial decisions.

    This helper belongs to Security Agent. It does not perform the protected
    operation. Instead, it creates a narrowly scoped approval request and later
    returns a signed approval receipt that the calling agent may verify.

    Main public methods:
        - create_approval_request()
        - record_approval()
        - record_denial()
        - record_decision()
        - get_approval_request()
        - list_approval_requests()
        - cancel_approval_request()
        - revoke_approval()
        - expire_pending_requests()
        - validate_approval()
        - validate_approval_receipt()
        - build_confirmation_prompt()
    """

    TERMINAL_STATUSES: Set[str] = {
        ApprovalStatus.APPROVED.value,
        ApprovalStatus.DENIED.value,
        ApprovalStatus.CANCELLED.value,
        ApprovalStatus.EXPIRED.value,
        ApprovalStatus.REVOKED.value,
        ApprovalStatus.SUPERSEDED.value,
    }

    ACTIVE_STATUSES: Set[str] = {
        ApprovalStatus.PENDING.value,
        ApprovalStatus.PARTIALLY_APPROVED.value,
    }

    SENSITIVE_DETAIL_KEYS: Set[str] = {
        "password",
        "passphrase",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "session",
        "private_key",
        "credit_card",
        "card_number",
        "cvv",
        "cvc",
        "pin",
        "otp",
        "biometric",
        "ssn",
        "national_id",
        "bank_account",
    }

    def __init__(
        self,
        config: Optional[ApprovalManagerConfig] = None,
        repository: Optional[ApprovalRepository] = None,
        permission_checker: Optional[Any] = None,
        risk_engine: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        receipt_signing_key: Optional[Union[str, bytes]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="ApprovalManager", **kwargs)

        self.config = config or ApprovalManagerConfig()
        self.repository: ApprovalRepository = (
            repository or InMemoryApprovalRepository()
        )
        self.permission_checker = permission_checker
        self.risk_engine = risk_engine
        self.audit_logger = audit_logger
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter

        self.logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )
        self._mutation_lock = threading.RLock()

        self._validate_config()

        if receipt_signing_key is None:
            # Ephemeral key is safe for import/testing but receipts will only
            # remain verifiable for the life of this process instance.
            self._receipt_signing_key = secrets.token_bytes(32)
            self._ephemeral_signing_key = True
        elif isinstance(receipt_signing_key, str):
            self._receipt_signing_key = receipt_signing_key.encode("utf-8")
            self._ephemeral_signing_key = False
        else:
            self._receipt_signing_key = bytes(receipt_signing_key)
            self._ephemeral_signing_key = False

    # -------------------------------------------------------------------------
    # Agent/registry compatibility
    # -------------------------------------------------------------------------

    @property
    def capabilities(self) -> List[str]:
        """Capabilities exposed to Agent Registry and Master Agent."""

        return [
            "security.approval.create",
            "security.approval.read",
            "security.approval.list",
            "security.approval.approve",
            "security.approval.deny",
            "security.approval.cancel",
            "security.approval.revoke",
            "security.approval.validate",
            "security.approval.expire",
            "security.confirmation_prompt.create",
        ]

    def get_agent_metadata(self) -> Dict[str, Any]:
        """Return registry-friendly component metadata."""

        return {
            "name": "ApprovalManager",
            "module": "security_agent",
            "file": "approval_manager.py",
            "version": self.config.module_version,
            "capabilities": self.capabilities,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "executes_protected_actions": False,
            "supports_async_callbacks": True,
            "repository": self.repository.__class__.__name__,
        }

    async def run(
        self,
        task: Mapping[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        BaseAgent-compatible task entry point.

        Expected task examples:
            {"operation": "create", ...}
            {"operation": "approve", ...}
            {"operation": "deny", ...}
            {"operation": "get", ...}
            {"operation": "list", ...}
            {"operation": "cancel", ...}
            {"operation": "revoke", ...}
            {"operation": "validate", ...}
            {"operation": "expire", ...}
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="ApprovalManager task must be a mapping.",
                error_code="invalid_task",
            )

        payload = dict(task)
        payload.update(kwargs)
        operation = str(
            payload.pop("operation", payload.pop("action", ""))
        ).strip().lower()

        dispatch: Dict[str, Callable[..., Dict[str, Any]]] = {
            "create": self.create_approval_request,
            "create_approval": self.create_approval_request,
            "approve": self.record_approval,
            "deny": self.record_denial,
            "decision": self.record_decision,
            "get": self.get_approval_request,
            "list": self.list_approval_requests,
            "cancel": self.cancel_approval_request,
            "revoke": self.revoke_approval,
            "validate": self.validate_approval,
            "expire": self.expire_pending_requests,
        }

        handler = dispatch.get(operation)
        if handler is None:
            return self._error_result(
                message=f"Unsupported approval operation: {operation or 'missing'}.",
                error_code="unsupported_operation",
                metadata={"supported_operations": sorted(dispatch.keys())},
            )

        try:
            result = handler(**payload)
            if inspect.isawaitable(result):
                result = await result
            return result
        except TypeError as exc:
            self.logger.exception("Invalid ApprovalManager task arguments.")
            return self._error_result(
                message="Invalid arguments supplied to ApprovalManager.",
                error_code="invalid_arguments",
                error_details=str(exc),
            )
        except Exception as exc:
            self.logger.exception("ApprovalManager task failed.")
            return self._error_result(
                message="ApprovalManager operation failed.",
                error_code="approval_manager_failure",
                error_details=str(exc),
            )

    # -------------------------------------------------------------------------
    # Public request creation
    # -------------------------------------------------------------------------

    def create_approval_request(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        action_type: str,
        action_summary: str,
        action_details: Optional[Mapping[str, Any]] = None,
        created_by: str,
        created_by_type: str = ActorType.AGENT.value,
        action_id: Optional[str] = None,
        risk_level: Optional[str] = None,
        channel: Optional[str] = None,
        approval_mode: str = ApprovalMode.SINGLE.value,
        required_approvals: Optional[int] = None,
        eligible_approver_ids: Optional[Sequence[str]] = None,
        eligible_roles: Optional[Sequence[str]] = None,
        expires_in_seconds: Optional[int] = None,
        idempotency_key: Optional[str] = None,
        prompt_overrides: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create an expiring confirmation request.

        Returns the raw confirmation token only once in the creation response.
        The repository stores only a salted token hash.

        The token should be delivered through the authenticated Dashboard/API
        session and must not be written to logs or Memory Agent.
        """

        started_at = time.monotonic()
        request_context_dict = dict(request_context or {})

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            actor_id=created_by,
            action_type=action_type,
        )
        if not validation["success"]:
            return validation

        if not str(action_summary).strip():
            return self._error_result(
                message="action_summary is required.",
                error_code="missing_action_summary",
                metadata=self._base_metadata(
                    user_id, workspace_id, task_id
                ),
            )

        normalized_mode = self._normalize_approval_mode(approval_mode)
        if normalized_mode is None:
            return self._error_result(
                message="Invalid approval mode.",
                error_code="invalid_approval_mode",
                metadata={
                    **self._base_metadata(user_id, workspace_id, task_id),
                    "allowed_modes": [item.value for item in ApprovalMode],
                },
            )

        normalized_channel = self._normalize_channel(
            channel or self.config.default_channel
        )
        if normalized_channel is None:
            return self._error_result(
                message="Invalid approval channel.",
                error_code="invalid_approval_channel",
                metadata={
                    **self._base_metadata(user_id, workspace_id, task_id),
                    "allowed_channels": [item.value for item in ApprovalChannel],
                },
            )

        safe_details = self._deep_copy_json_safe(action_details or {})
        safe_metadata = self._deep_copy_json_safe(metadata or {})

        resolved_risk = self._resolve_risk_level(
            risk_level=risk_level,
            action_type=action_type,
            action_details=safe_details,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )

        expiry_seconds_result = self._resolve_expiry_seconds(
            expires_in_seconds=expires_in_seconds,
            risk_level=resolved_risk,
        )
        if not expiry_seconds_result["success"]:
            return expiry_seconds_result

        expiry_seconds = int(
            expiry_seconds_result["data"]["expires_in_seconds"]
        )

        approver_ids = self._normalize_string_list(eligible_approver_ids)
        approver_roles = self._normalize_string_list(eligible_roles)

        resolved_required = self._resolve_required_approvals(
            approval_mode=normalized_mode,
            required_approvals=required_approvals,
            eligible_approver_ids=approver_ids,
        )
        if not resolved_required["success"]:
            return resolved_required

        required_count = int(
            resolved_required["data"]["required_approvals"]
        )

        pending_count = len(
            self.repository.list(
                user_id=user_id,
                workspace_id=workspace_id,
                statuses=list(self.ACTIVE_STATUSES),
                limit=self.config.maximum_pending_per_user_workspace + 1,
                offset=0,
            )
        )
        if pending_count >= self.config.maximum_pending_per_user_workspace:
            return self._error_result(
                message="Pending approval limit reached for this user and workspace.",
                error_code="pending_approval_limit_reached",
                metadata={
                    **self._base_metadata(user_id, workspace_id, task_id),
                    "limit": self.config.maximum_pending_per_user_workspace,
                },
            )

        action_id = str(action_id or self._new_id("action"))
        action_fingerprint = self._build_action_fingerprint(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action_id=action_id,
            action_type=action_type,
            action_summary=action_summary,
            action_details=safe_details,
        )

        idempotency_hash = None
        if idempotency_key:
            idempotency_hash = self._hash_idempotency_key(
                user_id=user_id,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
            existing = self.repository.find_by_idempotency_hash(
                user_id=user_id,
                workspace_id=workspace_id,
                idempotency_key_hash=idempotency_hash,
            )
            if existing is not None:
                existing = self._expire_record_if_needed(existing)
                return self._safe_result(
                    message="Existing approval request returned for idempotency key.",
                    data={
                        "approval": self._serialize_public_request(existing),
                        "confirmation_token": None,
                        "token_returned": False,
                        "idempotent_replay": True,
                    },
                    metadata={
                        **self._base_metadata(user_id, workspace_id, task_id),
                        "approval_id": existing["approval_id"],
                        "status": existing["status"],
                    },
                )

        if self._requires_security_check(
            action_type=action_type,
            risk_level=resolved_risk,
            operation="create_approval_request",
        ):
            security_result = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action_type=action_type,
                risk_level=resolved_risk,
                context={
                    "operation": "create_approval_request",
                    "created_by": created_by,
                    "request_context": request_context_dict,
                },
            )
            if not security_result["success"]:
                return security_result

        permission_result = self._check_permission(
            operation="create_approval_request",
            actor_id=created_by,
            actor_type=created_by_type,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action_type=action_type,
            request_context=request_context_dict,
        )
        if not permission_result["success"]:
            return permission_result

        created_at_dt = self._now()
        expires_at_dt = created_at_dt + timedelta(seconds=expiry_seconds)

        prompt_result = self.build_confirmation_prompt(
            action_type=action_type,
            action_summary=action_summary,
            action_details=safe_details,
            risk_level=resolved_risk,
            expires_at=self._iso(expires_at_dt),
            required_approvals=required_count,
            prompt_overrides=prompt_overrides,
        )
        if not prompt_result["success"]:
            return prompt_result

        raw_token = secrets.token_urlsafe(self.config.token_bytes)
        token_salt = secrets.token_hex(16)
        token_hash = self._hash_confirmation_token(
            token=raw_token,
            salt=token_salt,
        )

        approval_id = self._new_id("approval")

        request = ApprovalRequest(
            approval_id=approval_id,
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            task_id=str(task_id),
            action_id=action_id,
            action_type=str(action_type).strip(),
            action_summary=str(action_summary).strip(),
            action_details=safe_details,
            created_by=str(created_by),
            created_by_type=self._normalize_actor_type(created_by_type),
            created_at=self._iso(created_at_dt),
            updated_at=self._iso(created_at_dt),
            expires_at=self._iso(expires_at_dt),
            status=ApprovalStatus.PENDING.value,
            risk_level=resolved_risk,
            channel=normalized_channel,
            approval_mode=normalized_mode,
            required_approvals=required_count,
            approved_by=[],
            denied_by=[],
            eligible_approver_ids=approver_ids,
            eligible_roles=approver_roles,
            prompt=prompt_result["data"]["prompt"],
            token_hash=token_hash,
            token_salt=token_salt,
            idempotency_key_hash=idempotency_hash,
            action_fingerprint=action_fingerprint,
            decision_history=[],
            metadata={
                **safe_metadata,
                "request_context": self._sanitize_context_for_storage(
                    request_context_dict
                ),
                "token_version": 1,
                "receipt_version": 1,
            },
        )

        try:
            stored = self.repository.create(asdict(request))
        except Exception as exc:
            self.logger.exception("Failed to store approval request.")
            return self._error_result(
                message="Could not create approval request.",
                error_code="approval_storage_create_failed",
                error_details=str(exc),
                metadata=self._base_metadata(
                    user_id, workspace_id, task_id
                ),
            )

        audit_payload = {
            "event": "security.approval.created",
            "approval_id": approval_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "action_id": action_id,
            "action_type": action_type,
            "risk_level": resolved_risk,
            "created_by": created_by,
            "created_by_type": created_by_type,
            "status": ApprovalStatus.PENDING.value,
            "required_approvals": required_count,
            "expires_at": self._iso(expires_at_dt),
            "timestamp": self._iso(created_at_dt),
        }
        self._log_audit_event(audit_payload)
        self._emit_agent_event(audit_payload)

        verification_payload = self._prepare_verification_payload(
            approval=stored,
            event_type="approval_request_created",
            actor_id=created_by,
        )
        memory_payload = self._prepare_memory_payload(
            approval=stored,
            event_type="approval_request_created",
            actor_id=created_by,
        )

        elapsed_ms = round(
            (time.monotonic() - started_at) * 1000,
            2,
        )

        return self._safe_result(
            message="Approval request created successfully.",
            data={
                "approval": self._serialize_public_request(stored),
                "confirmation_token": raw_token,
                "token_returned": True,
                "idempotent_replay": False,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                **self._base_metadata(user_id, workspace_id, task_id),
                "approval_id": approval_id,
                "action_id": action_id,
                "status": ApprovalStatus.PENDING.value,
                "expires_in_seconds": expiry_seconds,
                "elapsed_ms": elapsed_ms,
                "ephemeral_receipt_signing_key": self._ephemeral_signing_key,
            },
        )

    # -------------------------------------------------------------------------
    # Prompt creation
    # -------------------------------------------------------------------------

    def build_confirmation_prompt(
        self,
        *,
        action_type: str,
        action_summary: str,
        action_details: Optional[Mapping[str, Any]] = None,
        risk_level: str = RiskLevel.MEDIUM.value,
        expires_at: Optional[str] = None,
        required_approvals: int = 1,
        prompt_overrides: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a clear user confirmation prompt.

        Sensitive fields are redacted before they enter the prompt.
        """

        normalized_risk = self._normalize_risk_level(risk_level)
        if normalized_risk is None:
            return self._error_result(
                message="Invalid risk level for confirmation prompt.",
                error_code="invalid_risk_level",
            )

        safe_details = self._redact_sensitive_data(
            self._deep_copy_json_safe(action_details or {})
        )

        action_label = self._humanize_action_type(action_type)
        title = f"Confirm {action_label}"

        warning_map = {
            RiskLevel.LOW.value: "Review this action before continuing.",
            RiskLevel.MEDIUM.value: (
                "This action may change data or account behavior."
            ),
            RiskLevel.HIGH.value: (
                "This is a high-risk action. Confirm only if you understand "
                "the expected result."
            ),
            RiskLevel.CRITICAL.value: (
                "Critical confirmation required. This action may be difficult "
                "or impossible to reverse."
            ),
        }

        consequences = self._infer_consequences(
            action_type=action_type,
            action_details=safe_details,
            risk_level=normalized_risk,
        )

        message = (
            f"William is requesting permission to {action_summary.strip()}. "
            "No protected action will be performed unless this request reaches "
            "the required approval state."
        )

        prompt = ApprovalPrompt(
            title=title,
            message=message,
            confirm_label="Approve",
            deny_label="Deny",
            warning=warning_map[normalized_risk],
            consequences=consequences,
            action_summary=action_summary.strip(),
            expires_at=expires_at,
            risk_level=normalized_risk,
            requires_reason=(
                normalized_risk == RiskLevel.CRITICAL.value
                and self.config.require_reason_for_critical_approval
            ),
            metadata={
                "action_type": str(action_type),
                "required_approvals": int(required_approvals),
                "display_details": (
                    safe_details
                    if self.config.include_action_details_in_prompt
                    else {}
                ),
            },
        )

        if prompt_overrides:
            allowed_override_keys = {
                "title",
                "message",
                "confirm_label",
                "deny_label",
                "warning",
                "consequences",
                "requires_reason",
            }
            prompt_dict = asdict(prompt)

            for key, value in prompt_overrides.items():
                if key in allowed_override_keys:
                    prompt_dict[key] = self._deep_copy_json_safe(value)

            prompt = ApprovalPrompt(**prompt_dict)

        return self._safe_result(
            message="Confirmation prompt created.",
            data={"prompt": asdict(prompt)},
            metadata={
                "risk_level": normalized_risk,
                "action_type": action_type,
            },
        )

    # -------------------------------------------------------------------------
    # Public decision methods
    # -------------------------------------------------------------------------

    def record_approval(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        decided_by: str,
        confirmation_token: Optional[str] = None,
        reason: Optional[str] = None,
        actor_type: str = ActorType.USER.value,
        actor_roles: Optional[Sequence[str]] = None,
        channel: Optional[str] = None,
        decision_idempotency_key: Optional[str] = None,
        request_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an approval decision."""

        return self.record_decision(
            approval_id=approval_id,
            user_id=user_id,
            workspace_id=workspace_id,
            decision=ApprovalDecision.APPROVE.value,
            decided_by=decided_by,
            confirmation_token=confirmation_token,
            reason=reason,
            actor_type=actor_type,
            actor_roles=actor_roles,
            channel=channel,
            decision_idempotency_key=decision_idempotency_key,
            request_context=request_context,
            metadata=metadata,
        )

    def record_denial(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        decided_by: str,
        confirmation_token: Optional[str] = None,
        reason: Optional[str] = None,
        actor_type: str = ActorType.USER.value,
        actor_roles: Optional[Sequence[str]] = None,
        channel: Optional[str] = None,
        decision_idempotency_key: Optional[str] = None,
        request_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a denial decision."""

        return self.record_decision(
            approval_id=approval_id,
            user_id=user_id,
            workspace_id=workspace_id,
            decision=ApprovalDecision.DENY.value,
            decided_by=decided_by,
            confirmation_token=confirmation_token,
            reason=reason,
            actor_type=actor_type,
            actor_roles=actor_roles,
            channel=channel,
            decision_idempotency_key=decision_idempotency_key,
            request_context=request_context,
            metadata=metadata,
        )

    def record_decision(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        decision: str,
        decided_by: str,
        confirmation_token: Optional[str] = None,
        reason: Optional[str] = None,
        actor_type: str = ActorType.USER.value,
        actor_roles: Optional[Sequence[str]] = None,
        channel: Optional[str] = None,
        decision_idempotency_key: Optional[str] = None,
        request_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record an approval or denial.

        Security behavior:
            - Tenant context must match.
            - Request must be pending and unexpired.
            - Confirmation token must match unless explicitly disabled.
            - Decision actor must be eligible.
            - Duplicate decisions by the same actor are idempotent.
            - One denial finalizes the request as denied.
            - Approval finalizes only after the required count is reached.
        """

        started_at = time.monotonic()
        normalized_decision = self._normalize_decision(decision)

        if normalized_decision is None:
            return self._error_result(
                message="Invalid approval decision.",
                error_code="invalid_decision",
                metadata={
                    "allowed_decisions": [
                        item.value for item in ApprovalDecision
                    ]
                },
            )

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=None,
            actor_id=decided_by,
            approval_id=approval_id,
        )
        if not validation["success"]:
            return validation

        request_context_dict = dict(request_context or {})
        actor_roles_list = self._normalize_string_list(actor_roles)
        normalized_channel = self._normalize_channel(
            channel or self.config.default_channel
        )
        if normalized_channel is None:
            return self._error_result(
                message="Invalid decision channel.",
                error_code="invalid_approval_channel",
                metadata={
                    "allowed_channels": [
                        item.value for item in ApprovalChannel
                    ]
                },
            )

        with self._mutation_lock:
            request = self.repository.get(
                approval_id=approval_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            if request is None:
                return self._error_result(
                    message="Approval request was not found in this user/workspace.",
                    error_code="approval_not_found",
                    metadata={
                        "approval_id": approval_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            request = self._expire_record_if_needed(request)

            current_status = str(request.get("status", "")).lower()

            idempotent_existing = self._find_existing_actor_decision(
                request=request,
                decided_by=decided_by,
                decision=normalized_decision,
                decision_idempotency_key=decision_idempotency_key,
            )
            if idempotent_existing:
                receipt = (
                    self._issue_approval_receipt(request)
                    if current_status == ApprovalStatus.APPROVED.value
                    else None
                )
                return self._safe_result(
                    message="Existing decision returned.",
                    data={
                        "approval": self._serialize_public_request(request),
                        "decision_record": idempotent_existing,
                        "approval_receipt": receipt,
                        "idempotent_replay": True,
                        "verification_payload": self._prepare_verification_payload(
                            approval=request,
                            event_type="approval_decision_replayed",
                            actor_id=decided_by,
                        ),
                    },
                    metadata={
                        **self._base_metadata(
                            user_id,
                            workspace_id,
                            request.get("task_id"),
                        ),
                        "approval_id": approval_id,
                        "status": current_status,
                    },
                )

            if current_status not in self.ACTIVE_STATUSES:
                return self._error_result(
                    message=(
                        "Approval request can no longer accept decisions because "
                        f"its status is '{current_status}'."
                    ),
                    error_code="approval_not_pending",
                    metadata={
                        **self._base_metadata(
                            user_id,
                            workspace_id,
                            request.get("task_id"),
                        ),
                        "approval_id": approval_id,
                        "status": current_status,
                    },
                )

            if (
                normalized_decision == ApprovalDecision.DENY.value
                and self.config.require_reason_for_denial
                and not str(reason or "").strip()
            ):
                return self._error_result(
                    message="A reason is required to deny this request.",
                    error_code="denial_reason_required",
                    metadata={"approval_id": approval_id},
                )

            if (
                normalized_decision == ApprovalDecision.APPROVE.value
                and request.get("risk_level") == RiskLevel.CRITICAL.value
                and self.config.require_reason_for_critical_approval
                and not str(reason or "").strip()
            ):
                return self._error_result(
                    message="A reason is required to approve this critical action.",
                    error_code="critical_approval_reason_required",
                    metadata={"approval_id": approval_id},
                )

            token_result = self._validate_confirmation_token(
                request=request,
                confirmation_token=confirmation_token,
            )
            if not token_result["success"]:
                self._log_audit_event(
                    {
                        "event": "security.approval.invalid_token",
                        "approval_id": approval_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "decided_by": decided_by,
                        "decision": normalized_decision,
                        "timestamp": self._now_iso(),
                    }
                )
                return token_result

            eligibility = self._validate_approver_eligibility(
                request=request,
                decided_by=decided_by,
                actor_roles=actor_roles_list,
            )
            if not eligibility["success"]:
                return eligibility

            permission_result = self._check_permission(
                operation=f"record_{normalized_decision}",
                actor_id=decided_by,
                actor_type=actor_type,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=request.get("task_id"),
                action_type=request.get("action_type"),
                request_context=request_context_dict,
            )
            if not permission_result["success"]:
                return permission_result

            if self._requires_security_check(
                action_type=str(request.get("action_type", "")),
                risk_level=str(request.get("risk_level", RiskLevel.MEDIUM.value)),
                operation=f"record_{normalized_decision}",
            ):
                security_result = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=str(request.get("task_id", "")),
                    action_type=str(request.get("action_type", "")),
                    risk_level=str(request.get("risk_level", "")),
                    context={
                        "operation": f"record_{normalized_decision}",
                        "approval_id": approval_id,
                        "decided_by": decided_by,
                    },
                )
                if not security_result["success"]:
                    return security_result

            now = self._now()
            decision_record = ApprovalDecisionRecord(
                decision_id=self._new_id("decision"),
                approval_id=approval_id,
                user_id=user_id,
                workspace_id=workspace_id,
                decision=normalized_decision,
                decided_by=str(decided_by),
                actor_type=self._normalize_actor_type(actor_type),
                reason=str(reason).strip() if reason else None,
                decided_at=self._iso(now),
                channel=normalized_channel,
                request_ip_hash=self._hash_context_value(
                    request_context_dict.get("ip_address")
                ),
                user_agent_hash=self._hash_context_value(
                    request_context_dict.get("user_agent")
                ),
                metadata={
                    **self._deep_copy_json_safe(metadata or {}),
                    "decision_idempotency_key_hash": (
                        self._hash_generic_value(
                            decision_idempotency_key
                        )
                        if decision_idempotency_key
                        else None
                    ),
                },
            )

            updated = copy.deepcopy(request)
            updated.setdefault("approved_by", [])
            updated.setdefault("denied_by", [])
            updated.setdefault("decision_history", [])

            if self.config.retain_decision_history:
                updated["decision_history"].append(asdict(decision_record))

            if normalized_decision == ApprovalDecision.DENY.value:
                if decided_by not in updated["denied_by"]:
                    updated["denied_by"].append(decided_by)

                updated["status"] = ApprovalStatus.DENIED.value
                updated["final_decision_id"] = decision_record.decision_id
                updated["final_decided_by"] = decided_by
                updated["final_decided_at"] = decision_record.decided_at
                updated["final_reason"] = decision_record.reason

            else:
                if decided_by not in updated["approved_by"]:
                    updated["approved_by"].append(decided_by)

                required = int(updated.get("required_approvals", 1))
                approved_count = len(set(updated["approved_by"]))

                if approved_count >= required:
                    updated["status"] = ApprovalStatus.APPROVED.value
                    updated["final_decision_id"] = decision_record.decision_id
                    updated["final_decided_by"] = decided_by
                    updated["final_decided_at"] = decision_record.decided_at
                    updated["final_reason"] = decision_record.reason

                    # Invalidate the one-time confirmation token once approval
                    # is final to reduce replay opportunities.
                    updated["token_hash"] = None
                    updated["token_salt"] = None
                else:
                    updated["status"] = ApprovalStatus.PARTIALLY_APPROVED.value

            updated["updated_at"] = self._iso(now)

            try:
                stored = self.repository.update(
                    approval_id=approval_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    request=updated,
                )
            except Exception as exc:
                self.logger.exception("Failed to record approval decision.")
                return self._error_result(
                    message="Could not record approval decision.",
                    error_code="approval_storage_update_failed",
                    error_details=str(exc),
                    metadata={
                        "approval_id": approval_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        event_type = (
            "security.approval.approved"
            if stored["status"] == ApprovalStatus.APPROVED.value
            else "security.approval.denied"
            if stored["status"] == ApprovalStatus.DENIED.value
            else "security.approval.partially_approved"
        )

        audit_payload = {
            "event": event_type,
            "approval_id": approval_id,
            "decision_id": decision_record.decision_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": stored.get("task_id"),
            "action_id": stored.get("action_id"),
            "action_type": stored.get("action_type"),
            "risk_level": stored.get("risk_level"),
            "decision": normalized_decision,
            "decided_by": decided_by,
            "actor_type": actor_type,
            "status": stored.get("status"),
            "approved_count": len(set(stored.get("approved_by", []))),
            "required_approvals": stored.get("required_approvals"),
            "timestamp": decision_record.decided_at,
        }
        self._log_audit_event(audit_payload)
        self._emit_agent_event(audit_payload)

        receipt = (
            self._issue_approval_receipt(stored)
            if stored["status"] == ApprovalStatus.APPROVED.value
            else None
        )

        verification_payload = self._prepare_verification_payload(
            approval=stored,
            event_type=event_type,
            actor_id=decided_by,
            decision_record=asdict(decision_record),
            approval_receipt=receipt,
        )
        memory_payload = self._prepare_memory_payload(
            approval=stored,
            event_type=event_type,
            actor_id=decided_by,
        )

        elapsed_ms = round(
            (time.monotonic() - started_at) * 1000,
            2,
        )

        return self._safe_result(
            message=(
                "Approval recorded successfully."
                if stored["status"] == ApprovalStatus.APPROVED.value
                else "Denial recorded successfully."
                if stored["status"] == ApprovalStatus.DENIED.value
                else "Partial approval recorded successfully."
            ),
            data={
                "approval": self._serialize_public_request(stored),
                "decision_record": asdict(decision_record),
                "approval_receipt": receipt,
                "idempotent_replay": False,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                **self._base_metadata(
                    user_id,
                    workspace_id,
                    stored.get("task_id"),
                ),
                "approval_id": approval_id,
                "status": stored["status"],
                "elapsed_ms": elapsed_ms,
            },
        )

    # -------------------------------------------------------------------------
    # Public read/list methods
    # -------------------------------------------------------------------------

    def get_approval_request(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        include_internal: bool = False,
    ) -> Dict[str, Any]:
        """Read one tenant-scoped approval request."""

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            approval_id=approval_id,
        )
        if not validation["success"]:
            return validation

        request = self.repository.get(
            approval_id=approval_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if request is None:
            return self._error_result(
                message="Approval request was not found.",
                error_code="approval_not_found",
                metadata={
                    "approval_id": approval_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        request = self._expire_record_if_needed(request)

        return self._safe_result(
            message="Approval request retrieved.",
            data={
                "approval": (
                    copy.deepcopy(request)
                    if include_internal
                    else self._serialize_public_request(request)
                )
            },
            metadata={
                **self._base_metadata(
                    user_id,
                    workspace_id,
                    request.get("task_id"),
                ),
                "approval_id": approval_id,
                "status": request.get("status"),
            },
        )

    def list_approval_requests(
        self,
        *,
        user_id: str,
        workspace_id: str,
        statuses: Optional[Sequence[str]] = None,
        limit: int = 100,
        offset: int = 0,
        include_internal: bool = False,
        auto_expire: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """List approval requests for one user/workspace."""

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not validation["success"]:
            return validation

        if limit < 1 or limit > 1000:
            return self._error_result(
                message="limit must be between 1 and 1000.",
                error_code="invalid_limit",
            )

        if offset < 0:
            return self._error_result(
                message="offset cannot be negative.",
                error_code="invalid_offset",
            )

        normalized_statuses = None
        if statuses:
            normalized_statuses = []
            valid_statuses = {status.value for status in ApprovalStatus}

            for status in statuses:
                normalized = str(status).strip().lower()
                if normalized not in valid_statuses:
                    return self._error_result(
                        message=f"Invalid approval status: {status}.",
                        error_code="invalid_status_filter",
                        metadata={
                            "allowed_statuses": sorted(valid_statuses)
                        },
                    )
                normalized_statuses.append(normalized)

        records = self.repository.list(
            user_id=user_id,
            workspace_id=workspace_id,
            statuses=normalized_statuses,
            limit=limit,
            offset=offset,
        )

        should_expire = (
            self.config.auto_expire_on_read
            if auto_expire is None
            else bool(auto_expire)
        )

        if should_expire:
            records = [
                self._expire_record_if_needed(record)
                for record in records
            ]

        serialized = [
            copy.deepcopy(record)
            if include_internal
            else self._serialize_public_request(record)
            for record in records
        ]

        return self._safe_result(
            message="Approval requests retrieved.",
            data={
                "approvals": serialized,
                "count": len(serialized),
                "limit": limit,
                "offset": offset,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "statuses": normalized_statuses,
            },
        )

    # -------------------------------------------------------------------------
    # Public lifecycle methods
    # -------------------------------------------------------------------------

    def cancel_approval_request(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        cancelled_by: str,
        reason: Optional[str] = None,
        actor_type: str = ActorType.USER.value,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Cancel a pending approval request."""

        return self._transition_request(
            approval_id=approval_id,
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=cancelled_by,
            actor_type=actor_type,
            target_status=ApprovalStatus.CANCELLED.value,
            reason=reason,
            allowed_current_statuses=self.ACTIVE_STATUSES,
            event_type="security.approval.cancelled",
            request_context=request_context,
        )

    def revoke_approval(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        revoked_by: str,
        reason: str,
        actor_type: str = ActorType.USER.value,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Revoke a previously approved request.

        Revocation does not reverse an action that has already executed. It
        invalidates future use of the approval receipt.
        """

        if not str(reason or "").strip():
            return self._error_result(
                message="A reason is required to revoke an approval.",
                error_code="revoke_reason_required",
            )

        return self._transition_request(
            approval_id=approval_id,
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=revoked_by,
            actor_type=actor_type,
            target_status=ApprovalStatus.REVOKED.value,
            reason=reason,
            allowed_current_statuses={
                ApprovalStatus.APPROVED.value,
            },
            event_type="security.approval.revoked",
            request_context=request_context,
        )

    def expire_pending_requests(
        self,
        *,
        user_id: str,
        workspace_id: str,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        """Mark expired pending requests within one tenant context."""

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not validation["success"]:
            return validation

        records = self.repository.list(
            user_id=user_id,
            workspace_id=workspace_id,
            statuses=list(self.ACTIVE_STATUSES),
            limit=min(max(limit, 1), 5000),
            offset=0,
        )

        expired_ids: List[str] = []

        for record in records:
            before_status = record.get("status")
            updated = self._expire_record_if_needed(record)

            if (
                before_status != ApprovalStatus.EXPIRED.value
                and updated.get("status") == ApprovalStatus.EXPIRED.value
            ):
                expired_ids.append(str(updated["approval_id"]))

        return self._safe_result(
            message=f"Expired {len(expired_ids)} approval request(s).",
            data={
                "expired_approval_ids": expired_ids,
                "expired_count": len(expired_ids),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # -------------------------------------------------------------------------
    # Approval and receipt validation
    # -------------------------------------------------------------------------

    def validate_approval(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        action_id: Optional[str] = None,
        action_type: Optional[str] = None,
        action_details: Optional[Mapping[str, Any]] = None,
        expected_action_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate whether an approval may authorize a protected action.

        The calling agent should provide as many expected scope fields as
        possible. A mismatch causes validation failure.
        """

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            approval_id=approval_id,
        )
        if not validation["success"]:
            return validation

        request = self.repository.get(
            approval_id=approval_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if request is None:
            return self._error_result(
                message="Approval request was not found.",
                error_code="approval_not_found",
                metadata={"approval_id": approval_id},
            )

        request = self._expire_record_if_needed(request)

        if request.get("status") != ApprovalStatus.APPROVED.value:
            return self._error_result(
                message="Approval request is not approved.",
                error_code="approval_not_effective",
                metadata={
                    "approval_id": approval_id,
                    "status": request.get("status"),
                },
            )

        mismatches: List[str] = []

        if task_id is not None and str(request.get("task_id")) != str(task_id):
            mismatches.append("task_id")

        if action_id is not None and str(request.get("action_id")) != str(action_id):
            mismatches.append("action_id")

        if (
            action_type is not None
            and str(request.get("action_type")) != str(action_type)
        ):
            mismatches.append("action_type")

        if expected_action_fingerprint is not None:
            if not hmac.compare_digest(
                str(request.get("action_fingerprint", "")),
                str(expected_action_fingerprint),
            ):
                mismatches.append("action_fingerprint")

        if action_details is not None:
            computed = self._build_action_fingerprint(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=str(task_id or request.get("task_id")),
                action_id=str(action_id or request.get("action_id")),
                action_type=str(action_type or request.get("action_type")),
                action_summary=str(request.get("action_summary", "")),
                action_details=self._deep_copy_json_safe(action_details),
            )
            if not hmac.compare_digest(
                str(request.get("action_fingerprint", "")),
                computed,
            ):
                mismatches.append("action_details")

        if mismatches:
            return self._error_result(
                message="Approval scope does not match the requested action.",
                error_code="approval_scope_mismatch",
                metadata={
                    "approval_id": approval_id,
                    "mismatched_fields": sorted(set(mismatches)),
                },
            )

        receipt = self._issue_approval_receipt(request)

        return self._safe_result(
            message="Approval is valid for the requested action.",
            data={
                "valid": True,
                "approval": self._serialize_public_request(request),
                "approval_receipt": receipt,
                "verification_payload": self._prepare_verification_payload(
                    approval=request,
                    event_type="approval_validated",
                    actor_id=None,
                    approval_receipt=receipt,
                ),
            },
            metadata={
                **self._base_metadata(
                    user_id,
                    workspace_id,
                    request.get("task_id"),
                ),
                "approval_id": approval_id,
                "status": request.get("status"),
            },
        )

    def validate_approval_receipt(
        self,
        *,
        receipt: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        action_id: Optional[str] = None,
        action_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate a signed approval receipt and its current request status."""

        required_fields = {
            "receipt_id",
            "approval_id",
            "user_id",
            "workspace_id",
            "task_id",
            "action_id",
            "action_type",
            "status",
            "approved_by",
            "issued_at",
            "expires_at",
            "action_fingerprint",
            "receipt_signature",
        }

        missing = sorted(required_fields - set(receipt.keys()))
        if missing:
            return self._error_result(
                message="Approval receipt is missing required fields.",
                error_code="invalid_approval_receipt",
                metadata={"missing_fields": missing},
            )

        if (
            str(receipt.get("user_id")) != str(user_id)
            or str(receipt.get("workspace_id")) != str(workspace_id)
        ):
            return self._error_result(
                message="Approval receipt tenant context does not match.",
                error_code="approval_receipt_context_mismatch",
            )

        if task_id is not None and str(receipt.get("task_id")) != str(task_id):
            return self._error_result(
                message="Approval receipt task scope does not match.",
                error_code="approval_receipt_task_mismatch",
            )

        if action_id is not None and str(receipt.get("action_id")) != str(action_id):
            return self._error_result(
                message="Approval receipt action id does not match.",
                error_code="approval_receipt_action_mismatch",
            )

        if (
            action_type is not None
            and str(receipt.get("action_type")) != str(action_type)
        ):
            return self._error_result(
                message="Approval receipt action type does not match.",
                error_code="approval_receipt_action_type_mismatch",
            )

        expiry = self._parse_datetime(receipt.get("expires_at"))
        if expiry is None or expiry <= self._now():
            return self._error_result(
                message="Approval receipt has expired.",
                error_code="approval_receipt_expired",
            )

        expected_signature = self._sign_receipt_payload(receipt)
        provided_signature = str(receipt.get("receipt_signature", ""))

        if not hmac.compare_digest(expected_signature, provided_signature):
            return self._error_result(
                message="Approval receipt signature is invalid.",
                error_code="invalid_approval_receipt_signature",
            )

        request = self.repository.get(
            approval_id=str(receipt["approval_id"]),
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if request is None:
            return self._error_result(
                message="Approval receipt references a missing request.",
                error_code="approval_not_found",
            )

        request = self._expire_record_if_needed(request)

        if request.get("status") != ApprovalStatus.APPROVED.value:
            return self._error_result(
                message="Approval receipt is no longer effective.",
                error_code="approval_receipt_not_effective",
                metadata={"current_status": request.get("status")},
            )

        if not hmac.compare_digest(
            str(request.get("action_fingerprint", "")),
            str(receipt.get("action_fingerprint", "")),
        ):
            return self._error_result(
                message="Approval receipt action fingerprint does not match.",
                error_code="approval_receipt_fingerprint_mismatch",
            )

        return self._safe_result(
            message="Approval receipt is valid.",
            data={
                "valid": True,
                "approval_id": request["approval_id"],
                "status": request["status"],
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": request.get("task_id"),
            },
        )

    # -------------------------------------------------------------------------
    # Required William/Jarvis compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        action_type: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate tenant and operation context."""

        if not isinstance(user_id, str) or not user_id.strip():
            return self._error_result(
                message="user_id is required.",
                error_code="missing_user_id",
            )

        if not isinstance(workspace_id, str) or not workspace_id.strip():
            return self._error_result(
                message="workspace_id is required.",
                error_code="missing_workspace_id",
                metadata={"user_id": user_id},
            )

        if task_id is not None and not str(task_id).strip():
            return self._error_result(
                message="task_id cannot be empty when provided.",
                error_code="invalid_task_id",
            )

        if actor_id is not None and not str(actor_id).strip():
            return self._error_result(
                message="Actor identifier cannot be empty.",
                error_code="invalid_actor_id",
            )

        if action_type is not None and not str(action_type).strip():
            return self._error_result(
                message="action_type cannot be empty.",
                error_code="invalid_action_type",
            )

        if approval_id is not None and not str(approval_id).strip():
            return self._error_result(
                message="approval_id cannot be empty.",
                error_code="invalid_approval_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={},
            metadata=self._base_metadata(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
            ),
        )

    def _requires_security_check(
        self,
        *,
        action_type: str,
        risk_level: str,
        operation: str,
    ) -> bool:
        """
        Determine whether an additional Security Agent policy check is required.

        ApprovalManager is already part of Security Agent. This hook allows the
        central policy engine or Security Agent coordinator to enforce stronger
        rules for critical operations.
        """

        if (
            risk_level == RiskLevel.CRITICAL.value
            and self.config.require_security_check_for_critical_creation
        ):
            return True

        protected_operation_fragments = {
            "payment",
            "transfer",
            "delete",
            "destructive",
            "credential",
            "permission",
            "admin",
            "system",
            "deploy",
            "publish",
            "send_message",
            "place_call",
        }

        normalized = f"{operation} {action_type}".lower()
        return any(fragment in normalized for fragment in protected_operation_fragments)

    def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        action_type: str,
        risk_level: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Invoke an injected central security/policy checker when available.

        This method never recursively creates another user approval request.
        """

        security_target = (
            getattr(self, "security_agent", None)
            or getattr(self, "policy_engine", None)
        )

        if security_target is None:
            # The ApprovalManager itself is a Security Agent component. In the
            # import-safe fallback path, continue while recording that the
            # central policy coordinator was unavailable.
            return self._safe_result(
                message="Security component validation completed with local policy.",
                data={
                    "approved": True,
                    "local_policy_fallback": True,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "risk_level": risk_level,
                },
            )

        method = (
            getattr(security_target, "evaluate_action", None)
            or getattr(security_target, "check_action", None)
            or getattr(security_target, "approve_action", None)
        )

        if not callable(method):
            return self._error_result(
                message="Configured security coordinator has no supported policy method.",
                error_code="security_policy_interface_unavailable",
            )

        try:
            result = method(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action_type=action_type,
                risk_level=risk_level,
                context=dict(context),
            )

            if inspect.isawaitable(result):
                return self._error_result(
                    message=(
                        "Async security policy result cannot be resolved from "
                        "the synchronous approval interface."
                    ),
                    error_code="async_security_policy_requires_async_adapter",
                )

            if isinstance(result, bool):
                if result:
                    return self._safe_result(
                        message="Security policy approved operation.",
                        data={"approved": True},
                    )
                return self._error_result(
                    message="Security policy denied operation.",
                    error_code="security_policy_denied",
                )

            if isinstance(result, Mapping):
                normalized = dict(result)
                if normalized.get("success") is False:
                    return self._error_result(
                        message=str(
                            normalized.get(
                                "message",
                                "Security policy denied operation.",
                            )
                        ),
                        error_code=str(
                            normalized.get(
                                "error_code",
                                "security_policy_denied",
                            )
                        ),
                        error_details=normalized.get("error"),
                        data=normalized.get("data"),
                        metadata=normalized.get("metadata"),
                    )

                approved = normalized.get(
                    "approved",
                    normalized.get("data", {}).get("approved", True)
                    if isinstance(normalized.get("data"), Mapping)
                    else True,
                )
                if not approved:
                    return self._error_result(
                        message="Security policy denied operation.",
                        error_code="security_policy_denied",
                    )

                return self._safe_result(
                    message="Security policy approved operation.",
                    data={"approved": True, "policy_result": normalized},
                )

            return self._error_result(
                message="Security policy returned an unsupported response.",
                error_code="invalid_security_policy_response",
            )

        except Exception as exc:
            self.logger.exception("Security policy check failed.")
            return self._error_result(
                message="Security policy check failed.",
                error_code="security_policy_check_failed",
                error_details=str(exc),
            )

    def _prepare_verification_payload(
        self,
        *,
        approval: Mapping[str, Any],
        event_type: str,
        actor_id: Optional[str],
        decision_record: Optional[Mapping[str, Any]] = None,
        approval_receipt: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build Verification Agent compatible payload."""

        return {
            "verification_id": self._new_id("verification"),
            "source_agent": "SecurityAgent",
            "source_component": "ApprovalManager",
            "event_type": event_type,
            "user_id": approval.get("user_id"),
            "workspace_id": approval.get("workspace_id"),
            "task_id": approval.get("task_id"),
            "approval_id": approval.get("approval_id"),
            "action_id": approval.get("action_id"),
            "action_type": approval.get("action_type"),
            "action_fingerprint": approval.get("action_fingerprint"),
            "approval_status": approval.get("status"),
            "risk_level": approval.get("risk_level"),
            "required_approvals": approval.get("required_approvals"),
            "approved_by": list(approval.get("approved_by", [])),
            "denied_by": list(approval.get("denied_by", [])),
            "actor_id": actor_id,
            "decision_record": self._deep_copy_json_safe(
                decision_record or {}
            ),
            "approval_receipt": self._deep_copy_json_safe(
                approval_receipt or {}
            ),
            "checks": {
                "tenant_scope_present": bool(
                    approval.get("user_id")
                    and approval.get("workspace_id")
                ),
                "action_scope_present": bool(
                    approval.get("task_id")
                    and approval.get("action_id")
                    and approval.get("action_fingerprint")
                ),
                "terminal_state": (
                    approval.get("status") in self.TERMINAL_STATUSES
                ),
            },
            "created_at": self._now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        approval: Mapping[str, Any],
        event_type: str,
        actor_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Build a safe Memory Agent operational summary.

        Raw tokens, token hashes, detailed sensitive inputs, IP addresses, and
        user-agent values are intentionally excluded.
        """

        return {
            "memory_id": self._new_id("security-memory"),
            "user_id": approval.get("user_id"),
            "workspace_id": approval.get("workspace_id"),
            "task_id": approval.get("task_id"),
            "category": "security.approval",
            "content": (
                f"Approval request {approval.get('approval_id')} for "
                f"{approval.get('action_type')} is "
                f"{approval.get('status')}."
            ),
            "importance": (
                0.8
                if approval.get("risk_level") in {
                    RiskLevel.HIGH.value,
                    RiskLevel.CRITICAL.value,
                }
                else 0.5
            ),
            "privacy_level": "internal",
            "source_agent": "SecurityAgent",
            "source_component": "ApprovalManager",
            "created_at": self._now_iso(),
            "metadata": {
                "event_type": event_type,
                "approval_id": approval.get("approval_id"),
                "action_id": approval.get("action_id"),
                "action_type": approval.get("action_type"),
                "status": approval.get("status"),
                "risk_level": approval.get("risk_level"),
                "actor_id": actor_id,
            },
        }

    def _emit_agent_event(self, event: Mapping[str, Any]) -> None:
        """Emit registry/dashboard event without breaking the main operation."""

        try:
            if callable(self.event_emitter):
                result = self.event_emitter(dict(event))
                if inspect.isawaitable(result):
                    self.logger.warning(
                        "Async event emitter returned awaitable from sync method."
                    )
            else:
                self.logger.debug("ApprovalManager event: %s", dict(event))
        except Exception:
            self.logger.exception("Failed to emit ApprovalManager event.")

    def _log_audit_event(self, event: Mapping[str, Any]) -> None:
        """Write an audit event through injected logger or Python logging."""

        safe_event = self._redact_sensitive_data(
            self._deep_copy_json_safe(dict(event))
        )

        try:
            if self.audit_logger is None:
                self.logger.info("ApprovalManager audit: %s", safe_event)
                return

            method = (
                getattr(self.audit_logger, "log_event", None)
                or getattr(self.audit_logger, "record", None)
                or getattr(self.audit_logger, "write", None)
            )

            if callable(method):
                result = method(safe_event)
                if inspect.isawaitable(result):
                    self.logger.warning(
                        "Async audit logger returned awaitable from sync method."
                    )
            elif callable(self.audit_logger):
                result = self.audit_logger(safe_event)
                if inspect.isawaitable(result):
                    self.logger.warning(
                        "Async audit callable returned awaitable from sync method."
                    )
            else:
                self.logger.info("ApprovalManager audit: %s", safe_event)

        except Exception:
            self.logger.exception("Failed to write ApprovalManager audit event.")

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William success result."""

        return {
            "success": True,
            "message": message,
            "data": self._deep_copy_json_safe(data or {}),
            "error": None,
            "metadata": self._deep_copy_json_safe(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error_code: str,
        error_details: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William error result."""

        return {
            "success": False,
            "message": message,
            "data": self._deep_copy_json_safe(data or {}),
            "error": {
                "code": error_code,
                "details": self._deep_copy_json_safe(error_details),
            },
            "metadata": self._deep_copy_json_safe(metadata or {}),
        }

    # -------------------------------------------------------------------------
    # Internal transition helpers
    # -------------------------------------------------------------------------

    def _transition_request(
        self,
        *,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        actor_type: str,
        target_status: str,
        reason: Optional[str],
        allowed_current_statuses: Set[str],
        event_type: str,
        request_context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Perform a controlled approval lifecycle transition."""

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            approval_id=approval_id,
        )
        if not validation["success"]:
            return validation

        with self._mutation_lock:
            request = self.repository.get(
                approval_id=approval_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if request is None:
                return self._error_result(
                    message="Approval request was not found.",
                    error_code="approval_not_found",
                )

            request = self._expire_record_if_needed(request)
            current_status = str(request.get("status", ""))

            if current_status == target_status:
                return self._safe_result(
                    message=f"Approval request is already {target_status}.",
                    data={
                        "approval": self._serialize_public_request(request),
                        "idempotent_replay": True,
                    },
                    metadata={
                        "approval_id": approval_id,
                        "status": current_status,
                    },
                )

            if current_status not in allowed_current_statuses:
                return self._error_result(
                    message=(
                        f"Cannot transition approval from '{current_status}' "
                        f"to '{target_status}'."
                    ),
                    error_code="invalid_approval_transition",
                    metadata={
                        "approval_id": approval_id,
                        "current_status": current_status,
                        "target_status": target_status,
                    },
                )

            permission_result = self._check_permission(
                operation=f"transition_to_{target_status}",
                actor_id=actor_id,
                actor_type=actor_type,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=request.get("task_id"),
                action_type=request.get("action_type"),
                request_context=dict(request_context or {}),
            )
            if not permission_result["success"]:
                return permission_result

            now_iso = self._now_iso()
            updated = copy.deepcopy(request)
            updated["status"] = target_status
            updated["updated_at"] = now_iso
            updated["token_hash"] = None
            updated["token_salt"] = None

            if target_status == ApprovalStatus.REVOKED.value:
                updated["revoked_at"] = now_iso
                updated["revoked_by"] = actor_id
                updated["revoke_reason"] = str(reason or "").strip() or None
            else:
                updated["final_decided_by"] = actor_id
                updated["final_decided_at"] = now_iso
                updated["final_reason"] = str(reason or "").strip() or None

            lifecycle_record = ApprovalDecisionRecord(
                decision_id=self._new_id("lifecycle"),
                approval_id=approval_id,
                user_id=user_id,
                workspace_id=workspace_id,
                decision=target_status,
                decided_by=actor_id,
                actor_type=self._normalize_actor_type(actor_type),
                reason=str(reason or "").strip() or None,
                decided_at=now_iso,
                channel=ApprovalChannel.INTERNAL.value,
                request_ip_hash=self._hash_context_value(
                    (request_context or {}).get("ip_address")
                ),
                user_agent_hash=self._hash_context_value(
                    (request_context or {}).get("user_agent")
                ),
                metadata={"lifecycle_transition": True},
            )

            if self.config.retain_decision_history:
                updated.setdefault("decision_history", []).append(
                    asdict(lifecycle_record)
                )

            try:
                stored = self.repository.update(
                    approval_id=approval_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    request=updated,
                )
            except Exception as exc:
                return self._error_result(
                    message="Could not update approval request.",
                    error_code="approval_storage_update_failed",
                    error_details=str(exc),
                )

        audit_payload = {
            "event": event_type,
            "approval_id": approval_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": stored.get("task_id"),
            "action_id": stored.get("action_id"),
            "actor_id": actor_id,
            "actor_type": actor_type,
            "reason": reason,
            "status": target_status,
            "timestamp": self._now_iso(),
        }
        self._log_audit_event(audit_payload)
        self._emit_agent_event(audit_payload)

        return self._safe_result(
            message=f"Approval request marked as {target_status}.",
            data={
                "approval": self._serialize_public_request(stored),
                "verification_payload": self._prepare_verification_payload(
                    approval=stored,
                    event_type=event_type,
                    actor_id=actor_id,
                    decision_record=asdict(lifecycle_record),
                ),
                "memory_payload": self._prepare_memory_payload(
                    approval=stored,
                    event_type=event_type,
                    actor_id=actor_id,
                ),
                "idempotent_replay": False,
            },
            metadata={
                **self._base_metadata(
                    user_id,
                    workspace_id,
                    stored.get("task_id"),
                ),
                "approval_id": approval_id,
                "status": target_status,
            },
        )

    def _expire_record_if_needed(
        self,
        request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Expire a request when its deadline has passed."""

        mutable = copy.deepcopy(dict(request))
        status = str(mutable.get("status", ""))

        if status not in self.ACTIVE_STATUSES:
            return mutable

        expiry = self._parse_datetime(mutable.get("expires_at"))
        if expiry is None or expiry > self._now():
            return mutable

        mutable["status"] = ApprovalStatus.EXPIRED.value
        mutable["updated_at"] = self._now_iso()
        mutable["token_hash"] = None
        mutable["token_salt"] = None
        mutable["final_decided_at"] = mutable["updated_at"]
        mutable["final_reason"] = "Approval request expired before completion."

        try:
            stored = self.repository.update(
                approval_id=str(mutable["approval_id"]),
                user_id=str(mutable["user_id"]),
                workspace_id=str(mutable["workspace_id"]),
                request=mutable,
            )
        except Exception:
            self.logger.exception("Failed to persist expired approval status.")
            return mutable

        event = {
            "event": "security.approval.expired",
            "approval_id": stored.get("approval_id"),
            "user_id": stored.get("user_id"),
            "workspace_id": stored.get("workspace_id"),
            "task_id": stored.get("task_id"),
            "action_id": stored.get("action_id"),
            "status": ApprovalStatus.EXPIRED.value,
            "timestamp": stored.get("updated_at"),
        }
        self._log_audit_event(event)
        self._emit_agent_event(event)

        return stored

    # -------------------------------------------------------------------------
    # Internal security/permission helpers
    # -------------------------------------------------------------------------

    def _check_permission(
        self,
        *,
        operation: str,
        actor_id: str,
        actor_type: str,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        action_type: Optional[str],
        request_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Call PermissionChecker if available."""

        if self.permission_checker is None:
            return self._safe_result(
                message="Permission accepted by local approval policy.",
                data={"allowed": True, "fallback": True},
            )

        method = (
            getattr(self.permission_checker, "check_permission", None)
            or getattr(self.permission_checker, "is_allowed", None)
            or getattr(self.permission_checker, "check", None)
        )

        if not callable(method):
            return self._error_result(
                message="Permission checker has no supported method.",
                error_code="permission_checker_interface_unavailable",
            )

        try:
            result = method(
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id,
                actor_type=actor_type,
                permission=f"security.approval.{operation}",
                task_id=task_id,
                action_type=action_type,
                context=dict(request_context),
            )

            if inspect.isawaitable(result):
                return self._error_result(
                    message=(
                        "Async permission result requires an async repository "
                        "or permission adapter."
                    ),
                    error_code="async_permission_checker_requires_adapter",
                )

            if isinstance(result, bool):
                allowed = result
            elif isinstance(result, Mapping):
                if result.get("success") is False:
                    allowed = False
                else:
                    allowed = bool(
                        result.get(
                            "allowed",
                            result.get("data", {}).get("allowed", True)
                            if isinstance(result.get("data"), Mapping)
                            else True,
                        )
                    )
            else:
                allowed = False

            if not allowed:
                return self._error_result(
                    message="Actor is not permitted to perform this approval operation.",
                    error_code="approval_permission_denied",
                    metadata={
                        "operation": operation,
                        "actor_id": actor_id,
                    },
                )

            return self._safe_result(
                message="Permission check passed.",
                data={"allowed": True},
            )

        except Exception as exc:
            self.logger.exception("Permission check failed.")
            return self._error_result(
                message="Permission check failed.",
                error_code="permission_check_failed",
                error_details=str(exc),
            )

    def _validate_approver_eligibility(
        self,
        *,
        request: Mapping[str, Any],
        decided_by: str,
        actor_roles: Sequence[str],
    ) -> Dict[str, Any]:
        """Validate approver id, role, duplicate participation, and creator rule."""

        eligible_ids = {
            str(value)
            for value in request.get("eligible_approver_ids", [])
        }
        eligible_roles = {
            str(value).lower()
            for value in request.get("eligible_roles", [])
        }
        normalized_actor_roles = {
            str(value).lower()
            for value in actor_roles
        }

        if (
            not self.config.allow_creator_to_approve
            and str(request.get("created_by")) == str(decided_by)
        ):
            return self._error_result(
                message="The request creator cannot approve this action.",
                error_code="creator_cannot_approve",
            )

        id_allowed = not eligible_ids or str(decided_by) in eligible_ids
        role_allowed = (
            not eligible_roles
            or bool(eligible_roles & normalized_actor_roles)
        )

        if eligible_ids and eligible_roles:
            eligible = id_allowed or role_allowed
        else:
            eligible = id_allowed and role_allowed

        if not eligible:
            return self._error_result(
                message="Actor is not an eligible approver for this request.",
                error_code="approver_not_eligible",
                metadata={
                    "decided_by": decided_by,
                    "eligible_by_id": id_allowed,
                    "eligible_by_role": role_allowed,
                },
            )

        if decided_by in request.get("denied_by", []):
            return self._error_result(
                message="Actor has already denied this request.",
                error_code="actor_already_denied",
            )

        return self._safe_result(
            message="Approver eligibility validated.",
            data={"eligible": True},
        )

    def _validate_confirmation_token(
        self,
        *,
        request: Mapping[str, Any],
        confirmation_token: Optional[str],
    ) -> Dict[str, Any]:
        """Validate the one-time confirmation token."""

        stored_hash = request.get("token_hash")
        stored_salt = request.get("token_salt")

        if not stored_hash or not stored_salt:
            return self._error_result(
                message="Approval confirmation token is no longer valid.",
                error_code="approval_token_unavailable",
            )

        if not confirmation_token:
            if self.config.allow_decision_without_token:
                return self._safe_result(
                    message="Token validation bypassed by configured policy.",
                    data={"valid": True, "bypassed": True},
                )

            return self._error_result(
                message="A confirmation token is required.",
                error_code="confirmation_token_required",
            )

        provided_hash = self._hash_confirmation_token(
            token=confirmation_token,
            salt=str(stored_salt),
        )

        if not hmac.compare_digest(str(stored_hash), provided_hash):
            return self._error_result(
                message="Confirmation token is invalid.",
                error_code="invalid_confirmation_token",
            )

        return self._safe_result(
            message="Confirmation token validated.",
            data={"valid": True},
        )

    # -------------------------------------------------------------------------
    # Internal receipt helpers
    # -------------------------------------------------------------------------

    def _issue_approval_receipt(
        self,
        request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Issue a short-lived signed receipt for an approved request."""

        issued_at = self._now()
        request_expiry = self._parse_datetime(request.get("expires_at"))
        configured_expiry = issued_at + timedelta(
            seconds=self.config.verification_receipt_ttl_seconds
        )

        if request_expiry is not None:
            receipt_expiry = min(configured_expiry, request_expiry)
        else:
            receipt_expiry = configured_expiry

        receipt = ApprovalReceipt(
            receipt_id=self._new_id("receipt"),
            approval_id=str(request["approval_id"]),
            user_id=str(request["user_id"]),
            workspace_id=str(request["workspace_id"]),
            task_id=str(request["task_id"]),
            action_id=str(request["action_id"]),
            action_type=str(request["action_type"]),
            status=str(request["status"]),
            approved_by=sorted(
                {str(value) for value in request.get("approved_by", [])}
            ),
            issued_at=self._iso(issued_at),
            expires_at=self._iso(receipt_expiry),
            action_fingerprint=str(request["action_fingerprint"]),
            receipt_signature="",
            metadata={
                "risk_level": request.get("risk_level"),
                "required_approvals": request.get("required_approvals"),
                "version": 1,
            },
        )

        receipt_dict = asdict(receipt)
        receipt_dict["receipt_signature"] = self._sign_receipt_payload(
            receipt_dict
        )
        return receipt_dict

    def _sign_receipt_payload(
        self,
        receipt: Mapping[str, Any],
    ) -> str:
        """Create HMAC signature for receipt fields excluding the signature."""

        payload = {
            key: value
            for key, value in receipt.items()
            if key != "receipt_signature"
        }
        serialized = self._canonical_json(payload).encode("utf-8")

        return hmac.new(
            self._receipt_signing_key,
            serialized,
            hashlib.sha256,
        ).hexdigest()

    # -------------------------------------------------------------------------
    # Internal risk and prompt helpers
    # -------------------------------------------------------------------------

    def _resolve_risk_level(
        self,
        *,
        risk_level: Optional[str],
        action_type: str,
        action_details: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
        task_id: str,
    ) -> str:
        """Resolve explicit or RiskEngine-derived risk."""

        normalized_explicit = (
            self._normalize_risk_level(risk_level)
            if risk_level is not None
            else None
        )
        if normalized_explicit is not None:
            return normalized_explicit

        if self.risk_engine is not None:
            method = (
                getattr(self.risk_engine, "evaluate", None)
                or getattr(self.risk_engine, "assess_risk", None)
                or getattr(self.risk_engine, "calculate_risk", None)
            )

            if callable(method):
                try:
                    result = method(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        action_type=action_type,
                        action_details=dict(action_details),
                    )

                    if not inspect.isawaitable(result):
                        if isinstance(result, str):
                            normalized = self._normalize_risk_level(result)
                            if normalized:
                                return normalized

                        if isinstance(result, Mapping):
                            candidate = (
                                result.get("risk_level")
                                or result.get("level")
                                or (
                                    result.get("data", {}).get("risk_level")
                                    if isinstance(result.get("data"), Mapping)
                                    else None
                                )
                            )
                            normalized = self._normalize_risk_level(candidate)
                            if normalized:
                                return normalized
                except Exception:
                    self.logger.exception(
                        "RiskEngine failed; using local risk classification."
                    )

        return self._classify_risk_locally(action_type, action_details)

    def _classify_risk_locally(
        self,
        action_type: str,
        action_details: Mapping[str, Any],
    ) -> str:
        """Conservative fallback risk classification."""

        normalized = str(action_type).lower()

        critical_fragments = {
            "transfer_money",
            "payment",
            "delete_account",
            "wipe",
            "format",
            "credential",
            "private_key",
            "root",
            "admin_grant",
            "emergency_lock_disable",
        }
        high_fragments = {
            "delete",
            "deploy",
            "publish",
            "send",
            "call",
            "browser_purchase",
            "permission",
            "install",
            "execute_command",
            "file_write",
            "database_write",
        }
        medium_fragments = {
            "update",
            "modify",
            "edit",
            "create",
            "upload",
            "download",
            "share",
            "export",
        }

        if any(fragment in normalized for fragment in critical_fragments):
            return RiskLevel.CRITICAL.value
        if any(fragment in normalized for fragment in high_fragments):
            return RiskLevel.HIGH.value
        if any(fragment in normalized for fragment in medium_fragments):
            return RiskLevel.MEDIUM.value

        if action_details.get("destructive") is True:
            return RiskLevel.HIGH.value
        if action_details.get("financial") is True:
            return RiskLevel.CRITICAL.value
        if action_details.get("external_side_effect") is True:
            return RiskLevel.HIGH.value

        return RiskLevel.MEDIUM.value

    def _infer_consequences(
        self,
        *,
        action_type: str,
        action_details: Mapping[str, Any],
        risk_level: str,
    ) -> List[str]:
        """Create user-facing consequences without exposing secrets."""

        normalized = action_type.lower()
        consequences: List[str] = []

        if "delete" in normalized or action_details.get("destructive"):
            consequences.append("Data may be removed or become unavailable.")

        if any(word in normalized for word in {"payment", "transfer", "purchase"}):
            consequences.append("Funds or billable resources may be used.")

        if any(word in normalized for word in {"send", "email", "message", "call"}):
            consequences.append("An external person or service may be contacted.")

        if any(word in normalized for word in {"publish", "post", "deploy"}):
            consequences.append("Content or software may become externally visible.")

        if any(word in normalized for word in {"permission", "admin", "access"}):
            consequences.append("Account or workspace access may change.")

        if "file" in normalized or "database" in normalized:
            consequences.append("Stored information may be changed.")

        if risk_level == RiskLevel.CRITICAL.value:
            consequences.append(
                "This confirmation should be approved only after reviewing all details."
            )

        if not consequences:
            consequences.append(
                "The requested action may change workspace state or external systems."
            )

        return consequences

    # -------------------------------------------------------------------------
    # Internal normalization and validation helpers
    # -------------------------------------------------------------------------

    def _validate_config(self) -> None:
        """Validate configuration at construction time."""

        if self.config.minimum_expiry_seconds < 1:
            raise ValueError("minimum_expiry_seconds must be positive")

        if (
            self.config.maximum_expiry_seconds
            < self.config.minimum_expiry_seconds
        ):
            raise ValueError(
                "maximum_expiry_seconds must be >= minimum_expiry_seconds"
            )

        if not (
            self.config.minimum_expiry_seconds
            <= self.config.default_expiry_seconds
            <= self.config.maximum_expiry_seconds
        ):
            raise ValueError(
                "default_expiry_seconds must be within configured bounds"
            )

        if self.config.token_bytes < 16:
            raise ValueError("token_bytes must be at least 16")

        if self.config.default_required_approvals < 1:
            raise ValueError("default_required_approvals must be positive")

        if self.config.maximum_required_approvals < 1:
            raise ValueError("maximum_required_approvals must be positive")

    def _resolve_expiry_seconds(
        self,
        *,
        expires_in_seconds: Optional[int],
        risk_level: str,
    ) -> Dict[str, Any]:
        """Validate and constrain approval expiry."""

        requested = (
            self.config.default_expiry_seconds
            if expires_in_seconds is None
            else expires_in_seconds
        )

        try:
            requested_int = int(requested)
        except (TypeError, ValueError):
            return self._error_result(
                message="expires_in_seconds must be an integer.",
                error_code="invalid_expiry",
            )

        maximum = self.config.maximum_expiry_seconds
        if risk_level == RiskLevel.CRITICAL.value:
            maximum = min(
                maximum,
                self.config.critical_maximum_expiry_seconds,
            )

        if requested_int < self.config.minimum_expiry_seconds:
            return self._error_result(
                message=(
                    "Approval expiry is below the configured minimum of "
                    f"{self.config.minimum_expiry_seconds} seconds."
                ),
                error_code="approval_expiry_too_short",
            )

        if requested_int > maximum:
            return self._error_result(
                message=(
                    "Approval expiry exceeds the maximum allowed for this "
                    f"risk level: {maximum} seconds."
                ),
                error_code="approval_expiry_too_long",
            )

        return self._safe_result(
            message="Approval expiry validated.",
            data={"expires_in_seconds": requested_int},
        )

    def _resolve_required_approvals(
        self,
        *,
        approval_mode: str,
        required_approvals: Optional[int],
        eligible_approver_ids: Sequence[str],
    ) -> Dict[str, Any]:
        """Resolve required approvals from mode and eligible approvers."""

        if approval_mode == ApprovalMode.SINGLE.value:
            resolved = 1

        elif approval_mode == ApprovalMode.UNANIMOUS.value:
            if not eligible_approver_ids:
                return self._error_result(
                    message=(
                        "Unanimous approval requires explicit eligible approver ids."
                    ),
                    error_code="unanimous_approvers_required",
                )
            resolved = len(set(eligible_approver_ids))

        else:
            resolved = (
                self.config.default_required_approvals
                if required_approvals is None
                else required_approvals
            )

        try:
            resolved_int = int(resolved)
        except (TypeError, ValueError):
            return self._error_result(
                message="required_approvals must be an integer.",
                error_code="invalid_required_approvals",
            )

        if resolved_int < 1:
            return self._error_result(
                message="At least one approval is required.",
                error_code="invalid_required_approvals",
            )

        if resolved_int > self.config.maximum_required_approvals:
            return self._error_result(
                message="Required approvals exceed the configured maximum.",
                error_code="required_approvals_limit_exceeded",
                metadata={
                    "maximum": self.config.maximum_required_approvals
                },
            )

        if (
            eligible_approver_ids
            and resolved_int > len(set(eligible_approver_ids))
        ):
            return self._error_result(
                message=(
                    "Required approval count exceeds the number of eligible "
                    "approvers."
                ),
                error_code="insufficient_eligible_approvers",
            )

        return self._safe_result(
            message="Required approval count resolved.",
            data={"required_approvals": resolved_int},
        )

    def _normalize_decision(self, value: Any) -> Optional[str]:
        normalized = str(value or "").strip().lower()
        aliases = {
            "approved": ApprovalDecision.APPROVE.value,
            "yes": ApprovalDecision.APPROVE.value,
            "allow": ApprovalDecision.APPROVE.value,
            "allowed": ApprovalDecision.APPROVE.value,
            "denied": ApprovalDecision.DENY.value,
            "no": ApprovalDecision.DENY.value,
            "reject": ApprovalDecision.DENY.value,
            "rejected": ApprovalDecision.DENY.value,
        }
        normalized = aliases.get(normalized, normalized)

        if normalized in {item.value for item in ApprovalDecision}:
            return normalized
        return None

    def _normalize_risk_level(self, value: Any) -> Optional[str]:
        normalized = str(value or "").strip().lower()
        if normalized in {item.value for item in RiskLevel}:
            return normalized
        return None

    def _normalize_channel(self, value: Any) -> Optional[str]:
        normalized = str(value or "").strip().lower()
        if normalized in {item.value for item in ApprovalChannel}:
            return normalized
        return None

    def _normalize_approval_mode(self, value: Any) -> Optional[str]:
        normalized = str(value or "").strip().lower()
        if normalized in {item.value for item in ApprovalMode}:
            return normalized
        return None

    def _normalize_actor_type(self, value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {item.value for item in ActorType}:
            return normalized
        return ActorType.UNKNOWN.value

    def _normalize_string_list(
        self,
        values: Optional[Sequence[Any]],
    ) -> List[str]:
        """Normalize, deduplicate, and preserve order."""

        result: List[str] = []
        seen: Set[str] = set()

        for value in values or []:
            normalized = str(value).strip()
            if normalized and normalized not in seen:
                result.append(normalized)
                seen.add(normalized)

        return result

    # -------------------------------------------------------------------------
    # Internal hashing/fingerprinting helpers
    # -------------------------------------------------------------------------

    def _hash_confirmation_token(
        self,
        *,
        token: str,
        salt: str,
    ) -> str:
        """Hash confirmation token using configured digest."""

        try:
            digest = hashlib.new(self.config.token_digest_algorithm)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported token digest algorithm: "
                f"{self.config.token_digest_algorithm}"
            ) from exc

        digest.update(f"{salt}:{token}".encode("utf-8"))
        return digest.hexdigest()

    def _hash_idempotency_key(
        self,
        *,
        user_id: str,
        workspace_id: str,
        idempotency_key: str,
    ) -> str:
        """Create tenant-scoped idempotency hash."""

        return hashlib.sha256(
            (
                f"{user_id}:{workspace_id}:{idempotency_key}"
            ).encode("utf-8")
        ).hexdigest()

    def _build_action_fingerprint(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        action_id: str,
        action_type: str,
        action_summary: str,
        action_details: Mapping[str, Any],
    ) -> str:
        """Create deterministic scope fingerprint for the protected action."""

        payload = {
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "task_id": str(task_id),
            "action_id": str(action_id),
            "action_type": str(action_type),
            "action_summary": str(action_summary).strip(),
            "action_details": self._deep_copy_json_safe(action_details),
        }
        return hashlib.sha256(
            self._canonical_json(payload).encode("utf-8")
        ).hexdigest()

    def _hash_context_value(self, value: Any) -> Optional[str]:
        """Hash request metadata instead of storing raw IP/user-agent values."""

        if value is None or not str(value).strip():
            return None
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    def _hash_generic_value(self, value: Any) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    # -------------------------------------------------------------------------
    # Internal serialization/redaction helpers
    # -------------------------------------------------------------------------

    def _serialize_public_request(
        self,
        request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Remove internal token and idempotency fields."""

        public = copy.deepcopy(dict(request))

        public.pop("token_hash", None)
        public.pop("token_salt", None)
        public.pop("idempotency_key_hash", None)

        public["action_details"] = self._redact_sensitive_data(
            public.get("action_details", {})
        )
        public["metadata"] = self._redact_sensitive_data(
            public.get("metadata", {})
        )

        return self._deep_copy_json_safe(public)

    def _redact_sensitive_data(self, value: Any) -> Any:
        """Recursively redact common secret fields."""

        if not self.config.redact_sensitive_details:
            return self._deep_copy_json_safe(value)

        if isinstance(value, Mapping):
            output: Dict[str, Any] = {}
            for key, item in value.items():
                normalized_key = str(key).strip().lower()
                if (
                    normalized_key in self.SENSITIVE_DETAIL_KEYS
                    or any(
                        fragment in normalized_key
                        for fragment in {
                            "password",
                            "secret",
                            "token",
                            "private_key",
                            "authorization",
                            "cookie",
                            "card_number",
                            "cvv",
                        }
                    )
                ):
                    output[str(key)] = "[REDACTED]"
                else:
                    output[str(key)] = self._redact_sensitive_data(item)
            return output

        if isinstance(value, (list, tuple, set)):
            return [self._redact_sensitive_data(item) for item in value]

        return self._deep_copy_json_safe(value)

    def _sanitize_context_for_storage(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Store safe request context without raw network/device identifiers."""

        sanitized = self._redact_sensitive_data(dict(context))

        if "ip_address" in sanitized:
            sanitized["ip_address_hash"] = self._hash_context_value(
                context.get("ip_address")
            )
            sanitized.pop("ip_address", None)

        if "user_agent" in sanitized:
            sanitized["user_agent_hash"] = self._hash_context_value(
                context.get("user_agent")
            )
            sanitized.pop("user_agent", None)

        return sanitized

    def _deep_copy_json_safe(self, value: Any) -> Any:
        """Convert arbitrary values to JSON-compatible safe structures."""

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, datetime):
            return self._iso(value)

        if isinstance(value, Mapping):
            return {
                str(key): self._deep_copy_json_safe(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                self._deep_copy_json_safe(item)
                for item in value
            ]

        if hasattr(value, "__dataclass_fields__"):
            return self._deep_copy_json_safe(asdict(value))

        try:
            json.dumps(value)
            return copy.deepcopy(value)
        except (TypeError, ValueError):
            return str(value)

    def _canonical_json(self, value: Any) -> str:
        """Stable JSON representation used for signatures and fingerprints."""

        return json.dumps(
            self._deep_copy_json_safe(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    # -------------------------------------------------------------------------
    # Internal utility helpers
    # -------------------------------------------------------------------------

    def _find_existing_actor_decision(
        self,
        *,
        request: Mapping[str, Any],
        decided_by: str,
        decision: str,
        decision_idempotency_key: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """Find duplicate actor decision for idempotent replay handling."""

        requested_hash = (
            self._hash_generic_value(decision_idempotency_key)
            if decision_idempotency_key
            else None
        )

        for record in reversed(request.get("decision_history", [])):
            if str(record.get("decided_by")) != str(decided_by):
                continue

            if str(record.get("decision")) != str(decision):
                continue

            stored_hash = (
                record.get("metadata", {})
                .get("decision_idempotency_key_hash")
            )

            if requested_hash is not None:
                if stored_hash == requested_hash:
                    return copy.deepcopy(record)
                continue

            # Without an explicit decision idempotency key, the same actor and
            # same decision is treated as idempotent.
            return copy.deepcopy(record)

        return None

    def _humanize_action_type(self, action_type: str) -> str:
        text = str(action_type).replace(".", " ").replace("_", " ").strip()
        return " ".join(word.capitalize() for word in text.split()) or "Action"

    def _base_metadata(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "agent": "SecurityAgent",
            "component": "ApprovalManager",
            "version": self.config.module_version,
        }

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex}"

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _now_iso(self) -> str:
        return self._iso(self._now())

    def _iso(self, value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        if value is None:
            return None

        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            try:
                parsed = datetime.fromtimestamp(
                    float(value),
                    tz=timezone.utc,
                )
            except (ValueError, OSError, OverflowError):
                return None
        else:
            text = str(value).strip()
            if not text:
                return None

            if text.endswith("Z"):
                text = text[:-1] + "+00:00"

            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)


# =============================================================================
# Convenience factory and exports
# =============================================================================

def create_approval_manager(
    *,
    repository: Optional[ApprovalRepository] = None,
    config: Optional[ApprovalManagerConfig] = None,
    receipt_signing_key: Optional[Union[str, bytes]] = None,
    **kwargs: Any,
) -> ApprovalManager:
    """Create a configured ApprovalManager instance."""

    return ApprovalManager(
        repository=repository,
        config=config,
        receipt_signing_key=receipt_signing_key,
        **kwargs,
    )


__all__ = [
    "ActorType",
    "ApprovalChannel",
    "ApprovalDecision",
    "ApprovalDecisionRecord",
    "ApprovalManager",
    "ApprovalManagerConfig",
    "ApprovalMode",
    "ApprovalPrompt",
    "ApprovalReceipt",
    "ApprovalRepository",
    "ApprovalRequest",
    "ApprovalStatus",
    "InMemoryApprovalRepository",
    "RiskLevel",
    "create_approval_manager",
]