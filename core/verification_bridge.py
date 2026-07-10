"""
core/verification_bridge.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Bridge completed task payloads from Master Agent / Task Manager / Router
    to the Verification Agent for proof-based confirmation.

This file is designed to be:
    - Import-safe even when future modules are not created yet
    - SaaS-ready with user_id and workspace_id isolation
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent, Security Agent, Memory Agent, Dashboard/API, and audit logs
    - Production-level, testable, and safe by default

Core responsibilities:
    - Validate task context before verification
    - Prepare structured verification payloads
    - Optionally request security approval before sensitive verification flows
    - Send payloads to Verification Agent when available
    - Provide fallback local verification records when Verification Agent is not available
    - Prepare Memory Agent-compatible payloads
    - Emit dashboard/registry events
    - Log audit events
    - Return structured JSON/dict results
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, Union


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from core.context import TaskContext  # type: ignore
except Exception:
    TaskContext = None  # type: ignore


try:
    from core.config import settings  # type: ignore
except Exception:
    settings = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps verification_bridge.py import-safe while the full William/Jarvis
        agent stack is still being generated.
        """

        name: str = "fallback_base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.name = kwargs.get("name", self.name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent has no runtime implementation.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.core.verification_bridge")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

DEFAULT_VERIFICATION_TIMEOUT_SECONDS = 30
DEFAULT_VERIFICATION_CONFIDENCE_THRESHOLD = 0.70
DEFAULT_MAX_PROOF_ITEMS = 50

SENSITIVE_ACTION_TYPES = {
    "system_action",
    "file_write",
    "file_delete",
    "browser_action",
    "email_send",
    "message_send",
    "call_action",
    "financial_action",
    "payment_action",
    "security_action",
    "credential_action",
    "external_api_action",
    "destructive_action",
}

PROOF_REQUIRED_ACTION_TYPES = {
    "system_action",
    "browser_action",
    "code_execution",
    "file_write",
    "workflow_execution",
    "business_action",
    "finance_action",
    "call_action",
    "creator_action",
    "external_api_action",
}


# =============================================================================
# Protocols for optional dependency compatibility
# =============================================================================

class VerificationAgentProtocol(Protocol):
    """
    Protocol expected from the Verification Agent.

    Any future VerificationAgent can implement one or more of these methods.
    """

    def verify_task(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def verify(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


class SecurityAgentProtocol(Protocol):
    """
    Protocol expected from the Security Agent.
    """

    def approve_action(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def check_permission(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


class EventEmitterProtocol(Protocol):
    """
    Protocol for event bus / dashboard / registry integrations.
    """

    def emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        ...


class AuditLoggerProtocol(Protocol):
    """
    Protocol for external audit logging integrations.
    """

    def log(self, event_name: str, payload: Dict[str, Any]) -> None:
        ...


# =============================================================================
# Enums
# =============================================================================

class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    REQUIRES_REVIEW = "requires_review"
    SECURITY_BLOCKED = "security_blocked"
    ERROR = "error"


class VerificationLevel(str, Enum):
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    FORENSIC = "forensic"


class ProofType(str, Enum):
    TEXT = "text"
    JSON = "json"
    SCREENSHOT = "screenshot"
    FILE_HASH = "file_hash"
    URL = "url"
    LOG = "log"
    API_RESPONSE = "api_response"
    METRIC = "metric"
    SYSTEM_STATE = "system_state"
    USER_CONFIRMATION = "user_confirmation"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class VerificationConfig:
    """
    Verification bridge configuration.

    This can later be hydrated from core/config.py, workspace settings,
    dashboard settings, subscription tier, or role policies.
    """

    enabled: bool = True
    require_security_for_sensitive_actions: bool = True
    confidence_threshold: float = DEFAULT_VERIFICATION_CONFIDENCE_THRESHOLD
    timeout_seconds: int = DEFAULT_VERIFICATION_TIMEOUT_SECONDS
    default_level: VerificationLevel = VerificationLevel.STANDARD
    max_proof_items: int = DEFAULT_MAX_PROOF_ITEMS
    allow_fallback_local_verification: bool = True
    emit_events: bool = True
    audit_enabled: bool = True
    memory_payload_enabled: bool = True


@dataclass
class ProofItem:
    """
    One evidence/proof item used by the Verification Agent.
    """

    proof_type: ProofType
    label: str
    value: Any
    source: Optional[str] = None
    confidence: Optional[float] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["proof_type"] = self.proof_type.value
        return payload


@dataclass
class VerificationRecord:
    """
    A local verification record.

    This can be stored in DB later by Dashboard/API or Task History service.
    """

    verification_id: str
    task_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    status: VerificationStatus
    action_type: str
    confidence: float
    message: str
    payload_hash: str
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(value: Any) -> str:
    """Safely JSON serialize any value."""
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return json.dumps(str(value), sort_keys=True, ensure_ascii=False)


def stable_hash(value: Any) -> str:
    """Generate a stable SHA256 hash for a payload."""
    raw = safe_json_dumps(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_id(value: Any) -> Optional[Union[str, int]]:
    """
    Normalize user/workspace/task identifiers.

    Returns None if the value is missing or empty.
    """
    if value is None:
        return None

    if isinstance(value, str):
        clean = value.strip()
        if not clean:
            return None
        return clean

    if isinstance(value, int):
        return value

    return str(value).strip() or None


def clamp_confidence(value: Any) -> float:
    """Clamp confidence into 0.0 - 1.0."""
    try:
        number = float(value)
    except Exception:
        return 0.0

    if number < 0:
        return 0.0
    if number > 1:
        return 1.0
    return number


# =============================================================================
# VerificationBridge
# =============================================================================

class VerificationBridge(BaseAgent):
    """
    Bridge between completed tasks and the Verification Agent.

    How this connects inside William/Jarvis:

    Master Agent:
        Calls VerificationBridge after a task is completed and before final
        response delivery, dashboard completion, or task-history finalization.

    Task Manager:
        Can call submit_for_verification() when a task status becomes completed.

    Agent Router:
        Can route verification-specific actions through this bridge instead of
        directly calling Verification Agent.

    Security Agent:
        Sensitive verification actions can be sent for permission approval before
        proof confirmation begins.

    Memory Agent:
        This bridge prepares memory-compatible payloads so verified outcomes can
        become useful future context without mixing users/workspaces.

    Dashboard/API:
        The returned structured dict can be stored, streamed, or displayed in
        task history, audit pages, verification timelines, or analytics widgets.

    Registry/Loader:
        The bridge is import-safe and exposes predictable public methods for
        agent registration and future plugin-style integrations.
    """

    name = "verification_bridge"
    version = "1.0.0"
    module = "core"
    description = "Bridge completed task payloads to Verification Agent for proof-based confirmation."

    def __init__(
        self,
        verification_agent: Optional[VerificationAgentProtocol] = None,
        security_agent: Optional[SecurityAgentProtocol] = None,
        event_emitter: Optional[EventEmitterProtocol] = None,
        audit_logger: Optional[AuditLoggerProtocol] = None,
        config: Optional[VerificationConfig] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        registry: Optional[Any] = None,
    ) -> None:
        super().__init__(name=self.name)

        self.verification_agent = verification_agent
        self.security_agent = security_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.memory_callback = memory_callback
        self.registry = registry

        self.config = config or self._load_config()
        self._records: Dict[str, VerificationRecord] = {}

    # -------------------------------------------------------------------------
    # Public methods
    # -------------------------------------------------------------------------

    def submit_for_verification(
        self,
        task_payload: Dict[str, Any],
        *,
        completed_result: Optional[Dict[str, Any]] = None,
        proof_items: Optional[List[Union[ProofItem, Dict[str, Any]]]] = None,
        verification_level: Optional[Union[VerificationLevel, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Submit a completed task to Verification Agent.

        Args:
            task_payload:
                Completed task payload from Master Agent, Router, Task Manager,
                Workflow Agent, or any other William/Jarvis agent.

            completed_result:
                Final task result that needs confirmation.

            proof_items:
                Evidence list, such as logs, screenshots, API responses, file hashes,
                browser states, or generated outputs.

            verification_level:
                basic, standard, strict, or forensic.

            metadata:
                Extra dashboard/API/registry metadata.

        Returns:
            Structured result:
                {
                    success,
                    message,
                    data,
                    error,
                    metadata
                }
        """
        started_at = time.time()
        metadata = metadata or {}

        try:
            if not isinstance(task_payload, dict):
                return self._error_result(
                    message="Task payload must be a dictionary.",
                    error="INVALID_TASK_PAYLOAD",
                    metadata={"received_type": type(task_payload).__name__},
                )

            validation = self._validate_task_context(task_payload)
            if not validation["success"]:
                return validation

            if not self.config.enabled:
                skipped_record = self._create_local_record(
                    task_payload=task_payload,
                    status=VerificationStatus.SKIPPED,
                    confidence=0.0,
                    message="Verification is disabled by configuration.",
                    data={"completed_result": completed_result or {}},
                    error=None,
                    metadata=metadata,
                )

                self._log_audit_event(
                    "verification.skipped",
                    {
                        "record": skipped_record.to_dict(),
                        "reason": "verification_disabled",
                    },
                )

                return self._safe_result(
                    message="Verification skipped because it is disabled.",
                    data={"verification": skipped_record.to_dict()},
                    metadata={"status": VerificationStatus.SKIPPED.value},
                )

            if self._requires_security_check(task_payload):
                security_result = self._request_security_approval(task_payload, metadata=metadata)
                if not security_result.get("success"):
                    blocked_record = self._create_local_record(
                        task_payload=task_payload,
                        status=VerificationStatus.SECURITY_BLOCKED,
                        confidence=0.0,
                        message="Verification blocked by Security Agent.",
                        data={"security_result": security_result},
                        error=security_result.get("error") or "SECURITY_BLOCKED",
                        metadata=metadata,
                    )

                    self._emit_agent_event(
                        "verification.security_blocked",
                        {
                            "verification": blocked_record.to_dict(),
                            "task": self._safe_task_summary(task_payload),
                        },
                    )

                    self._log_audit_event(
                        "verification.security_blocked",
                        {
                            "record": blocked_record.to_dict(),
                            "security_result": security_result,
                        },
                    )

                    return self._error_result(
                        message="Verification blocked by Security Agent.",
                        error=security_result.get("error") or "SECURITY_BLOCKED",
                        data={"verification": blocked_record.to_dict()},
                        metadata={"status": VerificationStatus.SECURITY_BLOCKED.value},
                    )

            verification_payload = self._prepare_verification_payload(
                task_payload=task_payload,
                completed_result=completed_result or {},
                proof_items=proof_items or [],
                verification_level=verification_level,
                metadata=metadata,
            )

            self._emit_agent_event(
                "verification.started",
                {
                    "verification_id": verification_payload["verification_id"],
                    "task_id": verification_payload["task_id"],
                    "user_id": verification_payload["user_id"],
                    "workspace_id": verification_payload["workspace_id"],
                    "level": verification_payload["verification_level"],
                },
            )

            verification_result = self._send_to_verification_agent(verification_payload)

            normalized = self._normalize_verification_result(
                verification_payload=verification_payload,
                verification_result=verification_result,
                started_at=started_at,
                metadata=metadata,
            )

            memory_payload = self._prepare_memory_payload(
                task_payload=task_payload,
                verification_result=normalized,
                metadata=metadata,
            )

            if self.config.memory_payload_enabled and self.memory_callback:
                try:
                    self.memory_callback(memory_payload)
                except Exception as exc:
                    logger.warning("Memory callback failed in VerificationBridge: %s", exc)

            self._emit_agent_event(
                "verification.completed",
                {
                    "verification": normalized.get("data", {}).get("verification", {}),
                    "memory_payload": memory_payload,
                },
            )

            self._log_audit_event(
                "verification.completed",
                {
                    "task": self._safe_task_summary(task_payload),
                    "verification": normalized.get("data", {}).get("verification", {}),
                    "memory_payload": memory_payload,
                },
            )

            return normalized

        except Exception as exc:
            logger.exception("VerificationBridge submit_for_verification failed.")

            return self._error_result(
                message="Verification bridge failed while submitting task.",
                error="VERIFICATION_BRIDGE_EXCEPTION",
                data={"exception": str(exc)},
                metadata=metadata,
            )

    def verify_completed_task(
        self,
        task_payload: Dict[str, Any],
        completed_result: Optional[Dict[str, Any]] = None,
        proof_items: Optional[List[Union[ProofItem, Dict[str, Any]]]] = None,
        verification_level: Optional[Union[VerificationLevel, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Alias for submit_for_verification().

        This name is easier for Master Agent / Task Manager integrations.
        """
        return self.submit_for_verification(
            task_payload=task_payload,
            completed_result=completed_result,
            proof_items=proof_items,
            verification_level=verification_level,
            metadata=metadata,
        )

    def create_proof_item(
        self,
        proof_type: Union[ProofType, str],
        label: str,
        value: Any,
        *,
        source: Optional[str] = None,
        confidence: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ProofItem:
        """
        Create a normalized proof item.

        Example:
            bridge.create_proof_item(
                proof_type="api_response",
                label="Google Sheets save response",
                value={"status": 200, "row_id": 10},
                source="sheets_api"
            )
        """
        normalized_type = self._normalize_proof_type(proof_type)

        return ProofItem(
            proof_type=normalized_type,
            label=str(label).strip() or "proof_item",
            value=value,
            source=source,
            confidence=clamp_confidence(confidence) if confidence is not None else None,
            metadata=metadata or {},
        )

    def get_verification_status(
        self,
        verification_id: str,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Return local verification status.

        SaaS isolation:
            If user_id/workspace_id is provided, it must match the record.
        """
        clean_id = str(verification_id).strip()
        if not clean_id:
            return self._error_result(
                message="verification_id is required.",
                error="MISSING_VERIFICATION_ID",
            )

        record = self._records.get(clean_id)
        if not record:
            return self._error_result(
                message="Verification record not found.",
                error="VERIFICATION_NOT_FOUND",
                metadata={"verification_id": clean_id},
            )

        if user_id is not None and str(record.user_id) != str(user_id):
            return self._error_result(
                message="Verification record does not belong to this user.",
                error="USER_SCOPE_MISMATCH",
                metadata={"verification_id": clean_id},
            )

        if workspace_id is not None and str(record.workspace_id) != str(workspace_id):
            return self._error_result(
                message="Verification record does not belong to this workspace.",
                error="WORKSPACE_SCOPE_MISMATCH",
                metadata={"verification_id": clean_id},
            )

        return self._safe_result(
            message="Verification record found.",
            data={"verification": record.to_dict()},
            metadata={"verification_id": clean_id},
        )

    def list_local_records(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        List local in-memory verification records.

        This is useful for local testing before database-backed task history exists.
        """
        safe_limit = max(1, min(int(limit or 100), 500))

        records = list(self._records.values())

        if user_id is not None:
            records = [item for item in records if str(item.user_id) == str(user_id)]

        if workspace_id is not None:
            records = [item for item in records if str(item.workspace_id) == str(workspace_id)]

        records = sorted(records, key=lambda item: item.created_at, reverse=True)[:safe_limit]

        return self._safe_result(
            message="Local verification records loaded.",
            data={"records": [item.to_dict() for item in records]},
            metadata={"count": len(records), "limit": safe_limit},
        )

    def run(self, payload: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible run method.

        Expected payload:
            {
                "task_payload": {...},
                "completed_result": {...},
                "proof_items": [...],
                "verification_level": "standard",
                "metadata": {...}
            }
        """
        if not isinstance(payload, dict):
            return self._error_result(
                message="VerificationBridge.run payload must be a dictionary.",
                error="INVALID_RUN_PAYLOAD",
            )

        task_payload = payload.get("task_payload") or payload.get("task") or payload
        completed_result = payload.get("completed_result") or payload.get("result") or {}
        proof_items = payload.get("proof_items") or payload.get("proof") or []
        verification_level = payload.get("verification_level")
        metadata = payload.get("metadata") or {}

        return self.submit_for_verification(
            task_payload=task_payload,
            completed_result=completed_result,
            proof_items=proof_items,
            verification_level=verification_level,
            metadata=metadata,
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate user/workspace/task context.

        Required by the William/Jarvis prompt bible.

        This prevents cross-user and cross-workspace leakage before verification.
        """
        user_id = normalize_id(
            task_payload.get("user_id")
            or task_payload.get("context", {}).get("user_id")
            or task_payload.get("metadata", {}).get("user_id")
        )

        workspace_id = normalize_id(
            task_payload.get("workspace_id")
            or task_payload.get("context", {}).get("workspace_id")
            or task_payload.get("metadata", {}).get("workspace_id")
        )

        task_id = normalize_id(
            task_payload.get("task_id")
            or task_payload.get("id")
            or task_payload.get("metadata", {}).get("task_id")
        )

        if user_id is None:
            return self._error_result(
                message="user_id is required for verification.",
                error="MISSING_USER_ID",
                metadata={"scope": "verification_context"},
            )

        if workspace_id is None:
            return self._error_result(
                message="workspace_id is required for verification.",
                error="MISSING_WORKSPACE_ID",
                metadata={"scope": "verification_context"},
            )

        if task_id is None:
            return self._error_result(
                message="task_id is required for verification.",
                error="MISSING_TASK_ID",
                metadata={"scope": "verification_context"},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def _requires_security_check(self, task_payload: Dict[str, Any]) -> bool:
        """
        Decide whether this verification request must go through Security Agent.

        Required by the William/Jarvis prompt bible.
        """
        if not self.config.require_security_for_sensitive_actions:
            return False

        action_type = self._get_action_type(task_payload)
        if action_type in SENSITIVE_ACTION_TYPES:
            return True

        sensitivity = str(
            task_payload.get("sensitivity")
            or task_payload.get("risk_level")
            or task_payload.get("metadata", {}).get("sensitivity")
            or ""
        ).lower()

        if sensitivity in {"high", "critical", "sensitive", "restricted"}:
            return True

        permissions = task_payload.get("permissions") or {}
        if isinstance(permissions, dict):
            if permissions.get("requires_security") is True:
                return True

        flags = task_payload.get("flags") or []
        if isinstance(flags, list):
            normalized_flags = {str(flag).lower() for flag in flags}
            if "requires_security" in normalized_flags or "sensitive" in normalized_flags:
                return True

        return False

    def _request_security_approval(
        self,
        task_payload: Dict[str, Any],
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Required by the William/Jarvis prompt bible.

        This method never performs sensitive actions itself. It only asks the
        Security Agent whether verification may continue.
        """
        metadata = metadata or {}

        security_payload = {
            "request_id": str(uuid.uuid4()),
            "type": "verification_security_approval",
            "action": "verify_completed_task",
            "action_type": self._get_action_type(task_payload),
            "user_id": self._extract_user_id(task_payload),
            "workspace_id": self._extract_workspace_id(task_payload),
            "task_id": self._extract_task_id(task_payload),
            "task_summary": self._safe_task_summary(task_payload),
            "created_at": utc_now_iso(),
            "metadata": metadata,
        }

        if not self.security_agent:
            return self._error_result(
                message="Security approval required, but Security Agent is not configured.",
                error="SECURITY_AGENT_NOT_CONFIGURED",
                data={"security_payload": security_payload},
            )

        try:
            if hasattr(self.security_agent, "approve_action"):
                result = self.security_agent.approve_action(security_payload)  # type: ignore
            elif hasattr(self.security_agent, "check_permission"):
                result = self.security_agent.check_permission(security_payload)  # type: ignore
            elif hasattr(self.security_agent, "run"):
                result = self.security_agent.run(security_payload)  # type: ignore
            else:
                return self._error_result(
                    message="Security Agent does not expose an approval method.",
                    error="SECURITY_AGENT_METHOD_MISSING",
                    data={"security_payload": security_payload},
                )

            if not isinstance(result, dict):
                return self._error_result(
                    message="Security Agent returned invalid response.",
                    error="INVALID_SECURITY_RESPONSE",
                    data={"raw_response": str(result)},
                )

            approved = bool(
                result.get("success") is True
                or result.get("approved") is True
                or result.get("data", {}).get("approved") is True
            )

            if not approved:
                return self._error_result(
                    message=result.get("message") or "Security Agent did not approve verification.",
                    error=result.get("error") or "SECURITY_APPROVAL_DENIED",
                    data={"security_result": result},
                )

            return self._safe_result(
                message="Security Agent approved verification.",
                data={"security_result": result},
            )

        except Exception as exc:
            logger.exception("Security approval request failed.")

            return self._error_result(
                message="Security approval request failed.",
                error="SECURITY_APPROVAL_EXCEPTION",
                data={"exception": str(exc), "security_payload": security_payload},
            )

    def _prepare_verification_payload(
        self,
        task_payload: Dict[str, Any],
        completed_result: Dict[str, Any],
        proof_items: List[Union[ProofItem, Dict[str, Any]]],
        verification_level: Optional[Union[VerificationLevel, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by the William/Jarvis prompt bible.
        """
        metadata = metadata or {}

        user_id = self._extract_user_id(task_payload)
        workspace_id = self._extract_workspace_id(task_payload)
        task_id = self._extract_task_id(task_payload)
        action_type = self._get_action_type(task_payload)

        normalized_level = self._normalize_verification_level(verification_level)
        normalized_proofs = self._normalize_proof_items(proof_items)

        verification_id = str(uuid.uuid4())

        payload = {
            "verification_id": verification_id,
            "type": "task_verification_request",
            "source": "core.verification_bridge",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "action_type": action_type,
            "verification_level": normalized_level.value,
            "confidence_threshold": self.config.confidence_threshold,
            "timeout_seconds": self.config.timeout_seconds,
            "task": self._safe_task_summary(task_payload),
            "completed_result": completed_result,
            "proof_items": normalized_proofs,
            "proof_count": len(normalized_proofs),
            "requires_proof": action_type in PROOF_REQUIRED_ACTION_TYPES,
            "payload_hash": stable_hash(
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "action_type": action_type,
                    "completed_result": completed_result,
                    "proof_items": normalized_proofs,
                }
            ),
            "created_at": utc_now_iso(),
            "metadata": {
                **metadata,
                "bridge_name": self.name,
                "bridge_version": self.version,
            },
        }

        return payload

    def _prepare_memory_payload(
        self,
        task_payload: Dict[str, Any],
        verification_result: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Required by the William/Jarvis prompt bible.

        This does not save memory directly. It creates a clean payload that the
        Memory Agent can safely store under the same user_id/workspace_id.
        """
        metadata = metadata or {}

        verification_data = verification_result.get("data", {}).get("verification", {})

        return {
            "type": "verified_task_memory",
            "source": "core.verification_bridge",
            "user_id": self._extract_user_id(task_payload),
            "workspace_id": self._extract_workspace_id(task_payload),
            "task_id": self._extract_task_id(task_payload),
            "verification_id": verification_data.get("verification_id"),
            "status": verification_data.get("status"),
            "confidence": verification_data.get("confidence"),
            "action_type": self._get_action_type(task_payload),
            "summary": {
                "task": self._safe_task_summary(task_payload),
                "verification_message": verification_data.get("message"),
                "verified_at": verification_data.get("updated_at") or utc_now_iso(),
            },
            "metadata": {
                **metadata,
                "memory_safe": True,
                "scope": "user_workspace",
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for Dashboard/API, Agent Registry, Agent Router, or event bus.

        Required by the William/Jarvis prompt bible.
        """
        if not self.config.emit_events:
            return

        safe_payload = {
            "event": event_name,
            "source": "core.verification_bridge",
            "created_at": utc_now_iso(),
            "payload": payload,
        }

        try:
            if self.event_emitter and hasattr(self.event_emitter, "emit"):
                self.event_emitter.emit(event_name, safe_payload)
                return

            if self.registry and hasattr(self.registry, "emit"):
                self.registry.emit(event_name, safe_payload)
                return

            logger.info("VerificationBridge event emitted: %s | %s", event_name, safe_json_dumps(safe_payload))

        except Exception as exc:
            logger.warning("Failed to emit verification event %s: %s", event_name, exc)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Log audit event for compliance, dashboard, and task history.

        Required by the William/Jarvis prompt bible.
        """
        if not self.config.audit_enabled:
            return

        audit_payload = {
            "event": event_name,
            "source": "core.verification_bridge",
            "created_at": utc_now_iso(),
            "payload": payload,
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(event_name, audit_payload)
                return

            logger.info("VerificationBridge audit event: %s | %s", event_name, safe_json_dumps(audit_payload))

        except Exception as exc:
            logger.warning("Failed to log verification audit event %s: %s", event_name, exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard success result.

        Required by the William/Jarvis prompt bible.
        """
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.

        Required by the William/Jarvis prompt bible.
        """
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Internal verification methods
    # -------------------------------------------------------------------------

    def _send_to_verification_agent(self, verification_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send payload to Verification Agent if available.

        If Verification Agent is not available and fallback is enabled, a local
        verification result is created so the system remains testable.
        """
        if self.verification_agent:
            try:
                if hasattr(self.verification_agent, "verify_task"):
                    result = self.verification_agent.verify_task(verification_payload)  # type: ignore
                elif hasattr(self.verification_agent, "verify"):
                    result = self.verification_agent.verify(verification_payload)  # type: ignore
                elif hasattr(self.verification_agent, "run"):
                    result = self.verification_agent.run(verification_payload)  # type: ignore
                else:
                    return self._error_result(
                        message="Verification Agent does not expose verify_task, verify, or run.",
                        error="VERIFICATION_AGENT_METHOD_MISSING",
                    )

                if not isinstance(result, dict):
                    return self._error_result(
                        message="Verification Agent returned invalid response.",
                        error="INVALID_VERIFICATION_AGENT_RESPONSE",
                        data={"raw_response": str(result)},
                    )

                return result

            except Exception as exc:
                logger.exception("Verification Agent call failed.")

                return self._error_result(
                    message="Verification Agent call failed.",
                    error="VERIFICATION_AGENT_EXCEPTION",
                    data={"exception": str(exc)},
                )

        if self.config.allow_fallback_local_verification:
            return self._fallback_local_verification(verification_payload)

        return self._error_result(
            message="Verification Agent is not configured.",
            error="VERIFICATION_AGENT_NOT_CONFIGURED",
        )

    def _fallback_local_verification(self, verification_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback proof check used before Verification Agent exists.

        This does not pretend to be full Verification Agent intelligence. It only
        applies safe deterministic checks so development can continue.
        """
        proof_items = verification_payload.get("proof_items") or []
        completed_result = verification_payload.get("completed_result") or {}
        requires_proof = bool(verification_payload.get("requires_proof"))

        confidence = 0.0
        status = VerificationStatus.REQUIRES_REVIEW
        reasons: List[str] = []

        if isinstance(completed_result, dict) and completed_result:
            confidence += 0.25
            reasons.append("completed_result_present")
        else:
            reasons.append("completed_result_missing")

        if proof_items:
            confidence += min(0.50, len(proof_items) * 0.10)
            reasons.append("proof_items_present")
        else:
            reasons.append("proof_items_missing")

        if verification_payload.get("payload_hash"):
            confidence += 0.10
            reasons.append("payload_hash_present")

        if not requires_proof and completed_result:
            confidence += 0.20
            reasons.append("proof_not_required_for_action_type")

        confidence = clamp_confidence(confidence)

        if requires_proof and not proof_items:
            status = VerificationStatus.REQUIRES_REVIEW
            message = "Fallback verification requires review because proof items are missing."
        elif confidence >= self.config.confidence_threshold:
            status = VerificationStatus.VERIFIED
            message = "Fallback local verification passed deterministic proof checks."
        elif confidence >= 0.40:
            status = VerificationStatus.PARTIAL
            message = "Fallback local verification partially passed and requires review."
        else:
            status = VerificationStatus.FAILED
            message = "Fallback local verification failed due to insufficient evidence."

        return self._safe_result(
            message=message,
            data={
                "status": status.value,
                "confidence": confidence,
                "reasons": reasons,
                "fallback": True,
            },
            metadata={
                "verification_id": verification_payload.get("verification_id"),
                "agent_available": False,
            },
        )

    def _normalize_verification_result(
        self,
        verification_payload: Dict[str, Any],
        verification_result: Dict[str, Any],
        *,
        started_at: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize Verification Agent response into a VerificationRecord.
        """
        metadata = metadata or {}

        elapsed_ms = int((time.time() - started_at) * 1000)

        success = bool(verification_result.get("success"))
        result_data = verification_result.get("data") or {}

        status_raw = (
            result_data.get("status")
            or verification_result.get("status")
            or (VerificationStatus.VERIFIED.value if success else VerificationStatus.FAILED.value)
        )

        status = self._normalize_status(status_raw)

        confidence = clamp_confidence(
            result_data.get("confidence")
            or verification_result.get("confidence")
            or (1.0 if status == VerificationStatus.VERIFIED else 0.0)
        )

        message = (
            verification_result.get("message")
            or result_data.get("message")
            or f"Verification finished with status: {status.value}"
        )

        if status == VerificationStatus.VERIFIED and confidence < self.config.confidence_threshold:
            status = VerificationStatus.REQUIRES_REVIEW
            message = "Verification confidence is below required threshold."

        record = VerificationRecord(
            verification_id=verification_payload["verification_id"],
            task_id=verification_payload["task_id"],
            user_id=verification_payload["user_id"],
            workspace_id=verification_payload["workspace_id"],
            status=status,
            action_type=verification_payload["action_type"],
            confidence=confidence,
            message=message,
            payload_hash=verification_payload["payload_hash"],
            data={
                "verification_agent_result": verification_result,
                "proof_count": verification_payload.get("proof_count", 0),
                "verification_level": verification_payload.get("verification_level"),
                "fallback": bool(result_data.get("fallback")),
            },
            error=verification_result.get("error"),
            metadata={
                **metadata,
                "elapsed_ms": elapsed_ms,
                "confidence_threshold": self.config.confidence_threshold,
            },
        )

        self._records[record.verification_id] = record

        if status in {VerificationStatus.VERIFIED, VerificationStatus.PARTIAL}:
            return self._safe_result(
                message=record.message,
                data={"verification": record.to_dict()},
                metadata={"status": status.value, "elapsed_ms": elapsed_ms},
            )

        return self._error_result(
            message=record.message,
            error=record.error or f"VERIFICATION_{status.value.upper()}",
            data={"verification": record.to_dict()},
            metadata={"status": status.value, "elapsed_ms": elapsed_ms},
        )

    def _create_local_record(
        self,
        task_payload: Dict[str, Any],
        status: VerificationStatus,
        confidence: float,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VerificationRecord:
        """
        Create and store an in-memory verification record.
        """
        verification_id = str(uuid.uuid4())

        record = VerificationRecord(
            verification_id=verification_id,
            task_id=str(self._extract_task_id(task_payload)),
            user_id=self._extract_user_id(task_payload),
            workspace_id=self._extract_workspace_id(task_payload),
            status=status,
            action_type=self._get_action_type(task_payload),
            confidence=clamp_confidence(confidence),
            message=message,
            payload_hash=stable_hash(task_payload),
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

        self._records[verification_id] = record
        return record

    # -------------------------------------------------------------------------
    # Normalization helpers
    # -------------------------------------------------------------------------

    def _normalize_verification_level(
        self,
        level: Optional[Union[VerificationLevel, str]],
    ) -> VerificationLevel:
        if isinstance(level, VerificationLevel):
            return level

        if isinstance(level, str):
            clean = level.strip().lower()
            for item in VerificationLevel:
                if item.value == clean:
                    return item

        return self.config.default_level

    def _normalize_status(self, status: Any) -> VerificationStatus:
        clean = str(status or "").strip().lower()

        for item in VerificationStatus:
            if item.value == clean:
                return item

        return VerificationStatus.ERROR

    def _normalize_proof_type(self, proof_type: Union[ProofType, str]) -> ProofType:
        if isinstance(proof_type, ProofType):
            return proof_type

        clean = str(proof_type or "").strip().lower()
        for item in ProofType:
            if item.value == clean:
                return item

        return ProofType.JSON

    def _normalize_proof_items(
        self,
        proof_items: List[Union[ProofItem, Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Normalize proof items and enforce max proof limit.
        """
        normalized: List[Dict[str, Any]] = []

        for item in proof_items[: self.config.max_proof_items]:
            if isinstance(item, ProofItem):
                normalized.append(item.to_dict())
                continue

            if isinstance(item, dict):
                proof_type = self._normalize_proof_type(item.get("proof_type") or item.get("type") or "json")

                normalized.append(
                    ProofItem(
                        proof_type=proof_type,
                        label=str(item.get("label") or item.get("name") or "proof_item"),
                        value=item.get("value", item),
                        source=item.get("source"),
                        confidence=(
                            clamp_confidence(item.get("confidence"))
                            if item.get("confidence") is not None
                            else None
                        ),
                        metadata=item.get("metadata") or {},
                    ).to_dict()
                )
                continue

            normalized.append(
                ProofItem(
                    proof_type=ProofType.TEXT,
                    label="raw_proof_item",
                    value=str(item),
                ).to_dict()
            )

        return normalized

    # -------------------------------------------------------------------------
    # Extraction helpers
    # -------------------------------------------------------------------------

    def _extract_user_id(self, task_payload: Dict[str, Any]) -> Union[str, int]:
        value = normalize_id(
            task_payload.get("user_id")
            or task_payload.get("context", {}).get("user_id")
            or task_payload.get("metadata", {}).get("user_id")
        )
        return value if value is not None else "unknown_user"

    def _extract_workspace_id(self, task_payload: Dict[str, Any]) -> Union[str, int]:
        value = normalize_id(
            task_payload.get("workspace_id")
            or task_payload.get("context", {}).get("workspace_id")
            or task_payload.get("metadata", {}).get("workspace_id")
        )
        return value if value is not None else "unknown_workspace"

    def _extract_task_id(self, task_payload: Dict[str, Any]) -> Union[str, int]:
        value = normalize_id(
            task_payload.get("task_id")
            or task_payload.get("id")
            or task_payload.get("metadata", {}).get("task_id")
        )
        return value if value is not None else f"task_{uuid.uuid4()}"

    def _get_action_type(self, task_payload: Dict[str, Any]) -> str:
        action_type = (
            task_payload.get("action_type")
            or task_payload.get("type")
            or task_payload.get("task_type")
            or task_payload.get("metadata", {}).get("action_type")
            or "generic_task"
        )

        return str(action_type).strip().lower() or "generic_task"

    def _safe_task_summary(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a safe task summary for verification/audit/memory.

        Avoids blindly copying huge payloads or secrets into logs.
        """
        secret_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "authorization",
            "access_token",
            "refresh_token",
            "credential",
            "private_key",
        }

        allowed_keys = {
            "task_id",
            "id",
            "title",
            "name",
            "description",
            "goal",
            "type",
            "task_type",
            "action_type",
            "agent",
            "agent_name",
            "status",
            "user_id",
            "workspace_id",
            "created_at",
            "updated_at",
        }

        summary: Dict[str, Any] = {}

        for key, value in task_payload.items():
            lower_key = str(key).lower()

            if lower_key in secret_keys or any(secret in lower_key for secret in secret_keys):
                summary[key] = "[REDACTED]"
                continue

            if key in allowed_keys:
                summary[key] = value
                continue

            if key == "metadata" and isinstance(value, dict):
                summary["metadata"] = {
                    meta_key: (
                        "[REDACTED]"
                        if str(meta_key).lower() in secret_keys
                        or any(secret in str(meta_key).lower() for secret in secret_keys)
                        else meta_value
                    )
                    for meta_key, meta_value in value.items()
                    if meta_key in {"source", "priority", "action_type", "task_id", "user_id", "workspace_id"}
                }

        if "task_id" not in summary:
            summary["task_id"] = self._extract_task_id(task_payload)

        if "user_id" not in summary:
            summary["user_id"] = self._extract_user_id(task_payload)

        if "workspace_id" not in summary:
            summary["workspace_id"] = self._extract_workspace_id(task_payload)

        if "action_type" not in summary:
            summary["action_type"] = self._get_action_type(task_payload)

        return summary

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    def _load_config(self) -> VerificationConfig:
        """
        Load bridge config from core.config.settings when available.

        Falls back to safe defaults.
        """
        config = VerificationConfig()

        if settings is None:
            return config

        try:
            enabled = getattr(settings, "VERIFICATION_BRIDGE_ENABLED", None)
            if enabled is not None:
                config.enabled = bool(enabled)

            threshold = getattr(settings, "VERIFICATION_CONFIDENCE_THRESHOLD", None)
            if threshold is not None:
                config.confidence_threshold = clamp_confidence(threshold)

            timeout = getattr(settings, "VERIFICATION_TIMEOUT_SECONDS", None)
            if timeout is not None:
                config.timeout_seconds = int(timeout)

            security_required = getattr(settings, "VERIFICATION_REQUIRE_SECURITY", None)
            if security_required is not None:
                config.require_security_for_sensitive_actions = bool(security_required)

            fallback = getattr(settings, "VERIFICATION_ALLOW_FALLBACK", None)
            if fallback is not None:
                config.allow_fallback_local_verification = bool(fallback)

            emit_events = getattr(settings, "VERIFICATION_EMIT_EVENTS", None)
            if emit_events is not None:
                config.emit_events = bool(emit_events)

            audit_enabled = getattr(settings, "VERIFICATION_AUDIT_ENABLED", None)
            if audit_enabled is not None:
                config.audit_enabled = bool(audit_enabled)

        except Exception as exc:
            logger.warning("Failed to load VerificationBridge settings. Using defaults. Error: %s", exc)

        return config


# =============================================================================
# Factory helpers
# =============================================================================

def create_verification_bridge(
    verification_agent: Optional[VerificationAgentProtocol] = None,
    security_agent: Optional[SecurityAgentProtocol] = None,
    event_emitter: Optional[EventEmitterProtocol] = None,
    audit_logger: Optional[AuditLoggerProtocol] = None,
    config: Optional[VerificationConfig] = None,
    memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    registry: Optional[Any] = None,
) -> VerificationBridge:
    """
    Factory helper for Agent Loader / Registry / FastAPI dependency injection.
    """
    return VerificationBridge(
        verification_agent=verification_agent,
        security_agent=security_agent,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
        config=config,
        memory_callback=memory_callback,
        registry=registry,
    )


def get_module_info() -> Dict[str, Any]:
    """
    Registry-compatible module metadata.
    """
    return {
        "module": "core",
        "file": "verification_bridge.py",
        "class": "VerificationBridge",
        "name": VerificationBridge.name,
        "version": VerificationBridge.version,
        "description": VerificationBridge.description,
        "safe_to_import": True,
        "requires": [],
        "optional_integrations": [
            "VerificationAgent",
            "SecurityAgent",
            "MemoryAgent",
            "AgentRegistry",
            "DashboardAPI",
            "AuditLogger",
            "EventEmitter",
        ],
        "public_methods": [
            "submit_for_verification",
            "verify_completed_task",
            "create_proof_item",
            "get_verification_status",
            "list_local_records",
            "run",
        ],
    }


# =============================================================================
# Self-test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    bridge = VerificationBridge()

    sample_task = {
        "task_id": "task_demo_001",
        "user_id": "user_1",
        "workspace_id": "workspace_1",
        "action_type": "code_execution",
        "title": "Generate response builder file",
        "status": "completed",
        "metadata": {
            "source": "local_self_test",
            "priority": "normal",
        },
    }

    sample_result = {
        "success": True,
        "message": "File generated successfully.",
        "file_path": "core/response_builder.py",
    }

    sample_proof = [
        {
            "proof_type": "file_hash",
            "label": "Generated file hash",
            "value": stable_hash(sample_result),
            "source": "local_self_test",
            "confidence": 0.95,
        },
        {
            "proof_type": "log",
            "label": "Completion log",
            "value": "FILE COMPLETE",
            "source": "local_self_test",
            "confidence": 0.90,
        },
    ]

    output = bridge.submit_for_verification(
        task_payload=sample_task,
        completed_result=sample_result,
        proof_items=sample_proof,
        verification_level="standard",
    )

    print(json.dumps(output, indent=2, default=str))