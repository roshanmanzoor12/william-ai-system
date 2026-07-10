"""
agents/workflow_agent/approval_gate.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Blocks sensitive workflow steps until Security Agent/user approval.

This module is part of the Workflow Agent. It is designed to sit between
workflow planning/routing and actual execution. Any workflow step that may be
sensitive, destructive, external-facing, financial, messaging-related, browser-
automation-related, or privileged can be paused here until the Security Agent
and/or a human user grants approval.

Architecture connections:
    - Master Agent / Agent Router:
        Can call ApprovalGate.evaluate_step(...) or enforce_before_execution(...)
        before routing a workflow step to any connector/agent.

    - Security Agent:
        Sensitive steps are routed through _request_security_approval(...).
        This file is import-safe even if the real Security Agent is not present.

    - Memory Agent:
        Approval decisions can be converted into safe memory-compatible payloads
        using _prepare_memory_payload(...). This file does not persist memory
        directly; it prepares structured payloads.

    - Verification Agent:
        Completed approval decisions prepare a verification payload via
        _prepare_verification_payload(...).

    - Dashboard / FastAPI:
        Public methods return structured JSON/dict style responses suitable for
        dashboard/API use:
            {
                "success": bool,
                "message": str,
                "data": dict,
                "error": Optional[str],
                "metadata": dict
            }

Safety:
    - Never executes the underlying workflow action.
    - Blocks sensitive actions unless explicit approval requirements are met.
    - Enforces user/workspace isolation on all approval lookups and mutations.
    - Uses safe defaults and fallback stubs for missing future modules.
"""

from __future__ import annotations

import hashlib
import inspect
import logging
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports / fallback compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for incomplete future project

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent so this file remains import-safe before the
        full William/Jarvis codebase is available.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", getattr(self, "agent_name", self.__class__.__name__))
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() called. No runtime implementation is attached.",
                "data": {},
                "error": "BASE_AGENT_FALLBACK",
                "metadata": {},
            }


try:
    from agents.workflow_agent.config import APPROVAL_GATE_DEFAULTS  # type: ignore
except Exception:  # pragma: no cover - config.py is the next planned file
    APPROVAL_GATE_DEFAULTS: Dict[str, Any] = {
        "default_ttl_seconds": 86400,
        "require_user_approval_for_high_risk": True,
        "require_security_approval_for_sensitive": True,
        "auto_approve_low_risk": True,
        "max_reason_length": 2000,
        "max_pending_requests_per_scope": 500,
    }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.workflow_agent.approval_gate")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums / data structures
# ---------------------------------------------------------------------------

class ApprovalStatus(str, Enum):
    """Approval request lifecycle states."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalDecision(str, Enum):
    """Decision values used by users/security systems."""

    APPROVE = "approve"
    REJECT = "reject"
    CANCEL = "cancel"


class ApprovalRiskLevel(str, Enum):
    """Risk classification for workflow steps."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalActorType(str, Enum):
    """Who/what made an approval decision."""

    USER = "user"
    SECURITY_AGENT = "security_agent"
    MASTER_AGENT = "master_agent"
    WORKFLOW_AGENT = "workflow_agent"
    SYSTEM = "system"


class ApprovalRequirement(str, Enum):
    """Approval requirement names."""

    NONE = "none"
    USER = "user"
    SECURITY = "security"
    USER_AND_SECURITY = "user_and_security"


@dataclass(frozen=True)
class ApprovalScope:
    """
    SaaS isolation boundary.

    All approval requests are keyed by user_id + workspace_id. Any read/write
    operation must match the original scope.
    """

    user_id: str
    workspace_id: str

    def key(self) -> str:
        return f"{self.user_id}:{self.workspace_id}"


@dataclass
class ApprovalPolicy:
    """
    Policy used by ApprovalGate to classify and block workflow actions.

    This is intentionally local/configurable so the future config.py can provide
    project-wide settings without making this file fragile.
    """

    sensitive_action_types: Tuple[str, ...] = (
        "send_email",
        "email_send",
        "email_reply",
        "send_whatsapp",
        "whatsapp_send",
        "send_sms",
        "sms_send",
        "send_slack",
        "send_discord",
        "send_notification",
        "outbound_call",
        "make_call",
        "browser_action",
        "browser_click",
        "browser_submit",
        "file_delete",
        "delete_file",
        "delete_record",
        "crm_delete",
        "crm_update",
        "sheet_write",
        "sheet_update",
        "sheet_delete",
        "payment",
        "refund",
        "invoice",
        "subscription_change",
        "webhook_send",
        "api_write",
        "system_command",
        "code_execute",
        "deploy",
        "credential_update",
        "permission_change",
        "role_change",
        "memory_write",
        "external_post",
        "social_post",
        "ad_launch",
        "ad_budget_change",
    )
    destructive_keywords: Tuple[str, ...] = (
        "delete",
        "remove",
        "destroy",
        "drop",
        "truncate",
        "wipe",
        "purge",
        "archive",
        "cancel",
        "disable",
        "ban",
        "revoke",
        "refund",
        "charge",
        "transfer",
        "deploy",
        "execute",
        "run_command",
        "shell",
    )
    external_communication_keywords: Tuple[str, ...] = (
        "send",
        "reply",
        "forward",
        "message",
        "email",
        "whatsapp",
        "sms",
        "call",
        "slack",
        "discord",
        "notify",
        "publish",
        "post",
        "comment",
    )
    high_risk_action_types: Tuple[str, ...] = (
        "payment",
        "refund",
        "subscription_change",
        "system_command",
        "code_execute",
        "deploy",
        "credential_update",
        "permission_change",
        "role_change",
        "file_delete",
        "delete_record",
        "crm_delete",
        "ad_budget_change",
    )
    critical_action_types: Tuple[str, ...] = (
        "system_command",
        "code_execute",
        "deploy",
        "credential_update",
        "permission_change",
        "role_change",
        "payment",
        "refund",
    )
    default_ttl_seconds: int = 86400
    auto_approve_low_risk: bool = True
    require_security_approval_for_sensitive: bool = True
    require_user_approval_for_high_risk: bool = True
    max_reason_length: int = 2000
    max_pending_requests_per_scope: int = 500


@dataclass
class ApprovalRecord:
    """
    Stored approval request.

    This in-memory implementation is suitable for local testing and import-safe
    operation. Production deployments can wrap/replace persistence through
    export_record/import_record or by composing this class behind a repository.
    """

    approval_id: str
    user_id: str
    workspace_id: str
    workflow_id: str
    step_id: str
    action_type: str
    risk_level: str
    requirement: str
    status: str
    reason: str
    step_summary: Dict[str, Any]
    requested_by: str
    created_at: str
    updated_at: str
    expires_at: str
    security_approved: bool = False
    user_approved: bool = False
    security_decision_by: Optional[str] = None
    user_decision_by: Optional[str] = None
    security_decision_reason: Optional[str] = None
    user_decision_reason: Optional[str] = None
    decision_history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def scope(self) -> ApprovalScope:
        return ApprovalScope(user_id=self.user_id, workspace_id=self.workspace_id)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat()


def _safe_string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _normalize_action_type(value: Any) -> str:
    raw = _safe_string(value, "unknown")
    raw = raw.lower().strip()
    raw = re.sub(r"[^a-z0-9_\-:.]+", "_", raw)
    return raw or "unknown"


def _hash_payload(payload: Mapping[str, Any]) -> str:
    """
    Create a stable short hash for metadata/audit correlation without storing
    secrets in logs.
    """

    safe_repr = repr(sorted((str(k), str(v)[:200]) for k, v in payload.items()))
    return hashlib.sha256(safe_repr.encode("utf-8")).hexdigest()[:24]


def _redact_sensitive_value(key: str, value: Any) -> Any:
    lowered = key.lower()
    sensitive_markers = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "private_key",
        "access_key",
        "refresh",
        "otp",
    )
    if any(marker in lowered for marker in sensitive_markers):
        return "***REDACTED***"
    if isinstance(value, Mapping):
        return {str(k): _redact_sensitive_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_sensitive_value(key, item) for item in value]
    return value


def _redact_payload(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        return {str(k): _redact_sensitive_value(str(k), v) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_redact_payload(item) for item in payload]
    return payload


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "approved", "allow", "allowed"}
    return bool(value)


def _call_maybe_sync(callback: Callable[..., Any], **kwargs: Any) -> Any:
    """
    Safely call a callback while tolerating different signatures.

    This supports early-stage project modules where Security Agent methods may
    not yet have the final exact signature.
    """

    signature = inspect.signature(callback)
    accepted_kwargs: Dict[str, Any] = {}
    has_var_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values())
    if has_var_kwargs:
        accepted_kwargs = kwargs
    else:
        for name in signature.parameters:
            if name in kwargs:
                accepted_kwargs[name] = kwargs[name]
    return callback(**accepted_kwargs)


# ---------------------------------------------------------------------------
# Approval Gate
# ---------------------------------------------------------------------------

class ApprovalGate(BaseAgent):
    """
    Blocks sensitive workflow steps until approval is granted.

    Main public methods:
        - evaluate_step(...)
        - enforce_before_execution(...)
        - request_approval(...)
        - approve_request(...)
        - reject_request(...)
        - cancel_request(...)
        - get_request(...)
        - list_pending(...)
        - cleanup_expired(...)

    The gate does not execute any workflow step. It only decides whether the
    caller may proceed.
    """

    agent_name = "workflow_approval_gate"
    registry_name = "ApprovalGate"
    module_name = "workflow_agent"
    compatible_agents = (
        "MasterAgent",
        "WorkflowAgent",
        "SecurityAgent",
        "VerificationAgent",
        "MemoryAgent",
    )

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        audit_logger: Optional[Callable[..., Any]] = None,
        policy: Optional[ApprovalPolicy] = None,
        config: Optional[Mapping[str, Any]] = None,
        agent_name: Optional[str] = None,
    ) -> None:
        super().__init__(agent_name=agent_name or self.agent_name)

        merged_config = dict(APPROVAL_GATE_DEFAULTS)
        if config:
            merged_config.update(dict(config))

        self.policy = policy or ApprovalPolicy(
            default_ttl_seconds=int(merged_config.get("default_ttl_seconds", 86400)),
            auto_approve_low_risk=bool(merged_config.get("auto_approve_low_risk", True)),
            require_security_approval_for_sensitive=bool(
                merged_config.get("require_security_approval_for_sensitive", True)
            ),
            require_user_approval_for_high_risk=bool(
                merged_config.get("require_user_approval_for_high_risk", True)
            ),
            max_reason_length=int(merged_config.get("max_reason_length", 2000)),
            max_pending_requests_per_scope=int(merged_config.get("max_pending_requests_per_scope", 500)),
        )

        self.security_agent = security_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self._records: Dict[str, ApprovalRecord] = {}
        self._lock = threading.RLock()
        self.logger = logging.getLogger("william.workflow_agent.approval_gate")

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        error_payload: Union[str, Dict[str, Any], None]
        if isinstance(error, Exception):
            error_payload = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error or message

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error_payload,
            metadata=metadata or {},
        )

    def _validate_task_context(
        self,
        task_context: Mapping[str, Any],
        require_workflow_step: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS context and required workflow identifiers.

        Required:
            - user_id
            - workspace_id

        Usually required for workflow steps:
            - workflow_id
            - step_id
        """

        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task_context. Expected a mapping/dict.",
                error="INVALID_TASK_CONTEXT",
            )

        user_id = _safe_string(task_context.get("user_id"))
        workspace_id = _safe_string(task_context.get("workspace_id"))

        missing: List[str] = []
        if not user_id:
            missing.append("user_id")
        if not workspace_id:
            missing.append("workspace_id")

        if require_workflow_step:
            if not _safe_string(task_context.get("workflow_id")):
                missing.append("workflow_id")
            if not _safe_string(task_context.get("step_id")):
                missing.append("step_id")

        if missing:
            return self._error_result(
                message=f"Missing required context fields: {', '.join(missing)}",
                error="MISSING_CONTEXT",
                metadata={"missing_fields": missing},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "workflow_id": _safe_string(task_context.get("workflow_id"), "unknown_workflow"),
                "step_id": _safe_string(task_context.get("step_id"), "unknown_step"),
            },
            metadata={"scope_key": f"{user_id}:{workspace_id}"},
        )

    def _requires_security_check(
        self,
        workflow_step: Mapping[str, Any],
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Determine whether a step is sensitive and requires approval.

        This method is intentionally conservative. If the action appears to
        involve messaging, external writes, destructive operations, financial
        changes, system execution, credentials, permissions, or browser actions,
        it requires approval.
        """

        try:
            action_type = self._extract_action_type(workflow_step)
            payload = workflow_step.get("payload", {}) if isinstance(workflow_step, Mapping) else {}
            text_blob = self._step_text_blob(workflow_step)
            risk_level = self._classify_risk(action_type=action_type, workflow_step=workflow_step)

            is_sensitive_type = action_type in self.policy.sensitive_action_types
            has_destructive_keyword = any(keyword in text_blob for keyword in self.policy.destructive_keywords)
            has_external_keyword = any(keyword in text_blob for keyword in self.policy.external_communication_keywords)
            explicit_sensitive = _coerce_bool(workflow_step.get("sensitive"), False)
            explicit_requires_approval = _coerce_bool(workflow_step.get("requires_approval"), False)
            payload_hash = _hash_payload(payload) if isinstance(payload, Mapping) else hashlib.sha256(str(payload).encode()).hexdigest()[:24]

            requires_security = (
                self.policy.require_security_approval_for_sensitive
                and (
                    explicit_sensitive
                    or explicit_requires_approval
                    or is_sensitive_type
                    or has_destructive_keyword
                    or action_type in self.policy.high_risk_action_types
                    or action_type in self.policy.critical_action_types
                )
            )

            requires_user = (
                explicit_requires_approval
                or (
                    self.policy.require_user_approval_for_high_risk
                    and risk_level in {ApprovalRiskLevel.HIGH.value, ApprovalRiskLevel.CRITICAL.value}
                )
                or (
                    has_external_keyword
                    and action_type in self.policy.sensitive_action_types
                    and risk_level != ApprovalRiskLevel.LOW.value
                )
            )

            if requires_security and requires_user:
                requirement = ApprovalRequirement.USER_AND_SECURITY.value
            elif requires_security:
                requirement = ApprovalRequirement.SECURITY.value
            elif requires_user:
                requirement = ApprovalRequirement.USER.value
            else:
                requirement = ApprovalRequirement.NONE.value

            required = requirement != ApprovalRequirement.NONE.value

            return self._safe_result(
                success=True,
                message="Security check requirement evaluated.",
                data={
                    "required": required,
                    "requires_security": requires_security,
                    "requires_user": requires_user,
                    "requirement": requirement,
                    "risk_level": risk_level,
                    "action_type": action_type,
                    "reasons": {
                        "is_sensitive_type": is_sensitive_type,
                        "has_destructive_keyword": has_destructive_keyword,
                        "has_external_keyword": has_external_keyword,
                        "explicit_sensitive": explicit_sensitive,
                        "explicit_requires_approval": explicit_requires_approval,
                    },
                },
                metadata={
                    "payload_hash": payload_hash,
                    "context_scope": self._scope_key_from_context(task_context or {}),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to evaluate security check requirement.")
            return self._error_result(
                message="Failed to evaluate security requirement.",
                error=exc,
            )

    def _request_security_approval(
        self,
        approval_record: ApprovalRecord,
        workflow_step: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Ask the Security Agent for approval.

        If no Security Agent is attached, the request remains pending unless the
        requirement does not include security approval.

        Supported Security Agent method names:
            - approve_workflow_step
            - request_approval
            - evaluate_action
            - run
        """

        if approval_record.requirement not in {
            ApprovalRequirement.SECURITY.value,
            ApprovalRequirement.USER_AND_SECURITY.value,
        }:
            return self._safe_result(
                message="Security approval is not required for this request.",
                data={"security_required": False, "security_approved": True},
            )

        if self.security_agent is None:
            return self._safe_result(
                success=True,
                message="Security approval is required and no Security Agent is attached. Request remains pending.",
                data={
                    "security_required": True,
                    "security_approved": False,
                    "status": approval_record.status,
                },
                metadata={"approval_id": approval_record.approval_id},
            )

        security_payload = {
            "approval_id": approval_record.approval_id,
            "user_id": approval_record.user_id,
            "workspace_id": approval_record.workspace_id,
            "workflow_id": approval_record.workflow_id,
            "step_id": approval_record.step_id,
            "action_type": approval_record.action_type,
            "risk_level": approval_record.risk_level,
            "reason": approval_record.reason,
            "workflow_step": _redact_payload(dict(workflow_step)),
            "task_context": _redact_payload(dict(task_context)),
        }

        method_names = (
            "approve_workflow_step",
            "request_approval",
            "evaluate_action",
            "run",
        )

        try:
            response: Any = None
            called_method: Optional[str] = None

            for method_name in method_names:
                candidate = getattr(self.security_agent, method_name, None)
                if callable(candidate):
                    response = _call_maybe_sync(
                        candidate,
                        approval_payload=security_payload,
                        payload=security_payload,
                        workflow_step=workflow_step,
                        task_context=task_context,
                        action_type=approval_record.action_type,
                        user_id=approval_record.user_id,
                        workspace_id=approval_record.workspace_id,
                    )
                    called_method = method_name
                    break

            if called_method is None:
                return self._safe_result(
                    success=True,
                    message="Attached Security Agent has no compatible approval method. Request remains pending.",
                    data={
                        "security_required": True,
                        "security_approved": False,
                        "status": approval_record.status,
                    },
                    metadata={"approval_id": approval_record.approval_id},
                )

            security_approved, security_reason = self._parse_security_response(response)

            if security_approved:
                return self.approve_request(
                    approval_id=approval_record.approval_id,
                    task_context=task_context,
                    actor_id="security_agent",
                    actor_type=ApprovalActorType.SECURITY_AGENT.value,
                    reason=security_reason or "Security Agent approved workflow step.",
                    security_decision=True,
                    user_decision=False,
                )

            if security_approved is False and self._is_explicit_rejection(response):
                return self.reject_request(
                    approval_id=approval_record.approval_id,
                    task_context=task_context,
                    actor_id="security_agent",
                    actor_type=ApprovalActorType.SECURITY_AGENT.value,
                    reason=security_reason or "Security Agent rejected workflow step.",
                    security_decision=True,
                    user_decision=False,
                )

            return self._safe_result(
                success=True,
                message="Security Agent did not issue a final approval. Request remains pending.",
                data={
                    "security_required": True,
                    "security_approved": False,
                    "status": ApprovalStatus.PENDING.value,
                    "security_response": self._safe_response_summary(response),
                },
                metadata={
                    "approval_id": approval_record.approval_id,
                    "security_method": called_method,
                },
            )
        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            self._log_audit_event(
                event_type="approval.security_error",
                task_context=task_context,
                payload={
                    "approval_id": approval_record.approval_id,
                    "error": str(exc),
                },
            )
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                metadata={"approval_id": approval_record.approval_id},
            )

    def _prepare_verification_payload(
        self,
        approval_record: ApprovalRecord,
        decision: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload after approval lifecycle
        changes. This does not call Verification Agent directly.
        """

        return {
            "verification_type": "workflow_approval_decision",
            "agent": self.agent_name,
            "user_id": approval_record.user_id,
            "workspace_id": approval_record.workspace_id,
            "workflow_id": approval_record.workflow_id,
            "step_id": approval_record.step_id,
            "approval_id": approval_record.approval_id,
            "status": approval_record.status,
            "decision": decision or approval_record.status,
            "risk_level": approval_record.risk_level,
            "requirement": approval_record.requirement,
            "security_approved": approval_record.security_approved,
            "user_approved": approval_record.user_approved,
            "created_at": approval_record.created_at,
            "updated_at": approval_record.updated_at,
            "expires_at": approval_record.expires_at,
            "evidence": {
                "action_type": approval_record.action_type,
                "reason": approval_record.reason,
                "decision_history_count": len(approval_record.decision_history),
                "step_summary": approval_record.step_summary,
            },
            "metadata": {
                "module": self.module_name,
                "registry_name": self.registry_name,
                "safe_to_execute": approval_record.status == ApprovalStatus.APPROVED.value,
            },
        }

    def _prepare_memory_payload(
        self,
        approval_record: ApprovalRecord,
        decision: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible context.

        This payload avoids secrets and raw message content. It focuses on useful
        operational memory such as approval preference, reason, action type, and
        workflow context.
        """

        return {
            "memory_type": "workflow_approval_context",
            "user_id": approval_record.user_id,
            "workspace_id": approval_record.workspace_id,
            "source_agent": self.agent_name,
            "content": {
                "workflow_id": approval_record.workflow_id,
                "step_id": approval_record.step_id,
                "approval_id": approval_record.approval_id,
                "action_type": approval_record.action_type,
                "risk_level": approval_record.risk_level,
                "requirement": approval_record.requirement,
                "status": approval_record.status,
                "decision": decision or approval_record.status,
                "reason": approval_record.reason,
                "security_approved": approval_record.security_approved,
                "user_approved": approval_record.user_approved,
            },
            "tags": [
                "workflow",
                "approval",
                approval_record.status,
                approval_record.risk_level,
                approval_record.action_type,
            ],
            "created_at": _utc_iso(),
            "metadata": {
                "safe_for_long_term_memory": approval_record.status in {
                    ApprovalStatus.APPROVED.value,
                    ApprovalStatus.REJECTED.value,
                },
                "contains_secret": False,
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        task_context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an event for dashboard/API/agent monitoring.

        If no event emitter is attached, this safely logs and returns success.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "module": self.module_name,
            "timestamp": _utc_iso(),
            "context": _redact_payload(dict(task_context or {})),
            "payload": _redact_payload(dict(payload or {})),
        }

        try:
            if callable(self.event_emitter):
                _call_maybe_sync(self.event_emitter, event=event, event_type=event_type, payload=event)
            else:
                self.logger.debug("Agent event emitted locally: %s", event)
            return self._safe_result(
                message="Agent event emitted.",
                data={"event": event},
            )
        except Exception as exc:
            self.logger.exception("Failed to emit agent event.")
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
                data={"event": event},
            )

    def _log_audit_event(
        self,
        event_type: str,
        task_context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log an audit event with strict user/workspace context.

        Production can pass an audit_logger callback. Without one, this logs to
        Python logging only.
        """

        context = dict(task_context or {})
        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "module": self.module_name,
            "timestamp": _utc_iso(),
            "user_id": _safe_string(context.get("user_id")),
            "workspace_id": _safe_string(context.get("workspace_id")),
            "workflow_id": _safe_string(context.get("workflow_id")),
            "step_id": _safe_string(context.get("step_id")),
            "payload": _redact_payload(dict(payload or {})),
        }

        try:
            if callable(self.audit_logger):
                _call_maybe_sync(self.audit_logger, event=audit_event, event_type=event_type, payload=audit_event)
            else:
                self.logger.info("Audit event: %s", audit_event)
            return self._safe_result(
                message="Audit event logged.",
                data={"audit_event": audit_event},
            )
        except Exception as exc:
            self.logger.exception("Failed to log audit event.")
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
                data={"audit_event": audit_event},
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_step(
        self,
        workflow_step: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluate whether a workflow step can proceed.

        Returns:
            - allowed=True when no approval is required.
            - allowed=False and status=pending when approval must be requested.
        """

        validation = self._validate_task_context(task_context, require_workflow_step=True)
        if not validation["success"]:
            return validation

        if not isinstance(workflow_step, Mapping):
            return self._error_result(
                message="Invalid workflow_step. Expected a mapping/dict.",
                error="INVALID_WORKFLOW_STEP",
            )

        requirement_result = self._requires_security_check(workflow_step, task_context)
        if not requirement_result["success"]:
            return requirement_result

        requirement_data = requirement_result["data"]
        if not requirement_data.get("required"):
            self._emit_agent_event(
                event_type="approval.not_required",
                task_context=task_context,
                payload={
                    "action_type": requirement_data.get("action_type"),
                    "risk_level": requirement_data.get("risk_level"),
                },
            )
            return self._safe_result(
                success=True,
                message="Approval is not required. Workflow step may proceed.",
                data={
                    "allowed": True,
                    "status": ApprovalStatus.NOT_REQUIRED.value,
                    "approval_required": False,
                    "approval_id": None,
                    "action_type": requirement_data.get("action_type"),
                    "risk_level": requirement_data.get("risk_level"),
                    "requirement": ApprovalRequirement.NONE.value,
                },
                metadata=requirement_result.get("metadata", {}),
            )

        existing = self.find_existing_pending_request(
            user_id=validation["data"]["user_id"],
            workspace_id=validation["data"]["workspace_id"],
            workflow_id=validation["data"]["workflow_id"],
            step_id=validation["data"]["step_id"],
        )

        if existing["success"] and existing["data"].get("approval_record"):
            record = existing["data"]["approval_record"]
            return self._safe_result(
                success=True,
                message="Approval is required and an existing pending request was found.",
                data={
                    "allowed": False,
                    "approval_required": True,
                    "status": record["status"],
                    "approval_id": record["approval_id"],
                    "action_type": record["action_type"],
                    "risk_level": record["risk_level"],
                    "requirement": record["requirement"],
                },
                metadata={"existing_request": True},
            )

        return self._safe_result(
            success=True,
            message="Approval is required before this workflow step may proceed.",
            data={
                "allowed": False,
                "approval_required": True,
                "approval_id": None,
                "action_type": requirement_data.get("action_type"),
                "risk_level": requirement_data.get("risk_level"),
                "requirement": requirement_data.get("requirement"),
                "reasons": requirement_data.get("reasons", {}),
            },
            metadata=requirement_result.get("metadata", {}),
        )

    def enforce_before_execution(
        self,
        workflow_step: Mapping[str, Any],
        task_context: Mapping[str, Any],
        auto_create_request: bool = True,
        requested_by: str = "workflow_agent",
    ) -> Dict[str, Any]:
        """
        One-call enforcement helper.

        Use this immediately before ActionRouter/WorkflowAgent executes a step.
        It returns allowed=True only when execution is safe.
        """

        evaluation = self.evaluate_step(workflow_step=workflow_step, task_context=task_context)
        if not evaluation["success"]:
            return evaluation

        if evaluation["data"].get("allowed") is True:
            return evaluation

        if not auto_create_request:
            return evaluation

        request_result = self.request_approval(
            workflow_step=workflow_step,
            task_context=task_context,
            requested_by=requested_by,
        )

        if not request_result["success"]:
            return request_result

        data = request_result["data"]
        status = data.get("status")

        return self._safe_result(
            success=True,
            message=(
                "Workflow step is blocked until approval is completed."
                if status != ApprovalStatus.APPROVED.value
                else "Workflow step approval completed. Step may proceed."
            ),
            data={
                "allowed": status == ApprovalStatus.APPROVED.value,
                "approval_required": True,
                "approval_id": data.get("approval_id"),
                "status": status,
                "requirement": data.get("requirement"),
                "risk_level": data.get("risk_level"),
                "action_type": data.get("action_type"),
                "verification_payload": data.get("verification_payload"),
                "memory_payload": data.get("memory_payload"),
            },
            metadata=request_result.get("metadata", {}),
        )

    def request_approval(
        self,
        workflow_step: Mapping[str, Any],
        task_context: Mapping[str, Any],
        requested_by: str = "workflow_agent",
        ttl_seconds: Optional[int] = None,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create an approval request for a sensitive workflow step.

        This method may also ask the Security Agent immediately if security
        approval is required. If Security Agent approves but user approval is
        also required, the request remains pending until user approval.
        """

        validation = self._validate_task_context(task_context, require_workflow_step=True)
        if not validation["success"]:
            return validation

        if not isinstance(workflow_step, Mapping):
            return self._error_result(
                message="Invalid workflow_step. Expected a mapping/dict.",
                error="INVALID_WORKFLOW_STEP",
            )

        requirement = self._requires_security_check(workflow_step, task_context)
        if not requirement["success"]:
            return requirement

        requirement_data = requirement["data"]
        action_type = requirement_data["action_type"]
        risk_level = requirement_data["risk_level"]
        approval_requirement = requirement_data["requirement"]

        if not requirement_data.get("required"):
            return self._safe_result(
                success=True,
                message="Approval request not created because approval is not required.",
                data={
                    "allowed": True,
                    "approval_required": False,
                    "status": ApprovalStatus.NOT_REQUIRED.value,
                    "approval_id": None,
                    "action_type": action_type,
                    "risk_level": risk_level,
                    "requirement": ApprovalRequirement.NONE.value,
                },
            )

        scope_count = self._pending_count_for_scope(
            user_id=validation["data"]["user_id"],
            workspace_id=validation["data"]["workspace_id"],
        )
        if scope_count >= self.policy.max_pending_requests_per_scope:
            return self._error_result(
                message="Too many pending approval requests for this user/workspace.",
                error="PENDING_APPROVAL_LIMIT_REACHED",
                metadata={
                    "pending_count": scope_count,
                    "max_pending_requests_per_scope": self.policy.max_pending_requests_per_scope,
                },
            )

        existing = self.find_existing_pending_request(
            user_id=validation["data"]["user_id"],
            workspace_id=validation["data"]["workspace_id"],
            workflow_id=validation["data"]["workflow_id"],
            step_id=validation["data"]["step_id"],
        )
        if existing["success"] and existing["data"].get("approval_record"):
            record = existing["data"]["approval_record"]
            return self._safe_result(
                success=True,
                message="Approval request already exists for this workflow step.",
                data={
                    "allowed": False,
                    "approval_required": True,
                    "approval_id": record["approval_id"],
                    "status": record["status"],
                    "action_type": record["action_type"],
                    "risk_level": record["risk_level"],
                    "requirement": record["requirement"],
                    "approval_record": record,
                },
                metadata={"existing_request": True},
            )

        now = _utc_now()
        ttl = int(ttl_seconds or self.policy.default_ttl_seconds)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl, tz=timezone.utc)

        approval_id = self._make_approval_id(
            user_id=validation["data"]["user_id"],
            workspace_id=validation["data"]["workspace_id"],
            workflow_id=validation["data"]["workflow_id"],
            step_id=validation["data"]["step_id"],
            action_type=action_type,
        )

        clean_reason = self._truncate_reason(
            reason
            or self._build_default_reason(
                action_type=action_type,
                risk_level=risk_level,
                requirement=approval_requirement,
                requirement_data=requirement_data,
            )
        )

        record = ApprovalRecord(
            approval_id=approval_id,
            user_id=validation["data"]["user_id"],
            workspace_id=validation["data"]["workspace_id"],
            workflow_id=validation["data"]["workflow_id"],
            step_id=validation["data"]["step_id"],
            action_type=action_type,
            risk_level=risk_level,
            requirement=approval_requirement,
            status=ApprovalStatus.PENDING.value,
            reason=clean_reason,
            step_summary=self._summarize_step(workflow_step),
            requested_by=_safe_string(requested_by, "workflow_agent"),
            created_at=now.isoformat(),
            updated_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            metadata={
                "ttl_seconds": ttl,
                "payload_hash": requirement.get("metadata", {}).get("payload_hash"),
                "custom_metadata": _redact_payload(dict(metadata or {})),
                "requirement_reasons": requirement_data.get("reasons", {}),
            },
        )

        with self._lock:
            self._records[approval_id] = record

        self._emit_agent_event(
            event_type="approval.requested",
            task_context=task_context,
            payload={
                "approval_id": approval_id,
                "action_type": action_type,
                "risk_level": risk_level,
                "requirement": approval_requirement,
                "status": record.status,
            },
        )
        self._log_audit_event(
            event_type="approval.requested",
            task_context=task_context,
            payload={
                "approval_id": approval_id,
                "requested_by": requested_by,
                "action_type": action_type,
                "risk_level": risk_level,
                "requirement": approval_requirement,
            },
        )

        security_result = self._request_security_approval(record, workflow_step, task_context)

        with self._lock:
            current_record = self._records.get(approval_id, record)

        verification_payload = self._prepare_verification_payload(current_record)
        memory_payload = self._prepare_memory_payload(current_record)

        return self._safe_result(
            success=True,
            message=(
                "Approval request created and approved."
                if current_record.status == ApprovalStatus.APPROVED.value
                else "Approval request created. Workflow step is blocked until approval is completed."
            ),
            data={
                "allowed": current_record.status == ApprovalStatus.APPROVED.value,
                "approval_required": True,
                "approval_id": approval_id,
                "status": current_record.status,
                "action_type": current_record.action_type,
                "risk_level": current_record.risk_level,
                "requirement": current_record.requirement,
                "approval_record": self._record_to_dict(current_record),
                "security_result": security_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "scope_key": current_record.scope().key(),
                "expires_at": current_record.expires_at,
            },
        )

    def approve_request(
        self,
        approval_id: str,
        task_context: Mapping[str, Any],
        actor_id: str,
        actor_type: str = ApprovalActorType.USER.value,
        reason: Optional[str] = None,
        security_decision: bool = False,
        user_decision: bool = True,
    ) -> Dict[str, Any]:
        """
        Approve a pending request.

        Args:
            security_decision:
                True when this approval should satisfy the security side.
            user_decision:
                True when this approval should satisfy the user side.
        """

        validation = self._validate_task_context(task_context, require_workflow_step=False)
        if not validation["success"]:
            return validation

        with self._lock:
            record = self._records.get(_safe_string(approval_id))

            if record is None:
                return self._error_result(
                    message="Approval request not found.",
                    error="APPROVAL_NOT_FOUND",
                    metadata={"approval_id": approval_id},
                )

            scope_check = self._assert_scope(record, task_context)
            if not scope_check["success"]:
                return scope_check

            expiry_result = self._expire_if_needed_locked(record)
            if not expiry_result["success"]:
                return expiry_result
            if record.status == ApprovalStatus.EXPIRED.value:
                return self._error_result(
                    message="Approval request has expired and cannot be approved.",
                    error="APPROVAL_EXPIRED",
                    data={"approval_record": self._record_to_dict(record)},
                )

            if record.status in {ApprovalStatus.REJECTED.value, ApprovalStatus.CANCELLED.value}:
                return self._error_result(
                    message=f"Approval request is already {record.status} and cannot be approved.",
                    error="APPROVAL_FINALIZED",
                    data={"approval_record": self._record_to_dict(record)},
                )

            if record.status == ApprovalStatus.APPROVED.value:
                return self._safe_result(
                    success=True,
                    message="Approval request is already approved.",
                    data=self._approval_response_data(record, decision=ApprovalDecision.APPROVE.value),
                    metadata={"idempotent": True},
                )

            actor_type_clean = self._normalize_actor_type(actor_type)
            reason_clean = self._truncate_reason(reason or "Approved.")

            if security_decision:
                record.security_approved = True
                record.security_decision_by = _safe_string(actor_id, actor_type_clean)
                record.security_decision_reason = reason_clean

            if user_decision:
                record.user_approved = True
                record.user_decision_by = _safe_string(actor_id, actor_type_clean)
                record.user_decision_reason = reason_clean

            record.decision_history.append(
                {
                    "decision": ApprovalDecision.APPROVE.value,
                    "actor_id": _safe_string(actor_id, actor_type_clean),
                    "actor_type": actor_type_clean,
                    "reason": reason_clean,
                    "security_decision": security_decision,
                    "user_decision": user_decision,
                    "timestamp": _utc_iso(),
                }
            )
            record.updated_at = _utc_iso()

            if self._approval_requirements_satisfied(record):
                record.status = ApprovalStatus.APPROVED.value

            self._records[record.approval_id] = record

        self._emit_agent_event(
            event_type="approval.approved" if record.status == ApprovalStatus.APPROVED.value else "approval.partially_approved",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "status": record.status,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "security_approved": record.security_approved,
                "user_approved": record.user_approved,
            },
        )
        self._log_audit_event(
            event_type="approval.approved" if record.status == ApprovalStatus.APPROVED.value else "approval.partially_approved",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "status": record.status,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        return self._safe_result(
            success=True,
            message=(
                "Approval request fully approved. Workflow step may proceed."
                if record.status == ApprovalStatus.APPROVED.value
                else "Approval recorded. Additional approval is still required."
            ),
            data=self._approval_response_data(record, decision=ApprovalDecision.APPROVE.value),
            metadata={"allowed": record.status == ApprovalStatus.APPROVED.value},
        )

    def reject_request(
        self,
        approval_id: str,
        task_context: Mapping[str, Any],
        actor_id: str,
        actor_type: str = ApprovalActorType.USER.value,
        reason: Optional[str] = None,
        security_decision: bool = False,
        user_decision: bool = True,
    ) -> Dict[str, Any]:
        """Reject a pending approval request."""

        validation = self._validate_task_context(task_context, require_workflow_step=False)
        if not validation["success"]:
            return validation

        with self._lock:
            record = self._records.get(_safe_string(approval_id))

            if record is None:
                return self._error_result(
                    message="Approval request not found.",
                    error="APPROVAL_NOT_FOUND",
                    metadata={"approval_id": approval_id},
                )

            scope_check = self._assert_scope(record, task_context)
            if not scope_check["success"]:
                return scope_check

            expiry_result = self._expire_if_needed_locked(record)
            if not expiry_result["success"]:
                return expiry_result

            if record.status == ApprovalStatus.APPROVED.value:
                return self._error_result(
                    message="Approval request is already approved and cannot be rejected.",
                    error="APPROVAL_ALREADY_APPROVED",
                    data={"approval_record": self._record_to_dict(record)},
                )

            if record.status == ApprovalStatus.REJECTED.value:
                return self._safe_result(
                    success=True,
                    message="Approval request is already rejected.",
                    data=self._approval_response_data(record, decision=ApprovalDecision.REJECT.value),
                    metadata={"idempotent": True},
                )

            reason_clean = self._truncate_reason(reason or "Rejected.")
            actor_type_clean = self._normalize_actor_type(actor_type)

            if security_decision:
                record.security_decision_by = _safe_string(actor_id, actor_type_clean)
                record.security_decision_reason = reason_clean

            if user_decision:
                record.user_decision_by = _safe_string(actor_id, actor_type_clean)
                record.user_decision_reason = reason_clean

            record.status = ApprovalStatus.REJECTED.value
            record.updated_at = _utc_iso()
            record.decision_history.append(
                {
                    "decision": ApprovalDecision.REJECT.value,
                    "actor_id": _safe_string(actor_id, actor_type_clean),
                    "actor_type": actor_type_clean,
                    "reason": reason_clean,
                    "security_decision": security_decision,
                    "user_decision": user_decision,
                    "timestamp": record.updated_at,
                }
            )
            self._records[record.approval_id] = record

        self._emit_agent_event(
            event_type="approval.rejected",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "status": record.status,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )
        self._log_audit_event(
            event_type="approval.rejected",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "status": record.status,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "reason": reason_clean,
            },
        )

        return self._safe_result(
            success=True,
            message="Approval request rejected. Workflow step remains blocked.",
            data=self._approval_response_data(record, decision=ApprovalDecision.REJECT.value),
            metadata={"allowed": False},
        )

    def cancel_request(
        self,
        approval_id: str,
        task_context: Mapping[str, Any],
        actor_id: str = "workflow_agent",
        actor_type: str = ApprovalActorType.WORKFLOW_AGENT.value,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a pending approval request."""

        validation = self._validate_task_context(task_context, require_workflow_step=False)
        if not validation["success"]:
            return validation

        with self._lock:
            record = self._records.get(_safe_string(approval_id))

            if record is None:
                return self._error_result(
                    message="Approval request not found.",
                    error="APPROVAL_NOT_FOUND",
                    metadata={"approval_id": approval_id},
                )

            scope_check = self._assert_scope(record, task_context)
            if not scope_check["success"]:
                return scope_check

            if record.status in {
                ApprovalStatus.APPROVED.value,
                ApprovalStatus.REJECTED.value,
                ApprovalStatus.CANCELLED.value,
                ApprovalStatus.EXPIRED.value,
            }:
                return self._safe_result(
                    success=True,
                    message=f"Approval request is already finalized as {record.status}.",
                    data=self._approval_response_data(record, decision=ApprovalDecision.CANCEL.value),
                    metadata={"idempotent": True},
                )

            reason_clean = self._truncate_reason(reason or "Cancelled.")
            actor_type_clean = self._normalize_actor_type(actor_type)
            record.status = ApprovalStatus.CANCELLED.value
            record.updated_at = _utc_iso()
            record.decision_history.append(
                {
                    "decision": ApprovalDecision.CANCEL.value,
                    "actor_id": _safe_string(actor_id, actor_type_clean),
                    "actor_type": actor_type_clean,
                    "reason": reason_clean,
                    "timestamp": record.updated_at,
                }
            )
            self._records[record.approval_id] = record

        self._emit_agent_event(
            event_type="approval.cancelled",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "status": record.status,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )
        self._log_audit_event(
            event_type="approval.cancelled",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "status": record.status,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "reason": reason_clean,
            },
        )

        return self._safe_result(
            success=True,
            message="Approval request cancelled.",
            data=self._approval_response_data(record, decision=ApprovalDecision.CANCEL.value),
            metadata={"allowed": False},
        )

    def get_request(
        self,
        approval_id: str,
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Get one approval request by ID, scoped to user/workspace."""

        validation = self._validate_task_context(task_context, require_workflow_step=False)
        if not validation["success"]:
            return validation

        with self._lock:
            record = self._records.get(_safe_string(approval_id))

            if record is None:
                return self._error_result(
                    message="Approval request not found.",
                    error="APPROVAL_NOT_FOUND",
                    metadata={"approval_id": approval_id},
                )

            scope_check = self._assert_scope(record, task_context)
            if not scope_check["success"]:
                return scope_check

            self._expire_if_needed_locked(record)
            self._records[record.approval_id] = record

            return self._safe_result(
                success=True,
                message="Approval request retrieved.",
                data={"approval_record": self._record_to_dict(record)},
                metadata={
                    "allowed": record.status == ApprovalStatus.APPROVED.value,
                    "scope_key": record.scope().key(),
                },
            )

    def list_pending(
        self,
        task_context: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        risk_level: Optional[str] = None,
        action_type: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        List pending approvals for a user/workspace.

        Never returns approvals from other users/workspaces.
        """

        validation = self._validate_task_context(task_context, require_workflow_step=False)
        if not validation["success"]:
            return validation

        user_id = validation["data"]["user_id"]
        workspace_id = validation["data"]["workspace_id"]
        limit_safe = max(1, min(int(limit), 500))

        with self._lock:
            results: List[ApprovalRecord] = []
            for record in self._records.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue

                self._expire_if_needed_locked(record)

                if record.status != ApprovalStatus.PENDING.value:
                    continue
                if workflow_id and record.workflow_id != workflow_id:
                    continue
                if risk_level and record.risk_level != risk_level:
                    continue
                if action_type and record.action_type != _normalize_action_type(action_type):
                    continue

                results.append(record)

            results.sort(key=lambda item: item.created_at, reverse=True)
            selected = results[:limit_safe]

        return self._safe_result(
            success=True,
            message="Pending approval requests listed.",
            data={
                "approval_records": [self._record_to_dict(record) for record in selected],
                "count": len(selected),
                "total_matching": len(results),
            },
            metadata={
                "scope_key": f"{user_id}:{workspace_id}",
                "limit": limit_safe,
            },
        )

    def find_existing_pending_request(
        self,
        user_id: str,
        workspace_id: str,
        workflow_id: str,
        step_id: str,
    ) -> Dict[str, Any]:
        """Find an existing pending request for the same workflow step."""

        with self._lock:
            for record in self._records.values():
                if (
                    record.user_id == user_id
                    and record.workspace_id == workspace_id
                    and record.workflow_id == workflow_id
                    and record.step_id == step_id
                ):
                    self._expire_if_needed_locked(record)
                    if record.status == ApprovalStatus.PENDING.value:
                        return self._safe_result(
                            success=True,
                            message="Existing pending approval request found.",
                            data={"approval_record": self._record_to_dict(record)},
                        )

        return self._safe_result(
            success=True,
            message="No existing pending approval request found.",
            data={"approval_record": None},
        )

    def is_approved(
        self,
        approval_id: str,
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Return whether an approval ID is approved and safe to execute."""

        request = self.get_request(approval_id=approval_id, task_context=task_context)
        if not request["success"]:
            return request

        record = request["data"]["approval_record"]
        approved = record["status"] == ApprovalStatus.APPROVED.value
        return self._safe_result(
            success=True,
            message="Approval status checked.",
            data={
                "approved": approved,
                "allowed": approved,
                "status": record["status"],
                "approval_id": record["approval_id"],
                "approval_record": record,
            },
            metadata={"safe_to_execute": approved},
        )

    def cleanup_expired(
        self,
        task_context: Optional[Mapping[str, Any]] = None,
        remove: bool = False,
    ) -> Dict[str, Any]:
        """
        Mark expired pending approvals as expired.

        If task_context is provided, cleanup is scoped to that user/workspace.
        If remove=True, expired records are deleted from the in-memory store.
        """

        scope_user: Optional[str] = None
        scope_workspace: Optional[str] = None

        if task_context is not None:
            validation = self._validate_task_context(task_context, require_workflow_step=False)
            if not validation["success"]:
                return validation
            scope_user = validation["data"]["user_id"]
            scope_workspace = validation["data"]["workspace_id"]

        expired_ids: List[str] = []
        removed_ids: List[str] = []

        with self._lock:
            for approval_id, record in list(self._records.items()):
                if scope_user and record.user_id != scope_user:
                    continue
                if scope_workspace and record.workspace_id != scope_workspace:
                    continue

                before = record.status
                self._expire_if_needed_locked(record)
                if record.status == ApprovalStatus.EXPIRED.value and before != ApprovalStatus.EXPIRED.value:
                    expired_ids.append(approval_id)

                if remove and record.status == ApprovalStatus.EXPIRED.value:
                    del self._records[approval_id]
                    removed_ids.append(approval_id)

        return self._safe_result(
            success=True,
            message="Expired approval cleanup completed.",
            data={
                "expired_ids": expired_ids,
                "removed_ids": removed_ids,
                "expired_count": len(expired_ids),
                "removed_count": len(removed_ids),
            },
            metadata={
                "scoped": task_context is not None,
                "remove": remove,
            },
        )

    def export_record(
        self,
        approval_id: str,
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Export an approval record for external persistence.

        Useful for future database-backed repository integration.
        """

        return self.get_request(approval_id=approval_id, task_context=task_context)

    def import_record(
        self,
        record_data: Mapping[str, Any],
        task_context: Mapping[str, Any],
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """
        Import a previously exported approval record.

        Scope must match task_context to prevent cross-user/workspace injection.
        """

        validation = self._validate_task_context(task_context, require_workflow_step=False)
        if not validation["success"]:
            return validation

        try:
            record = ApprovalRecord(
                approval_id=_safe_string(record_data["approval_id"]),
                user_id=_safe_string(record_data["user_id"]),
                workspace_id=_safe_string(record_data["workspace_id"]),
                workflow_id=_safe_string(record_data["workflow_id"]),
                step_id=_safe_string(record_data["step_id"]),
                action_type=_normalize_action_type(record_data["action_type"]),
                risk_level=_safe_string(record_data["risk_level"]),
                requirement=_safe_string(record_data["requirement"]),
                status=_safe_string(record_data["status"]),
                reason=_safe_string(record_data["reason"]),
                step_summary=dict(record_data.get("step_summary", {})),
                requested_by=_safe_string(record_data.get("requested_by", "unknown")),
                created_at=_safe_string(record_data["created_at"]),
                updated_at=_safe_string(record_data["updated_at"]),
                expires_at=_safe_string(record_data["expires_at"]),
                security_approved=bool(record_data.get("security_approved", False)),
                user_approved=bool(record_data.get("user_approved", False)),
                security_decision_by=record_data.get("security_decision_by"),
                user_decision_by=record_data.get("user_decision_by"),
                security_decision_reason=record_data.get("security_decision_reason"),
                user_decision_reason=record_data.get("user_decision_reason"),
                decision_history=list(record_data.get("decision_history", [])),
                metadata=dict(record_data.get("metadata", {})),
            )
        except Exception as exc:
            return self._error_result(
                message="Invalid approval record data.",
                error=exc,
            )

        scope_check = self._assert_scope(record, task_context)
        if not scope_check["success"]:
            return scope_check

        with self._lock:
            if record.approval_id in self._records and not overwrite:
                return self._error_result(
                    message="Approval record already exists. Set overwrite=True to replace it.",
                    error="APPROVAL_ALREADY_EXISTS",
                    metadata={"approval_id": record.approval_id},
                )
            self._records[record.approval_id] = record

        self._log_audit_event(
            event_type="approval.imported",
            task_context=task_context,
            payload={
                "approval_id": record.approval_id,
                "overwrite": overwrite,
            },
        )

        return self._safe_result(
            success=True,
            message="Approval record imported.",
            data={"approval_record": self._record_to_dict(record)},
            metadata={"overwrite": overwrite},
        )

    def run(self, task: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible generic runner.

        Expected task format:
            {
                "operation": "evaluate_step" | "request_approval" | "approve" |
                             "reject" | "cancel" | "get" | "list_pending" |
                             "is_approved" | "cleanup_expired",
                "workflow_step": {...},
                "task_context": {...},
                ...
            }
        """

        task_payload: Dict[str, Any] = dict(task or {})
        task_payload.update(kwargs)

        operation = _safe_string(task_payload.get("operation"), "evaluate_step").lower()
        task_context = task_payload.get("task_context") or task_payload.get("context") or {}

        try:
            if operation == "evaluate_step":
                return self.evaluate_step(
                    workflow_step=task_payload.get("workflow_step", {}),
                    task_context=task_context,
                )

            if operation == "enforce_before_execution":
                return self.enforce_before_execution(
                    workflow_step=task_payload.get("workflow_step", {}),
                    task_context=task_context,
                    auto_create_request=_coerce_bool(task_payload.get("auto_create_request"), True),
                    requested_by=_safe_string(task_payload.get("requested_by"), "workflow_agent"),
                )

            if operation == "request_approval":
                return self.request_approval(
                    workflow_step=task_payload.get("workflow_step", {}),
                    task_context=task_context,
                    requested_by=_safe_string(task_payload.get("requested_by"), "workflow_agent"),
                    ttl_seconds=task_payload.get("ttl_seconds"),
                    reason=task_payload.get("reason"),
                    metadata=task_payload.get("metadata"),
                )

            if operation in {"approve", "approve_request"}:
                return self.approve_request(
                    approval_id=_safe_string(task_payload.get("approval_id")),
                    task_context=task_context,
                    actor_id=_safe_string(task_payload.get("actor_id"), "user"),
                    actor_type=_safe_string(task_payload.get("actor_type"), ApprovalActorType.USER.value),
                    reason=task_payload.get("reason"),
                    security_decision=_coerce_bool(task_payload.get("security_decision"), False),
                    user_decision=_coerce_bool(task_payload.get("user_decision"), True),
                )

            if operation in {"reject", "reject_request"}:
                return self.reject_request(
                    approval_id=_safe_string(task_payload.get("approval_id")),
                    task_context=task_context,
                    actor_id=_safe_string(task_payload.get("actor_id"), "user"),
                    actor_type=_safe_string(task_payload.get("actor_type"), ApprovalActorType.USER.value),
                    reason=task_payload.get("reason"),
                    security_decision=_coerce_bool(task_payload.get("security_decision"), False),
                    user_decision=_coerce_bool(task_payload.get("user_decision"), True),
                )

            if operation in {"cancel", "cancel_request"}:
                return self.cancel_request(
                    approval_id=_safe_string(task_payload.get("approval_id")),
                    task_context=task_context,
                    actor_id=_safe_string(task_payload.get("actor_id"), "workflow_agent"),
                    actor_type=_safe_string(task_payload.get("actor_type"), ApprovalActorType.WORKFLOW_AGENT.value),
                    reason=task_payload.get("reason"),
                )

            if operation in {"get", "get_request"}:
                return self.get_request(
                    approval_id=_safe_string(task_payload.get("approval_id")),
                    task_context=task_context,
                )

            if operation == "list_pending":
                return self.list_pending(
                    task_context=task_context,
                    workflow_id=task_payload.get("workflow_id"),
                    risk_level=task_payload.get("risk_level"),
                    action_type=task_payload.get("action_type"),
                    limit=int(task_payload.get("limit", 100)),
                )

            if operation == "is_approved":
                return self.is_approved(
                    approval_id=_safe_string(task_payload.get("approval_id")),
                    task_context=task_context,
                )

            if operation == "cleanup_expired":
                return self.cleanup_expired(
                    task_context=task_context if task_context else None,
                    remove=_coerce_bool(task_payload.get("remove"), False),
                )

            return self._error_result(
                message=f"Unsupported ApprovalGate operation: {operation}",
                error="UNSUPPORTED_OPERATION",
                metadata={
                    "supported_operations": [
                        "evaluate_step",
                        "enforce_before_execution",
                        "request_approval",
                        "approve",
                        "reject",
                        "cancel",
                        "get",
                        "list_pending",
                        "is_approved",
                        "cleanup_expired",
                    ]
                },
            )
        except Exception as exc:
            self.logger.exception("ApprovalGate.run failed.")
            return self._error_result(
                message="ApprovalGate operation failed.",
                error=exc,
                metadata={"operation": operation},
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_action_type(self, workflow_step: Mapping[str, Any]) -> str:
        candidates = (
            workflow_step.get("action_type"),
            workflow_step.get("type"),
            workflow_step.get("name"),
            workflow_step.get("operation"),
            workflow_step.get("connector_action"),
        )
        for candidate in candidates:
            if _safe_string(candidate):
                return _normalize_action_type(candidate)

        connector = _safe_string(workflow_step.get("connector"))
        action = _safe_string(workflow_step.get("action"))
        if connector or action:
            return _normalize_action_type(f"{connector}_{action}")

        return "unknown"

    def _step_text_blob(self, workflow_step: Mapping[str, Any]) -> str:
        pieces: List[str] = []
        for key in ("action_type", "type", "name", "operation", "connector", "action", "description", "summary"):
            if key in workflow_step:
                pieces.append(str(workflow_step.get(key)))
        payload = workflow_step.get("payload")
        if isinstance(payload, Mapping):
            for key, value in payload.items():
                pieces.append(str(key))
                if isinstance(value, (str, int, float, bool)):
                    pieces.append(str(value))
        return " ".join(pieces).lower()

    def _classify_risk(self, action_type: str, workflow_step: Mapping[str, Any]) -> str:
        explicit = _safe_string(workflow_step.get("risk_level")).lower()
        if explicit in {item.value for item in ApprovalRiskLevel}:
            return explicit

        if action_type in self.policy.critical_action_types:
            return ApprovalRiskLevel.CRITICAL.value
        if action_type in self.policy.high_risk_action_types:
            return ApprovalRiskLevel.HIGH.value
        if action_type in self.policy.sensitive_action_types:
            return ApprovalRiskLevel.MEDIUM.value

        text_blob = self._step_text_blob(workflow_step)
        if any(keyword in text_blob for keyword in self.policy.destructive_keywords):
            return ApprovalRiskLevel.HIGH.value
        if any(keyword in text_blob for keyword in self.policy.external_communication_keywords):
            return ApprovalRiskLevel.MEDIUM.value

        return ApprovalRiskLevel.LOW.value

    def _summarize_step(self, workflow_step: Mapping[str, Any]) -> Dict[str, Any]:
        payload = workflow_step.get("payload", {})
        payload_summary: Dict[str, Any] = {}

        if isinstance(payload, Mapping):
            for key, value in payload.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    payload_summary[str(key)] = _redact_sensitive_value(str(key), value)
                elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                    payload_summary[str(key)] = f"list[{len(value)}]"
                elif isinstance(value, Mapping):
                    payload_summary[str(key)] = f"dict[{len(value)}]"
                else:
                    payload_summary[str(key)] = type(value).__name__

        return {
            "action_type": self._extract_action_type(workflow_step),
            "connector": _safe_string(workflow_step.get("connector")),
            "action": _safe_string(workflow_step.get("action")),
            "description": _safe_string(workflow_step.get("description"))[:500],
            "payload_summary": payload_summary,
        }

    def _build_default_reason(
        self,
        action_type: str,
        risk_level: str,
        requirement: str,
        requirement_data: Mapping[str, Any],
    ) -> str:
        reasons = requirement_data.get("reasons", {})
        triggered = [key for key, value in dict(reasons).items() if value]
        trigger_text = ", ".join(triggered) if triggered else "policy match"
        return (
            f"Workflow step '{action_type}' is classified as {risk_level} risk and "
            f"requires {requirement} approval before execution. Triggered by: {trigger_text}."
        )

    def _truncate_reason(self, reason: str) -> str:
        clean = _safe_string(reason, "No reason provided.")
        if len(clean) > self.policy.max_reason_length:
            return clean[: self.policy.max_reason_length - 3] + "..."
        return clean

    def _make_approval_id(
        self,
        user_id: str,
        workspace_id: str,
        workflow_id: str,
        step_id: str,
        action_type: str,
    ) -> str:
        seed = f"{user_id}:{workspace_id}:{workflow_id}:{step_id}:{action_type}:{time.time_ns()}:{uuid.uuid4()}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
        return f"appr_{digest}"

    def _record_to_dict(self, record: ApprovalRecord) -> Dict[str, Any]:
        return asdict(record)

    def _scope_key_from_context(self, task_context: Mapping[str, Any]) -> str:
        user_id = _safe_string(task_context.get("user_id"))
        workspace_id = _safe_string(task_context.get("workspace_id"))
        if not user_id or not workspace_id:
            return ""
        return f"{user_id}:{workspace_id}"

    def _assert_scope(
        self,
        record: ApprovalRecord,
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        user_id = _safe_string(task_context.get("user_id"))
        workspace_id = _safe_string(task_context.get("workspace_id"))

        if record.user_id != user_id or record.workspace_id != workspace_id:
            self._log_audit_event(
                event_type="approval.scope_violation",
                task_context=task_context,
                payload={
                    "approval_id": record.approval_id,
                    "record_user_id": record.user_id,
                    "record_workspace_id": record.workspace_id,
                    "requested_user_id": user_id,
                    "requested_workspace_id": workspace_id,
                },
            )
            return self._error_result(
                message="Approval request does not belong to this user/workspace.",
                error="SCOPE_VIOLATION",
                metadata={
                    "approval_id": record.approval_id,
                    "requested_scope": f"{user_id}:{workspace_id}",
                },
            )

        return self._safe_result(
            success=True,
            message="Approval scope validated.",
            metadata={"scope_key": record.scope().key()},
        )

    def _expire_if_needed_locked(self, record: ApprovalRecord) -> Dict[str, Any]:
        if record.status != ApprovalStatus.PENDING.value:
            return self._safe_result(message="Approval request is not pending; expiry unchanged.")

        try:
            expires_at = datetime.fromisoformat(record.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except Exception:
            record.status = ApprovalStatus.EXPIRED.value
            record.updated_at = _utc_iso()
            record.decision_history.append(
                {
                    "decision": ApprovalStatus.EXPIRED.value,
                    "actor_id": "system",
                    "actor_type": ApprovalActorType.SYSTEM.value,
                    "reason": "Invalid expiry timestamp; request marked expired for safety.",
                    "timestamp": record.updated_at,
                }
            )
            return self._safe_result(
                success=True,
                message="Approval request marked expired due to invalid expiry timestamp.",
            )

        if _utc_now() >= expires_at:
            record.status = ApprovalStatus.EXPIRED.value
            record.updated_at = _utc_iso()
            record.decision_history.append(
                {
                    "decision": ApprovalStatus.EXPIRED.value,
                    "actor_id": "system",
                    "actor_type": ApprovalActorType.SYSTEM.value,
                    "reason": "Approval request expired.",
                    "timestamp": record.updated_at,
                }
            )
            return self._safe_result(
                success=True,
                message="Approval request expired.",
            )

        return self._safe_result(
            success=True,
            message="Approval request has not expired.",
        )

    def _approval_requirements_satisfied(self, record: ApprovalRecord) -> bool:
        if record.requirement == ApprovalRequirement.NONE.value:
            return True
        if record.requirement == ApprovalRequirement.SECURITY.value:
            return record.security_approved
        if record.requirement == ApprovalRequirement.USER.value:
            return record.user_approved
        if record.requirement == ApprovalRequirement.USER_AND_SECURITY.value:
            return record.security_approved and record.user_approved
        return False

    def _approval_response_data(
        self,
        record: ApprovalRecord,
        decision: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "allowed": record.status == ApprovalStatus.APPROVED.value,
            "approval_required": True,
            "approval_id": record.approval_id,
            "status": record.status,
            "action_type": record.action_type,
            "risk_level": record.risk_level,
            "requirement": record.requirement,
            "security_approved": record.security_approved,
            "user_approved": record.user_approved,
            "approval_record": self._record_to_dict(record),
            "verification_payload": self._prepare_verification_payload(record, decision=decision),
            "memory_payload": self._prepare_memory_payload(record, decision=decision),
        }

    def _pending_count_for_scope(self, user_id: str, workspace_id: str) -> int:
        count = 0
        with self._lock:
            for record in self._records.values():
                if record.user_id == user_id and record.workspace_id == workspace_id:
                    self._expire_if_needed_locked(record)
                    if record.status == ApprovalStatus.PENDING.value:
                        count += 1
        return count

    def _normalize_actor_type(self, actor_type: str) -> str:
        clean = _safe_string(actor_type, ApprovalActorType.USER.value).lower()
        allowed = {item.value for item in ApprovalActorType}
        return clean if clean in allowed else ApprovalActorType.USER.value

    def _parse_security_response(self, response: Any) -> Tuple[Optional[bool], Optional[str]]:
        """
        Normalize different possible Security Agent response styles.

        Returns:
            (approved, reason)
                approved True  = security approved
                approved False = security rejected or not approved
                approved None  = no final decision
        """

        if response is None:
            return None, None

        if isinstance(response, bool):
            return response, "Security Agent returned boolean decision."

        if isinstance(response, Mapping):
            data = response.get("data", {})
            if not isinstance(data, Mapping):
                data = {}

            candidates = (
                response.get("approved"),
                response.get("allowed"),
                response.get("success") if response.get("decision") in {"approved", "approve"} else None,
                data.get("approved"),
                data.get("allowed"),
                data.get("security_approved"),
            )

            for candidate in candidates:
                if candidate is not None:
                    approved = _coerce_bool(candidate)
                    reason = (
                        _safe_string(response.get("message"))
                        or _safe_string(response.get("reason"))
                        or _safe_string(data.get("reason"))
                        or _safe_string(data.get("message"))
                    )
                    return approved, reason

            decision = _safe_string(response.get("decision") or data.get("decision")).lower()
            if decision in {"approved", "approve", "allow", "allowed"}:
                return True, _safe_string(response.get("message") or data.get("message"), "Security approved.")
            if decision in {"rejected", "reject", "deny", "denied", "blocked"}:
                return False, _safe_string(response.get("message") or data.get("message"), "Security rejected.")

        return None, None

    def _is_explicit_rejection(self, response: Any) -> bool:
        if isinstance(response, Mapping):
            data = response.get("data", {})
            if not isinstance(data, Mapping):
                data = {}
            decision = _safe_string(response.get("decision") or data.get("decision")).lower()
            status = _safe_string(response.get("status") or data.get("status")).lower()
            error = response.get("error")
            if decision in {"rejected", "reject", "deny", "denied", "blocked"}:
                return True
            if status in {"rejected", "denied", "blocked"}:
                return True
            if error and response.get("success") is False:
                return True
        return False

    def _safe_response_summary(self, response: Any) -> Any:
        if isinstance(response, Mapping):
            allowed_keys = {
                "success",
                "message",
                "approved",
                "allowed",
                "decision",
                "status",
                "error",
                "metadata",
            }
            return _redact_payload({str(k): v for k, v in response.items() if str(k) in allowed_keys})
        if isinstance(response, (str, int, float, bool)) or response is None:
            return response
        return type(response).__name__


__all__ = [
    "ApprovalGate",
    "ApprovalPolicy",
    "ApprovalRecord",
    "ApprovalScope",
    "ApprovalStatus",
    "ApprovalDecision",
    "ApprovalRiskLevel",
    "ApprovalActorType",
    "ApprovalRequirement",
]