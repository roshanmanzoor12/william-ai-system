"""
agents/workflow_agent/retry_handler.py

William / Jarvis Multi-Agent AI SaaS System
Workflow Agent - Retry Handler

Purpose:
    Retries safe failed workflow steps without creating duplicate leads, duplicate
    messages, duplicate CRM records, duplicate sheet rows, duplicate emails, or
    duplicate downstream side effects.

Architecture connections:
    - Master Agent / Agent Router:
        Exposes the RetryHandler class with clear public methods that accept
        structured task payloads and return structured dict/JSON-style results.

    - Security Agent:
        Sensitive retry actions can be routed through security approval hooks before
        execution. This file does not directly execute destructive/system/financial/
        messaging/calling/browser actions unless permission hooks approve the action.

    - Workflow Agent:
        Provides retry classification, retry policy evaluation, idempotency guard,
        retry plan generation, safe execution wrapper, and retry event reporting.

    - Verification Agent:
        Every completed retry prepares a verification payload describing what was
        retried, whether the action was safe, and the idempotency status.

    - Memory Agent:
        Useful retry context can be converted into a memory payload for future
        workflow optimization and failure pattern analysis.

    - Dashboard/API:
        Structured results include success, message, data, error, and metadata.
        Audit/event payloads are serializable and ready for dashboard display.

Import safety:
    This file uses optional imports and fallback stubs so it can be imported even
    when the broader William/Jarvis codebase is not fully generated yet.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import json
import logging
import math
import random
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent import with fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for incomplete future project

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent may provide richer registry, routing,
        permissions, event bus, memory, and audit integrations. This fallback keeps
        retry_handler.py import-safe during staged generation.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.NullHandler()


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

class RetryStatus(str, enum.Enum):
    """Status values for retry attempts."""

    PENDING = "pending"
    APPROVED = "approved"
    SKIPPED = "skipped"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    EXHAUSTED = "exhausted"
    DUPLICATE_PREVENTED = "duplicate_prevented"
    SECURITY_REVIEW_REQUIRED = "security_review_required"


class RetryDecision(str, enum.Enum):
    """Retry decision classification."""

    RETRY_NOW = "retry_now"
    RETRY_LATER = "retry_later"
    DO_NOT_RETRY = "do_not_retry"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    DUPLICATE_RISK_BLOCKED = "duplicate_risk_blocked"


class StepSafetyLevel(str, enum.Enum):
    """Safety level used to decide whether retry is allowed."""

    SAFE = "safe"
    CAUTION = "caution"
    SENSITIVE = "sensitive"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


class DuplicatePolicy(str, enum.Enum):
    """Controls duplicate protection behavior."""

    STRICT = "strict"
    WARN_ONLY = "warn_only"
    DISABLED = "disabled"


class RetryableErrorType(str, enum.Enum):
    """Known failure types."""

    NETWORK = "network"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_PROVIDER_ERROR = "temporary_provider_error"
    LOCK_CONFLICT = "lock_conflict"
    VALIDATION = "validation"
    AUTHORIZATION = "authorization"
    PERMISSION = "permission"
    DUPLICATE = "duplicate"
    UNKNOWN = "unknown"


DEFAULT_SAFE_ACTIONS = {
    "read",
    "fetch",
    "lookup",
    "validate",
    "verify",
    "parse",
    "transform",
    "score",
    "filter",
    "dedupe_check",
    "prepare",
    "generate_report",
    "update_status",
    "poll",
}

DEFAULT_CAUTION_ACTIONS = {
    "write_sheet",
    "create_sheet_row",
    "update_sheet_row",
    "create_crm_note",
    "update_crm_contact",
    "update_crm_deal",
    "create_task",
    "send_internal_notification",
    "send_dashboard_alert",
    "send_slack_alert",
    "send_discord_alert",
}

DEFAULT_SENSITIVE_ACTIONS = {
    "send_email",
    "send_whatsapp",
    "send_sms",
    "send_message",
    "send_notification",
    "create_crm_contact",
    "create_crm_deal",
    "create_lead",
    "create_invoice",
    "charge_payment",
    "call_phone",
    "browser_submit_form",
    "external_api_write",
}

DEFAULT_UNSAFE_ACTIONS = {
    "delete",
    "bulk_delete",
    "purge",
    "drop_table",
    "transfer_money",
    "send_mass_email",
    "send_mass_whatsapp",
    "disable_security",
    "change_permissions",
    "export_all_user_data",
}

TRANSIENT_ERROR_KEYWORDS = {
    RetryableErrorType.NETWORK: (
        "network",
        "connection",
        "dns",
        "socket",
        "temporarily unavailable",
        "connection reset",
        "connection refused",
    ),
    RetryableErrorType.TIMEOUT: (
        "timeout",
        "timed out",
        "deadline",
        "gateway timeout",
        "504",
    ),
    RetryableErrorType.RATE_LIMIT: (
        "rate limit",
        "rate_limited",
        "too many requests",
        "429",
        "quota exceeded",
        "throttle",
    ),
    RetryableErrorType.TEMPORARY_PROVIDER_ERROR: (
        "temporary",
        "try again",
        "provider unavailable",
        "service unavailable",
        "503",
        "502",
        "bad gateway",
        "internal server error",
        "500",
    ),
    RetryableErrorType.LOCK_CONFLICT: (
        "lock",
        "conflict",
        "deadlock",
        "resource busy",
        "already processing",
    ),
}

PERMANENT_ERROR_KEYWORDS = {
    RetryableErrorType.VALIDATION: (
        "validation",
        "invalid",
        "missing required",
        "malformed",
        "schema",
        "bad request",
        "400",
    ),
    RetryableErrorType.AUTHORIZATION: (
        "unauthorized",
        "auth",
        "token expired",
        "invalid token",
        "401",
    ),
    RetryableErrorType.PERMISSION: (
        "permission",
        "forbidden",
        "not allowed",
        "403",
    ),
    RetryableErrorType.DUPLICATE: (
        "duplicate",
        "already exists",
        "idempotency conflict",
        "unique constraint",
    ),
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class RetryPolicy:
    """
    Retry policy for workflow steps.

    max_attempts:
        Total number of attempts including the first failed attempt.
    base_delay_seconds:
        Base delay used for exponential backoff.
    max_delay_seconds:
        Maximum delay cap.
    backoff_multiplier:
        Multiplier for exponential backoff.
    jitter_seconds:
        Random jitter upper bound.
    duplicate_policy:
        Strict blocks duplicate-risk retries; warn_only allows with metadata;
        disabled skips duplicate checks.
    require_security_for_sensitive:
        Sensitive action retries must request Security Agent approval.
    allow_caution_without_security:
        Caution-level actions may retry if duplicate guard passes.
    allow_unknown_action_retry:
        Unknown actions are blocked by default.
    """

    max_attempts: int = 3
    base_delay_seconds: float = 2.0
    max_delay_seconds: float = 300.0
    backoff_multiplier: float = 2.0
    jitter_seconds: float = 0.5
    duplicate_policy: DuplicatePolicy = DuplicatePolicy.STRICT
    require_security_for_sensitive: bool = True
    allow_caution_without_security: bool = True
    allow_unknown_action_retry: bool = False
    retryable_error_types: Tuple[RetryableErrorType, ...] = (
        RetryableErrorType.NETWORK,
        RetryableErrorType.TIMEOUT,
        RetryableErrorType.RATE_LIMIT,
        RetryableErrorType.TEMPORARY_PROVIDER_ERROR,
        RetryableErrorType.LOCK_CONFLICT,
        RetryableErrorType.UNKNOWN,
    )

    def normalized(self) -> "RetryPolicy":
        """Return a safe normalized copy."""
        return RetryPolicy(
            max_attempts=max(1, int(self.max_attempts)),
            base_delay_seconds=max(0.0, float(self.base_delay_seconds)),
            max_delay_seconds=max(0.0, float(self.max_delay_seconds)),
            backoff_multiplier=max(1.0, float(self.backoff_multiplier)),
            jitter_seconds=max(0.0, float(self.jitter_seconds)),
            duplicate_policy=self.duplicate_policy,
            require_security_for_sensitive=bool(self.require_security_for_sensitive),
            allow_caution_without_security=bool(self.allow_caution_without_security),
            allow_unknown_action_retry=bool(self.allow_unknown_action_retry),
            retryable_error_types=tuple(self.retryable_error_types),
        )


@dataclasses.dataclass
class RetryRecord:
    """Serializable record for an attempted retry."""

    retry_id: str
    user_id: str
    workspace_id: str
    workflow_id: str
    run_id: str
    step_id: str
    action: str
    attempt_number: int
    status: RetryStatus
    idempotency_key: str
    created_at: str
    updated_at: str
    message: str = ""
    error_type: str = RetryableErrorType.UNKNOWN.value
    error: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-safe dict."""
        return {
            "retry_id": self.retry_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "action": self.action,
            "attempt_number": self.attempt_number,
            "status": self.status.value if isinstance(self.status, RetryStatus) else str(self.status),
            "idempotency_key": self.idempotency_key,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "message": self.message,
            "error_type": self.error_type,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclasses.dataclass
class IdempotencyEntry:
    """Tracks idempotency state for duplicate prevention."""

    key: str
    user_id: str
    workspace_id: str
    workflow_id: str
    run_id: str
    step_id: str
    action: str
    status: str
    result_fingerprint: Optional[str]
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-safe dict."""
        return {
            "key": self.key,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "action": self.action,
            "status": self.status,
            "result_fingerprint": self.result_fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# RetryHandler
# ---------------------------------------------------------------------------

class RetryHandler(BaseAgent):
    """
    Handles retrying failed workflow steps safely.

    Public methods:
        - analyze_failed_step()
        - should_retry()
        - build_retry_plan()
        - register_failed_step()
        - execute_retry()
        - execute_retry_plan()
        - record_success()
        - record_failure()
        - get_retry_history()
        - get_idempotency_entry()
        - clear_expired_records()

    This class intentionally does not know the internals of every connector.
    Step execution is supplied through a callable executor or through a registered
    action executor. This prevents unsafe direct side effects and keeps routing
    compatible with Master Agent / Action Router / connector files.
    """

    agent_name = "workflow_retry_handler"
    agent_type = "workflow_agent_helper"
    module_name = "workflow_agent"
    file_name = "retry_handler.py"

    def __init__(
        self,
        policy: Optional[RetryPolicy] = None,
        action_executors: Optional[Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        clock: Optional[Callable[[], datetime]] = None,
        enable_in_memory_store: bool = True,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize RetryHandler.

        Args:
            policy: Default retry policy.
            action_executors: Optional mapping of action name -> executor callable.
            security_client: Optional Security Agent/client integration.
            memory_client: Optional Memory Agent/client integration.
            verification_client: Optional Verification Agent/client integration.
            audit_logger: Optional audit integration.
            event_emitter: Optional dashboard/event bus integration.
            clock: Optional datetime provider for tests.
            enable_in_memory_store: Enables local idempotency and retry history store.
            **kwargs: Passed to BaseAgent when available.
        """
        try:
            super().__init__(**kwargs)
        except TypeError:
            super().__init__()

        self.logger = logger_instance or getattr(self, "logger", logging.getLogger(self.__class__.__name__))
        self.policy = (policy or RetryPolicy()).normalized()
        self.action_executors: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = dict(action_executors or {})
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.enable_in_memory_store = bool(enable_in_memory_store)

        self._lock = threading.RLock()
        self._retry_history: Dict[str, List[RetryRecord]] = {}
        self._idempotency_store: Dict[str, IdempotencyEntry] = {}
        self._completed_step_fingerprints: Dict[str, Dict[str, Any]] = {}

    # ---------------------------------------------------------------------
    # Result helpers
    # ---------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return a structured successful result.

        Compatible with dashboard/API/Master Agent response expectations.
        """
        return {
            "success": bool(success),
            "message": str(message),
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
        """
        Return a structured error result.

        Exceptions are converted to safe strings. Traceback details are only
        included in metadata when explicitly passed by caller.
        """
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any], None] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": str(message),
            "data": data or {},
            "error": error_payload,
            "metadata": metadata or {},
        }

    # ---------------------------------------------------------------------
    # Context validation and safety
    # ---------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate user/workspace isolation and workflow step context.

        Required:
            user_id, workspace_id, workflow_id, run_id, step_id

        Optional:
            action, payload, metadata, attempt_number
        """
        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                error="task_context must be a mapping/dict.",
                metadata={"hook": "_validate_task_context"},
            )

        required = ("user_id", "workspace_id", "workflow_id", "run_id", "step_id")
        missing = [key for key in required if not str(task_context.get(key, "")).strip()]
        if missing:
            return self._error_result(
                message="Missing required workflow context.",
                error={"missing_fields": missing},
                metadata={"hook": "_validate_task_context"},
            )

        user_id = str(task_context.get("user_id")).strip()
        workspace_id = str(task_context.get("workspace_id")).strip()

        if user_id.lower() in {"none", "null", "undefined"}:
            return self._error_result(
                message="Invalid user_id.",
                error="user_id cannot be null-like.",
                metadata={"hook": "_validate_task_context"},
            )

        if workspace_id.lower() in {"none", "null", "undefined"}:
            return self._error_result(
                message="Invalid workspace_id.",
                error="workspace_id cannot be null-like.",
                metadata={"hook": "_validate_task_context"},
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "workflow_id": str(task_context.get("workflow_id")).strip(),
                "run_id": str(task_context.get("run_id")).strip(),
                "step_id": str(task_context.get("step_id")).strip(),
                "action": str(task_context.get("action", "")).strip(),
            },
            metadata={"hook": "_validate_task_context"},
        )

    def classify_action_safety(self, action: str, step: Optional[Mapping[str, Any]] = None) -> StepSafetyLevel:
        """
        Classify action safety for retry decisions.

        This is intentionally conservative. Unknown actions are blocked unless
        policy.allow_unknown_action_retry is enabled.
        """
        normalized = self._normalize_action(action)
        step = step or {}

        explicit = str(step.get("safety_level", "") or step.get("safety", "")).strip().lower()
        if explicit:
            for level in StepSafetyLevel:
                if explicit == level.value:
                    return level

        if normalized in DEFAULT_UNSAFE_ACTIONS:
            return StepSafetyLevel.UNSAFE
        if normalized in DEFAULT_SENSITIVE_ACTIONS:
            return StepSafetyLevel.SENSITIVE
        if normalized in DEFAULT_CAUTION_ACTIONS:
            return StepSafetyLevel.CAUTION
        if normalized in DEFAULT_SAFE_ACTIONS:
            return StepSafetyLevel.SAFE

        if normalized.startswith("read_") or normalized.startswith("fetch_") or normalized.startswith("validate_"):
            return StepSafetyLevel.SAFE
        if normalized.startswith("send_") or normalized.startswith("create_") or normalized.startswith("charge_"):
            return StepSafetyLevel.SENSITIVE
        if normalized.startswith("delete_") or normalized.startswith("bulk_"):
            return StepSafetyLevel.UNSAFE

        return StepSafetyLevel.UNKNOWN

    def _requires_security_check(self, action: str, task_context: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide whether retry needs Security Agent approval.

        Sensitive actions, unknown actions, and actions explicitly marked as
        requiring approval must go through the security hook.
        """
        task_context = task_context or {}
        if bool(task_context.get("requires_security_check")):
            return True

        safety = self.classify_action_safety(action, task_context)
        if safety == StepSafetyLevel.SENSITIVE:
            return bool(self.policy.require_security_for_sensitive)
        if safety in {StepSafetyLevel.UNSAFE, StepSafetyLevel.UNKNOWN}:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        task_context: Mapping[str, Any],
        retry_plan: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent/client.

        Fallback behavior:
            - Unsafe actions are denied.
            - Sensitive actions require explicit security_client if policy says so.
            - Safe/caution actions are approved locally.
        """
        safety = self.classify_action_safety(action, task_context)
        payload = {
            "request_id": self._new_id("sec"),
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "safety_level": safety.value,
            "task_context": self._redact_sensitive(copy.deepcopy(dict(task_context))),
            "retry_plan": self._redact_sensitive(copy.deepcopy(dict(retry_plan or {}))),
            "created_at": self._now_iso(),
        }

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve_retry"):
                    response = self.security_client.approve_retry(payload)
                elif hasattr(self.security_client, "request_approval"):
                    response = self.security_client.request_approval(payload)
                elif callable(self.security_client):
                    response = self.security_client(payload)
                else:
                    response = None

                if isinstance(response, Mapping):
                    approved = bool(response.get("approved", response.get("success", False)))
                    return self._safe_result(
                        success=approved,
                        message="Security approval granted." if approved else "Security approval denied.",
                        data={"approved": approved, "response": dict(response)},
                        metadata={"hook": "_request_security_approval", "safety_level": safety.value},
                    )

                if isinstance(response, bool):
                    return self._safe_result(
                        success=response,
                        message="Security approval granted." if response else "Security approval denied.",
                        data={"approved": response},
                        metadata={"hook": "_request_security_approval", "safety_level": safety.value},
                    )
            except Exception as exc:
                self.logger.exception("Security approval request failed.")
                return self._error_result(
                    message="Security approval request failed.",
                    error=exc,
                    metadata={"hook": "_request_security_approval", "safety_level": safety.value},
                )

        if safety == StepSafetyLevel.UNSAFE:
            return self._error_result(
                message="Retry blocked because action is unsafe.",
                error={"action": action, "safety_level": safety.value},
                metadata={"hook": "_request_security_approval"},
            )

        if safety == StepSafetyLevel.SENSITIVE and self.policy.require_security_for_sensitive:
            return self._error_result(
                message="Retry requires Security Agent approval but no security client is configured.",
                error={"action": action, "safety_level": safety.value},
                metadata={"hook": "_request_security_approval"},
            )

        if safety == StepSafetyLevel.UNKNOWN and not self.policy.allow_unknown_action_retry:
            return self._error_result(
                message="Retry blocked because action safety is unknown.",
                error={"action": action, "safety_level": safety.value},
                metadata={"hook": "_request_security_approval"},
            )

        return self._safe_result(
            message="Local retry approval granted.",
            data={"approved": True, "fallback": True},
            metadata={"hook": "_request_security_approval", "safety_level": safety.value},
        )

    # ---------------------------------------------------------------------
    # Public retry analysis methods
    # ---------------------------------------------------------------------

    def analyze_failed_step(
        self,
        failed_step: Mapping[str, Any],
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        policy: Optional[RetryPolicy] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a failed workflow step and produce a retry decision.

        Args:
            failed_step: Workflow step context including user_id/workspace_id.
            error: Optional error details from failed execution.
            policy: Optional policy override.

        Returns:
            Structured result with decision, safety, duplicate risk, error type,
            delay, and idempotency key.
        """
        validation = self._validate_task_context(failed_step)
        if not validation["success"]:
            return validation

        active_policy = (policy or self.policy).normalized()
        action = str(failed_step.get("action", "") or failed_step.get("step_type", "")).strip()
        safety = self.classify_action_safety(action, failed_step)
        error_type = self.classify_error(error or failed_step.get("error") or failed_step.get("last_error"))

        attempt_number = self._safe_int(
            failed_step.get("attempt_number", failed_step.get("attempt", failed_step.get("retry_count", 0))),
            default=0,
        )
        next_attempt = attempt_number + 1

        idempotency_key = self.build_idempotency_key(failed_step)
        duplicate_check = self.check_duplicate_risk(failed_step, idempotency_key=idempotency_key)

        decision = RetryDecision.RETRY_NOW
        reasons: List[str] = []

        if next_attempt >= active_policy.max_attempts:
            decision = RetryDecision.DO_NOT_RETRY
            reasons.append("max_attempts_reached")

        if safety == StepSafetyLevel.UNSAFE:
            decision = RetryDecision.DO_NOT_RETRY
            reasons.append("unsafe_action")

        if safety == StepSafetyLevel.UNKNOWN and not active_policy.allow_unknown_action_retry:
            decision = RetryDecision.DO_NOT_RETRY
            reasons.append("unknown_action_blocked")

        if safety == StepSafetyLevel.CAUTION and not active_policy.allow_caution_without_security:
            decision = RetryDecision.REQUIRE_SECURITY_APPROVAL
            reasons.append("caution_requires_security")

        if safety == StepSafetyLevel.SENSITIVE and active_policy.require_security_for_sensitive:
            decision = RetryDecision.REQUIRE_SECURITY_APPROVAL
            reasons.append("sensitive_requires_security")

        if error_type not in active_policy.retryable_error_types:
            decision = RetryDecision.DO_NOT_RETRY
            reasons.append(f"non_retryable_error:{error_type.value}")

        duplicate_risk = bool(duplicate_check.get("data", {}).get("duplicate_risk"))
        if active_policy.duplicate_policy == DuplicatePolicy.STRICT and duplicate_risk:
            decision = RetryDecision.DUPLICATE_RISK_BLOCKED
            reasons.append("duplicate_risk_detected")

        delay_seconds = self.compute_retry_delay(
            attempt_number=next_attempt,
            policy=active_policy,
            error_type=error_type,
        )

        return self._safe_result(
            message="Failed step analyzed.",
            data={
                "decision": decision.value,
                "reasons": reasons,
                "action": action,
                "safety_level": safety.value,
                "error_type": error_type.value,
                "attempt_number": attempt_number,
                "next_attempt": next_attempt,
                "max_attempts": active_policy.max_attempts,
                "delay_seconds": delay_seconds,
                "idempotency_key": idempotency_key,
                "duplicate_check": duplicate_check.get("data", {}),
                "policy": self.policy_to_dict(active_policy),
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
                "created_at": self._now_iso(),
            },
        )

    def should_retry(
        self,
        failed_step: Mapping[str, Any],
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        policy: Optional[RetryPolicy] = None,
    ) -> Dict[str, Any]:
        """
        Return whether a failed step should retry.

        This is a convenience wrapper around analyze_failed_step().
        """
        analysis = self.analyze_failed_step(failed_step=failed_step, error=error, policy=policy)
        if not analysis["success"]:
            return analysis

        decision = analysis["data"].get("decision")
        allowed = decision in {RetryDecision.RETRY_NOW.value, RetryDecision.RETRY_LATER.value}
        requires_security = decision == RetryDecision.REQUIRE_SECURITY_APPROVAL.value

        return self._safe_result(
            message="Retry eligibility evaluated.",
            data={
                "should_retry": allowed,
                "requires_security_approval": requires_security,
                "decision": decision,
                "analysis": analysis["data"],
            },
            metadata=analysis.get("metadata", {}),
        )

    def build_retry_plan(
        self,
        failed_step: Mapping[str, Any],
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        policy: Optional[RetryPolicy] = None,
    ) -> Dict[str, Any]:
        """
        Build a safe retry plan for a failed step.

        The plan can be shown in dashboard/API, routed through Master Agent,
        or executed by execute_retry_plan().
        """
        analysis = self.analyze_failed_step(failed_step=failed_step, error=error, policy=policy)
        if not analysis["success"]:
            return analysis

        data = analysis["data"]
        retry_id = self._new_id("retry")
        now = self._now_iso()

        plan = {
            "retry_id": retry_id,
            "status": RetryStatus.PENDING.value,
            "decision": data["decision"],
            "user_id": str(failed_step.get("user_id")),
            "workspace_id": str(failed_step.get("workspace_id")),
            "workflow_id": str(failed_step.get("workflow_id")),
            "run_id": str(failed_step.get("run_id")),
            "step_id": str(failed_step.get("step_id")),
            "action": data["action"],
            "safety_level": data["safety_level"],
            "error_type": data["error_type"],
            "attempt_number": data["next_attempt"],
            "max_attempts": data["max_attempts"],
            "delay_seconds": data["delay_seconds"],
            "idempotency_key": data["idempotency_key"],
            "duplicate_check": data["duplicate_check"],
            "created_at": now,
            "updated_at": now,
            "execution_allowed": data["decision"] in {
                RetryDecision.RETRY_NOW.value,
                RetryDecision.RETRY_LATER.value,
                RetryDecision.REQUIRE_SECURITY_APPROVAL.value,
            },
            "requires_security_approval": data["decision"] == RetryDecision.REQUIRE_SECURITY_APPROVAL.value,
            "reasons": data["reasons"],
            "step_snapshot": self._redact_sensitive(copy.deepcopy(dict(failed_step))),
        }

        return self._safe_result(
            message="Retry plan built.",
            data={"retry_plan": plan},
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
                "created_at": now,
            },
        )

    # ---------------------------------------------------------------------
    # Retry registration and execution
    # ---------------------------------------------------------------------

    def register_failed_step(
        self,
        failed_step: Mapping[str, Any],
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        policy: Optional[RetryPolicy] = None,
    ) -> Dict[str, Any]:
        """
        Register a failed step and store retry metadata.

        This does not execute the retry. It creates a RetryRecord for dashboard,
        monitoring, and audit visibility.
        """
        plan_result = self.build_retry_plan(failed_step=failed_step, error=error, policy=policy)
        if not plan_result["success"]:
            return plan_result

        plan = plan_result["data"]["retry_plan"]
        record = RetryRecord(
            retry_id=plan["retry_id"],
            user_id=plan["user_id"],
            workspace_id=plan["workspace_id"],
            workflow_id=plan["workflow_id"],
            run_id=plan["run_id"],
            step_id=plan["step_id"],
            action=plan["action"],
            attempt_number=plan["attempt_number"],
            status=RetryStatus.PENDING,
            idempotency_key=plan["idempotency_key"],
            created_at=plan["created_at"],
            updated_at=plan["updated_at"],
            message="Failed step registered for retry analysis.",
            error_type=plan["error_type"],
            error=self._error_to_string(error),
            metadata={
                "decision": plan["decision"],
                "safety_level": plan["safety_level"],
                "duplicate_check": plan["duplicate_check"],
                "requires_security_approval": plan["requires_security_approval"],
                "reasons": plan["reasons"],
            },
        )

        self._store_retry_record(record)

        self._log_audit_event(
            event_type="workflow.retry.registered",
            task_context=failed_step,
            details={"record": record.to_dict()},
        )
        self._emit_agent_event(
            event_type="workflow_retry_registered",
            payload={"record": record.to_dict()},
        )

        return self._safe_result(
            message="Failed step registered.",
            data={"retry_record": record.to_dict(), "retry_plan": plan},
            metadata={"agent": self.agent_name, "created_at": self._now_iso()},
        )

    def execute_retry(
        self,
        failed_step: Mapping[str, Any],
        executor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        policy: Optional[RetryPolicy] = None,
        wait: bool = False,
    ) -> Dict[str, Any]:
        """
        Build and execute a retry plan.

        Args:
            failed_step: Failed step context.
            executor: Callable that performs the actual retry. If omitted,
                action_executors[action] will be used.
            error: Optional previous error.
            policy: Optional retry policy override.
            wait: If True, sleeps for the plan delay before executing. For web/API
                contexts, keep False and let scheduler handle delayed retry.

        Returns:
            Structured result with retry execution details.
        """
        plan_result = self.build_retry_plan(failed_step=failed_step, error=error, policy=policy)
        if not plan_result["success"]:
            return plan_result

        plan = plan_result["data"]["retry_plan"]
        return self.execute_retry_plan(retry_plan=plan, executor=executor, wait=wait)

    def execute_retry_plan(
        self,
        retry_plan: Mapping[str, Any],
        executor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        wait: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a prebuilt retry plan safely.

        Duplicate guard is checked immediately before execution. Sensitive actions
        request security approval. Actual side effect execution is delegated to the
        supplied executor or a registered action executor.
        """
        if not isinstance(retry_plan, Mapping):
            return self._error_result(
                message="Invalid retry plan.",
                error="retry_plan must be a mapping/dict.",
            )

        step_snapshot = retry_plan.get("step_snapshot") or retry_plan
        validation = self._validate_task_context(step_snapshot)
        if not validation["success"]:
            return validation

        action = str(retry_plan.get("action") or step_snapshot.get("action") or "").strip()
        decision = str(retry_plan.get("decision", "")).strip()
        idempotency_key = str(retry_plan.get("idempotency_key") or self.build_idempotency_key(step_snapshot))
        duplicate_check = self.check_duplicate_risk(step_snapshot, idempotency_key=idempotency_key)
        duplicate_risk = bool(duplicate_check.get("data", {}).get("duplicate_risk"))

        if self.policy.duplicate_policy == DuplicatePolicy.STRICT and duplicate_risk:
            record = self._record_from_plan(
                retry_plan,
                status=RetryStatus.DUPLICATE_PREVENTED,
                message="Retry blocked to prevent duplicate side effect.",
                error="duplicate_risk_detected",
                metadata={"duplicate_check": duplicate_check.get("data", {})},
            )
            self._store_retry_record(record)
            self._log_audit_event(
                event_type="workflow.retry.duplicate_prevented",
                task_context=step_snapshot,
                details={"record": record.to_dict()},
            )
            return self._safe_result(
                success=False,
                message="Retry blocked to prevent duplicate leads/messages.",
                data={"retry_record": record.to_dict(), "duplicate_check": duplicate_check.get("data", {})},
                error={"code": "duplicate_risk_detected"},
                metadata={"status": RetryStatus.DUPLICATE_PREVENTED.value},
            )

        if decision in {
            RetryDecision.DO_NOT_RETRY.value,
            RetryDecision.DUPLICATE_RISK_BLOCKED.value,
        }:
            record = self._record_from_plan(
                retry_plan,
                status=RetryStatus.BLOCKED,
                message="Retry plan decision blocks execution.",
                error={"decision": decision},
            )
            self._store_retry_record(record)
            return self._error_result(
                message="Retry execution blocked by retry plan.",
                error={"decision": decision, "reasons": list(retry_plan.get("reasons", []))},
                data={"retry_record": record.to_dict()},
                metadata={"status": RetryStatus.BLOCKED.value},
            )

        if self._requires_security_check(action, step_snapshot):
            approval = self._request_security_approval(action=action, task_context=step_snapshot, retry_plan=retry_plan)
            if not approval["success"] or not bool(approval.get("data", {}).get("approved")):
                record = self._record_from_plan(
                    retry_plan,
                    status=RetryStatus.SECURITY_REVIEW_REQUIRED,
                    message="Retry requires security approval.",
                    error=approval.get("error"),
                    metadata={"security_approval": approval},
                )
                self._store_retry_record(record)
                self._log_audit_event(
                    event_type="workflow.retry.security_blocked",
                    task_context=step_snapshot,
                    details={"record": record.to_dict(), "security_approval": approval},
                )
                return self._error_result(
                    message="Retry requires Security Agent approval.",
                    error=approval.get("error") or {"code": "security_approval_required"},
                    data={"retry_record": record.to_dict(), "security_approval": approval.get("data", {})},
                    metadata={"status": RetryStatus.SECURITY_REVIEW_REQUIRED.value},
                )

        delay = self._safe_float(retry_plan.get("delay_seconds"), default=0.0)
        if wait and delay > 0:
            time.sleep(min(delay, self.policy.max_delay_seconds))

        chosen_executor = executor or self.action_executors.get(action)
        if chosen_executor is None:
            record = self._record_from_plan(
                retry_plan,
                status=RetryStatus.BLOCKED,
                message="No executor configured for retry action.",
                error={"action": action},
            )
            self._store_retry_record(record)
            return self._error_result(
                message="No executor configured for retry action.",
                error={"action": action},
                data={"retry_record": record.to_dict()},
                metadata={"status": RetryStatus.BLOCKED.value},
            )

        running_record = self._record_from_plan(
            retry_plan,
            status=RetryStatus.RUNNING,
            message="Retry execution started.",
        )
        self._store_retry_record(running_record)
        self._mark_idempotency_started(idempotency_key, step_snapshot, retry_plan)

        self._emit_agent_event(
            event_type="workflow_retry_started",
            payload={"retry_record": running_record.to_dict()},
        )

        started_at = time.monotonic()
        try:
            execution_context = self._build_execution_context(retry_plan, step_snapshot)
            raw_result = chosen_executor(execution_context)

            if not isinstance(raw_result, Mapping):
                raw_result = {
                    "success": True,
                    "message": "Executor completed.",
                    "data": {"raw_result": raw_result},
                    "error": None,
                    "metadata": {},
                }

            normalized_result = self._normalize_executor_result(raw_result)
            duration_ms = int((time.monotonic() - started_at) * 1000)

            if normalized_result["success"]:
                success_result = self.record_success(
                    retry_plan=retry_plan,
                    result=normalized_result,
                    duration_ms=duration_ms,
                )
                return success_result

            failure_result = self.record_failure(
                retry_plan=retry_plan,
                error=normalized_result.get("error") or normalized_result.get("message"),
                executor_result=normalized_result,
                duration_ms=duration_ms,
            )
            return failure_result

        except Exception as exc:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            self.logger.exception("Retry executor failed.")
            return self.record_failure(
                retry_plan=retry_plan,
                error=exc,
                executor_result=None,
                duration_ms=duration_ms,
                include_traceback=True,
            )

    def record_success(
        self,
        retry_plan: Mapping[str, Any],
        result: Mapping[str, Any],
        duration_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Record successful retry and update idempotency store.

        This prepares verification and memory payloads for downstream agents.
        """
        step_snapshot = retry_plan.get("step_snapshot") or retry_plan
        idempotency_key = str(retry_plan.get("idempotency_key") or self.build_idempotency_key(step_snapshot))

        result_fingerprint = self._fingerprint(result.get("data", result))
        self._mark_idempotency_completed(
            idempotency_key=idempotency_key,
            task_context=step_snapshot,
            retry_plan=retry_plan,
            result_fingerprint=result_fingerprint,
            result=result,
        )

        record = self._record_from_plan(
            retry_plan,
            status=RetryStatus.SUCCEEDED,
            message=str(result.get("message", "Retry succeeded.")),
            metadata={
                "executor_result": self._redact_sensitive(copy.deepcopy(dict(result))),
                "duration_ms": duration_ms,
                "result_fingerprint": result_fingerprint,
            },
        )
        self._store_retry_record(record)

        verification_payload = self._prepare_verification_payload(
            task_context=step_snapshot,
            retry_record=record.to_dict(),
            result=dict(result),
            status=RetryStatus.SUCCEEDED,
        )
        memory_payload = self._prepare_memory_payload(
            task_context=step_snapshot,
            retry_record=record.to_dict(),
            result=dict(result),
        )

        self._send_verification_payload(verification_payload)
        self._send_memory_payload(memory_payload)

        self._log_audit_event(
            event_type="workflow.retry.succeeded",
            task_context=step_snapshot,
            details={
                "record": record.to_dict(),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
        )
        self._emit_agent_event(
            event_type="workflow_retry_succeeded",
            payload={"retry_record": record.to_dict(), "verification_payload": verification_payload},
        )

        return self._safe_result(
            message="Retry succeeded.",
            data={
                "retry_record": record.to_dict(),
                "executor_result": dict(result),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "status": RetryStatus.SUCCEEDED.value,
                "duration_ms": duration_ms,
                "agent": self.agent_name,
            },
        )

    def record_failure(
        self,
        retry_plan: Mapping[str, Any],
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        executor_result: Optional[Mapping[str, Any]] = None,
        duration_ms: Optional[int] = None,
        include_traceback: bool = False,
    ) -> Dict[str, Any]:
        """
        Record failed retry attempt.

        If attempts are exhausted, status becomes EXHAUSTED.
        """
        step_snapshot = retry_plan.get("step_snapshot") or retry_plan
        attempt_number = self._safe_int(retry_plan.get("attempt_number"), default=1)
        max_attempts = self._safe_int(retry_plan.get("max_attempts"), default=self.policy.max_attempts)
        status = RetryStatus.EXHAUSTED if attempt_number >= max_attempts else RetryStatus.FAILED
        error_type = self.classify_error(error).value

        metadata: Dict[str, Any] = {
            "duration_ms": duration_ms,
            "error_type": error_type,
        }
        if executor_result is not None:
            metadata["executor_result"] = self._redact_sensitive(copy.deepcopy(dict(executor_result)))
        if include_traceback:
            metadata["traceback"] = traceback.format_exc()

        record = self._record_from_plan(
            retry_plan,
            status=status,
            message="Retry failed." if status == RetryStatus.FAILED else "Retry attempts exhausted.",
            error=self._error_to_safe_payload(error),
            metadata=metadata,
        )
        record.error_type = error_type
        self._store_retry_record(record)

        idempotency_key = str(retry_plan.get("idempotency_key") or self.build_idempotency_key(step_snapshot))
        self._mark_idempotency_failed(idempotency_key, step_snapshot, retry_plan, error)

        verification_payload = self._prepare_verification_payload(
            task_context=step_snapshot,
            retry_record=record.to_dict(),
            result=dict(executor_result or {}),
            status=status,
        )

        self._send_verification_payload(verification_payload)

        self._log_audit_event(
            event_type="workflow.retry.failed",
            task_context=step_snapshot,
            details={"record": record.to_dict(), "verification_payload": verification_payload},
        )
        self._emit_agent_event(
            event_type="workflow_retry_failed",
            payload={"retry_record": record.to_dict(), "verification_payload": verification_payload},
        )

        return self._error_result(
            message=record.message,
            error=record.error,
            data={
                "retry_record": record.to_dict(),
                "executor_result": dict(executor_result or {}),
                "verification_payload": verification_payload,
            },
            metadata={
                "status": status.value,
                "duration_ms": duration_ms,
                "agent": self.agent_name,
            },
        )

    # ---------------------------------------------------------------------
    # Idempotency and duplicate prevention
    # ---------------------------------------------------------------------

    def build_idempotency_key(self, task_context: Mapping[str, Any]) -> str:
        """
        Build a stable idempotency key scoped by user/workspace/workflow/step/action.

        This prevents cross-user/workspace mixing and duplicate side effects.
        The payload fingerprint includes common duplicate-sensitive fields such as
        recipient, phone, email, lead identity, CRM entity, sheet row identity, and
        external id.
        """
        user_id = str(task_context.get("user_id", "")).strip()
        workspace_id = str(task_context.get("workspace_id", "")).strip()
        workflow_id = str(task_context.get("workflow_id", "")).strip()
        run_id = str(task_context.get("run_id", "")).strip()
        step_id = str(task_context.get("step_id", "")).strip()
        action = self._normalize_action(str(task_context.get("action", "") or task_context.get("step_type", "")))

        payload = task_context.get("payload", {})
        metadata = task_context.get("metadata", {})

        dedupe_material = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "workflow_id": workflow_id,
            "run_id": run_id,
            "step_id": step_id,
            "action": action,
            "dedupe": self._extract_dedupe_fields(payload if isinstance(payload, Mapping) else {}),
            "metadata_dedupe": self._extract_dedupe_fields(metadata if isinstance(metadata, Mapping) else {}),
        }

        explicit_key = task_context.get("idempotency_key") or task_context.get("dedupe_key")
        if explicit_key:
            dedupe_material["explicit_key"] = str(explicit_key)

        fingerprint = self._fingerprint(dedupe_material)
        return f"idem:{user_id}:{workspace_id}:{workflow_id}:{step_id}:{action}:{fingerprint}"

    def check_duplicate_risk(
        self,
        task_context: Mapping[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check whether retry could duplicate a completed side effect.

        Checks:
            - Idempotency key already completed/processing.
            - Similar completed fingerprint for same user/workspace/action.
            - Explicit duplicate markers in task context.
        """
        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        key = idempotency_key or self.build_idempotency_key(task_context)
        action = self._normalize_action(str(task_context.get("action", "") or task_context.get("step_type", "")))
        user_id = str(task_context.get("user_id"))
        workspace_id = str(task_context.get("workspace_id"))

        duplicate_risk = False
        reasons: List[str] = []
        matched_entries: List[Dict[str, Any]] = []

        explicit_duplicate = bool(task_context.get("duplicate_detected") or task_context.get("already_completed"))
        if explicit_duplicate:
            duplicate_risk = True
            reasons.append("explicit_duplicate_marker")

        with self._lock:
            entry = self._idempotency_store.get(key)
            if entry is not None and entry.status in {"completed", "processing"}:
                duplicate_risk = True
                reasons.append(f"idempotency_key_{entry.status}")
                matched_entries.append(entry.to_dict())

            fingerprint = self._side_effect_fingerprint(task_context)
            scoped_key = f"{user_id}:{workspace_id}:{action}:{fingerprint}"
            existing = self._completed_step_fingerprints.get(scoped_key)
            if existing:
                duplicate_risk = True
                reasons.append("matching_completed_side_effect_fingerprint")
                matched_entries.append(copy.deepcopy(existing))

        safety = self.classify_action_safety(action, task_context)
        duplicate_sensitive = safety in {StepSafetyLevel.CAUTION, StepSafetyLevel.SENSITIVE}

        return self._safe_result(
            message="Duplicate risk checked.",
            data={
                "duplicate_risk": bool(duplicate_risk and duplicate_sensitive),
                "raw_duplicate_match": duplicate_risk,
                "duplicate_sensitive": duplicate_sensitive,
                "reasons": reasons,
                "idempotency_key": key,
                "matched_entries": matched_entries,
                "duplicate_policy": self.policy.duplicate_policy.value,
            },
            metadata={
                "agent": self.agent_name,
                "checked_at": self._now_iso(),
            },
        )

    def get_idempotency_entry(self, idempotency_key: str) -> Dict[str, Any]:
        """Return one idempotency entry by key."""
        with self._lock:
            entry = self._idempotency_store.get(str(idempotency_key))
            if not entry:
                return self._error_result(
                    message="Idempotency entry not found.",
                    error={"idempotency_key": idempotency_key},
                )
            return self._safe_result(
                message="Idempotency entry found.",
                data={"entry": entry.to_dict()},
            )

    # ---------------------------------------------------------------------
    # History and registry-style helpers
    # ---------------------------------------------------------------------

    def register_action_executor(
        self,
        action: str,
        executor: Callable[[Dict[str, Any]], Dict[str, Any]],
        replace: bool = True,
    ) -> Dict[str, Any]:
        """
        Register an executor for an action.

        The Master Agent or Action Router can use this to bind connector methods.
        """
        normalized = self._normalize_action(action)
        if not normalized:
            return self._error_result("Action name is required.", error="empty_action")
        if not callable(executor):
            return self._error_result("Executor must be callable.", error="non_callable_executor")

        if not replace and normalized in self.action_executors:
            return self._error_result(
                message="Executor already registered.",
                error={"action": normalized},
            )

        self.action_executors[normalized] = executor
        return self._safe_result(
            message="Action executor registered.",
            data={"action": normalized, "replace": replace},
        )

    def get_retry_history(
        self,
        user_id: str,
        workspace_id: str,
        workflow_id: Optional[str] = None,
        run_id: Optional[str] = None,
        step_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return retry history scoped by user/workspace.

        Never returns records from another user/workspace.
        """
        if not str(user_id).strip() or not str(workspace_id).strip():
            return self._error_result(
                message="user_id and workspace_id are required.",
                error="missing_scope",
            )

        records: List[Dict[str, Any]] = []
        with self._lock:
            for record_list in self._retry_history.values():
                for record in record_list:
                    if record.user_id != str(user_id) or record.workspace_id != str(workspace_id):
                        continue
                    if workflow_id and record.workflow_id != str(workflow_id):
                        continue
                    if run_id and record.run_id != str(run_id):
                        continue
                    if step_id and record.step_id != str(step_id):
                        continue
                    records.append(record.to_dict())

        records.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
        safe_limit = max(1, min(int(limit), 1000))

        return self._safe_result(
            message="Retry history retrieved.",
            data={
                "records": records[:safe_limit],
                "count": min(len(records), safe_limit),
                "total_matching": len(records),
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "limit": safe_limit,
            },
        )

    def clear_expired_records(
        self,
        older_than_seconds: int = 86400 * 30,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Clear old in-memory retry/idempotency records.

        In production this would be backed by a database TTL/archive job. This
        method is safe and scoped when user_id/workspace_id are provided.
        """
        cutoff = self.clock().timestamp() - max(0, int(older_than_seconds))
        removed_retry_records = 0
        removed_idempotency_entries = 0

        with self._lock:
            for key in list(self._retry_history.keys()):
                kept: List[RetryRecord] = []
                for record in self._retry_history[key]:
                    if user_id and record.user_id != str(user_id):
                        kept.append(record)
                        continue
                    if workspace_id and record.workspace_id != str(workspace_id):
                        kept.append(record)
                        continue
                    record_time = self._parse_iso_timestamp(record.updated_at)
                    if record_time is not None and record_time < cutoff:
                        removed_retry_records += 1
                    else:
                        kept.append(record)

                if kept:
                    self._retry_history[key] = kept
                else:
                    self._retry_history.pop(key, None)

            for key, entry in list(self._idempotency_store.items()):
                if user_id and entry.user_id != str(user_id):
                    continue
                if workspace_id and entry.workspace_id != str(workspace_id):
                    continue
                entry_time = self._parse_iso_timestamp(entry.updated_at)
                if entry_time is not None and entry_time < cutoff:
                    self._idempotency_store.pop(key, None)
                    removed_idempotency_entries += 1

        return self._safe_result(
            message="Expired retry records cleared.",
            data={
                "removed_retry_records": removed_retry_records,
                "removed_idempotency_entries": removed_idempotency_entries,
            },
            metadata={
                "older_than_seconds": older_than_seconds,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return metadata useful for Agent Registry / Agent Loader.
        """
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module_name": self.module_name,
            "file_name": self.file_name,
            "class_name": self.__class__.__name__,
            "public_methods": [
                "analyze_failed_step",
                "should_retry",
                "build_retry_plan",
                "register_failed_step",
                "execute_retry",
                "execute_retry_plan",
                "record_success",
                "record_failure",
                "get_retry_history",
                "get_idempotency_entry",
                "clear_expired_records",
                "register_action_executor",
                "get_registry_metadata",
                "health_check",
            ],
            "supports_user_workspace_isolation": True,
            "requires_security_for_sensitive_actions": self.policy.require_security_for_sensitive,
            "supports_idempotency": True,
            "supports_verification_payload": True,
            "supports_memory_payload": True,
            "import_safe": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for dashboard/API readiness.
        """
        with self._lock:
            retry_records = sum(len(items) for items in self._retry_history.values())
            idempotency_entries = len(self._idempotency_store)

        return self._safe_result(
            message="RetryHandler is healthy.",
            data={
                "agent": self.agent_name,
                "module": self.module_name,
                "policy": self.policy_to_dict(self.policy),
                "registered_executors": sorted(self.action_executors.keys()),
                "retry_records": retry_records,
                "idempotency_entries": idempotency_entries,
                "enable_in_memory_store": self.enable_in_memory_store,
            },
            metadata={"checked_at": self._now_iso()},
        )

    # ---------------------------------------------------------------------
    # Verification, memory, events, audit
    # ---------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        task_context: Mapping[str, Any],
        retry_record: Mapping[str, Any],
        result: Optional[Mapping[str, Any]] = None,
        status: RetryStatus = RetryStatus.SUCCEEDED,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can confirm:
            - Retry did not cross user/workspace boundary.
            - Idempotency key was used.
            - Sensitive retries had security path.
            - Output matches expected structured result.
        """
        return {
            "verification_id": self._new_id("verify"),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "event": "workflow_retry_completed",
            "status": status.value if isinstance(status, RetryStatus) else str(status),
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "workflow_id": str(task_context.get("workflow_id", "")),
            "run_id": str(task_context.get("run_id", "")),
            "step_id": str(task_context.get("step_id", "")),
            "action": str(task_context.get("action", "")),
            "checks": {
                "user_workspace_isolation": True,
                "idempotency_key_present": bool(retry_record.get("idempotency_key")),
                "duplicate_prevention_checked": True,
                "structured_result": True,
                "security_hook_available": True,
            },
            "retry_record": self._redact_sensitive(copy.deepcopy(dict(retry_record))),
            "result_summary": self._summarize_result(result or {}),
            "created_at": self._now_iso(),
        }

    def _prepare_memory_payload(
        self,
        task_context: Mapping[str, Any],
        retry_record: Mapping[str, Any],
        result: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Useful for learning failure patterns, retry success rates, provider issues,
        and workflow optimization. It remains scoped by user/workspace.
        """
        return {
            "memory_id": self._new_id("mem"),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "memory_type": "workflow_retry_event",
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "workflow_id": str(task_context.get("workflow_id", "")),
            "run_id": str(task_context.get("run_id", "")),
            "step_id": str(task_context.get("step_id", "")),
            "action": str(task_context.get("action", "")),
            "summary": {
                "retry_status": retry_record.get("status"),
                "attempt_number": retry_record.get("attempt_number"),
                "error_type": retry_record.get("error_type"),
                "message": retry_record.get("message"),
                "result_success": bool((result or {}).get("success", False)),
            },
            "tags": [
                "workflow",
                "retry",
                str(retry_record.get("status", "unknown")),
                str(retry_record.get("error_type", "unknown")),
            ],
            "created_at": self._now_iso(),
            "retention_hint": "medium_term_operational_analytics",
        }

    def _emit_agent_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        """
        Emit event for Dashboard/API/Agent Router.

        Silent failure by design so retry flow is not broken by dashboard outage.
        """
        event = {
            "event_id": self._new_id("evt"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "payload": self._redact_sensitive(copy.deepcopy(dict(payload))),
            "created_at": self._now_iso(),
        }

        try:
            if self.event_emitter is not None:
                if hasattr(self.event_emitter, "emit"):
                    self.event_emitter.emit(event_type, event)
                elif callable(self.event_emitter):
                    self.event_emitter(event_type, event)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_type, event)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("BaseAgent emit_event failed.", exc_info=True)
        except Exception:
            self.logger.debug("Event emission failed.", exc_info=True)

    def _log_audit_event(
        self,
        event_type: str,
        task_context: Mapping[str, Any],
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event with user/workspace isolation.

        Silent failure by design; audit integrations should not crash retry flow.
        """
        payload = {
            "audit_id": self._new_id("audit"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "workflow_id": str(task_context.get("workflow_id", "")),
            "run_id": str(task_context.get("run_id", "")),
            "step_id": str(task_context.get("step_id", "")),
            "action": str(task_context.get("action", "")),
            "details": self._redact_sensitive(copy.deepcopy(dict(details or {}))),
            "created_at": self._now_iso(),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(payload)
                elif hasattr(self.audit_logger, "log_audit"):
                    self.audit_logger.log_audit(payload)
                elif callable(self.audit_logger):
                    self.audit_logger(payload)
                return

            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(payload)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("BaseAgent audit log failed.", exc_info=True)
        except Exception:
            self.logger.debug("Audit logging failed.", exc_info=True)

    def _send_verification_payload(self, payload: Mapping[str, Any]) -> None:
        """Send payload to Verification Agent/client if configured."""
        try:
            if self.verification_client is None:
                return
            if hasattr(self.verification_client, "verify"):
                self.verification_client.verify(dict(payload))
            elif hasattr(self.verification_client, "submit"):
                self.verification_client.submit(dict(payload))
            elif callable(self.verification_client):
                self.verification_client(dict(payload))
        except Exception:
            self.logger.debug("Verification payload send failed.", exc_info=True)

    def _send_memory_payload(self, payload: Mapping[str, Any]) -> None:
        """Send payload to Memory Agent/client if configured."""
        try:
            if self.memory_client is None:
                return
            if hasattr(self.memory_client, "remember"):
                self.memory_client.remember(dict(payload))
            elif hasattr(self.memory_client, "store"):
                self.memory_client.store(dict(payload))
            elif callable(self.memory_client):
                self.memory_client(dict(payload))
        except Exception:
            self.logger.debug("Memory payload send failed.", exc_info=True)

    # ---------------------------------------------------------------------
    # Error classification and delay
    # ---------------------------------------------------------------------

    def classify_error(self, error: Optional[Union[str, Exception, Mapping[str, Any]]]) -> RetryableErrorType:
        """
        Classify error into retryable/permanent categories.
        """
        if error is None:
            return RetryableErrorType.UNKNOWN

        if isinstance(error, Mapping):
            explicit = str(
                error.get("error_type")
                or error.get("type")
                or error.get("code")
                or error.get("category")
                or ""
            ).strip().lower()
            for item in RetryableErrorType:
                if explicit == item.value:
                    return item
            text = json.dumps(self._json_safe(error), sort_keys=True).lower()
        elif isinstance(error, Exception):
            text = f"{error.__class__.__name__}: {error}".lower()
        else:
            text = str(error).lower()

        for error_type, keywords in PERMANENT_ERROR_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                return error_type

        for error_type, keywords in TRANSIENT_ERROR_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                return error_type

        return RetryableErrorType.UNKNOWN

    def compute_retry_delay(
        self,
        attempt_number: int,
        policy: Optional[RetryPolicy] = None,
        error_type: RetryableErrorType = RetryableErrorType.UNKNOWN,
    ) -> float:
        """
        Compute exponential backoff with jitter.

        Rate limits receive a slightly stronger delay multiplier.
        """
        active_policy = (policy or self.policy).normalized()
        attempt = max(1, int(attempt_number))

        base = active_policy.base_delay_seconds
        multiplier = active_policy.backoff_multiplier
        if error_type == RetryableErrorType.RATE_LIMIT:
            multiplier = max(multiplier, 2.5)
            base = max(base, 5.0)

        delay = base * math.pow(multiplier, attempt - 1)
        delay = min(delay, active_policy.max_delay_seconds)

        if active_policy.jitter_seconds > 0:
            delay += random.uniform(0, active_policy.jitter_seconds)

        return round(max(0.0, delay), 3)

    # ---------------------------------------------------------------------
    # Internal stores
    # ---------------------------------------------------------------------

    def _store_retry_record(self, record: RetryRecord) -> None:
        """Store retry record in memory if enabled."""
        if not self.enable_in_memory_store:
            return

        scoped_key = self._history_key(
            user_id=record.user_id,
            workspace_id=record.workspace_id,
            workflow_id=record.workflow_id,
            run_id=record.run_id,
            step_id=record.step_id,
        )
        with self._lock:
            self._retry_history.setdefault(scoped_key, []).append(record)

    def _mark_idempotency_started(
        self,
        idempotency_key: str,
        task_context: Mapping[str, Any],
        retry_plan: Mapping[str, Any],
    ) -> None:
        """Mark idempotency key as processing."""
        if not self.enable_in_memory_store:
            return

        now = self._now_iso()
        entry = IdempotencyEntry(
            key=idempotency_key,
            user_id=str(task_context.get("user_id", "")),
            workspace_id=str(task_context.get("workspace_id", "")),
            workflow_id=str(task_context.get("workflow_id", "")),
            run_id=str(task_context.get("run_id", "")),
            step_id=str(task_context.get("step_id", "")),
            action=self._normalize_action(str(task_context.get("action", retry_plan.get("action", "")))),
            status="processing",
            result_fingerprint=None,
            created_at=now,
            updated_at=now,
            metadata={
                "retry_id": retry_plan.get("retry_id"),
                "attempt_number": retry_plan.get("attempt_number"),
            },
        )
        with self._lock:
            self._idempotency_store[idempotency_key] = entry

    def _mark_idempotency_completed(
        self,
        idempotency_key: str,
        task_context: Mapping[str, Any],
        retry_plan: Mapping[str, Any],
        result_fingerprint: str,
        result: Mapping[str, Any],
    ) -> None:
        """Mark idempotency key as completed and store side-effect fingerprint."""
        if not self.enable_in_memory_store:
            return

        now = self._now_iso()
        action = self._normalize_action(str(task_context.get("action", retry_plan.get("action", ""))))
        entry = IdempotencyEntry(
            key=idempotency_key,
            user_id=str(task_context.get("user_id", "")),
            workspace_id=str(task_context.get("workspace_id", "")),
            workflow_id=str(task_context.get("workflow_id", "")),
            run_id=str(task_context.get("run_id", "")),
            step_id=str(task_context.get("step_id", "")),
            action=action,
            status="completed",
            result_fingerprint=result_fingerprint,
            created_at=now,
            updated_at=now,
            metadata={
                "retry_id": retry_plan.get("retry_id"),
                "attempt_number": retry_plan.get("attempt_number"),
                "result_summary": self._summarize_result(result),
            },
        )

        side_effect_key = (
            f"{entry.user_id}:{entry.workspace_id}:{action}:"
            f"{self._side_effect_fingerprint(task_context)}"
        )

        with self._lock:
            self._idempotency_store[idempotency_key] = entry
            self._completed_step_fingerprints[side_effect_key] = entry.to_dict()

    def _mark_idempotency_failed(
        self,
        idempotency_key: str,
        task_context: Mapping[str, Any],
        retry_plan: Mapping[str, Any],
        error: Optional[Union[str, Exception, Mapping[str, Any]]],
    ) -> None:
        """Mark idempotency entry as failed."""
        if not self.enable_in_memory_store:
            return

        now = self._now_iso()
        entry = IdempotencyEntry(
            key=idempotency_key,
            user_id=str(task_context.get("user_id", "")),
            workspace_id=str(task_context.get("workspace_id", "")),
            workflow_id=str(task_context.get("workflow_id", "")),
            run_id=str(task_context.get("run_id", "")),
            step_id=str(task_context.get("step_id", "")),
            action=self._normalize_action(str(task_context.get("action", retry_plan.get("action", "")))),
            status="failed",
            result_fingerprint=None,
            created_at=now,
            updated_at=now,
            metadata={
                "retry_id": retry_plan.get("retry_id"),
                "attempt_number": retry_plan.get("attempt_number"),
                "error": self._error_to_safe_payload(error),
            },
        )
        with self._lock:
            self._idempotency_store[idempotency_key] = entry

    # ---------------------------------------------------------------------
    # Internal record/context builders
    # ---------------------------------------------------------------------

    def _record_from_plan(
        self,
        retry_plan: Mapping[str, Any],
        status: RetryStatus,
        message: str,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RetryRecord:
        """Build RetryRecord from retry plan."""
        now = self._now_iso()
        step_snapshot = retry_plan.get("step_snapshot") or retry_plan

        return RetryRecord(
            retry_id=str(retry_plan.get("retry_id") or self._new_id("retry")),
            user_id=str(retry_plan.get("user_id") or step_snapshot.get("user_id", "")),
            workspace_id=str(retry_plan.get("workspace_id") or step_snapshot.get("workspace_id", "")),
            workflow_id=str(retry_plan.get("workflow_id") or step_snapshot.get("workflow_id", "")),
            run_id=str(retry_plan.get("run_id") or step_snapshot.get("run_id", "")),
            step_id=str(retry_plan.get("step_id") or step_snapshot.get("step_id", "")),
            action=str(retry_plan.get("action") or step_snapshot.get("action", "")),
            attempt_number=self._safe_int(retry_plan.get("attempt_number"), default=1),
            status=status,
            idempotency_key=str(retry_plan.get("idempotency_key") or self.build_idempotency_key(step_snapshot)),
            created_at=str(retry_plan.get("created_at") or now),
            updated_at=now,
            message=message,
            error_type=str(retry_plan.get("error_type") or RetryableErrorType.UNKNOWN.value),
            error=self._error_to_string(error),
            metadata=metadata or {},
        )

    def _build_execution_context(
        self,
        retry_plan: Mapping[str, Any],
        step_snapshot: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Build executor context.

        Executors receive this structured context and should return:
            {"success": bool, "message": str, "data": dict, "error": any, "metadata": dict}
        """
        context = copy.deepcopy(dict(step_snapshot))
        context["retry"] = {
            "retry_id": retry_plan.get("retry_id"),
            "attempt_number": retry_plan.get("attempt_number"),
            "max_attempts": retry_plan.get("max_attempts"),
            "idempotency_key": retry_plan.get("idempotency_key"),
            "safety_level": retry_plan.get("safety_level"),
            "created_at": retry_plan.get("created_at"),
        }
        context["idempotency_key"] = retry_plan.get("idempotency_key")
        context["is_retry"] = True
        return context

    # ---------------------------------------------------------------------
    # Utility methods
    # ---------------------------------------------------------------------

    def policy_to_dict(self, policy: Optional[RetryPolicy] = None) -> Dict[str, Any]:
        """Convert RetryPolicy to dict."""
        active_policy = (policy or self.policy).normalized()
        return {
            "max_attempts": active_policy.max_attempts,
            "base_delay_seconds": active_policy.base_delay_seconds,
            "max_delay_seconds": active_policy.max_delay_seconds,
            "backoff_multiplier": active_policy.backoff_multiplier,
            "jitter_seconds": active_policy.jitter_seconds,
            "duplicate_policy": active_policy.duplicate_policy.value,
            "require_security_for_sensitive": active_policy.require_security_for_sensitive,
            "allow_caution_without_security": active_policy.allow_caution_without_security,
            "allow_unknown_action_retry": active_policy.allow_unknown_action_retry,
            "retryable_error_types": [item.value for item in active_policy.retryable_error_types],
        }

    def _normalize_executor_result(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize executor result to William/Jarvis structured result format."""
        return {
            "success": bool(result.get("success", False)),
            "message": str(result.get("message", "Executor returned result.")),
            "data": dict(result.get("data", {}) or {}),
            "error": result.get("error"),
            "metadata": dict(result.get("metadata", {}) or {}),
        }

    def _extract_dedupe_fields(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Extract duplicate-sensitive fields from payload.

        Avoids hashing entire payload with volatile values while preserving
        lead/message/CRM/sheet/email duplicate protection.
        """
        important_keys = {
            "lead_id",
            "contact_id",
            "deal_id",
            "customer_id",
            "external_id",
            "provider_id",
            "message_id",
            "thread_id",
            "email",
            "to",
            "recipient",
            "phone",
            "phone_number",
            "whatsapp",
            "full_name",
            "name",
            "company",
            "domain",
            "sheet_id",
            "row_id",
            "record_id",
            "crm_id",
            "subject",
            "template_id",
            "campaign_id",
            "form_id",
            "submission_id",
        }

        extracted: Dict[str, Any] = {}
        for key, value in payload.items():
            key_str = str(key)
            lower = key_str.lower()
            if lower in important_keys or lower.endswith("_id") or lower.endswith("_email") or lower.endswith("_phone"):
                extracted[lower] = self._normalize_dedupe_value(value)

        nested_keys = ("lead", "contact", "deal", "customer", "message", "email_payload", "crm", "sheet", "form")
        for nested_key in nested_keys:
            nested = payload.get(nested_key)
            if isinstance(nested, Mapping):
                nested_extracted = self._extract_dedupe_fields(nested)
                if nested_extracted:
                    extracted[nested_key] = nested_extracted

        if not extracted:
            extracted["payload_fingerprint"] = self._fingerprint(self._strip_volatile_fields(payload))

        return extracted

    def _side_effect_fingerprint(self, task_context: Mapping[str, Any]) -> str:
        """Build duplicate-sensitive side-effect fingerprint."""
        payload = task_context.get("payload", {})
        metadata = task_context.get("metadata", {})
        material = {
            "action": self._normalize_action(str(task_context.get("action", "") or task_context.get("step_type", ""))),
            "step_id": str(task_context.get("step_id", "")),
            "dedupe": self._extract_dedupe_fields(payload if isinstance(payload, Mapping) else {}),
            "metadata_dedupe": self._extract_dedupe_fields(metadata if isinstance(metadata, Mapping) else {}),
        }
        return self._fingerprint(material)

    def _strip_volatile_fields(self, value: Any) -> Any:
        """Remove volatile fields before fingerprinting."""
        volatile_keys = {
            "timestamp",
            "created_at",
            "updated_at",
            "last_seen",
            "attempt",
            "attempt_number",
            "retry_count",
            "nonce",
            "request_id",
            "trace_id",
            "span_id",
            "session_id",
        }

        if isinstance(value, Mapping):
            return {
                str(k): self._strip_volatile_fields(v)
                for k, v in value.items()
                if str(k).lower() not in volatile_keys
            }
        if isinstance(value, list):
            return [self._strip_volatile_fields(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._strip_volatile_fields(item) for item in value)
        return value

    def _normalize_dedupe_value(self, value: Any) -> Any:
        """Normalize values used for duplicate checks."""
        if isinstance(value, str):
            return " ".join(value.strip().lower().split())
        if isinstance(value, Mapping):
            return {str(k).lower(): self._normalize_dedupe_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._normalize_dedupe_value(v) for v in value]
        return value

    def _fingerprint(self, value: Any) -> str:
        """Create deterministic SHA256 fingerprint."""
        safe_value = self._json_safe(value)
        encoded = json.dumps(safe_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:32]

    def _json_safe(self, value: Any) -> Any:
        """Convert arbitrary Python value into JSON-safe structure."""
        if dataclasses.is_dataclass(value):
            return self._json_safe(dataclasses.asdict(value))
        if isinstance(value, enum.Enum):
            return value.value
        if isinstance(value, Mapping):
            return {str(k): self._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe(v) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    def _redact_sensitive(self, value: Any) -> Any:
        """Redact secrets/tokens/passwords from payloads before audit/events."""
        sensitive_fragments = (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth_key",
            "private_key",
            "access_key",
            "refresh",
            "bearer",
            "cookie",
        )

        if isinstance(value, Mapping):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                key_str = str(key)
                if any(fragment in key_str.lower() for fragment in sensitive_fragments):
                    redacted[key_str] = "***REDACTED***"
                else:
                    redacted[key_str] = self._redact_sensitive(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_sensitive(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact_sensitive(item) for item in value)
        return value

    def _summarize_result(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Return safe compact result summary."""
        data = result.get("data", {}) if isinstance(result, Mapping) else {}
        metadata = result.get("metadata", {}) if isinstance(result, Mapping) else {}

        return {
            "success": bool(result.get("success", False)) if isinstance(result, Mapping) else False,
            "message": str(result.get("message", ""))[:300] if isinstance(result, Mapping) else "",
            "data_keys": sorted([str(k) for k in data.keys()]) if isinstance(data, Mapping) else [],
            "metadata_keys": sorted([str(k) for k in metadata.keys()]) if isinstance(metadata, Mapping) else [],
            "error_present": bool(result.get("error")) if isinstance(result, Mapping) else False,
        }

    def _normalize_action(self, action: str) -> str:
        """Normalize action names."""
        return str(action or "").strip().lower().replace(" ", "_").replace("-", "_")

    def _new_id(self, prefix: str) -> str:
        """Generate readable unique ID."""
        return f"{prefix}_{uuid.uuid4().hex}"

    def _now_iso(self) -> str:
        """Return current UTC ISO timestamp."""
        return self.clock().astimezone(timezone.utc).isoformat()

    def _history_key(
        self,
        user_id: str,
        workspace_id: str,
        workflow_id: str,
        run_id: str,
        step_id: str,
    ) -> str:
        """Scoped retry history key."""
        return f"{user_id}:{workspace_id}:{workflow_id}:{run_id}:{step_id}"

    def _safe_int(self, value: Any, default: int = 0) -> int:
        """Safely parse int."""
        try:
            if value is None or value == "":
                return default
            return int(value)
        except Exception:
            return default

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Safely parse float."""
        try:
            if value is None or value == "":
                return default
            return float(value)
        except Exception:
            return default

    def _error_to_string(self, error: Optional[Any]) -> Optional[str]:
        """Convert error to safe string."""
        if error is None:
            return None
        if isinstance(error, Exception):
            return f"{error.__class__.__name__}: {error}"
        if isinstance(error, Mapping):
            return json.dumps(self._json_safe(self._redact_sensitive(error)), sort_keys=True)
        return str(error)

    def _error_to_safe_payload(self, error: Optional[Any]) -> Optional[Union[str, Dict[str, Any]]]:
        """Convert error to safe structured payload."""
        if error is None:
            return None
        if isinstance(error, Exception):
            return {"type": error.__class__.__name__, "message": str(error)}
        if isinstance(error, Mapping):
            return self._redact_sensitive(self._json_safe(error))
        return str(error)

    def _parse_iso_timestamp(self, value: str) -> Optional[float]:
        """Parse ISO timestamp to UNIX seconds."""
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Convenience factory and module exports
# ---------------------------------------------------------------------------

def create_retry_handler(
    policy: Optional[RetryPolicy] = None,
    action_executors: Optional[Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
    **kwargs: Any,
) -> RetryHandler:
    """
    Factory used by Agent Loader / Registry.

    Example:
        handler = create_retry_handler()
    """
    return RetryHandler(policy=policy, action_executors=action_executors, **kwargs)


__all__ = [
    "RetryHandler",
    "RetryPolicy",
    "RetryRecord",
    "IdempotencyEntry",
    "RetryStatus",
    "RetryDecision",
    "StepSafetyLevel",
    "DuplicatePolicy",
    "RetryableErrorType",
    "create_retry_handler",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    handler = RetryHandler()

    def demo_executor(context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Demo retry executed safely.",
            "data": {
                "received_retry_id": context.get("retry", {}).get("retry_id"),
                "idempotency_key": context.get("idempotency_key"),
            },
            "error": None,
            "metadata": {"demo": True},
        }

    handler.register_action_executor("validate", demo_executor)

    demo_step = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "workflow_id": "workflow_001",
        "run_id": "run_001",
        "step_id": "step_validate_001",
        "action": "validate",
        "attempt_number": 0,
        "payload": {
            "lead_id": "lead_123",
            "email": "client@example.com",
            "phone": "+15551234567",
        },
        "metadata": {
            "source": "retry_handler_self_test",
        },
    }

    print(json.dumps(handler.execute_retry(demo_step, error="temporary timeout"), indent=2))