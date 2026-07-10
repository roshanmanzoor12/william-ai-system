"""
agents/verification_agent/retry_manager.py

RetryManager for William / Jarvis Verification Agent.

Purpose:
    Retries safe failed tasks and stops risky/infinite retries.

Architecture Fit:
    - Master Agent can route failed task results here to decide whether a retry is safe.
    - Verification Agent can use this file after ErrorDetector/ResultValidator/ActionReplayChecker.
    - Security Agent is consulted for sensitive or uncertain retry decisions.
    - Memory Agent can receive retry patterns, repeated failures, and final outcomes.
    - Dashboard/API can display retry plans, attempts, backoff, blocked retries, and audit data.
    - Agent Registry/Loader can import this file safely even before the full system exists.

Safety Principles:
    - Never retries destructive, financial, messaging, call, browser automation, or system actions
      unless explicitly approved by the security gate.
    - Stops infinite retries with max attempts, retry windows, circuit breaker, and repeated error checks.
    - Always preserves SaaS isolation through user_id and workspace_id validation.
    - Produces structured dict results using success, message, data, error, metadata.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import random
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import-safe standalone use
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps RetryManager import-safe while the William/Jarvis platform is
        being assembled file-by-file. The real BaseAgent should provide richer
        registry, router, audit, and event behavior.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

        async def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class RetryDecision(str, Enum):
    """Possible retry decisions returned by RetryManager."""

    RETRY = "retry"
    DO_NOT_RETRY = "do_not_retry"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    CIRCUIT_OPEN = "circuit_open"
    MAX_ATTEMPTS_REACHED = "max_attempts_reached"
    INVALID_CONTEXT = "invalid_context"


class RetryRiskLevel(str, Enum):
    """Risk level for a retryable task."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class RetryErrorCategory(str, Enum):
    """Normalized categories for retry failure reasons."""

    TRANSIENT = "transient"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    NETWORK = "network"
    LOCKED_RESOURCE = "locked_resource"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    VALIDATION = "validation"
    PERMISSION_DENIED = "permission_denied"
    AUTHENTICATION = "authentication"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    PERMANENT = "permanent"
    DESTRUCTIVE_RISK = "destructive_risk"
    UNKNOWN = "unknown"


class RetryTaskType(str, Enum):
    """Known task types. Unknown task types are handled conservatively."""

    VERIFICATION = "verification"
    STATE_CHECK = "state_check"
    SCREENSHOT_CHECK = "screenshot_check"
    RESULT_VALIDATION = "result_validation"
    APP_STATE_CHECK = "app_state_check"
    FILE_STATE_CHECK = "file_state_check"
    BROWSER_STATE_CHECK = "browser_state_check"
    CODE_STATE_CHECK = "code_state_check"
    DEVICE_STATE_CHECK = "device_state_check"
    UI_ELEMENT_CHECK = "ui_element_check"
    ACTION_REPLAY_CHECK = "action_replay_check"
    ERROR_DETECTION = "error_detection"
    PROOF_COLLECTION = "proof_collection"
    REPORT_GENERATION = "report_generation"
    MEMORY_WRITE = "memory_write"
    AUDIT_WRITE = "audit_write"
    EXTERNAL_API_READ = "external_api_read"
    EXTERNAL_API_WRITE = "external_api_write"
    BROWSER_ACTION = "browser_action"
    SYSTEM_ACTION = "system_action"
    FILE_MUTATION = "file_mutation"
    MESSAGE_SEND = "message_send"
    CALL_ACTION = "call_action"
    FINANCIAL_ACTION = "financial_action"
    UNKNOWN = "unknown"


@dataclass
class RetryPolicy:
    """
    Retry configuration.

    Defaults are intentionally conservative for production SaaS safety.
    """

    max_attempts: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    jitter_seconds: float = 0.35
    backoff_multiplier: float = 2.0
    retry_window_seconds: int = 300
    circuit_breaker_failures: int = 5
    circuit_breaker_window_seconds: int = 600
    circuit_breaker_cooldown_seconds: int = 180
    retry_same_error_limit: int = 2
    require_security_for_medium_risk: bool = True
    require_security_for_unknown: bool = True
    allow_read_only_browser_retry: bool = True
    allow_read_only_external_api_retry: bool = True
    allow_file_read_retry: bool = True
    allow_code_check_retry: bool = True
    allow_device_check_retry: bool = True
    allow_memory_retry: bool = False
    allow_audit_retry: bool = True
    allow_destructive_retry: bool = False
    allowed_error_categories: Tuple[RetryErrorCategory, ...] = (
        RetryErrorCategory.TRANSIENT,
        RetryErrorCategory.TIMEOUT,
        RetryErrorCategory.RATE_LIMIT,
        RetryErrorCategory.NETWORK,
        RetryErrorCategory.LOCKED_RESOURCE,
        RetryErrorCategory.DEPENDENCY_UNAVAILABLE,
        RetryErrorCategory.CONFLICT,
    )
    blocked_error_categories: Tuple[RetryErrorCategory, ...] = (
        RetryErrorCategory.PERMISSION_DENIED,
        RetryErrorCategory.AUTHENTICATION,
        RetryErrorCategory.VALIDATION,
        RetryErrorCategory.NOT_FOUND,
        RetryErrorCategory.PERMANENT,
        RetryErrorCategory.DESTRUCTIVE_RISK,
    )


@dataclass
class RetryAttempt:
    """A single retry attempt record."""

    attempt_number: int
    task_id: str
    user_id: str
    workspace_id: str
    task_type: str
    error_category: str
    error_signature: str
    decision: str
    risk_level: str
    message: str
    delay_seconds: float
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetryState:
    """Runtime retry state for a task."""

    task_id: str
    user_id: str
    workspace_id: str
    task_type: str
    created_at: float
    updated_at: float
    attempts: List[RetryAttempt] = field(default_factory=list)
    last_error_signature: Optional[str] = None
    same_error_count: int = 0
    final_decision: Optional[str] = None
    circuit_open_until: Optional[float] = None


@dataclass
class RetryPlan:
    """Retry decision plan returned before execution."""

    task_id: str
    decision: RetryDecision
    risk_level: RetryRiskLevel
    error_category: RetryErrorCategory
    attempt_number: int
    max_attempts: int
    delay_seconds: float
    message: str
    reason_codes: List[str]
    requires_security_approval: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RetryManager
# ---------------------------------------------------------------------------

class RetryManager(BaseAgent):
    """
    Retries safe failed tasks and stops risky/infinite retries.

    Main public methods:
        - evaluate_retry(...)
        - execute_with_retry(...)
        - record_attempt(...)
        - get_retry_state(...)
        - reset_retry_state(...)
        - classify_error(...)
        - classify_task_risk(...)

    The manager does not directly perform real system/browser/financial/call/message
    actions. If a callable is passed to execute_with_retry, this class only runs it
    after the retry policy approves the attempt and after security approval when
    required.
    """

    SAFE_TASK_TYPES = {
        RetryTaskType.VERIFICATION.value,
        RetryTaskType.STATE_CHECK.value,
        RetryTaskType.SCREENSHOT_CHECK.value,
        RetryTaskType.RESULT_VALIDATION.value,
        RetryTaskType.APP_STATE_CHECK.value,
        RetryTaskType.FILE_STATE_CHECK.value,
        RetryTaskType.BROWSER_STATE_CHECK.value,
        RetryTaskType.CODE_STATE_CHECK.value,
        RetryTaskType.DEVICE_STATE_CHECK.value,
        RetryTaskType.UI_ELEMENT_CHECK.value,
        RetryTaskType.ERROR_DETECTION.value,
        RetryTaskType.PROOF_COLLECTION.value,
        RetryTaskType.REPORT_GENERATION.value,
        RetryTaskType.EXTERNAL_API_READ.value,
    }

    MEDIUM_RISK_TASK_TYPES = {
        RetryTaskType.ACTION_REPLAY_CHECK.value,
        RetryTaskType.MEMORY_WRITE.value,
        RetryTaskType.AUDIT_WRITE.value,
        RetryTaskType.BROWSER_ACTION.value,
    }

    HIGH_RISK_TASK_TYPES = {
        RetryTaskType.EXTERNAL_API_WRITE.value,
        RetryTaskType.SYSTEM_ACTION.value,
        RetryTaskType.FILE_MUTATION.value,
    }

    BLOCKED_TASK_TYPES = {
        RetryTaskType.MESSAGE_SEND.value,
        RetryTaskType.CALL_ACTION.value,
        RetryTaskType.FINANCIAL_ACTION.value,
    }

    TRANSIENT_ERROR_KEYWORDS = (
        "temporarily unavailable",
        "temporary",
        "try again",
        "connection reset",
        "connection aborted",
        "connection refused",
        "connection error",
        "network",
        "dns",
        "timeout",
        "timed out",
        "deadline exceeded",
        "gateway timeout",
        "bad gateway",
        "service unavailable",
        "too many requests",
        "rate limit",
        "throttle",
        "locked",
        "resource busy",
        "conflict",
        "stale",
        "server error",
        "internal server error",
        "502",
        "503",
        "504",
        "429",
    )

    PERMANENT_ERROR_KEYWORDS = (
        "invalid input",
        "invalid request",
        "schema",
        "validation",
        "not found",
        "404",
        "permission denied",
        "forbidden",
        "unauthorized",
        "401",
        "403",
        "authentication",
        "credentials",
        "malformed",
        "unsupported",
        "does not exist",
        "no such file",
        "cannot retry",
        "permanent",
        "destructive",
        "insufficient permissions",
    )

    DESTRUCTIVE_KEYWORDS = (
        "delete",
        "remove",
        "drop",
        "truncate",
        "overwrite",
        "send",
        "charge",
        "refund",
        "payment",
        "purchase",
        "transfer",
        "call",
        "sms",
        "email customer",
        "message customer",
        "deploy",
        "shutdown",
        "restart",
        "format",
    )

    def __init__(
        self,
        policy: Optional[RetryPolicy] = None,
        security_agent: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "RetryManager",
        agent_id: str = "verification_retry_manager",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        self.policy = policy or RetryPolicy()
        self.security_agent = security_agent
        self.logger = logger or getattr(self, "logger", logging.getLogger(agent_name))
        self._states: Dict[str, RetryState] = {}
        self._circuit_failures: Dict[str, List[float]] = {}
        self._security_agent_factory = SecurityAgent
        self._validate_policy()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_retry(
        self,
        *,
        task_id: Optional[str],
        user_id: str,
        workspace_id: str,
        task_type: Union[str, RetryTaskType],
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        failed_result: Optional[Mapping[str, Any]] = None,
        task_payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate whether a failed task should be retried.

        This method does not execute the task. It returns a structured retry plan.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            task_type=str(task_type.value if isinstance(task_type, RetryTaskType) else task_type),
        )
        if not context_result["success"]:
            return context_result

        normalized_task_id = context_result["data"]["task_id"]
        normalized_task_type = context_result["data"]["task_type"]
        error_category = self.classify_error(error=error, failed_result=failed_result)
        error_signature = self._build_error_signature(error=error, failed_result=failed_result)
        risk_level = self.classify_task_risk(
            task_type=normalized_task_type,
            task_payload=task_payload,
            metadata=metadata,
        )

        state = self._get_or_create_state(
            task_id=normalized_task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            task_type=normalized_task_type,
        )
        self._refresh_same_error_state(state, error_signature)
        circuit_result = self._check_circuit(
            user_id=user_id,
            workspace_id=workspace_id,
            task_type=normalized_task_type,
        )
        if not circuit_result["success"]:
            plan = RetryPlan(
                task_id=normalized_task_id,
                decision=RetryDecision.CIRCUIT_OPEN,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=len(state.attempts) + 1,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message=circuit_result["message"],
                reason_codes=["circuit_open"],
                requires_security_approval=False,
                metadata=dict(metadata or {}),
            )
            return self._safe_result(
                message=plan.message,
                data={"retry_plan": self._serialize_retry_plan(plan)},
                metadata=self._base_metadata(user_id, workspace_id, normalized_task_id),
            )

        plan = self._build_retry_plan(
            state=state,
            risk_level=risk_level,
            error_category=error_category,
            error_signature=error_signature,
            metadata=dict(metadata or {}),
        )

        return self._safe_result(
            message=plan.message,
            data={"retry_plan": self._serialize_retry_plan(plan)},
            metadata=self._base_metadata(user_id, workspace_id, normalized_task_id),
        )

    async def execute_with_retry(
        self,
        *,
        task_callable: Callable[..., Union[Any, Awaitable[Any]]],
        user_id: str,
        workspace_id: str,
        task_type: Union[str, RetryTaskType],
        task_id: Optional[str] = None,
        task_payload: Optional[Mapping[str, Any]] = None,
        callable_args: Optional[Iterable[Any]] = None,
        callable_kwargs: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a callable with safe retry control.

        The callable may be sync or async. It is retried only when:
            - context is valid,
            - task type and error are retry-safe,
            - max attempts are not exceeded,
            - circuit breaker is not open,
            - Security Agent approval is granted when required.

        Use this for verification checks and read-only validations, not for direct
        destructive actions.
        """

        if not callable(task_callable):
            return self._error_result(
                message="task_callable must be callable.",
                error={"code": "invalid_callable", "details": "Provided task_callable is not callable."},
                metadata=dict(metadata or {}),
            )

        normalized_task_type = str(task_type.value if isinstance(task_type, RetryTaskType) else task_type)
        normalized_task_id = task_id or self._new_task_id("retry_task")
        callable_args_tuple = tuple(callable_args or ())
        callable_kwargs_dict = dict(callable_kwargs or {})
        run_metadata = dict(metadata or {})
        last_error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None
        last_failed_result: Optional[Mapping[str, Any]] = None

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=normalized_task_id,
            task_type=normalized_task_type,
        )
        if not context_result["success"]:
            return context_result

        await self._emit_agent_event(
            event_type="verification.retry.started",
            payload={
                "task_id": normalized_task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_type": normalized_task_type,
                "metadata": run_metadata,
            },
        )

        for _ in range(self.policy.max_attempts):
            evaluation = self.evaluate_retry(
                task_id=normalized_task_id,
                user_id=user_id,
                workspace_id=workspace_id,
                task_type=normalized_task_type,
                error=last_error,
                failed_result=last_failed_result,
                task_payload=task_payload,
                metadata=run_metadata,
            )
            if not evaluation["success"]:
                await self._log_audit_event(
                    action="retry_context_rejected",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=normalized_task_id,
                    details=evaluation,
                )
                return evaluation

            plan_data = evaluation["data"]["retry_plan"]
            decision = plan_data["decision"]
            attempt_number = int(plan_data["attempt_number"])

            if decision == RetryDecision.REQUIRE_SECURITY_APPROVAL.value:
                approval = await self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action="retry_failed_task",
                    task_payload={
                        "task_id": normalized_task_id,
                        "task_type": normalized_task_type,
                        "retry_plan": plan_data,
                        "original_task_payload": dict(task_payload or {}),
                    },
                    metadata=run_metadata,
                )
                if not approval["success"] or not approval["data"].get("approved", False):
                    self.record_attempt(
                        task_id=normalized_task_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_type=normalized_task_type,
                        decision=RetryDecision.DO_NOT_RETRY.value,
                        risk_level=plan_data["risk_level"],
                        error_category=plan_data["error_category"],
                        error_signature=self._build_error_signature(last_error, last_failed_result),
                        delay_seconds=0.0,
                        message="Retry blocked because security approval was not granted.",
                        metadata={"approval": approval, **run_metadata},
                    )
                    return self._error_result(
                        message="Retry blocked because security approval was not granted.",
                        error={"code": "security_approval_denied", "details": approval.get("error")},
                        data={
                            "retry_plan": plan_data,
                            "verification_payload": self._prepare_verification_payload(
                                user_id=user_id,
                                workspace_id=workspace_id,
                                task_id=normalized_task_id,
                                status="blocked",
                                details={"reason": "security_approval_denied"},
                            ),
                            "memory_payload": self._prepare_memory_payload(
                                user_id=user_id,
                                workspace_id=workspace_id,
                                task_id=normalized_task_id,
                                summary="Retry blocked by security approval gate.",
                                metadata=run_metadata,
                            ),
                        },
                        metadata=self._base_metadata(user_id, workspace_id, normalized_task_id),
                    )

                decision = RetryDecision.RETRY.value

            if decision != RetryDecision.RETRY.value:
                final_result = self._safe_result(
                    success=False,
                    message=plan_data["message"],
                    data={
                        "retry_plan": plan_data,
                        "verification_payload": self._prepare_verification_payload(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            task_id=normalized_task_id,
                            status="not_retried",
                            details={"decision": decision, "plan": plan_data},
                        ),
                        "memory_payload": self._prepare_memory_payload(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            task_id=normalized_task_id,
                            summary=f"Retry stopped with decision: {decision}.",
                            metadata=run_metadata,
                        ),
                    },
                    error={"code": decision, "details": plan_data.get("reason_codes", [])},
                    metadata=self._base_metadata(user_id, workspace_id, normalized_task_id),
                )
                await self._emit_agent_event("verification.retry.stopped", final_result)
                return final_result

            delay_seconds = float(plan_data.get("delay_seconds", 0.0))
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)

            try:
                result = task_callable(*callable_args_tuple, **callable_kwargs_dict)
                if inspect.isawaitable(result):
                    result = await result

                if self._result_indicates_failure(result):
                    last_failed_result = result if isinstance(result, Mapping) else {"result": result}
                    last_error = last_failed_result.get("error") or last_failed_result.get("message") or "Task returned unsuccessful result."
                    self._record_failure_for_circuit(user_id, workspace_id, normalized_task_type)
                    self.record_attempt(
                        task_id=normalized_task_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_type=normalized_task_type,
                        decision=RetryDecision.RETRY.value,
                        risk_level=plan_data["risk_level"],
                        error_category=self.classify_error(error=last_error, failed_result=last_failed_result).value,
                        error_signature=self._build_error_signature(last_error, last_failed_result),
                        delay_seconds=delay_seconds,
                        message="Retry attempt completed but result still indicates failure.",
                        metadata={"attempt_result": self._safe_preview(result), **run_metadata},
                    )
                    continue

                success_payload = self._safe_result(
                    message="Task succeeded within retry policy.",
                    data={
                        "result": result,
                        "attempt_number": attempt_number,
                        "retry_state": self.get_retry_state(
                            task_id=normalized_task_id,
                            user_id=user_id,
                            workspace_id=workspace_id,
                        )["data"],
                        "verification_payload": self._prepare_verification_payload(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            task_id=normalized_task_id,
                            status="success",
                            details={"attempt_number": attempt_number},
                        ),
                        "memory_payload": self._prepare_memory_payload(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            task_id=normalized_task_id,
                            summary="Task succeeded after retry manager evaluation.",
                            metadata=run_metadata,
                        ),
                    },
                    metadata=self._base_metadata(user_id, workspace_id, normalized_task_id),
                )
                await self._emit_agent_event("verification.retry.succeeded", success_payload)
                await self._log_audit_event(
                    action="retry_succeeded",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=normalized_task_id,
                    details={"attempt_number": attempt_number, "task_type": normalized_task_type},
                )
                return success_payload

            except Exception as exc:
                last_error = exc
                last_failed_result = {
                    "success": False,
                    "message": str(exc),
                    "error": {
                        "type": exc.__class__.__name__,
                        "details": str(exc),
                    },
                }
                self._record_failure_for_circuit(user_id, workspace_id, normalized_task_type)
                self.record_attempt(
                    task_id=normalized_task_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_type=normalized_task_type,
                    decision=RetryDecision.RETRY.value,
                    risk_level=plan_data["risk_level"],
                    error_category=self.classify_error(error=exc).value,
                    error_signature=self._build_error_signature(exc, last_failed_result),
                    delay_seconds=delay_seconds,
                    message="Retry attempt raised an exception.",
                    metadata={
                        "exception_type": exc.__class__.__name__,
                        "traceback": self._safe_traceback(exc),
                        **run_metadata,
                    },
                )
                continue

        final_state = self.get_retry_state(
            task_id=normalized_task_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        final_payload = self._error_result(
            message="Maximum retry attempts reached. Task stopped to prevent infinite retries.",
            error={
                "code": RetryDecision.MAX_ATTEMPTS_REACHED.value,
                "details": self._safe_preview(last_error),
            },
            data={
                "retry_state": final_state.get("data"),
                "verification_payload": self._prepare_verification_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=normalized_task_id,
                    status="failed",
                    details={"reason": "max_attempts_reached"},
                ),
                "memory_payload": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=normalized_task_id,
                    summary="Task stopped after maximum retry attempts.",
                    metadata=run_metadata,
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id, normalized_task_id),
        )
        await self._emit_agent_event("verification.retry.failed", final_payload)
        await self._log_audit_event(
            action="retry_max_attempts_reached",
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=normalized_task_id,
            details=final_payload,
        )
        return final_payload

    def record_attempt(
        self,
        *,
        task_id: str,
        user_id: str,
        workspace_id: str,
        task_type: str,
        decision: str,
        risk_level: str,
        error_category: str,
        error_signature: str,
        delay_seconds: float,
        message: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a retry attempt in in-memory runtime state."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            task_type=task_type,
        )
        if not context_result["success"]:
            return context_result

        state = self._get_or_create_state(
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            task_type=task_type,
        )
        attempt = RetryAttempt(
            attempt_number=len(state.attempts) + 1,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            task_type=task_type,
            error_category=error_category,
            error_signature=error_signature,
            decision=decision,
            risk_level=risk_level,
            message=message,
            delay_seconds=max(0.0, float(delay_seconds)),
            timestamp=self._utc_now_iso(),
            metadata=dict(metadata or {}),
        )
        state.attempts.append(attempt)
        state.updated_at = time.time()
        state.final_decision = decision

        return self._safe_result(
            message="Retry attempt recorded.",
            data={"attempt": asdict(attempt), "retry_state": self._serialize_state(state)},
            metadata=self._base_metadata(user_id, workspace_id, task_id),
        )

    def get_retry_state(
        self,
        *,
        task_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Return retry state for a task, enforcing user/workspace isolation."""

        state = self._states.get(task_id)
        if not state:
            return self._safe_result(
                message="No retry state found for task.",
                data={"retry_state": None},
                metadata=self._base_metadata(user_id, workspace_id, task_id),
            )

        if state.user_id != user_id or state.workspace_id != workspace_id:
            return self._error_result(
                message="Retry state access denied due to workspace isolation mismatch.",
                error={"code": "workspace_isolation_violation"},
                metadata=self._base_metadata(user_id, workspace_id, task_id),
            )

        return self._safe_result(
            message="Retry state found.",
            data={"retry_state": self._serialize_state(state)},
            metadata=self._base_metadata(user_id, workspace_id, task_id),
        )

    def reset_retry_state(
        self,
        *,
        task_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Reset retry state for one task, enforcing SaaS isolation."""

        state = self._states.get(task_id)
        if not state:
            return self._safe_result(
                message="Retry state was already empty.",
                data={"removed": False},
                metadata=self._base_metadata(user_id, workspace_id, task_id),
            )

        if state.user_id != user_id or state.workspace_id != workspace_id:
            return self._error_result(
                message="Cannot reset retry state due to workspace isolation mismatch.",
                error={"code": "workspace_isolation_violation"},
                metadata=self._base_metadata(user_id, workspace_id, task_id),
            )

        del self._states[task_id]
        return self._safe_result(
            message="Retry state reset.",
            data={"removed": True},
            metadata=self._base_metadata(user_id, workspace_id, task_id),
        )

    def classify_error(
        self,
        *,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        failed_result: Optional[Mapping[str, Any]] = None,
    ) -> RetryErrorCategory:
        """Classify an error or failed result into a retry category."""

        combined = self._normalize_error_text(error, failed_result)

        if not combined:
            return RetryErrorCategory.TRANSIENT

        text = combined.lower()

        if any(word in text for word in ("429", "too many requests", "rate limit", "throttle")):
            return RetryErrorCategory.RATE_LIMIT
        if any(word in text for word in ("timeout", "timed out", "deadline exceeded", "504")):
            return RetryErrorCategory.TIMEOUT
        if any(word in text for word in ("network", "connection", "dns", "socket", "502", "503")):
            return RetryErrorCategory.NETWORK
        if any(word in text for word in ("locked", "resource busy", "file busy")):
            return RetryErrorCategory.LOCKED_RESOURCE
        if any(word in text for word in ("service unavailable", "dependency", "backend unavailable")):
            return RetryErrorCategory.DEPENDENCY_UNAVAILABLE
        if any(word in text for word in ("permission denied", "forbidden", "403")):
            return RetryErrorCategory.PERMISSION_DENIED
        if any(word in text for word in ("unauthorized", "authentication", "credentials", "401")):
            return RetryErrorCategory.AUTHENTICATION
        if any(word in text for word in ("not found", "404", "no such file", "does not exist")):
            return RetryErrorCategory.NOT_FOUND
        if any(word in text for word in ("validation", "invalid input", "schema", "malformed")):
            return RetryErrorCategory.VALIDATION
        if any(word in text for word in ("conflict", "409", "stale")):
            return RetryErrorCategory.CONFLICT
        if any(word in text for word in self.DESTRUCTIVE_KEYWORDS):
            return RetryErrorCategory.DESTRUCTIVE_RISK
        if any(word in text for word in self.PERMANENT_ERROR_KEYWORDS):
            return RetryErrorCategory.PERMANENT
        if any(word in text for word in self.TRANSIENT_ERROR_KEYWORDS):
            return RetryErrorCategory.TRANSIENT

        return RetryErrorCategory.UNKNOWN

    def classify_task_risk(
        self,
        *,
        task_type: Union[str, RetryTaskType],
        task_payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> RetryRiskLevel:
        """Classify task retry risk using task type and payload keywords."""

        normalized = str(task_type.value if isinstance(task_type, RetryTaskType) else task_type).strip().lower()
        payload_text = self._safe_jsonish_text({"task_payload": dict(task_payload or {}), "metadata": dict(metadata or {})}).lower()

        if normalized in self.BLOCKED_TASK_TYPES:
            return RetryRiskLevel.BLOCKED

        if any(keyword in payload_text for keyword in self.DESTRUCTIVE_KEYWORDS):
            if normalized in self.SAFE_TASK_TYPES and "read" in payload_text and "write" not in payload_text:
                return RetryRiskLevel.LOW
            return RetryRiskLevel.HIGH

        if normalized in self.SAFE_TASK_TYPES:
            return RetryRiskLevel.SAFE
        if normalized in self.MEDIUM_RISK_TASK_TYPES:
            return RetryRiskLevel.MEDIUM
        if normalized in self.HIGH_RISK_TASK_TYPES:
            return RetryRiskLevel.HIGH
        if normalized == RetryTaskType.UNKNOWN.value or not normalized:
            return RetryRiskLevel.MEDIUM

        return RetryRiskLevel.MEDIUM

    def should_retry(self, **kwargs: Any) -> bool:
        """Convenience boolean wrapper around evaluate_retry."""

        result = self.evaluate_retry(**kwargs)
        if not result.get("success"):
            return False
        plan = result.get("data", {}).get("retry_plan", {})
        return plan.get("decision") == RetryDecision.RETRY.value

    def get_public_status(self) -> Dict[str, Any]:
        """Return dashboard-friendly status of the retry manager."""

        return self._safe_result(
            message="Retry manager status ready.",
            data={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "policy": self._serialize_policy(),
                "tracked_tasks": len(self._states),
                "circuit_keys": len(self._circuit_failures),
                "safe_task_types": sorted(self.SAFE_TASK_TYPES),
                "medium_risk_task_types": sorted(self.MEDIUM_RISK_TASK_TYPES),
                "high_risk_task_types": sorted(self.HIGH_RISK_TASK_TYPES),
                "blocked_task_types": sorted(self.BLOCKED_TASK_TYPES),
            },
            metadata={"timestamp": self._utc_now_iso()},
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str],
        task_type: Optional[str],
    ) -> Dict[str, Any]:
        """Validate SaaS isolation context for any retry operation."""

        errors: List[str] = []

        if not isinstance(user_id, str) or not user_id.strip():
            errors.append("user_id is required.")
        if not isinstance(workspace_id, str) or not workspace_id.strip():
            errors.append("workspace_id is required.")
        if task_id is not None and not isinstance(task_id, str):
            errors.append("task_id must be a string when provided.")
        if not isinstance(task_type, str) or not task_type.strip():
            errors.append("task_type is required.")

        if errors:
            return self._error_result(
                message="Invalid retry task context.",
                error={"code": RetryDecision.INVALID_CONTEXT.value, "details": errors},
                metadata={"timestamp": self._utc_now_iso()},
            )

        return self._safe_result(
            message="Retry task context is valid.",
            data={
                "user_id": user_id.strip(),
                "workspace_id": workspace_id.strip(),
                "task_id": task_id.strip() if isinstance(task_id, str) and task_id.strip() else self._new_task_id("retry_task"),
                "task_type": task_type.strip().lower(),
            },
            metadata={"timestamp": self._utc_now_iso()},
        )

    def _requires_security_check(
        self,
        *,
        risk_level: Union[str, RetryRiskLevel],
        task_type: str,
        error_category: Union[str, RetryErrorCategory],
        task_payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Return True when retry must be approved by Security Agent."""

        risk = str(risk_level.value if isinstance(risk_level, RetryRiskLevel) else risk_level)
        category = str(error_category.value if isinstance(error_category, RetryErrorCategory) else error_category)

        if risk in {RetryRiskLevel.HIGH.value, RetryRiskLevel.BLOCKED.value}:
            return True
        if risk == RetryRiskLevel.MEDIUM.value and self.policy.require_security_for_medium_risk:
            return True
        if category == RetryErrorCategory.UNKNOWN.value and self.policy.require_security_for_unknown:
            return True

        payload_text = self._safe_jsonish_text(dict(task_payload or {})).lower()
        return any(keyword in payload_text for keyword in self.DESTRUCTIVE_KEYWORDS)

    async def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        task_payload: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        If Security Agent is unavailable, approval is denied safely.
        """

        approval_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "task_payload": dict(task_payload),
            "metadata": dict(metadata or {}),
            "requested_by": self.agent_id,
            "timestamp": self._utc_now_iso(),
        }

        agent = self.security_agent
        if agent is None and self._security_agent_factory is not None:
            try:
                agent = self._security_agent_factory()
            except Exception as exc:
                self.logger.warning("SecurityAgent factory failed: %s", exc)
                agent = None

        if agent is None:
            return self._safe_result(
                success=False,
                message="Security approval unavailable. Retry denied safely.",
                data={"approved": False, "reason": "security_agent_unavailable"},
                error={"code": "security_agent_unavailable"},
                metadata=approval_payload,
            )

        try:
            if hasattr(agent, "approve_action"):
                response = agent.approve_action(approval_payload)
                if inspect.isawaitable(response):
                    response = await response
                approved = bool(response.get("approved", response.get("success", False))) if isinstance(response, Mapping) else bool(response)
                return self._safe_result(
                    success=approved,
                    message="Security approval response received.",
                    data={"approved": approved, "response": self._safe_preview(response)},
                    metadata=approval_payload,
                )

            if hasattr(agent, "validate_permission"):
                response = agent.validate_permission(approval_payload)
                if inspect.isawaitable(response):
                    response = await response
                approved = bool(response.get("approved", response.get("success", False))) if isinstance(response, Mapping) else bool(response)
                return self._safe_result(
                    success=approved,
                    message="Security permission response received.",
                    data={"approved": approved, "response": self._safe_preview(response)},
                    metadata=approval_payload,
                )

            return self._safe_result(
                success=False,
                message="Security Agent does not expose a supported approval method. Retry denied safely.",
                data={"approved": False, "reason": "unsupported_security_agent_interface"},
                error={"code": "unsupported_security_agent_interface"},
                metadata=approval_payload,
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed. Retry denied safely.",
                error={
                    "code": "security_approval_failed",
                    "type": exc.__class__.__name__,
                    "details": str(exc),
                },
                data={"approved": False},
                metadata=approval_payload,
            )

    def _prepare_verification_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        status: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare payload that Verification Agent/report generator can consume."""

        return {
            "agent": self.agent_id,
            "payload_type": "verification_retry",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "status": status,
            "details": dict(details or {}),
            "timestamp": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        summary: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Memory Agent compatible context payload."""

        return {
            "agent": self.agent_id,
            "memory_type": "verification_retry_pattern",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "summary": summary,
            "metadata": dict(metadata or {}),
            "timestamp": self._utc_now_iso(),
        }

    async def _emit_agent_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Emit a router/dashboard/registry event if BaseAgent supports it."""

        try:
            if hasattr(super(), "emit_event"):
                result = super().emit_event(event_type, dict(payload))  # type: ignore[misc]
                if inspect.isawaitable(result):
                    await result
                return
        except Exception as exc:
            self.logger.debug("BaseAgent emit_event failed: %s", exc)

        try:
            self.logger.info("Agent event: %s | %s", event_type, self._safe_preview(payload))
        except Exception:
            pass

    async def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        task_id: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Log audit event with SaaS context."""

        payload = {
            "action": action,
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "details": dict(details or {}),
            "timestamp": self._utc_now_iso(),
        }

        try:
            if hasattr(super(), "log_audit"):
                result = super().log_audit(payload)  # type: ignore[misc]
                if inspect.isawaitable(result):
                    await result
                return
        except Exception as exc:
            self.logger.debug("BaseAgent log_audit failed: %s", exc)

        self.logger.info("Audit event: %s", self._safe_preview(payload))

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis structured result."""

        return {
            "success": bool(success),
            "message": message,
            "data": dict(data or {}),
            "error": dict(error or {}) if error else None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or {"code": "retry_manager_error"},
            metadata=metadata or {"timestamp": self._utc_now_iso()},
        )

    # ------------------------------------------------------------------
    # Internal decision logic
    # ------------------------------------------------------------------

    def _build_retry_plan(
        self,
        *,
        state: RetryState,
        risk_level: RetryRiskLevel,
        error_category: RetryErrorCategory,
        error_signature: str,
        metadata: Mapping[str, Any],
    ) -> RetryPlan:
        """Build the retry plan using policy, risk, error category, and state."""

        attempt_number = len(state.attempts) + 1
        reason_codes: List[str] = []

        if attempt_number > self.policy.max_attempts:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.MAX_ATTEMPTS_REACHED,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message="Maximum retry attempts reached. Stopping to prevent infinite retries.",
                reason_codes=["max_attempts_reached"],
                requires_security_approval=False,
                metadata=dict(metadata),
            )

        if state.same_error_count >= self.policy.retry_same_error_limit:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.DO_NOT_RETRY,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message="Same error repeated too many times. Stopping to prevent infinite retry loop.",
                reason_codes=["same_error_limit_reached", error_signature],
                requires_security_approval=False,
                metadata=dict(metadata),
            )

        if risk_level == RetryRiskLevel.BLOCKED:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.DO_NOT_RETRY,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message="Retry blocked because task type is not safe for automatic retry.",
                reason_codes=["blocked_task_type"],
                requires_security_approval=False,
                metadata=dict(metadata),
            )

        if risk_level == RetryRiskLevel.HIGH and not self.policy.allow_destructive_retry:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.DO_NOT_RETRY,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message="Retry blocked because high-risk/destructive retries are disabled.",
                reason_codes=["high_risk_retry_disabled"],
                requires_security_approval=False,
                metadata=dict(metadata),
            )

        if error_category in self.policy.blocked_error_categories:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.DO_NOT_RETRY,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message=f"Retry blocked because error category is not retry-safe: {error_category.value}.",
                reason_codes=["blocked_error_category", error_category.value],
                requires_security_approval=False,
                metadata=dict(metadata),
            )

        if error_category not in self.policy.allowed_error_categories and error_category != RetryErrorCategory.UNKNOWN:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.DO_NOT_RETRY,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=0.0,
                message=f"Retry blocked because error category is not allowed: {error_category.value}.",
                reason_codes=["error_category_not_allowed", error_category.value],
                requires_security_approval=False,
                metadata=dict(metadata),
            )

        requires_security = self._requires_security_check(
            risk_level=risk_level,
            task_type=state.task_type,
            error_category=error_category,
            task_payload=metadata,
        )
        delay = self._calculate_delay(attempt_number)

        if requires_security:
            return RetryPlan(
                task_id=state.task_id,
                decision=RetryDecision.REQUIRE_SECURITY_APPROVAL,
                risk_level=risk_level,
                error_category=error_category,
                attempt_number=attempt_number,
                max_attempts=self.policy.max_attempts,
                delay_seconds=delay,
                message="Retry requires Security Agent approval before execution.",
                reason_codes=["security_approval_required"],
                requires_security_approval=True,
                metadata=dict(metadata),
            )

        return RetryPlan(
            task_id=state.task_id,
            decision=RetryDecision.RETRY,
            risk_level=risk_level,
            error_category=error_category,
            attempt_number=attempt_number,
            max_attempts=self.policy.max_attempts,
            delay_seconds=delay,
            message="Retry approved by retry policy.",
            reason_codes=["retry_safe", error_category.value, risk_level.value],
            requires_security_approval=False,
            metadata=dict(metadata),
        )

    def _calculate_delay(self, attempt_number: int) -> float:
        """Calculate exponential backoff delay with jitter."""

        attempt_index = max(0, attempt_number - 1)
        raw_delay = self.policy.base_delay_seconds * (self.policy.backoff_multiplier ** attempt_index)
        jitter = random.uniform(0, max(0.0, self.policy.jitter_seconds))
        return round(min(self.policy.max_delay_seconds, raw_delay + jitter), 3)

    def _get_or_create_state(
        self,
        *,
        task_id: str,
        user_id: str,
        workspace_id: str,
        task_type: str,
    ) -> RetryState:
        """Get or create retry state for a task."""

        state = self._states.get(task_id)
        now = time.time()

        if state:
            if state.user_id != user_id or state.workspace_id != workspace_id:
                raise PermissionError("Retry state isolation mismatch.")
            state.updated_at = now
            return state

        state = RetryState(
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            task_type=task_type,
            created_at=now,
            updated_at=now,
        )
        self._states[task_id] = state
        return state

    def _refresh_same_error_state(self, state: RetryState, error_signature: str) -> None:
        """Track repeated identical error signatures."""

        if not error_signature:
            state.same_error_count = 0
            state.last_error_signature = None
            return

        if state.last_error_signature == error_signature:
            state.same_error_count += 1
        else:
            state.last_error_signature = error_signature
            state.same_error_count = 0

        state.updated_at = time.time()

    def _record_failure_for_circuit(self, user_id: str, workspace_id: str, task_type: str) -> None:
        """Record a failure for circuit breaker tracking."""

        key = self._circuit_key(user_id, workspace_id, task_type)
        now = time.time()
        window_start = now - self.policy.circuit_breaker_window_seconds
        existing = [ts for ts in self._circuit_failures.get(key, []) if ts >= window_start]
        existing.append(now)
        self._circuit_failures[key] = existing

    def _check_circuit(self, user_id: str, workspace_id: str, task_type: str) -> Dict[str, Any]:
        """Check whether circuit breaker is open for this context/task type."""

        key = self._circuit_key(user_id, workspace_id, task_type)
        now = time.time()
        window_start = now - self.policy.circuit_breaker_window_seconds
        failures = [ts for ts in self._circuit_failures.get(key, []) if ts >= window_start]
        self._circuit_failures[key] = failures

        if len(failures) >= self.policy.circuit_breaker_failures:
            oldest_failure = min(failures)
            cooldown_until = oldest_failure + self.policy.circuit_breaker_cooldown_seconds
            if now < cooldown_until:
                return self._error_result(
                    message="Circuit breaker is open for this task type. Retry stopped temporarily.",
                    error={
                        "code": RetryDecision.CIRCUIT_OPEN.value,
                        "failure_count": len(failures),
                        "cooldown_until": self._iso_from_timestamp(cooldown_until),
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_type": task_type,
                        "timestamp": self._utc_now_iso(),
                    },
                )

        return self._safe_result(
            message="Circuit breaker is closed.",
            data={"failure_count": len(failures)},
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_type": task_type,
                "timestamp": self._utc_now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _validate_policy(self) -> None:
        """Validate retry policy and normalize unsafe values."""

        if self.policy.max_attempts < 1:
            self.policy.max_attempts = 1
        if self.policy.max_attempts > 10:
            self.policy.max_attempts = 10
        if self.policy.base_delay_seconds < 0:
            self.policy.base_delay_seconds = 0.0
        if self.policy.max_delay_seconds < self.policy.base_delay_seconds:
            self.policy.max_delay_seconds = self.policy.base_delay_seconds
        if self.policy.backoff_multiplier < 1:
            self.policy.backoff_multiplier = 1.0
        if self.policy.retry_same_error_limit < 1:
            self.policy.retry_same_error_limit = 1
        if self.policy.circuit_breaker_failures < 1:
            self.policy.circuit_breaker_failures = 1
        if self.policy.circuit_breaker_window_seconds < 1:
            self.policy.circuit_breaker_window_seconds = 60
        if self.policy.circuit_breaker_cooldown_seconds < 1:
            self.policy.circuit_breaker_cooldown_seconds = 60

    def _result_indicates_failure(self, result: Any) -> bool:
        """Detect standard structured failure result."""

        if isinstance(result, Mapping):
            if result.get("success") is False:
                return True
            status = str(result.get("status", "")).lower()
            if status in {"failed", "error", "blocked", "denied"}:
                return True
        return False

    def _normalize_error_text(
        self,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]],
        failed_result: Optional[Mapping[str, Any]],
    ) -> str:
        """Convert error sources into lower-risk text for classification."""

        parts: List[str] = []

        if error is not None:
            if isinstance(error, BaseException):
                parts.append(error.__class__.__name__)
                parts.append(str(error))
            elif isinstance(error, Mapping):
                parts.append(self._safe_jsonish_text(error))
            else:
                parts.append(str(error))

        if failed_result:
            parts.append(self._safe_jsonish_text(failed_result))

        return " | ".join(part for part in parts if part).strip()

    def _build_error_signature(
        self,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        failed_result: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Build stable low-cardinality error signature."""

        text = self._normalize_error_text(error, failed_result).lower().strip()
        if not text:
            return "no_error"

        for volatile in ("\n", "\r", "\t"):
            text = text.replace(volatile, " ")

        collapsed = " ".join(text.split())
        return collapsed[:300]

    def _safe_traceback(self, exc: BaseException) -> str:
        """Return bounded traceback for diagnostics without exposing huge logs."""

        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return tb[-4000:]

    def _safe_preview(self, value: Any, limit: int = 2000) -> Any:
        """Return a bounded preview suitable for logs/results."""

        if isinstance(value, (str, int, float, bool)) or value is None:
            text = str(value)
            return text[:limit] if len(text) > limit else value

        try:
            text = self._safe_jsonish_text(value)
            return text[:limit] if len(text) > limit else text
        except Exception:
            text = repr(value)
            return text[:limit]

    def _safe_jsonish_text(self, value: Any) -> str:
        """Convert a value to deterministic JSON-ish text without requiring json serialization."""

        if isinstance(value, Mapping):
            items = []
            for key in sorted(value.keys(), key=lambda item: str(item)):
                items.append(f"{key}: {self._safe_jsonish_text(value[key])}")
            return "{" + ", ".join(items) + "}"
        if isinstance(value, (list, tuple, set)):
            return "[" + ", ".join(self._safe_jsonish_text(item) for item in list(value)[:50]) + "]"
        if isinstance(value, BaseException):
            return f"{value.__class__.__name__}: {str(value)}"
        return str(value)

    def _serialize_retry_plan(self, plan: RetryPlan) -> Dict[str, Any]:
        """Serialize RetryPlan to dict."""

        data = asdict(plan)
        data["decision"] = plan.decision.value
        data["risk_level"] = plan.risk_level.value
        data["error_category"] = plan.error_category.value
        return data

    def _serialize_state(self, state: RetryState) -> Dict[str, Any]:
        """Serialize RetryState to dashboard/API-safe dict."""

        return {
            "task_id": state.task_id,
            "user_id": state.user_id,
            "workspace_id": state.workspace_id,
            "task_type": state.task_type,
            "created_at": self._iso_from_timestamp(state.created_at),
            "updated_at": self._iso_from_timestamp(state.updated_at),
            "attempts": [asdict(attempt) for attempt in state.attempts],
            "last_error_signature": state.last_error_signature,
            "same_error_count": state.same_error_count,
            "final_decision": state.final_decision,
            "circuit_open_until": self._iso_from_timestamp(state.circuit_open_until) if state.circuit_open_until else None,
        }

    def _serialize_policy(self) -> Dict[str, Any]:
        """Serialize policy for dashboard/API display."""

        data = asdict(self.policy)
        data["allowed_error_categories"] = [item.value for item in self.policy.allowed_error_categories]
        data["blocked_error_categories"] = [item.value for item in self.policy.blocked_error_categories]
        return data

    def _base_metadata(self, user_id: str, workspace_id: str, task_id: Optional[str] = None) -> Dict[str, Any]:
        """Base metadata attached to standard results."""

        return {
            "agent": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "timestamp": self._utc_now_iso(),
        }

    def _circuit_key(self, user_id: str, workspace_id: str, task_type: str) -> str:
        """Create circuit breaker key scoped by user/workspace/task type."""

        return f"{user_id.strip()}::{workspace_id.strip()}::{task_type.strip().lower()}"

    def _new_task_id(self, prefix: str) -> str:
        """Generate safe unique task ID."""

        return f"{prefix}_{uuid.uuid4().hex}"

    def _utc_now_iso(self) -> str:
        """Current UTC ISO timestamp."""

        return datetime.now(timezone.utc).isoformat()

    def _iso_from_timestamp(self, value: Optional[float]) -> Optional[str]:
        """Convert unix timestamp to UTC ISO timestamp."""

        if value is None:
            return None
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Factory and module-level exports
# ---------------------------------------------------------------------------

def create_retry_manager(
    policy: Optional[RetryPolicy] = None,
    security_agent: Optional[Any] = None,
    **kwargs: Any,
) -> RetryManager:
    """
    Factory for Agent Loader / Registry.

    Example:
        manager = create_retry_manager()
    """

    return RetryManager(policy=policy, security_agent=security_agent, **kwargs)


__all__ = [
    "RetryManager",
    "RetryPolicy",
    "RetryAttempt",
    "RetryState",
    "RetryPlan",
    "RetryDecision",
    "RetryRiskLevel",
    "RetryErrorCategory",
    "RetryTaskType",
    "create_retry_manager",
]