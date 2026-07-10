"""
agents/verification_agent/action_replay_checker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Checks multi-step automation execution/replay traces and identifies the failed step.

This module is part of the Verification Agent layer. It does NOT execute real browser,
system, financial, messaging, call, or destructive actions. Instead, it safely analyzes
expected automation steps against observed/actual replay data and returns structured
verification results.

Architecture Connections:
    - Master Agent / Router:
        Can route verification tasks here when an automation/workflow has multiple
        steps and the system needs to know where it failed.

    - Verification Agent:
        Uses this helper to produce structured proof/status about multi-step automation.

    - Security Agent:
        Sensitive or destructive verification requests can be routed through security
        approval hooks before analysis continues.

    - Memory Agent:
        Useful replay summaries can be prepared as memory-compatible payloads without
        leaking cross-user/workspace data.

    - Dashboard / API:
        All public methods return dict/JSON-style responses suitable for FastAPI,
        dashboard panels, task history, audit logs, and analytics.

    - Agent Registry / Loader:
        The class is import-safe and includes fallback stubs if BaseAgent or other
        William modules are not available yet.

Important Safety Rules:
    - Never mixes user/workspace data.
    - Requires user_id and workspace_id for user-scoped verification.
    - Does not perform the original automation actions.
    - Does not execute destructive/system/browser/message/call operations.
    - Produces structured results with success, message, data, error, metadata.
"""

from __future__ import annotations

import difflib
import json
import logging
import math
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional / Safe Imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for incomplete project state
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe while the William/Jarvis project is still
        being generated file-by-file. The real BaseAgent should replace this when
        available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.verification.action_replay_checker")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "ActionReplayChecker"
DEFAULT_VERSION = "1.0.0"

DEFAULT_CONFIDENCE_PASS = 0.92
DEFAULT_CONFIDENCE_WARNING = 0.68
DEFAULT_CONFIDENCE_FAIL = 0.90
DEFAULT_TEXT_SIMILARITY_THRESHOLD = 0.72
DEFAULT_TIME_TOLERANCE_SECONDS = 5.0

MAX_SAFE_STEPS = 500
MAX_SAFE_EVIDENCE_ITEMS_PER_STEP = 30
MAX_SAFE_STRING_LENGTH = 5000

SENSITIVE_ACTION_KEYWORDS = {
    "delete",
    "remove",
    "destroy",
    "drop",
    "truncate",
    "wipe",
    "reset",
    "send",
    "email",
    "sms",
    "message",
    "call",
    "purchase",
    "payment",
    "refund",
    "transfer",
    "withdraw",
    "trade",
    "subscribe",
    "unsubscribe",
    "deploy",
    "restart",
    "shutdown",
    "kill",
    "block",
    "ban",
    "permission",
    "credential",
    "password",
    "secret",
    "token",
    "key",
}

TERMINAL_FAILURE_STATUSES = {
    "failed",
    "error",
    "timeout",
    "blocked",
    "permission_denied",
    "security_denied",
    "not_found",
    "crashed",
    "exception",
    "aborted",
}

PASS_STATUSES = {
    "passed",
    "pass",
    "success",
    "successful",
    "completed",
    "done",
    "ok",
    "verified",
}

WARNING_STATUSES = {
    "warning",
    "partial",
    "unknown",
    "review",
    "skipped",
    "inconclusive",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReplayStatus(str, Enum):
    """Overall replay status."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    INCONCLUSIVE = "inconclusive"


class StepStatus(str, Enum):
    """Normalized step status."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    MISSING = "missing"
    EXTRA = "extra"
    SKIPPED = "skipped"
    INCONCLUSIVE = "inconclusive"


class FailureReason(str, Enum):
    """Failure categories for dashboard/API analytics."""

    NONE = "none"
    MISSING_STEP = "missing_step"
    EXTRA_UNEXPECTED_STEP = "extra_unexpected_step"
    STATUS_FAILED = "status_failed"
    OUTPUT_MISMATCH = "output_mismatch"
    TARGET_MISMATCH = "target_mismatch"
    ACTION_MISMATCH = "action_mismatch"
    ORDER_MISMATCH = "order_mismatch"
    TIMEOUT = "timeout"
    EXCEPTION = "exception"
    SECURITY_BLOCKED = "security_blocked"
    PERMISSION_DENIED = "permission_denied"
    VALIDATION_FAILED = "validation_failed"
    LOW_CONFIDENCE = "low_confidence"
    UNKNOWN = "unknown"


class MatchStrategy(str, Enum):
    """
    Matching strategy for expected steps vs actual replay steps.

    STRICT_ORDER:
        Expected index N must match actual index N.

    STEP_ID:
        Match by stable step_id/id/name where possible.

    FLEXIBLE:
        Match by ID first, then action/target similarity, while allowing minor order shifts.
    """

    STRICT_ORDER = "strict_order"
    STEP_ID = "step_id"
    FLEXIBLE = "flexible"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReplayContext:
    """
    SaaS-safe replay context.

    user_id and workspace_id are required to prevent cross-user/workspace mixing.
    """

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    automation_id: Optional[str] = None
    replay_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    requested_by: Optional[str] = None
    source: str = "verification_agent"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayStep:
    """
    Normalized automation step.

    This class supports both expected and actual step records.
    """

    index: int
    step_id: Optional[str] = None
    name: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    expected_output: Any = None
    actual_output: Any = None
    status: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    duration_ms: Optional[float] = None
    timeout_ms: Optional[float] = None
    error: Optional[Union[str, Dict[str, Any]]] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StepComparison:
    """
    Result of comparing one expected step against one actual step.
    """

    expected_index: Optional[int]
    actual_index: Optional[int]
    expected_step_id: Optional[str]
    actual_step_id: Optional[str]
    status: StepStatus
    reason: FailureReason
    confidence: float
    message: str
    expected_step: Optional[Dict[str, Any]] = None
    actual_step: Optional[Dict[str, Any]] = None
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayAnalysisConfig:
    """
    Configuration for replay analysis.

    Safe defaults are used for production import and testing.
    """

    match_strategy: MatchStrategy = MatchStrategy.FLEXIBLE
    require_order: bool = True
    allow_extra_steps: bool = False
    allow_missing_optional_steps: bool = True
    text_similarity_threshold: float = DEFAULT_TEXT_SIMILARITY_THRESHOLD
    time_tolerance_seconds: float = DEFAULT_TIME_TOLERANCE_SECONDS
    max_steps: int = MAX_SAFE_STEPS
    include_raw_steps: bool = False
    include_evidence: bool = True
    fail_on_warning: bool = False
    compare_outputs: bool = True
    compare_targets: bool = True
    compare_actions: bool = True
    compare_timing: bool = True
    security_required_for_sensitive_replay: bool = True
    confidence_pass_threshold: float = DEFAULT_CONFIDENCE_PASS
    confidence_warning_threshold: float = DEFAULT_CONFIDENCE_WARNING


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_jsonable(value: Any, max_string_length: int = MAX_SAFE_STRING_LENGTH) -> Any:
    """
    Convert unknown values into JSON-safe structures.

    This prevents dashboards/API responses from breaking on non-serializable objects.
    """

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        if len(value) > max_string_length:
            return value[:max_string_length] + "...[truncated]"
        return value

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Mapping):
        safe: Dict[str, Any] = {}
        for key, item in value.items():
            safe[str(key)] = _safe_jsonable(item, max_string_length=max_string_length)
        return safe

    if isinstance(value, (list, tuple, set)):
        return [_safe_jsonable(item, max_string_length=max_string_length) for item in list(value)]

    if hasattr(value, "__dict__"):
        return _safe_jsonable(vars(value), max_string_length=max_string_length)

    try:
        json.dumps(value)
        return value
    except Exception:
        text = repr(value)
        if len(text) > max_string_length:
            text = text[:max_string_length] + "...[truncated]"
        return text


def _normalize_text(value: Any) -> str:
    """Normalize values for string comparison."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        try:
            value = json.dumps(value, sort_keys=True, default=str)
        except Exception:
            value = str(value)
    text = str(value).strip().lower()
    return " ".join(text.split())


def _text_similarity(left: Any, right: Any) -> float:
    """Return similarity score between two values converted to text."""
    left_text = _normalize_text(left)
    right_text = _normalize_text(right)

    if not left_text and not right_text:
        return 1.0
    if not left_text or not right_text:
        return 0.0
    if left_text == right_text:
        return 1.0

    return float(difflib.SequenceMatcher(None, left_text, right_text).ratio())


def _clamp_confidence(value: float) -> float:
    """Clamp confidence into 0.0-1.0 range."""
    if math.isnan(value) or math.isinf(value):
        return 0.0
    return max(0.0, min(1.0, float(value)))


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Coerce mixed input into bool."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _parse_timestamp_to_epoch(value: Optional[str]) -> Optional[float]:
    """Parse an ISO timestamp into epoch seconds."""
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _duration_seconds(step: ReplayStep) -> Optional[float]:
    """Get duration in seconds from duration_ms or timestamps."""
    if step.duration_ms is not None:
        try:
            return float(step.duration_ms) / 1000.0
        except Exception:
            return None

    started = _parse_timestamp_to_epoch(step.started_at)
    ended = _parse_timestamp_to_epoch(step.ended_at)
    if started is not None and ended is not None and ended >= started:
        return ended - started

    return None


def _normalize_status(status: Any, error: Any = None) -> StepStatus:
    """Normalize raw step status into StepStatus."""
    if error:
        error_text = _normalize_text(error)
        if "timeout" in error_text:
            return StepStatus.FAILED
        if "permission" in error_text or "denied" in error_text:
            return StepStatus.FAILED
        return StepStatus.FAILED

    text = _normalize_text(status)

    if not text:
        return StepStatus.INCONCLUSIVE

    if text in PASS_STATUSES:
        return StepStatus.PASSED

    if text in TERMINAL_FAILURE_STATUSES:
        return StepStatus.FAILED

    if text in WARNING_STATUSES:
        if text == "skipped":
            return StepStatus.SKIPPED
        return StepStatus.WARNING

    return StepStatus.INCONCLUSIVE


def _failure_reason_from_step(step: ReplayStep) -> FailureReason:
    """Infer failure reason from step error/status."""
    status_text = _normalize_text(step.status)
    error_text = _normalize_text(step.error)

    combined = f"{status_text} {error_text}".strip()

    if "security" in combined and ("denied" in combined or "blocked" in combined):
        return FailureReason.SECURITY_BLOCKED
    if "permission" in combined or "unauthorized" in combined or "forbidden" in combined:
        return FailureReason.PERMISSION_DENIED
    if "timeout" in combined:
        return FailureReason.TIMEOUT
    if "exception" in combined or "traceback" in combined:
        return FailureReason.EXCEPTION
    if "validation" in combined:
        return FailureReason.VALIDATION_FAILED
    if status_text in TERMINAL_FAILURE_STATUSES:
        return FailureReason.STATUS_FAILED

    return FailureReason.UNKNOWN


def _limit_evidence(evidence: Any) -> List[Dict[str, Any]]:
    """Normalize and limit evidence items."""
    if evidence is None:
        return []

    items: List[Any]
    if isinstance(evidence, list):
        items = evidence
    else:
        items = [evidence]

    normalized: List[Dict[str, Any]] = []
    for item in items[:MAX_SAFE_EVIDENCE_ITEMS_PER_STEP]:
        if isinstance(item, Mapping):
            normalized.append(_safe_jsonable(dict(item)))
        else:
            normalized.append({"value": _safe_jsonable(item)})

    return normalized


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class ActionReplayChecker(BaseAgent):
    """
    Checks multi-step automation replay traces and identifies the failed step.

    Public methods:
        - check_action_replay(...)
        - replay_check(...)
        - identify_failed_step(...)
        - compare_step_sequences(...)
        - prepare_dashboard_payload(...)

    This class analyzes data only. It does not perform the original automation actions.
    """

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        config: Optional[Union[ReplayAnalysisConfig, Dict[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize ActionReplayChecker.

        Args:
            security_agent:
                Optional SecurityAgent instance. If not provided, security approval
                falls back to safe local rules.

            config:
                ReplayAnalysisConfig or dict override.

            logger:
                Optional logger.

            **kwargs:
                Additional BaseAgent-compatible arguments.
        """
        try:
            super().__init__(agent_name=DEFAULT_AGENT_NAME, **kwargs)
        except TypeError:
            try:
                super().__init__(**kwargs)
            except Exception:
                pass

        self.agent_name = DEFAULT_AGENT_NAME
        self.version = DEFAULT_VERSION
        self.logger = logger or LOGGER
        self.security_agent = security_agent
        self.config = self._build_config(config)

        self.capabilities = {
            "multi_step_replay_analysis": True,
            "failed_step_detection": True,
            "expected_vs_actual_comparison": True,
            "order_mismatch_detection": True,
            "output_mismatch_detection": True,
            "timing_timeout_detection": True,
            "verification_payload": True,
            "memory_payload": True,
            "audit_events": True,
            "saas_isolation": True,
            "safe_import_fallbacks": True,
        }

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def check_action_replay(
        self,
        expected_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        actual_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
        automation_id: Optional[str] = None,
        replay_id: Optional[str] = None,
        context: Optional[Union[ReplayContext, Mapping[str, Any]]] = None,
        config: Optional[Union[ReplayAnalysisConfig, Mapping[str, Any]]] = None,
        custom_comparator: Optional[Callable[[ReplayStep, ReplayStep], Optional[StepComparison]]] = None,
    ) -> Dict[str, Any]:
        """
        Main entry point.

        Compares expected automation steps with actual replay/trace steps and
        identifies the first failed step.

        Args:
            expected_steps:
                Expected automation plan steps.

            actual_steps:
                Actual replay trace/execution steps.

            user_id:
                SaaS user ID. Required if context is not supplied.

            workspace_id:
                SaaS workspace ID. Required if context is not supplied.

            task_id:
                Optional task identifier.

            automation_id:
                Optional automation/workflow identifier.

            replay_id:
                Optional replay identifier.

            context:
                Optional ReplayContext or context dict.

            config:
                Optional per-call config override.

            custom_comparator:
                Optional callable for project-specific comparison logic.
                It must not execute real actions.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """
        started_at = time.time()

        try:
            replay_context = self._coerce_context(
                context=context,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                automation_id=automation_id,
                replay_id=replay_id,
            )
            validation = self._validate_task_context(replay_context)
            if not validation["success"]:
                return validation

            active_config = self._build_config(config, base=self.config)

            normalized_expected = self._normalize_steps(expected_steps, kind="expected")
            normalized_actual = self._normalize_steps(actual_steps, kind="actual")

            size_validation = self._validate_step_limits(
                expected_steps=normalized_expected,
                actual_steps=normalized_actual,
                config=active_config,
            )
            if not size_validation["success"]:
                return size_validation

            requires_security = self._requires_security_check(
                expected_steps=normalized_expected,
                actual_steps=normalized_actual,
                context=replay_context,
                config=active_config,
            )

            if requires_security:
                approval = self._request_security_approval(
                    action="verification.action_replay_check",
                    context=replay_context,
                    payload={
                        "expected_step_count": len(normalized_expected),
                        "actual_step_count": len(normalized_actual),
                        "automation_id": replay_context.automation_id,
                        "task_id": replay_context.task_id,
                        "reason": "Sensitive action keywords detected in replay data.",
                    },
                )
                if not approval.get("approved", False):
                    result = self._error_result(
                        message="Security approval denied for sensitive action replay analysis.",
                        error="security_approval_denied",
                        metadata={
                            "context": asdict(replay_context),
                            "approval": _safe_jsonable(approval),
                            "duration_ms": self._elapsed_ms(started_at),
                        },
                    )
                    self._log_audit_event(
                        "verification.action_replay.security_denied",
                        replay_context,
                        result,
                    )
                    return result

            comparisons = self.compare_step_sequences(
                expected_steps=normalized_expected,
                actual_steps=normalized_actual,
                config=active_config,
                custom_comparator=custom_comparator,
            )

            failure = self.identify_failed_step_from_comparisons(comparisons)

            summary = self._build_summary(
                expected_steps=normalized_expected,
                actual_steps=normalized_actual,
                comparisons=comparisons,
                failure=failure,
                config=active_config,
            )

            verification_payload = self._prepare_verification_payload(
                context=replay_context,
                summary=summary,
                comparisons=comparisons,
                failure=failure,
            )

            memory_payload = self._prepare_memory_payload(
                context=replay_context,
                summary=summary,
                failure=failure,
            )

            data = {
                "replay_status": summary["replay_status"],
                "passed": summary["replay_status"] == ReplayStatus.PASSED.value,
                "failed": summary["replay_status"] == ReplayStatus.FAILED.value,
                "warning": summary["replay_status"] == ReplayStatus.WARNING.value,
                "inconclusive": summary["replay_status"] == ReplayStatus.INCONCLUSIVE.value,
                "summary": summary,
                "failed_step": failure,
                "comparisons": [self._comparison_to_dict(item, active_config) for item in comparisons],
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            }

            success = summary["replay_status"] in {
                ReplayStatus.PASSED.value,
                ReplayStatus.WARNING.value,
                ReplayStatus.INCONCLUSIVE.value,
            }

            if summary["replay_status"] == ReplayStatus.PASSED.value:
                message = "Action replay passed. All expected steps matched the actual replay."
            elif summary["replay_status"] == ReplayStatus.WARNING.value:
                message = "Action replay completed with warnings. Review flagged steps."
            elif summary["replay_status"] == ReplayStatus.INCONCLUSIVE.value:
                message = "Action replay was inconclusive. More evidence is needed."
            else:
                failed_index = failure.get("expected_index")
                if failed_index is None:
                    failed_index = failure.get("actual_index")
                message = f"Action replay failed at step {failed_index}."

            result = self._safe_result(
                success=success,
                message=message,
                data=data,
                metadata={
                    "agent": self.agent_name,
                    "version": self.version,
                    "context": asdict(replay_context),
                    "duration_ms": self._elapsed_ms(started_at),
                    "timestamp": _utc_now_iso(),
                },
            )

            self._emit_agent_event("verification.action_replay.checked", replay_context, result)
            self._log_audit_event("verification.action_replay.checked", replay_context, result)

            return result

        except Exception as exc:
            error_payload = {
                "exception": exc.__class__.__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
                "duration_ms": self._elapsed_ms(started_at),
            }
            self.logger.exception("Action replay check failed unexpectedly.")
            return self._error_result(
                message="Action replay check failed unexpectedly.",
                error=error_payload,
                metadata={
                    "agent": self.agent_name,
                    "version": self.version,
                    "timestamp": _utc_now_iso(),
                },
            )

    def replay_check(
        self,
        expected_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        actual_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Alias for check_action_replay.

        Kept for simple router/Master Agent method discovery.
        """
        return self.check_action_replay(
            expected_steps=expected_steps,
            actual_steps=actual_steps,
            **kwargs,
        )

    def identify_failed_step(
        self,
        expected_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        actual_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convenience method that returns only failed-step-focused data.

        Args:
            expected_steps:
                Expected plan.

            actual_steps:
                Actual replay trace.

            user_id:
                Required SaaS user ID.

            workspace_id:
                Required SaaS workspace ID.

            **kwargs:
                Passed to check_action_replay.

        Returns:
            Structured result containing failed_step and summary.
        """
        result = self.check_action_replay(
            expected_steps=expected_steps,
            actual_steps=actual_steps,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        if not result.get("success") and not result.get("data"):
            return result

        data = result.get("data", {})
        focused_data = {
            "replay_status": data.get("replay_status"),
            "failed_step": data.get("failed_step"),
            "summary": data.get("summary"),
            "verification_payload": data.get("verification_payload"),
        }

        return self._safe_result(
            success=result.get("success", False),
            message=result.get("message", "Failed step analysis completed."),
            data=focused_data,
            metadata=result.get("metadata", {}),
        )

    def compare_step_sequences(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        config: Optional[ReplayAnalysisConfig] = None,
        custom_comparator: Optional[Callable[[ReplayStep, ReplayStep], Optional[StepComparison]]] = None,
    ) -> List[StepComparison]:
        """
        Compare expected and actual step sequences.

        This method is pure analysis and safe for unit tests.
        """
        active_config = config or self.config

        if active_config.match_strategy == MatchStrategy.STRICT_ORDER:
            return self._compare_strict_order(
                expected_steps=expected_steps,
                actual_steps=actual_steps,
                config=active_config,
                custom_comparator=custom_comparator,
            )

        if active_config.match_strategy == MatchStrategy.STEP_ID:
            return self._compare_by_step_id(
                expected_steps=expected_steps,
                actual_steps=actual_steps,
                config=active_config,
                custom_comparator=custom_comparator,
            )

        return self._compare_flexible(
            expected_steps=expected_steps,
            actual_steps=actual_steps,
            config=active_config,
            custom_comparator=custom_comparator,
        )

    def identify_failed_step_from_comparisons(
        self,
        comparisons: Sequence[StepComparison],
    ) -> Optional[Dict[str, Any]]:
        """
        Identify first failed/warning/inconclusive step from comparison output.

        True failed steps are prioritized over warning/inconclusive findings.
        """
        failure_priority = [
            StepStatus.FAILED,
            StepStatus.MISSING,
            StepStatus.EXTRA,
            StepStatus.WARNING,
            StepStatus.SKIPPED,
            StepStatus.INCONCLUSIVE,
        ]

        for status in failure_priority:
            for comparison in comparisons:
                if comparison.status == status:
                    return {
                        "expected_index": comparison.expected_index,
                        "actual_index": comparison.actual_index,
                        "expected_step_id": comparison.expected_step_id,
                        "actual_step_id": comparison.actual_step_id,
                        "status": comparison.status.value,
                        "reason": comparison.reason.value,
                        "confidence": round(comparison.confidence, 4),
                        "message": comparison.message,
                        "mismatches": _safe_jsonable(comparison.mismatches),
                        "evidence": _safe_jsonable(comparison.evidence),
                        "metadata": _safe_jsonable(comparison.metadata),
                        "expected_step": _safe_jsonable(comparison.expected_step),
                        "actual_step": _safe_jsonable(comparison.actual_step),
                    }

        return None

    def prepare_dashboard_payload(
        self,
        replay_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a compact dashboard-friendly payload from a replay result.
        """
        data = replay_result.get("data", {}) if isinstance(replay_result, Mapping) else {}
        summary = data.get("summary", {}) if isinstance(data, Mapping) else {}
        failed_step = data.get("failed_step") if isinstance(data, Mapping) else None

        return {
            "success": bool(replay_result.get("success", False)),
            "message": replay_result.get("message", ""),
            "status": summary.get("replay_status", data.get("replay_status")),
            "confidence": summary.get("confidence"),
            "total_expected_steps": summary.get("total_expected_steps"),
            "total_actual_steps": summary.get("total_actual_steps"),
            "passed_steps": summary.get("passed_steps"),
            "failed_steps": summary.get("failed_steps"),
            "warning_steps": summary.get("warning_steps"),
            "missing_steps": summary.get("missing_steps"),
            "extra_steps": summary.get("extra_steps"),
            "failed_step": failed_step,
            "timestamp": replay_result.get("metadata", {}).get("timestamp", _utc_now_iso()),
            "metadata": _safe_jsonable(replay_result.get("metadata", {})),
        }

    # -----------------------------------------------------------------------
    # Comparison Strategies
    # -----------------------------------------------------------------------

    def _compare_strict_order(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        config: ReplayAnalysisConfig,
        custom_comparator: Optional[Callable[[ReplayStep, ReplayStep], Optional[StepComparison]]] = None,
    ) -> List[StepComparison]:
        """Compare steps strictly by index/order."""
        comparisons: List[StepComparison] = []
        max_len = max(len(expected_steps), len(actual_steps))

        for index in range(max_len):
            expected = expected_steps[index] if index < len(expected_steps) else None
            actual = actual_steps[index] if index < len(actual_steps) else None

            if expected is None and actual is not None:
                comparisons.append(self._extra_step_comparison(actual, config))
                continue

            if expected is not None and actual is None:
                comparisons.append(self._missing_step_comparison(expected, config))
                continue

            if expected is not None and actual is not None:
                comparisons.append(
                    self._compare_single_step(
                        expected=expected,
                        actual=actual,
                        config=config,
                        custom_comparator=custom_comparator,
                    )
                )

        return comparisons

    def _compare_by_step_id(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        config: ReplayAnalysisConfig,
        custom_comparator: Optional[Callable[[ReplayStep, ReplayStep], Optional[StepComparison]]] = None,
    ) -> List[StepComparison]:
        """Compare steps by step_id/name/action-target fallback."""
        comparisons: List[StepComparison] = []
        actual_used: set[int] = set()

        actual_index_by_key = self._build_step_lookup(actual_steps)

        for expected in expected_steps:
            expected_key = self._step_match_key(expected)
            actual_index = actual_index_by_key.get(expected_key)

            if actual_index is None:
                comparisons.append(self._missing_step_comparison(expected, config))
                continue

            actual = actual_steps[actual_index]
            actual_used.add(actual_index)
            comparison = self._compare_single_step(
                expected=expected,
                actual=actual,
                config=config,
                custom_comparator=custom_comparator,
            )

            if config.require_order and expected.index != actual.index and comparison.status == StepStatus.PASSED:
                comparison.status = StepStatus.WARNING
                comparison.reason = FailureReason.ORDER_MISMATCH
                comparison.confidence = min(comparison.confidence, 0.78)
                comparison.message = (
                    f"Step matched by ID/key but order changed: expected index "
                    f"{expected.index}, actual index {actual.index}."
                )
                comparison.mismatches.append({
                    "field": "index",
                    "expected": expected.index,
                    "actual": actual.index,
                    "reason": FailureReason.ORDER_MISMATCH.value,
                })

            comparisons.append(comparison)

        for index, actual in enumerate(actual_steps):
            if index not in actual_used:
                comparisons.append(self._extra_step_comparison(actual, config))

        return comparisons

    def _compare_flexible(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        config: ReplayAnalysisConfig,
        custom_comparator: Optional[Callable[[ReplayStep, ReplayStep], Optional[StepComparison]]] = None,
    ) -> List[StepComparison]:
        """
        Flexible sequence comparison.

        Matching priority:
            1. Exact step_id/name key
            2. Best action+target similarity
            3. Same index fallback
        """
        comparisons: List[StepComparison] = []
        actual_used: set[int] = set()
        actual_key_lookup = self._build_step_lookup(actual_steps)

        for expected_position, expected in enumerate(expected_steps):
            matched_index: Optional[int] = None

            expected_key = self._step_match_key(expected)
            key_match = actual_key_lookup.get(expected_key)
            if key_match is not None and key_match not in actual_used:
                matched_index = key_match

            if matched_index is None:
                matched_index = self._find_best_flexible_match(
                    expected=expected,
                    actual_steps=actual_steps,
                    actual_used=actual_used,
                    threshold=max(0.50, config.text_similarity_threshold - 0.15),
                )

            if matched_index is None and expected_position < len(actual_steps):
                if expected_position not in actual_used:
                    matched_index = expected_position

            if matched_index is None:
                comparisons.append(self._missing_step_comparison(expected, config))
                continue

            actual = actual_steps[matched_index]
            actual_used.add(matched_index)
            comparison = self._compare_single_step(
                expected=expected,
                actual=actual,
                config=config,
                custom_comparator=custom_comparator,
            )

            if config.require_order and expected.index != actual.index:
                if comparison.status == StepStatus.PASSED:
                    comparison.status = StepStatus.WARNING
                    comparison.reason = FailureReason.ORDER_MISMATCH
                    comparison.confidence = min(comparison.confidence, 0.80)
                    comparison.message = (
                        f"Step matched but order differs: expected index "
                        f"{expected.index}, actual index {actual.index}."
                    )
                comparison.mismatches.append({
                    "field": "index",
                    "expected": expected.index,
                    "actual": actual.index,
                    "reason": FailureReason.ORDER_MISMATCH.value,
                })

            comparisons.append(comparison)

        for actual_index, actual in enumerate(actual_steps):
            if actual_index not in actual_used:
                comparisons.append(self._extra_step_comparison(actual, config))

        return comparisons

    def _compare_single_step(
        self,
        expected: ReplayStep,
        actual: ReplayStep,
        config: ReplayAnalysisConfig,
        custom_comparator: Optional[Callable[[ReplayStep, ReplayStep], Optional[StepComparison]]] = None,
    ) -> StepComparison:
        """Compare one expected step against one actual step."""
        if custom_comparator is not None:
            custom_result = custom_comparator(expected, actual)
            if custom_result is not None:
                return custom_result

        mismatches: List[Dict[str, Any]] = []
        evidence: List[Dict[str, Any]] = []

        expected_dict = self._step_to_dict(expected, include_raw=config.include_raw_steps)
        actual_dict = self._step_to_dict(actual, include_raw=config.include_raw_steps)

        actual_status = _normalize_status(actual.status, actual.error)

        if config.include_evidence:
            evidence.extend(_limit_evidence(expected.evidence))
            evidence.extend(_limit_evidence(actual.evidence))

        if actual_status == StepStatus.FAILED:
            reason = _failure_reason_from_step(actual)
            return StepComparison(
                expected_index=expected.index,
                actual_index=actual.index,
                expected_step_id=expected.step_id,
                actual_step_id=actual.step_id,
                status=StepStatus.FAILED,
                reason=reason,
                confidence=DEFAULT_CONFIDENCE_FAIL,
                message=self._build_failed_status_message(expected, actual, reason),
                expected_step=expected_dict,
                actual_step=actual_dict,
                mismatches=[{
                    "field": "status",
                    "expected": "passed/success",
                    "actual": actual.status,
                    "error": _safe_jsonable(actual.error),
                    "reason": reason.value,
                }],
                evidence=evidence,
                metadata={
                    "detected_by": "actual_status_or_error",
                    "raw_status": actual.status,
                },
            )

        if actual_status in {StepStatus.WARNING, StepStatus.SKIPPED, StepStatus.INCONCLUSIVE}:
            mismatches.append({
                "field": "status",
                "expected": "passed/success",
                "actual": actual.status,
                "reason": actual_status.value,
            })

        action_score = 1.0
        target_score = 1.0
        output_score = 1.0
        timing_score = 1.0

        if config.compare_actions:
            action_score = self._compare_field_similarity(
                expected_value=expected.action,
                actual_value=actual.action,
                threshold=config.text_similarity_threshold,
                field_name="action",
                reason=FailureReason.ACTION_MISMATCH,
                mismatches=mismatches,
            )

        if config.compare_targets:
            target_score = self._compare_field_similarity(
                expected_value=expected.target,
                actual_value=actual.target,
                threshold=config.text_similarity_threshold,
                field_name="target",
                reason=FailureReason.TARGET_MISMATCH,
                mismatches=mismatches,
            )

        if config.compare_outputs:
            output_score = self._compare_outputs(
                expected=expected,
                actual=actual,
                threshold=config.text_similarity_threshold,
                mismatches=mismatches,
            )

        if config.compare_timing:
            timing_score = self._compare_timing(
                expected=expected,
                actual=actual,
                tolerance_seconds=config.time_tolerance_seconds,
                mismatches=mismatches,
            )

        confidence = self._calculate_step_confidence(
            status=actual_status,
            action_score=action_score,
            target_score=target_score,
            output_score=output_score,
            timing_score=timing_score,
            mismatch_count=len(mismatches),
        )

        if mismatches:
            primary_reason = self._primary_reason_from_mismatches(mismatches)
            if actual_status in {StepStatus.WARNING, StepStatus.SKIPPED}:
                status = StepStatus.WARNING
            elif confidence < config.confidence_warning_threshold:
                status = StepStatus.FAILED
            else:
                status = StepStatus.WARNING

            message = self._build_mismatch_message(expected, actual, mismatches, confidence)
        else:
            primary_reason = FailureReason.NONE
            status = StepStatus.PASSED
            message = f"Step {expected.index} matched successfully."

        return StepComparison(
            expected_index=expected.index,
            actual_index=actual.index,
            expected_step_id=expected.step_id,
            actual_step_id=actual.step_id,
            status=status,
            reason=primary_reason,
            confidence=confidence,
            message=message,
            expected_step=expected_dict,
            actual_step=actual_dict,
            mismatches=mismatches,
            evidence=evidence,
            metadata={
                "action_score": round(action_score, 4),
                "target_score": round(target_score, 4),
                "output_score": round(output_score, 4),
                "timing_score": round(timing_score, 4),
                "actual_status": actual_status.value,
            },
        )

    # -----------------------------------------------------------------------
    # Field Comparisons
    # -----------------------------------------------------------------------

    def _compare_field_similarity(
        self,
        expected_value: Any,
        actual_value: Any,
        threshold: float,
        field_name: str,
        reason: FailureReason,
        mismatches: List[Dict[str, Any]],
    ) -> float:
        """Compare one text-like field and append mismatch if needed."""
        if expected_value is None or expected_value == "":
            return 1.0

        similarity = _text_similarity(expected_value, actual_value)

        if similarity < threshold:
            mismatches.append({
                "field": field_name,
                "expected": _safe_jsonable(expected_value),
                "actual": _safe_jsonable(actual_value),
                "similarity": round(similarity, 4),
                "threshold": threshold,
                "reason": reason.value,
            })

        return similarity

    def _compare_outputs(
        self,
        expected: ReplayStep,
        actual: ReplayStep,
        threshold: float,
        mismatches: List[Dict[str, Any]],
    ) -> float:
        """Compare expected output vs actual output."""
        expected_output = expected.expected_output

        if expected_output is None:
            if "expected_output" in expected.metadata:
                expected_output = expected.metadata.get("expected_output")
            else:
                return 1.0

        actual_output = actual.actual_output
        if actual_output is None:
            actual_output = actual.raw.get("output")
        if actual_output is None:
            actual_output = actual.raw.get("result")
        if actual_output is None:
            actual_output = actual.raw.get("actual_output")

        if isinstance(expected_output, Mapping) and isinstance(actual_output, Mapping):
            return self._compare_mapping_outputs(
                expected_output=expected_output,
                actual_output=actual_output,
                threshold=threshold,
                mismatches=mismatches,
            )

        similarity = _text_similarity(expected_output, actual_output)

        if similarity < threshold:
            mismatches.append({
                "field": "output",
                "expected": _safe_jsonable(expected_output),
                "actual": _safe_jsonable(actual_output),
                "similarity": round(similarity, 4),
                "threshold": threshold,
                "reason": FailureReason.OUTPUT_MISMATCH.value,
            })

        return similarity

    def _compare_mapping_outputs(
        self,
        expected_output: Mapping[str, Any],
        actual_output: Mapping[str, Any],
        threshold: float,
        mismatches: List[Dict[str, Any]],
    ) -> float:
        """Compare dict-like outputs by expected keys."""
        if not expected_output:
            return 1.0

        scores: List[float] = []

        for key, expected_value in expected_output.items():
            actual_exists = key in actual_output
            actual_value = actual_output.get(key)

            if not actual_exists:
                scores.append(0.0)
                mismatches.append({
                    "field": f"output.{key}",
                    "expected": _safe_jsonable(expected_value),
                    "actual": None,
                    "similarity": 0.0,
                    "threshold": threshold,
                    "reason": FailureReason.OUTPUT_MISMATCH.value,
                    "detail": "Expected output key missing from actual output.",
                })
                continue

            score = _text_similarity(expected_value, actual_value)
            scores.append(score)

            if score < threshold:
                mismatches.append({
                    "field": f"output.{key}",
                    "expected": _safe_jsonable(expected_value),
                    "actual": _safe_jsonable(actual_value),
                    "similarity": round(score, 4),
                    "threshold": threshold,
                    "reason": FailureReason.OUTPUT_MISMATCH.value,
                })

        if not scores:
            return 1.0

        return _clamp_confidence(sum(scores) / len(scores))

    def _compare_timing(
        self,
        expected: ReplayStep,
        actual: ReplayStep,
        tolerance_seconds: float,
        mismatches: List[Dict[str, Any]],
    ) -> float:
        """Compare timing/timeout rules."""
        actual_duration = _duration_seconds(actual)

        timeout_ms = expected.timeout_ms
        if timeout_ms is None:
            timeout_ms = actual.timeout_ms

        if timeout_ms is None or actual_duration is None:
            return 1.0

        timeout_seconds = float(timeout_ms) / 1000.0
        allowed_seconds = timeout_seconds + tolerance_seconds

        if actual_duration <= allowed_seconds:
            return 1.0

        over_by = actual_duration - allowed_seconds

        mismatches.append({
            "field": "duration",
            "expected_max_seconds": round(allowed_seconds, 4),
            "actual_seconds": round(actual_duration, 4),
            "over_by_seconds": round(over_by, 4),
            "reason": FailureReason.TIMEOUT.value,
        })

        if actual_duration <= 0:
            return 0.0

        return _clamp_confidence(allowed_seconds / actual_duration)

    def _calculate_step_confidence(
        self,
        status: StepStatus,
        action_score: float,
        target_score: float,
        output_score: float,
        timing_score: float,
        mismatch_count: int,
    ) -> float:
        """Calculate confidence for a step comparison."""
        if status == StepStatus.FAILED:
            return DEFAULT_CONFIDENCE_FAIL

        weighted = (
            action_score * 0.22
            + target_score * 0.22
            + output_score * 0.36
            + timing_score * 0.12
            + (1.0 if status == StepStatus.PASSED else 0.65) * 0.08
        )

        penalty = min(0.25, mismatch_count * 0.04)
        return _clamp_confidence(weighted - penalty)

    # -----------------------------------------------------------------------
    # Missing / Extra Step Comparisons
    # -----------------------------------------------------------------------

    def _missing_step_comparison(
        self,
        expected: ReplayStep,
        config: ReplayAnalysisConfig,
    ) -> StepComparison:
        """Create comparison for missing actual step."""
        optional = self._is_optional_step(expected)

        if optional and config.allow_missing_optional_steps:
            status = StepStatus.SKIPPED
            reason = FailureReason.MISSING_STEP
            confidence = 0.74
            message = f"Optional expected step {expected.index} was missing/skipped."
        else:
            status = StepStatus.MISSING
            reason = FailureReason.MISSING_STEP
            confidence = 0.96
            message = f"Expected step {expected.index} was not found in actual replay."

        return StepComparison(
            expected_index=expected.index,
            actual_index=None,
            expected_step_id=expected.step_id,
            actual_step_id=None,
            status=status,
            reason=reason,
            confidence=confidence,
            message=message,
            expected_step=self._step_to_dict(expected, include_raw=config.include_raw_steps),
            actual_step=None,
            mismatches=[{
                "field": "step",
                "expected": "present",
                "actual": "missing",
                "reason": FailureReason.MISSING_STEP.value,
                "optional": optional,
            }],
            evidence=_limit_evidence(expected.evidence) if config.include_evidence else [],
            metadata={
                "optional": optional,
                "detected_by": "sequence_matcher",
            },
        )

    def _extra_step_comparison(
        self,
        actual: ReplayStep,
        config: ReplayAnalysisConfig,
    ) -> StepComparison:
        """Create comparison for unexpected actual step."""
        if config.allow_extra_steps:
            status = StepStatus.WARNING
            confidence = 0.72
            message = f"Unexpected extra step {actual.index} found but extra steps are allowed."
        else:
            status = StepStatus.EXTRA
            confidence = 0.91
            message = f"Unexpected extra step {actual.index} found in actual replay."

        return StepComparison(
            expected_index=None,
            actual_index=actual.index,
            expected_step_id=None,
            actual_step_id=actual.step_id,
            status=status,
            reason=FailureReason.EXTRA_UNEXPECTED_STEP,
            confidence=confidence,
            message=message,
            expected_step=None,
            actual_step=self._step_to_dict(actual, include_raw=config.include_raw_steps),
            mismatches=[{
                "field": "step",
                "expected": "not_present",
                "actual": "present",
                "reason": FailureReason.EXTRA_UNEXPECTED_STEP.value,
            }],
            evidence=_limit_evidence(actual.evidence) if config.include_evidence else [],
            metadata={
                "allowed": config.allow_extra_steps,
                "detected_by": "sequence_matcher",
            },
        )

    # -----------------------------------------------------------------------
    # Summary Builders
    # -----------------------------------------------------------------------

    def _build_summary(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        comparisons: Sequence[StepComparison],
        failure: Optional[Dict[str, Any]],
        config: ReplayAnalysisConfig,
    ) -> Dict[str, Any]:
        """Build replay analysis summary."""
        counts = {
            StepStatus.PASSED.value: 0,
            StepStatus.FAILED.value: 0,
            StepStatus.WARNING.value: 0,
            StepStatus.MISSING.value: 0,
            StepStatus.EXTRA.value: 0,
            StepStatus.SKIPPED.value: 0,
            StepStatus.INCONCLUSIVE.value: 0,
        }

        confidences: List[float] = []

        for comparison in comparisons:
            counts[comparison.status.value] = counts.get(comparison.status.value, 0) + 1
            confidences.append(comparison.confidence)

        failed_count = (
            counts[StepStatus.FAILED.value]
            + counts[StepStatus.MISSING.value]
            + (0 if config.allow_extra_steps else counts[StepStatus.EXTRA.value])
        )
        warning_count = (
            counts[StepStatus.WARNING.value]
            + counts[StepStatus.SKIPPED.value]
            + counts[StepStatus.INCONCLUSIVE.value]
        )

        average_confidence = (
            _clamp_confidence(sum(confidences) / len(confidences))
            if confidences
            else 0.0
        )

        if failed_count > 0:
            replay_status = ReplayStatus.FAILED
        elif warning_count > 0:
            replay_status = ReplayStatus.FAILED if config.fail_on_warning else ReplayStatus.WARNING
        elif not comparisons and expected_steps:
            replay_status = ReplayStatus.INCONCLUSIVE
        elif average_confidence < config.confidence_warning_threshold:
            replay_status = ReplayStatus.INCONCLUSIVE
        else:
            replay_status = ReplayStatus.PASSED

        return {
            "replay_status": replay_status.value,
            "confidence": round(average_confidence, 4),
            "total_expected_steps": len(expected_steps),
            "total_actual_steps": len(actual_steps),
            "total_comparisons": len(comparisons),
            "passed_steps": counts[StepStatus.PASSED.value],
            "failed_steps": counts[StepStatus.FAILED.value],
            "warning_steps": counts[StepStatus.WARNING.value],
            "missing_steps": counts[StepStatus.MISSING.value],
            "extra_steps": counts[StepStatus.EXTRA.value],
            "skipped_steps": counts[StepStatus.SKIPPED.value],
            "inconclusive_steps": counts[StepStatus.INCONCLUSIVE.value],
            "first_problem_step": failure,
            "match_strategy": config.match_strategy.value,
            "require_order": config.require_order,
            "allow_extra_steps": config.allow_extra_steps,
            "compare_outputs": config.compare_outputs,
            "compare_targets": config.compare_targets,
            "compare_actions": config.compare_actions,
            "compare_timing": config.compare_timing,
        }

    def _prepare_verification_payload(
        self,
        context: ReplayContext,
        summary: Mapping[str, Any],
        comparisons: Sequence[StepComparison],
        failure: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This is suitable for task history, proof reports, dashboards, and API responses.
        """
        return {
            "type": "action_replay_verification",
            "agent": self.agent_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "automation_id": context.automation_id,
            "replay_id": context.replay_id,
            "correlation_id": context.correlation_id,
            "status": summary.get("replay_status"),
            "confidence": summary.get("confidence"),
            "passed": summary.get("replay_status") == ReplayStatus.PASSED.value,
            "failed_step": _safe_jsonable(failure),
            "step_counts": {
                "expected": summary.get("total_expected_steps"),
                "actual": summary.get("total_actual_steps"),
                "passed": summary.get("passed_steps"),
                "failed": summary.get("failed_steps"),
                "warnings": summary.get("warning_steps"),
                "missing": summary.get("missing_steps"),
                "extra": summary.get("extra_steps"),
                "inconclusive": summary.get("inconclusive_steps"),
            },
            "comparison_digest": [
                {
                    "expected_index": item.expected_index,
                    "actual_index": item.actual_index,
                    "status": item.status.value,
                    "reason": item.reason.value,
                    "confidence": round(item.confidence, 4),
                    "message": item.message,
                }
                for item in comparisons[:50]
            ],
            "created_at": _utc_now_iso(),
            "metadata": {
                "source": context.source,
                "requested_by": context.requested_by,
                "context_metadata": _safe_jsonable(context.metadata),
            },
        }

    def _prepare_memory_payload(
        self,
        context: ReplayContext,
        summary: Mapping[str, Any],
        failure: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        The payload is scoped by user_id and workspace_id to prevent leakage.
        """
        return {
            "memory_type": "verification_action_replay_summary",
            "scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "task_id": context.task_id,
            "automation_id": context.automation_id,
            "replay_id": context.replay_id,
            "summary": {
                "status": summary.get("replay_status"),
                "confidence": summary.get("confidence"),
                "total_expected_steps": summary.get("total_expected_steps"),
                "total_actual_steps": summary.get("total_actual_steps"),
                "failed_step_index": None if not failure else failure.get("expected_index"),
                "failure_reason": None if not failure else failure.get("reason"),
                "failure_message": None if not failure else failure.get("message"),
            },
            "importance": self._memory_importance(summary, failure),
            "created_at": _utc_now_iso(),
        }

    def _memory_importance(
        self,
        summary: Mapping[str, Any],
        failure: Optional[Dict[str, Any]],
    ) -> str:
        """Calculate memory importance label."""
        if summary.get("replay_status") == ReplayStatus.FAILED.value:
            return "high"
        if failure:
            return "medium"
        if summary.get("replay_status") == ReplayStatus.WARNING.value:
            return "medium"
        return "low"

    # -----------------------------------------------------------------------
    # Context / Validation / Config
    # -----------------------------------------------------------------------

    def _build_config(
        self,
        config: Optional[Union[ReplayAnalysisConfig, Mapping[str, Any]]],
        base: Optional[ReplayAnalysisConfig] = None,
    ) -> ReplayAnalysisConfig:
        """Build ReplayAnalysisConfig from dict/dataclass/default."""
        if config is None and base is not None:
            return ReplayAnalysisConfig(**asdict(base))

        if config is None:
            return ReplayAnalysisConfig()

        if isinstance(config, ReplayAnalysisConfig):
            return ReplayAnalysisConfig(**asdict(config))

        base_dict = asdict(base) if base is not None else asdict(ReplayAnalysisConfig())

        for key, value in dict(config).items():
            if key not in base_dict:
                continue

            if key == "match_strategy":
                try:
                    value = MatchStrategy(str(value))
                except Exception:
                    value = base_dict[key]

            base_dict[key] = value

        try:
            return ReplayAnalysisConfig(**base_dict)
        except Exception:
            self.logger.warning("Invalid replay config received. Falling back to defaults.")
            return ReplayAnalysisConfig()

    def _coerce_context(
        self,
        context: Optional[Union[ReplayContext, Mapping[str, Any]]],
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str],
        automation_id: Optional[str],
        replay_id: Optional[str],
    ) -> ReplayContext:
        """Coerce context inputs into ReplayContext."""
        if isinstance(context, ReplayContext):
            if user_id:
                context.user_id = user_id
            if workspace_id:
                context.workspace_id = workspace_id
            if task_id:
                context.task_id = task_id
            if automation_id:
                context.automation_id = automation_id
            if replay_id:
                context.replay_id = replay_id
            return context

        context_dict = dict(context or {})

        return ReplayContext(
            user_id=str(user_id or context_dict.get("user_id") or ""),
            workspace_id=str(workspace_id or context_dict.get("workspace_id") or ""),
            task_id=task_id or context_dict.get("task_id"),
            automation_id=automation_id or context_dict.get("automation_id"),
            replay_id=replay_id or context_dict.get("replay_id") or str(uuid.uuid4()),
            requested_by=context_dict.get("requested_by"),
            source=context_dict.get("source", "verification_agent"),
            correlation_id=context_dict.get("correlation_id") or str(uuid.uuid4()),
            metadata=_safe_jsonable(context_dict.get("metadata", {})),
        )

    def _validate_task_context(self, context: ReplayContext) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required compatibility hook.
        """
        errors: List[str] = []

        if not context.user_id or not str(context.user_id).strip():
            errors.append("user_id is required for action replay verification.")

        if not context.workspace_id or not str(context.workspace_id).strip():
            errors.append("workspace_id is required for action replay verification.")

        if errors:
            return self._error_result(
                message="Invalid action replay context.",
                error={
                    "code": "invalid_context",
                    "details": errors,
                },
                metadata={
                    "agent": self.agent_name,
                    "timestamp": _utc_now_iso(),
                },
            )

        return self._safe_result(
            success=True,
            message="Context validated.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "automation_id": context.automation_id,
                "replay_id": context.replay_id,
            },
            metadata={
                "agent": self.agent_name,
                "timestamp": _utc_now_iso(),
            },
        )

    def _validate_step_limits(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        config: ReplayAnalysisConfig,
    ) -> Dict[str, Any]:
        """Validate safe step limits."""
        if len(expected_steps) > config.max_steps:
            return self._error_result(
                message="Too many expected steps for safe replay analysis.",
                error={
                    "code": "too_many_expected_steps",
                    "count": len(expected_steps),
                    "max_steps": config.max_steps,
                },
            )

        if len(actual_steps) > config.max_steps:
            return self._error_result(
                message="Too many actual steps for safe replay analysis.",
                error={
                    "code": "too_many_actual_steps",
                    "count": len(actual_steps),
                    "max_steps": config.max_steps,
                },
            )

        return self._safe_result(
            success=True,
            message="Step limits validated.",
            data={
                "expected_count": len(expected_steps),
                "actual_count": len(actual_steps),
            },
        )

    def _requires_security_check(
        self,
        expected_steps: Sequence[ReplayStep],
        actual_steps: Sequence[ReplayStep],
        context: ReplayContext,
        config: Optional[ReplayAnalysisConfig] = None,
    ) -> bool:
        """
        Determine whether replay analysis should be security-gated.

        Required compatibility hook.
        """
        active_config = config or self.config

        if not active_config.security_required_for_sensitive_replay:
            return False

        if _coerce_bool(context.metadata.get("force_security_check"), default=False):
            return True

        for step in list(expected_steps) + list(actual_steps):
            searchable = " ".join([
                _normalize_text(step.name),
                _normalize_text(step.action),
                _normalize_text(step.target),
                _normalize_text(step.expected_output),
                _normalize_text(step.actual_output),
                _normalize_text(step.error),
                _normalize_text(step.metadata),
            ])

            if any(keyword in searchable for keyword in SENSITIVE_ACTION_KEYWORDS):
                return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: ReplayContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Required compatibility hook.

        This method is safe by default. If a real SecurityAgent exists and provides
        an approval/check method, it is used. Otherwise local non-execution approval
        is returned for analysis-only verification.
        """
        approval_payload = {
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "automation_id": context.automation_id,
            "replay_id": context.replay_id,
            "payload": _safe_jsonable(payload),
            "requested_at": _utc_now_iso(),
            "analysis_only": True,
        }

        agent = self.security_agent

        if agent is not None:
            for method_name in (
                "approve_action",
                "request_approval",
                "check_permission",
                "authorize",
            ):
                method = getattr(agent, method_name, None)
                if callable(method):
                    try:
                        response = method(approval_payload)
                        if isinstance(response, Mapping):
                            return {
                                "approved": bool(
                                    response.get("approved")
                                    or response.get("success")
                                    or response.get("allowed")
                                ),
                                "source": f"security_agent.{method_name}",
                                "response": _safe_jsonable(response),
                            }
                    except Exception as exc:
                        self.logger.warning(
                            "Security approval method %s failed: %s",
                            method_name,
                            exc,
                        )
                        return {
                            "approved": False,
                            "source": f"security_agent.{method_name}",
                            "error": str(exc),
                        }

        return {
            "approved": True,
            "source": "local_analysis_only_policy",
            "reason": (
                "Replay checker performs analysis only and does not execute sensitive "
                "or destructive actions."
            ),
        }

    # -----------------------------------------------------------------------
    # Step Normalization / Matching
    # -----------------------------------------------------------------------

    def _normalize_steps(
        self,
        steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
        kind: str,
    ) -> List[ReplayStep]:
        """Normalize mixed step inputs into ReplayStep objects."""
        normalized: List[ReplayStep] = []

        for index, step in enumerate(steps or []):
            if isinstance(step, ReplayStep):
                if step.index is None:
                    step.index = index
                normalized.append(step)
                continue

            if not isinstance(step, Mapping):
                step = {
                    "name": str(step),
                    "action": str(step),
                    "status": None,
                    "raw_value": _safe_jsonable(step),
                }

            raw = dict(step)
            metadata = dict(raw.get("metadata") or {})

            normalized_step = ReplayStep(
                index=int(raw.get("index", raw.get("step_index", index))),
                step_id=self._first_string(
                    raw.get("step_id"),
                    raw.get("id"),
                    raw.get("uuid"),
                    raw.get("key"),
                ),
                name=self._first_string(
                    raw.get("name"),
                    raw.get("title"),
                    raw.get("label"),
                    raw.get("description"),
                ),
                action=self._first_string(
                    raw.get("action"),
                    raw.get("type"),
                    raw.get("operation"),
                    raw.get("command"),
                ),
                target=self._first_string(
                    raw.get("target"),
                    raw.get("selector"),
                    raw.get("url"),
                    raw.get("path"),
                    raw.get("resource"),
                    raw.get("element"),
                ),
                expected_output=raw.get("expected_output", raw.get("expected")),
                actual_output=raw.get("actual_output", raw.get("actual", raw.get("output", raw.get("result")))),
                status=self._first_string(
                    raw.get("status"),
                    raw.get("state"),
                    raw.get("result_status"),
                    raw.get("verification_status"),
                ),
                started_at=self._first_string(raw.get("started_at"), raw.get("start_time")),
                ended_at=self._first_string(raw.get("ended_at"), raw.get("end_time")),
                duration_ms=self._safe_float(raw.get("duration_ms", raw.get("elapsed_ms"))),
                timeout_ms=self._safe_float(raw.get("timeout_ms")),
                error=raw.get("error", raw.get("exception")),
                evidence=_limit_evidence(raw.get("evidence", raw.get("proof"))),
                metadata=metadata,
                raw=raw,
            )

            if kind == "expected" and normalized_step.expected_output is None:
                normalized_step.expected_output = raw.get("output")

            normalized.append(normalized_step)

        normalized.sort(key=lambda item: item.index)
        return normalized

    def _build_step_lookup(self, steps: Sequence[ReplayStep]) -> Dict[str, int]:
        """Build lookup from stable step key to index."""
        lookup: Dict[str, int] = {}
        for index, step in enumerate(steps):
            key = self._step_match_key(step)
            if key and key not in lookup:
                lookup[key] = index
        return lookup

    def _step_match_key(self, step: ReplayStep) -> str:
        """Generate stable match key for a step."""
        if step.step_id:
            return f"id:{_normalize_text(step.step_id)}"
        if step.name:
            return f"name:{_normalize_text(step.name)}"

        action = _normalize_text(step.action)
        target = _normalize_text(step.target)

        if action or target:
            return f"action_target:{action}|{target}"

        return f"index:{step.index}"

    def _find_best_flexible_match(
        self,
        expected: ReplayStep,
        actual_steps: Sequence[ReplayStep],
        actual_used: set[int],
        threshold: float,
    ) -> Optional[int]:
        """Find best available actual step for expected step."""
        best_index: Optional[int] = None
        best_score = 0.0

        expected_text = " ".join([
            _normalize_text(expected.name),
            _normalize_text(expected.action),
            _normalize_text(expected.target),
        ]).strip()

        for index, actual in enumerate(actual_steps):
            if index in actual_used:
                continue

            actual_text = " ".join([
                _normalize_text(actual.name),
                _normalize_text(actual.action),
                _normalize_text(actual.target),
            ]).strip()

            score = _text_similarity(expected_text, actual_text)

            if score > best_score:
                best_score = score
                best_index = index

        if best_index is not None and best_score >= threshold:
            return best_index

        return None

    def _is_optional_step(self, step: ReplayStep) -> bool:
        """Determine whether expected step is optional."""
        optional = step.metadata.get("optional")
        if optional is None:
            optional = step.raw.get("optional")
        return _coerce_bool(optional, default=False)

    # -----------------------------------------------------------------------
    # Result / Event / Audit Hooks
    # -----------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standardized success result.

        Required compatibility hook.
        """
        return {
            "success": bool(success),
            "message": str(message),
            "data": _safe_jsonable(data if data is not None else {}),
            "error": _safe_jsonable(error),
            "metadata": _safe_jsonable(metadata if metadata is not None else {}),
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standardized error result.

        Required compatibility hook.
        """
        return {
            "success": False,
            "message": str(message),
            "data": _safe_jsonable(data if data is not None else {}),
            "error": _safe_jsonable(error),
            "metadata": _safe_jsonable(metadata if metadata is not None else {}),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        context: ReplayContext,
        result: Mapping[str, Any],
    ) -> None:
        """
        Emit event for Agent Registry / Dashboard / Analytics.

        Required compatibility hook.
        """
        payload = {
            "event_type": event_type,
            "agent": self.agent_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "automation_id": context.automation_id,
            "replay_id": context.replay_id,
            "correlation_id": context.correlation_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "timestamp": _utc_now_iso(),
        }

        try:
            emit = getattr(super(), "emit_event", None)
            if callable(emit):
                emit(event_type, payload)
                return
        except Exception:
            pass

        try:
            emit_self = getattr(self, "emit_event", None)
            if callable(emit_self) and emit_self is not self._emit_agent_event:
                emit_self(event_type, payload)
                return
        except Exception:
            pass

        self.logger.debug("Agent event emitted locally: %s", payload)

    def _log_audit_event(
        self,
        event_type: str,
        context: ReplayContext,
        result: Mapping[str, Any],
    ) -> None:
        """
        Log audit event.

        Required compatibility hook.
        """
        payload = {
            "event_type": event_type,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "automation_id": context.automation_id,
            "replay_id": context.replay_id,
            "correlation_id": context.correlation_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "error": result.get("error"),
            "timestamp": _utc_now_iso(),
        }

        try:
            audit = getattr(super(), "log_audit", None)
            if callable(audit):
                audit(payload)
                return
        except Exception:
            pass

        try:
            audit_self = getattr(self, "log_audit", None)
            if callable(audit_self) and audit_self is not self._log_audit_event:
                audit_self(payload)
                return
        except Exception:
            pass

        self.logger.info("Audit event: %s", _safe_jsonable(payload))

    # -----------------------------------------------------------------------
    # Serialization / Message Helpers
    # -----------------------------------------------------------------------

    def _comparison_to_dict(
        self,
        comparison: StepComparison,
        config: ReplayAnalysisConfig,
    ) -> Dict[str, Any]:
        """Serialize StepComparison to dict."""
        data = asdict(comparison)
        data["status"] = comparison.status.value
        data["reason"] = comparison.reason.value
        data["confidence"] = round(comparison.confidence, 4)

        if not config.include_evidence:
            data["evidence"] = []

        if not config.include_raw_steps:
            for key in ("expected_step", "actual_step"):
                if isinstance(data.get(key), dict):
                    data[key].pop("raw", None)

        return _safe_jsonable(data)

    def _step_to_dict(
        self,
        step: ReplayStep,
        include_raw: bool = False,
    ) -> Dict[str, Any]:
        """Serialize ReplayStep to dict."""
        data = asdict(step)
        if not include_raw:
            data.pop("raw", None)
        return _safe_jsonable(data)

    def _build_failed_status_message(
        self,
        expected: ReplayStep,
        actual: ReplayStep,
        reason: FailureReason,
    ) -> str:
        """Build message for failed actual status."""
        label = expected.name or expected.action or expected.step_id or f"step {expected.index}"
        actual_status = actual.status or "failed"

        if actual.error:
            return (
                f"Step {expected.index} ({label}) failed with status "
                f"'{actual_status}'. Reason: {reason.value}. Error: {_normalize_text(actual.error)}"
            )

        return (
            f"Step {expected.index} ({label}) failed with status "
            f"'{actual_status}'. Reason: {reason.value}."
        )

    def _build_mismatch_message(
        self,
        expected: ReplayStep,
        actual: ReplayStep,
        mismatches: Sequence[Mapping[str, Any]],
        confidence: float,
    ) -> str:
        """Build user-readable mismatch message."""
        fields = [str(item.get("field")) for item in mismatches[:4]]
        field_text = ", ".join(fields) if fields else "unknown fields"

        return (
            f"Step {expected.index} matched actual step {actual.index}, but mismatch "
            f"was detected in: {field_text}. Confidence: {round(confidence, 4)}."
        )

    def _primary_reason_from_mismatches(
        self,
        mismatches: Sequence[Mapping[str, Any]],
    ) -> FailureReason:
        """Get primary failure reason from mismatch list."""
        priority = [
            FailureReason.SECURITY_BLOCKED,
            FailureReason.PERMISSION_DENIED,
            FailureReason.TIMEOUT,
            FailureReason.STATUS_FAILED,
            FailureReason.ACTION_MISMATCH,
            FailureReason.TARGET_MISMATCH,
            FailureReason.OUTPUT_MISMATCH,
            FailureReason.ORDER_MISMATCH,
            FailureReason.LOW_CONFIDENCE,
            FailureReason.UNKNOWN,
        ]

        reasons = {
            str(item.get("reason"))
            for item in mismatches
            if item.get("reason") is not None
        }

        for reason in priority:
            if reason.value in reasons:
                return reason

        return FailureReason.UNKNOWN

    def _first_string(self, *values: Any) -> Optional[str]:
        """Return first non-empty string from values."""
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return None

    def _safe_float(self, value: Any) -> Optional[float]:
        """Safely parse float."""
        if value is None or value == "":
            return None
        try:
            parsed = float(value)
            if math.isnan(parsed) or math.isinf(parsed):
                return None
            return parsed
        except Exception:
            return None

    def _elapsed_ms(self, started_at: float) -> float:
        """Return elapsed milliseconds."""
        return round((time.time() - started_at) * 1000.0, 3)

    # -----------------------------------------------------------------------
    # Registry / Router Metadata
    # -----------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """
        Return Agent Registry compatible metadata.
        """
        return {
            "name": self.agent_name,
            "class_name": self.__class__.__name__,
            "version": self.version,
            "module": "agents.verification_agent.action_replay_checker",
            "capabilities": self.capabilities,
            "public_methods": [
                "check_action_replay",
                "replay_check",
                "identify_failed_step",
                "compare_step_sequences",
                "prepare_dashboard_payload",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "executes_real_actions": False,
            "safe_to_import": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for dashboard/API readiness.
        """
        return self._safe_result(
            success=True,
            message="ActionReplayChecker is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.version,
                "capabilities": self.capabilities,
                "config": _safe_jsonable(asdict(self.config)),
            },
            metadata={
                "timestamp": _utc_now_iso(),
            },
        )


# ---------------------------------------------------------------------------
# Module-Level Convenience Function
# ---------------------------------------------------------------------------

def check_action_replay(
    expected_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
    actual_steps: Sequence[Union[ReplayStep, Mapping[str, Any]]],
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Convenience function for direct module usage.

    Example:
        result = check_action_replay(
            expected_steps=[{"action": "open", "target": "dashboard"}],
            actual_steps=[{"action": "open", "target": "dashboard", "status": "success"}],
            user_id="user_123",
            workspace_id="workspace_123",
        )
    """
    checker = ActionReplayChecker()
    return checker.check_action_replay(
        expected_steps=expected_steps,
        actual_steps=actual_steps,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


__all__ = [
    "ActionReplayChecker",
    "ReplayContext",
    "ReplayStep",
    "StepComparison",
    "ReplayAnalysisConfig",
    "ReplayStatus",
    "StepStatus",
    "FailureReason",
    "MatchStrategy",
    "check_action_replay",
]


# ---------------------------------------------------------------------------
# Safe Manual Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    demo_expected = [
        {
            "index": 0,
            "step_id": "open_dashboard",
            "name": "Open dashboard",
            "action": "open_page",
            "target": "/dashboard",
            "expected_output": {"page": "dashboard"},
            "timeout_ms": 5000,
        },
        {
            "index": 1,
            "step_id": "click_settings",
            "name": "Click settings",
            "action": "click",
            "target": "#settings",
            "expected_output": {"panel": "settings"},
            "timeout_ms": 3000,
        },
        {
            "index": 2,
            "step_id": "save_profile",
            "name": "Save profile",
            "action": "click",
            "target": "#save-profile",
            "expected_output": {"toast": "Profile saved"},
            "timeout_ms": 3000,
        },
    ]

    demo_actual = [
        {
            "index": 0,
            "step_id": "open_dashboard",
            "name": "Open dashboard",
            "action": "open_page",
            "target": "/dashboard",
            "actual_output": {"page": "dashboard"},
            "status": "success",
            "duration_ms": 1200,
        },
        {
            "index": 1,
            "step_id": "click_settings",
            "name": "Click settings",
            "action": "click",
            "target": "#settings",
            "actual_output": {"panel": "settings"},
            "status": "success",
            "duration_ms": 900,
        },
        {
            "index": 2,
            "step_id": "save_profile",
            "name": "Save profile",
            "action": "click",
            "target": "#save-profile",
            "actual_output": {"toast": "Validation error"},
            "status": "failed",
            "error": "Validation failed: missing required field",
            "duration_ms": 800,
        },
    ]

    demo_checker = ActionReplayChecker()
    demo_result = demo_checker.check_action_replay(
        expected_steps=demo_expected,
        actual_steps=demo_actual,
        user_id="demo_user",
        workspace_id="demo_workspace",
        task_id="demo_task",
        automation_id="demo_automation",
    )
    print(json.dumps(demo_result, indent=2, default=str))