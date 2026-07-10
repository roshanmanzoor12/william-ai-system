"""
File: agents/verification_agent/result_validator.py
Project: William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Compares an expected result against an actual result and returns a structured
    validation status, confidence score, difference report, and verification payload.

Agent/Module:
    Verification Agent

Required Class:
    ResultValidator

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is not available yet.
    - MasterAgent / Agent Registry / Agent Loader safe import.
    - SaaS user/workspace isolation aware.
    - Security Agent hook compatible.
    - Memory Agent payload compatible.
    - Dashboard/API ready structured responses.

This file is intentionally import-safe:
    If future William/Jarvis modules do not exist yet, local fallback stubs are used.
"""

from __future__ import annotations

import copy
import dataclasses
import difflib
import json
import logging
import math
import re
import time
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project stages
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent can provide richer event, audit, security,
        registry, and routing behavior later without breaking this class.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "verification")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit_event: %s %s", event_name, payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.verification_agent.result_validator")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants / Enums
# ---------------------------------------------------------------------------

DEFAULT_CONFIDENCE_THRESHOLD = 0.85
DEFAULT_PARTIAL_CONFIDENCE_THRESHOLD = 0.55
DEFAULT_TEXT_SIMILARITY_THRESHOLD = 0.88
DEFAULT_NUMERIC_TOLERANCE = 0.0
MAX_DIFF_ITEMS = 250
MAX_STRING_PREVIEW = 500
MAX_RECURSION_DEPTH = 50


class ValidationStatus(str, Enum):
    """High-level validation result status."""

    PASSED = "passed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class DifferenceType(str, Enum):
    """Difference categories used in validation reports."""

    MISSING_KEY = "missing_key"
    EXTRA_KEY = "extra_key"
    VALUE_MISMATCH = "value_mismatch"
    TYPE_MISMATCH = "type_mismatch"
    LENGTH_MISMATCH = "length_mismatch"
    TEXT_SIMILARITY_LOW = "text_similarity_low"
    NUMERIC_TOLERANCE_EXCEEDED = "numeric_tolerance_exceeded"
    ORDER_MISMATCH = "order_mismatch"
    CUSTOM_RULE_FAILED = "custom_rule_failed"
    UNSUPPORTED_COMPARISON = "unsupported_comparison"


class ComparisonMode(str, Enum):
    """
    Validation comparison modes.

    STRICT:
        Types, keys, list order, and values must match unless tolerance/rules allow.

    FLEXIBLE:
        Allows text similarity, numeric tolerance, subset dict matching if configured,
        and softer scoring.

    SUBSET:
        Expected data must exist in actual data, but actual may contain extra keys/items.

    SCHEMA:
        Expected describes type/schema expectations rather than exact values.
    """

    STRICT = "strict"
    FLEXIBLE = "flexible"
    SUBSET = "subset"
    SCHEMA = "schema"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Difference:
    """Single difference record between expected and actual result."""

    path: str
    difference_type: str
    expected: Any = None
    actual: Any = None
    message: str = ""
    severity: str = "medium"
    score_impact: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "difference_type": self.difference_type,
            "expected": ResultValidator.safe_preview_static(self.expected),
            "actual": ResultValidator.safe_preview_static(self.actual),
            "message": self.message,
            "severity": self.severity,
            "score_impact": round(float(self.score_impact), 6),
        }


@dataclasses.dataclass
class ValidationOptions:
    """Configuration for one validation run."""

    comparison_mode: ComparisonMode = ComparisonMode.FLEXIBLE
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    partial_confidence_threshold: float = DEFAULT_PARTIAL_CONFIDENCE_THRESHOLD
    text_similarity_threshold: float = DEFAULT_TEXT_SIMILARITY_THRESHOLD
    numeric_tolerance: float = DEFAULT_NUMERIC_TOLERANCE
    allow_extra_keys: bool = True
    allow_missing_optional_keys: bool = True
    ignore_order: bool = False
    case_sensitive: bool = False
    trim_strings: bool = True
    normalize_whitespace: bool = True
    strict_types: bool = False
    max_diff_items: int = MAX_DIFF_ITEMS
    max_recursion_depth: int = MAX_RECURSION_DEPTH
    ignored_paths: Tuple[str, ...] = ()
    required_paths: Tuple[str, ...] = ()
    optional_paths: Tuple[str, ...] = ()
    sensitive_keys: Tuple[str, ...] = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "authorization",
        "cookie",
        "session",
    )

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "ValidationOptions":
        if not data:
            return cls()

        safe_data = dict(data)

        mode = safe_data.get("comparison_mode", safe_data.get("mode", ComparisonMode.FLEXIBLE.value))
        if isinstance(mode, ComparisonMode):
            comparison_mode = mode
        else:
            try:
                comparison_mode = ComparisonMode(str(mode).lower())
            except Exception:
                comparison_mode = ComparisonMode.FLEXIBLE

        def as_float(name: str, default: float) -> float:
            try:
                return float(safe_data.get(name, default))
            except Exception:
                return default

        def as_bool(name: str, default: bool) -> bool:
            value = safe_data.get(name, default)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in {"true", "1", "yes", "y", "on"}
            return bool(value)

        def as_tuple(name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
            value = safe_data.get(name, default)
            if value is None:
                return default
            if isinstance(value, str):
                return (value,)
            if isinstance(value, Iterable):
                return tuple(str(item) for item in value)
            return default

        return cls(
            comparison_mode=comparison_mode,
            confidence_threshold=as_float("confidence_threshold", DEFAULT_CONFIDENCE_THRESHOLD),
            partial_confidence_threshold=as_float(
                "partial_confidence_threshold",
                DEFAULT_PARTIAL_CONFIDENCE_THRESHOLD,
            ),
            text_similarity_threshold=as_float(
                "text_similarity_threshold",
                DEFAULT_TEXT_SIMILARITY_THRESHOLD,
            ),
            numeric_tolerance=as_float("numeric_tolerance", DEFAULT_NUMERIC_TOLERANCE),
            allow_extra_keys=as_bool("allow_extra_keys", comparison_mode != ComparisonMode.STRICT),
            allow_missing_optional_keys=as_bool("allow_missing_optional_keys", True),
            ignore_order=as_bool("ignore_order", False),
            case_sensitive=as_bool("case_sensitive", False),
            trim_strings=as_bool("trim_strings", True),
            normalize_whitespace=as_bool("normalize_whitespace", True),
            strict_types=as_bool("strict_types", comparison_mode == ComparisonMode.STRICT),
            max_diff_items=max(1, int(safe_data.get("max_diff_items", MAX_DIFF_ITEMS) or MAX_DIFF_ITEMS)),
            max_recursion_depth=max(
                1,
                int(safe_data.get("max_recursion_depth", MAX_RECURSION_DEPTH) or MAX_RECURSION_DEPTH),
            ),
            ignored_paths=as_tuple("ignored_paths", ()),
            required_paths=as_tuple("required_paths", ()),
            optional_paths=as_tuple("optional_paths", ()),
            sensitive_keys=as_tuple(
                "sensitive_keys",
                (
                    "password",
                    "secret",
                    "token",
                    "api_key",
                    "apikey",
                    "access_token",
                    "refresh_token",
                    "private_key",
                    "authorization",
                    "cookie",
                    "session",
                ),
            ),
        )


@dataclasses.dataclass
class ComparisonScore:
    """Internal score object used while comparing nested structures."""

    matched: float = 0.0
    possible: float = 0.0
    critical_failures: int = 0

    @property
    def confidence(self) -> float:
        if self.possible <= 0:
            return 1.0
        return max(0.0, min(1.0, self.matched / self.possible))

    def add(self, matched: float, possible: float, critical_failures: int = 0) -> None:
        self.matched += float(matched)
        self.possible += float(possible)
        self.critical_failures += int(critical_failures)

    def merge(self, other: "ComparisonScore") -> None:
        self.matched += other.matched
        self.possible += other.possible
        self.critical_failures += other.critical_failures


# ---------------------------------------------------------------------------
# ResultValidator
# ---------------------------------------------------------------------------

class ResultValidator(BaseAgent):
    """
    Verification Agent helper that validates expected vs actual result.

    This class is designed to be called by:
        - Master Agent after an agent completes an action.
        - Verification Agent orchestration flow.
        - Dashboard/API verification endpoints.
        - Retry Manager to decide whether action replay is needed.
        - Memory Agent to store useful validation outcomes.

    Public methods:
        - validate_result()
        - compare()
        - validate_task_result()
        - calculate_confidence()
        - build_report()
    """

    agent_name = "verification_result_validator"
    agent_type = "verification"
    module_name = "verification_agent"
    file_name = "result_validator.py"

    def __init__(
        self,
        *,
        default_options: Optional[Union[ValidationOptions, Mapping[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.logger = logger or getattr(self, "logger", LOGGER)
        self.security_client = security_client
        self.memory_client = memory_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        if isinstance(default_options, ValidationOptions):
            self.default_options = default_options
        else:
            self.default_options = ValidationOptions.from_dict(default_options)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_result(
        self,
        expected: Any,
        actual: Any,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action_name: Optional[str] = None,
        options: Optional[Union[ValidationOptions, Mapping[str, Any]]] = None,
        criteria: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compare expected result against actual result and return structured validation.

        Args:
            expected:
                Expected output/result/state.
            actual:
                Actual output/result/state returned by another agent or action.
            user_id:
                SaaS user identifier. Required for user-specific verification.
            workspace_id:
                SaaS workspace identifier. Required for workspace-specific verification.
            task_id:
                Optional task identifier from MasterAgent/task history.
            agent_name:
                Name of the agent whose result is being verified.
            action_name:
                Action or method name being verified.
            options:
                ValidationOptions object or dictionary.
            criteria:
                Optional custom validation criteria.
            context:
                Extra context from MasterAgent/Dashboard/API.

        Returns:
            Structured dict:
                {
                    success,
                    message,
                    data,
                    error,
                    metadata
                }
        """

        started_at = time.time()
        validation_context = {
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "agent_name": agent_name,
            "action_name": action_name,
            "context": dict(context or {}),
        }

        try:
            task_context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                context=context,
            )
            if not task_context_result["success"]:
                return task_context_result

            run_options = self._merge_options(options, criteria)

            if self._requires_security_check(expected=expected, actual=actual, options=run_options):
                security_result = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    action="validate_result",
                    metadata={
                        "agent_name": agent_name,
                        "action_name": action_name,
                        "reason": "sensitive_fields_detected",
                    },
                )
                if not security_result.get("approved", False):
                    return self._safe_result(
                        success=False,
                        message="Result validation requires security approval and was not approved.",
                        data={
                            "status": ValidationStatus.SKIPPED.value,
                            "confidence": 0.0,
                            "approved": False,
                        },
                        metadata=self._metadata(
                            started_at=started_at,
                            validation_context=validation_context,
                            options=run_options,
                        ),
                    )

            comparison = self.compare(
                expected=expected,
                actual=actual,
                options=run_options,
                criteria=criteria,
            )

            confidence = comparison["confidence"]
            status = self._status_from_confidence(
                confidence=confidence,
                critical_failures=comparison.get("critical_failures", 0),
                options=run_options,
            )

            report = self.build_report(
                expected=expected,
                actual=actual,
                comparison=comparison,
                status=status,
                confidence=confidence,
                options=run_options,
                validation_context=validation_context,
            )

            verification_payload = self._prepare_verification_payload(
                expected=expected,
                actual=actual,
                status=status,
                confidence=confidence,
                report=report,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                agent_name=agent_name,
                action_name=action_name,
            )

            memory_payload = self._prepare_memory_payload(
                verification_payload=verification_payload,
                context=validation_context,
            )

            self._emit_agent_event(
                event_name="verification.result_validated",
                payload={
                    "user_id": str(user_id) if user_id is not None else None,
                    "workspace_id": str(workspace_id) if workspace_id is not None else None,
                    "task_id": task_id,
                    "agent_name": agent_name,
                    "action_name": action_name,
                    "status": status.value,
                    "confidence": confidence,
                    "difference_count": len(comparison.get("differences", [])),
                },
            )

            self._log_audit_event(
                event_name="verification_result_validation_completed",
                payload={
                    "user_id": str(user_id) if user_id is not None else None,
                    "workspace_id": str(workspace_id) if workspace_id is not None else None,
                    "task_id": task_id,
                    "agent_name": agent_name,
                    "action_name": action_name,
                    "status": status.value,
                    "confidence": confidence,
                    "duration_ms": round((time.time() - started_at) * 1000, 3),
                },
            )

            return self._safe_result(
                success=status in {ValidationStatus.PASSED, ValidationStatus.PARTIAL},
                message=self._message_for_status(status, confidence, comparison),
                data={
                    "status": status.value,
                    "confidence": confidence,
                    "passed": status == ValidationStatus.PASSED,
                    "partial": status == ValidationStatus.PARTIAL,
                    "failed": status == ValidationStatus.FAILED,
                    "comparison": comparison,
                    "report": report,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata=self._metadata(
                    started_at=started_at,
                    validation_context=validation_context,
                    options=run_options,
                ),
            )

        except Exception as exc:
            self.logger.exception("Result validation failed unexpectedly.")
            self._log_audit_event(
                event_name="verification_result_validation_error",
                payload={
                    "user_id": str(user_id) if user_id is not None else None,
                    "workspace_id": str(workspace_id) if workspace_id is not None else None,
                    "task_id": task_id,
                    "agent_name": agent_name,
                    "action_name": action_name,
                    "error": str(exc),
                },
            )
            return self._error_result(
                message="Result validation failed due to an internal error.",
                error=exc,
                metadata=self._metadata(
                    started_at=started_at,
                    validation_context=validation_context,
                    options=self._merge_options(options, criteria),
                ),
            )

    def validate_task_result(
        self,
        task_payload: Mapping[str, Any],
        *,
        options: Optional[Union[ValidationOptions, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Validate a task payload containing expected and actual result.

        Expected payload keys:
            - expected_result or expected
            - actual_result or actual
            - user_id
            - workspace_id
            - task_id
            - agent_name
            - action_name
            - criteria
            - context
        """

        payload = dict(task_payload or {})
        expected = payload.get("expected_result", payload.get("expected"))
        actual = payload.get("actual_result", payload.get("actual"))

        merged_options = options or payload.get("options")

        return self.validate_result(
            expected=expected,
            actual=actual,
            user_id=payload.get("user_id"),
            workspace_id=payload.get("workspace_id"),
            task_id=payload.get("task_id"),
            agent_name=payload.get("agent_name"),
            action_name=payload.get("action_name"),
            options=merged_options,
            criteria=payload.get("criteria"),
            context=payload.get("context"),
        )

    def compare(
        self,
        expected: Any,
        actual: Any,
        *,
        options: Optional[Union[ValidationOptions, Mapping[str, Any]]] = None,
        criteria: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compare expected and actual data and return raw comparison metrics.

        This method does not emit audit/memory/security events. It is suitable for
        tests, internal scoring, and report generation.
        """

        run_options = self._merge_options(options, criteria)
        differences: List[Difference] = []
        score = self._compare_value(
            expected=expected,
            actual=actual,
            path="$",
            options=run_options,
            differences=differences,
            depth=0,
        )

        required_path_failures = self._check_required_paths(
            actual=actual,
            required_paths=run_options.required_paths,
            options=run_options,
            differences=differences,
        )
        if required_path_failures:
            score.add(0.0, float(required_path_failures), critical_failures=required_path_failures)

        confidence = self.calculate_confidence(score=score, differences=differences)

        serialized_diffs = [
            difference.to_dict()
            for difference in differences[: run_options.max_diff_items]
        ]

        truncated = len(differences) > run_options.max_diff_items

        return {
            "confidence": confidence,
            "matched_score": round(score.matched, 6),
            "possible_score": round(score.possible, 6),
            "critical_failures": score.critical_failures,
            "difference_count": len(differences),
            "differences_truncated": truncated,
            "differences": serialized_diffs,
            "mode": run_options.comparison_mode.value,
            "summary": self._comparison_summary(
                confidence=confidence,
                difference_count=len(differences),
                critical_failures=score.critical_failures,
                truncated=truncated,
            ),
        }

    def calculate_confidence(
        self,
        *,
        score: Optional[ComparisonScore] = None,
        differences: Optional[Sequence[Union[Difference, Mapping[str, Any]]]] = None,
        matched_score: Optional[float] = None,
        possible_score: Optional[float] = None,
    ) -> float:
        """
        Calculate normalized confidence between 0.0 and 1.0.

        Can be called with a ComparisonScore or raw matched/possible values.
        """

        if score is not None:
            confidence = score.confidence
        else:
            possible = float(possible_score or 0.0)
            matched = float(matched_score or 0.0)
            confidence = 1.0 if possible <= 0 else matched / possible

        penalty = 0.0
        if differences:
            for item in differences:
                if isinstance(item, Difference):
                    severity = item.severity
                    impact = item.score_impact
                else:
                    severity = str(item.get("severity", "medium"))
                    impact = float(item.get("score_impact", 0.0) or 0.0)

                if impact > 0:
                    penalty += impact * 0.01
                elif severity == "critical":
                    penalty += 0.03
                elif severity == "high":
                    penalty += 0.015

        confidence = max(0.0, min(1.0, confidence - penalty))
        return round(confidence, 6)

    def build_report(
        self,
        *,
        expected: Any,
        actual: Any,
        comparison: Mapping[str, Any],
        status: ValidationStatus,
        confidence: float,
        options: ValidationOptions,
        validation_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build dashboard/API friendly validation report.
        """

        differences = list(comparison.get("differences", []))
        grouped: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for diff in differences:
            difference_type = str(diff.get("difference_type", "unknown"))
            severity = str(diff.get("severity", "medium"))
            grouped[difference_type] = grouped.get(difference_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "status": status.value,
            "confidence": confidence,
            "passed": status == ValidationStatus.PASSED,
            "partial": status == ValidationStatus.PARTIAL,
            "failed": status == ValidationStatus.FAILED,
            "mode": options.comparison_mode.value,
            "difference_count": int(comparison.get("difference_count", len(differences))),
            "critical_failures": int(comparison.get("critical_failures", 0)),
            "differences_by_type": grouped,
            "differences_by_severity": severity_counts,
            "summary": comparison.get("summary", ""),
            "expected_preview": self.safe_preview(expected, options=options),
            "actual_preview": self.safe_preview(actual, options=options),
            "recommendation": self._recommendation_for_status(status, confidence, differences),
            "context": dict(validation_context or {}),
            "generated_at": self._utc_now_iso(),
        }

    # ------------------------------------------------------------------
    # Core comparison logic
    # ------------------------------------------------------------------

    def _compare_value(
        self,
        *,
        expected: Any,
        actual: Any,
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
        depth: int,
    ) -> ComparisonScore:
        if depth > options.max_recursion_depth:
            self._add_difference(
                differences,
                Difference(
                    path=path,
                    difference_type=DifferenceType.UNSUPPORTED_COMPARISON.value,
                    expected=expected,
                    actual=actual,
                    message="Maximum comparison recursion depth exceeded.",
                    severity="high",
                    score_impact=0.1,
                ),
                options,
            )
            return ComparisonScore(matched=0.0, possible=1.0, critical_failures=1)

        if self._is_ignored_path(path, options):
            return ComparisonScore(matched=1.0, possible=1.0)

        if options.comparison_mode == ComparisonMode.SCHEMA:
            return self._compare_schema(
                expected_schema=expected,
                actual=actual,
                path=path,
                options=options,
                differences=differences,
                depth=depth,
            )

        if expected is None or actual is None:
            return self._compare_none(
                expected=expected,
                actual=actual,
                path=path,
                options=options,
                differences=differences,
            )

        if options.strict_types and type(expected) is not type(actual):
            self._add_difference(
                differences,
                Difference(
                    path=path,
                    difference_type=DifferenceType.TYPE_MISMATCH.value,
                    expected=type(expected).__name__,
                    actual=type(actual).__name__,
                    message="Type mismatch in strict comparison mode.",
                    severity="high",
                    score_impact=0.1,
                ),
                options,
            )
            return ComparisonScore(matched=0.0, possible=1.0, critical_failures=1)

        if isinstance(expected, Mapping) and isinstance(actual, Mapping):
            return self._compare_mapping(
                expected=expected,
                actual=actual,
                path=path,
                options=options,
                differences=differences,
                depth=depth,
            )

        if isinstance(expected, (list, tuple)) and isinstance(actual, (list, tuple)):
            return self._compare_sequence(
                expected=list(expected),
                actual=list(actual),
                path=path,
                options=options,
                differences=differences,
                depth=depth,
            )

        if isinstance(expected, str) and isinstance(actual, str):
            return self._compare_string(
                expected=expected,
                actual=actual,
                path=path,
                options=options,
                differences=differences,
            )

        if self._is_number(expected) and self._is_number(actual):
            return self._compare_number(
                expected=float(expected),
                actual=float(actual),
                original_expected=expected,
                original_actual=actual,
                path=path,
                options=options,
                differences=differences,
            )

        if isinstance(expected, bool) or isinstance(actual, bool):
            return self._compare_exact(
                expected=expected,
                actual=actual,
                path=path,
                options=options,
                differences=differences,
            )

        return self._compare_exact(
            expected=expected,
            actual=actual,
            path=path,
            options=options,
            differences=differences,
        )

    def _compare_none(
        self,
        *,
        expected: Any,
        actual: Any,
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
    ) -> ComparisonScore:
        if expected is actual:
            return ComparisonScore(matched=1.0, possible=1.0)

        severity = "high" if self._is_required_path(path, options) else "medium"
        self._add_difference(
            differences,
            Difference(
                path=path,
                difference_type=DifferenceType.VALUE_MISMATCH.value,
                expected=expected,
                actual=actual,
                message="One value is null while the other is not.",
                severity=severity,
                score_impact=0.08 if severity == "high" else 0.03,
            ),
            options,
        )
        return ComparisonScore(
            matched=0.0,
            possible=1.0,
            critical_failures=1 if severity == "high" else 0,
        )

    def _compare_mapping(
        self,
        *,
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
        depth: int,
    ) -> ComparisonScore:
        score = ComparisonScore()

        expected_keys = set(expected.keys())
        actual_keys = set(actual.keys())

        missing_keys = expected_keys - actual_keys
        extra_keys = actual_keys - expected_keys

        for key in sorted(missing_keys, key=str):
            child_path = self._join_path(path, key)
            if self._is_ignored_path(child_path, options):
                continue

            is_optional = self._is_optional_path(child_path, options)
            if is_optional and options.allow_missing_optional_keys:
                score.add(1.0, 1.0)
                continue

            self._add_difference(
                differences,
                Difference(
                    path=child_path,
                    difference_type=DifferenceType.MISSING_KEY.value,
                    expected=expected.get(key),
                    actual=None,
                    message="Expected key is missing from actual result.",
                    severity="high" if self._is_required_path(child_path, options) else "medium",
                    score_impact=0.08,
                ),
                options,
            )
            score.add(
                0.0,
                1.0,
                critical_failures=1 if self._is_required_path(child_path, options) else 0,
            )

        if not options.allow_extra_keys and options.comparison_mode != ComparisonMode.SUBSET:
            for key in sorted(extra_keys, key=str):
                child_path = self._join_path(path, key)
                if self._is_ignored_path(child_path, options):
                    continue

                self._add_difference(
                    differences,
                    Difference(
                        path=child_path,
                        difference_type=DifferenceType.EXTRA_KEY.value,
                        expected=None,
                        actual=actual.get(key),
                        message="Actual result contains an unexpected extra key.",
                        severity="low",
                        score_impact=0.01,
                    ),
                    options,
                )
                score.add(0.5, 1.0)
        else:
            for key in sorted(extra_keys, key=str):
                child_path = self._join_path(path, key)
                if not self._is_ignored_path(child_path, options):
                    score.add(0.25, 0.25)

        common_keys = expected_keys & actual_keys
        for key in sorted(common_keys, key=str):
            child_path = self._join_path(path, key)
            child_score = self._compare_value(
                expected=expected[key],
                actual=actual[key],
                path=child_path,
                options=options,
                differences=differences,
                depth=depth + 1,
            )
            score.merge(child_score)

        if not expected_keys and not actual_keys:
            score.add(1.0, 1.0)

        return score

    def _compare_sequence(
        self,
        *,
        expected: List[Any],
        actual: List[Any],
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
        depth: int,
    ) -> ComparisonScore:
        if options.ignore_order or options.comparison_mode == ComparisonMode.SUBSET:
            return self._compare_sequence_unordered(
                expected=expected,
                actual=actual,
                path=path,
                options=options,
                differences=differences,
                depth=depth,
            )

        score = ComparisonScore()
        expected_len = len(expected)
        actual_len = len(actual)

        if expected_len != actual_len:
            severity = "medium"
            if options.comparison_mode == ComparisonMode.STRICT:
                severity = "high"

            self._add_difference(
                differences,
                Difference(
                    path=path,
                    difference_type=DifferenceType.LENGTH_MISMATCH.value,
                    expected=expected_len,
                    actual=actual_len,
                    message="Sequence length does not match.",
                    severity=severity,
                    score_impact=0.05,
                ),
                options,
            )

        max_len = max(expected_len, actual_len)
        min_len = min(expected_len, actual_len)

        for index in range(min_len):
            child_path = f"{path}[{index}]"
            child_score = self._compare_value(
                expected=expected[index],
                actual=actual[index],
                path=child_path,
                options=options,
                differences=differences,
                depth=depth + 1,
            )
            score.merge(child_score)

        for index in range(min_len, expected_len):
            child_path = f"{path}[{index}]"
            self._add_difference(
                differences,
                Difference(
                    path=child_path,
                    difference_type=DifferenceType.MISSING_KEY.value,
                    expected=expected[index],
                    actual=None,
                    message="Expected list item is missing from actual result.",
                    severity="medium",
                    score_impact=0.03,
                ),
                options,
            )
            score.add(0.0, 1.0)

        if not options.allow_extra_keys and options.comparison_mode != ComparisonMode.SUBSET:
            for index in range(min_len, actual_len):
                child_path = f"{path}[{index}]"
                self._add_difference(
                    differences,
                    Difference(
                        path=child_path,
                        difference_type=DifferenceType.EXTRA_KEY.value,
                        expected=None,
                        actual=actual[index],
                        message="Actual list contains an unexpected extra item.",
                        severity="low",
                        score_impact=0.01,
                    ),
                    options,
                )
                score.add(0.5, 1.0)
        else:
            if actual_len > expected_len:
                score.add(float(actual_len - expected_len) * 0.25, float(actual_len - expected_len) * 0.25)

        if max_len == 0:
            score.add(1.0, 1.0)

        return score

    def _compare_sequence_unordered(
        self,
        *,
        expected: List[Any],
        actual: List[Any],
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
        depth: int,
    ) -> ComparisonScore:
        score = ComparisonScore()

        if not expected and not actual:
            score.add(1.0, 1.0)
            return score

        used_actual_indexes: set[int] = set()

        for expected_index, expected_item in enumerate(expected):
            best_index: Optional[int] = None
            best_confidence = -1.0
            best_score: Optional[ComparisonScore] = None
            best_differences: List[Difference] = []

            for actual_index, actual_item in enumerate(actual):
                if actual_index in used_actual_indexes:
                    continue

                temp_differences: List[Difference] = []
                temp_score = self._compare_value(
                    expected=expected_item,
                    actual=actual_item,
                    path=f"{path}[{expected_index}]",
                    options=options,
                    differences=temp_differences,
                    depth=depth + 1,
                )
                temp_confidence = temp_score.confidence

                if temp_confidence > best_confidence:
                    best_confidence = temp_confidence
                    best_index = actual_index
                    best_score = temp_score
                    best_differences = temp_differences

            if best_index is not None and best_score is not None and best_confidence >= 0.5:
                used_actual_indexes.add(best_index)
                score.merge(best_score)
                for diff in best_differences:
                    self._add_difference(differences, diff, options)
            else:
                self._add_difference(
                    differences,
                    Difference(
                        path=f"{path}[{expected_index}]",
                        difference_type=DifferenceType.MISSING_KEY.value,
                        expected=expected_item,
                        actual=None,
                        message="Expected unordered list item was not found in actual result.",
                        severity="medium",
                        score_impact=0.03,
                    ),
                    options,
                )
                score.add(0.0, 1.0)

        extra_count = len(actual) - len(used_actual_indexes)
        if extra_count > 0:
            if not options.allow_extra_keys and options.comparison_mode != ComparisonMode.SUBSET:
                for actual_index, actual_item in enumerate(actual):
                    if actual_index not in used_actual_indexes:
                        self._add_difference(
                            differences,
                            Difference(
                                path=f"{path}[actual:{actual_index}]",
                                difference_type=DifferenceType.EXTRA_KEY.value,
                                expected=None,
                                actual=actual_item,
                                message="Actual unordered list contains an unexpected extra item.",
                                severity="low",
                                score_impact=0.01,
                            ),
                            options,
                        )
                        score.add(0.5, 1.0)
            else:
                score.add(extra_count * 0.25, extra_count * 0.25)

        return score

    def _compare_string(
        self,
        *,
        expected: str,
        actual: str,
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
    ) -> ComparisonScore:
        normalized_expected = self._normalize_string(expected, options)
        normalized_actual = self._normalize_string(actual, options)

        if normalized_expected == normalized_actual:
            return ComparisonScore(matched=1.0, possible=1.0)

        if options.comparison_mode == ComparisonMode.STRICT:
            self._add_difference(
                differences,
                Difference(
                    path=path,
                    difference_type=DifferenceType.VALUE_MISMATCH.value,
                    expected=expected,
                    actual=actual,
                    message="String values do not match in strict mode.",
                    severity="medium",
                    score_impact=0.04,
                ),
                options,
            )
            return ComparisonScore(matched=0.0, possible=1.0)

        similarity = difflib.SequenceMatcher(None, normalized_expected, normalized_actual).ratio()

        if similarity >= options.text_similarity_threshold:
            return ComparisonScore(matched=similarity, possible=1.0)

        diff_message = "String similarity is below threshold."
        self._add_difference(
            differences,
            Difference(
                path=path,
                difference_type=DifferenceType.TEXT_SIMILARITY_LOW.value,
                expected=expected,
                actual=actual,
                message=f"{diff_message} similarity={round(similarity, 6)}, threshold={options.text_similarity_threshold}",
                severity="medium",
                score_impact=max(0.01, 1.0 - similarity),
            ),
            options,
        )
        return ComparisonScore(matched=similarity, possible=1.0)

    def _compare_number(
        self,
        *,
        expected: float,
        actual: float,
        original_expected: Any,
        original_actual: Any,
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
    ) -> ComparisonScore:
        if math.isclose(expected, actual, abs_tol=options.numeric_tolerance):
            return ComparisonScore(matched=1.0, possible=1.0)

        delta = abs(expected - actual)
        if options.numeric_tolerance > 0 and delta <= options.numeric_tolerance:
            return ComparisonScore(matched=1.0, possible=1.0)

        relative_score = 0.0
        denominator = max(abs(expected), abs(actual), 1.0)
        relative_error = delta / denominator
        relative_score = max(0.0, 1.0 - relative_error)

        self._add_difference(
            differences,
            Difference(
                path=path,
                difference_type=DifferenceType.NUMERIC_TOLERANCE_EXCEEDED.value,
                expected=original_expected,
                actual=original_actual,
                message=f"Numeric values differ by {delta}, tolerance={options.numeric_tolerance}.",
                severity="medium",
                score_impact=min(0.2, relative_error),
            ),
            options,
        )

        return ComparisonScore(matched=relative_score, possible=1.0)

    def _compare_exact(
        self,
        *,
        expected: Any,
        actual: Any,
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
    ) -> ComparisonScore:
        if expected == actual:
            return ComparisonScore(matched=1.0, possible=1.0)

        self._add_difference(
            differences,
            Difference(
                path=path,
                difference_type=DifferenceType.VALUE_MISMATCH.value,
                expected=expected,
                actual=actual,
                message="Values do not match.",
                severity="medium",
                score_impact=0.05,
            ),
            options,
        )
        return ComparisonScore(matched=0.0, possible=1.0)

    def _compare_schema(
        self,
        *,
        expected_schema: Any,
        actual: Any,
        path: str,
        options: ValidationOptions,
        differences: List[Difference],
        depth: int,
    ) -> ComparisonScore:
        """
        Compare actual data against a lightweight schema.

        Supported schema examples:
            {"type": "dict", "required": ["success"], "properties": {...}}
            {"type": "string"}
            {"type": "number"}
            {"type": "boolean"}
            {"type": "list", "items": {"type": "string"}}
            str / int / float / bool / list / dict classes
        """

        score = ComparisonScore()

        if isinstance(expected_schema, type):
            if isinstance(actual, expected_schema):
                return ComparisonScore(matched=1.0, possible=1.0)

            self._add_difference(
                differences,
                Difference(
                    path=path,
                    difference_type=DifferenceType.TYPE_MISMATCH.value,
                    expected=expected_schema.__name__,
                    actual=type(actual).__name__,
                    message="Actual value does not match expected schema type.",
                    severity="high",
                    score_impact=0.1,
                ),
                options,
            )
            return ComparisonScore(matched=0.0, possible=1.0, critical_failures=1)

        if not isinstance(expected_schema, Mapping):
            return self._compare_value(
                expected=expected_schema,
                actual=actual,
                path=path,
                options=dataclasses.replace(options, comparison_mode=ComparisonMode.FLEXIBLE),
                differences=differences,
                depth=depth + 1,
            )

        schema_type = expected_schema.get("type")
        required = expected_schema.get("required", [])
        properties = expected_schema.get("properties", {})
        items_schema = expected_schema.get("items")

        if schema_type:
            type_ok = self._schema_type_matches(schema_type, actual)
            if type_ok:
                score.add(1.0, 1.0)
            else:
                self._add_difference(
                    differences,
                    Difference(
                        path=path,
                        difference_type=DifferenceType.TYPE_MISMATCH.value,
                        expected=schema_type,
                        actual=type(actual).__name__,
                        message="Actual value does not match expected schema type.",
                        severity="high",
                        score_impact=0.1,
                    ),
                    options,
                )
                score.add(0.0, 1.0, critical_failures=1)

        if isinstance(actual, Mapping):
            for key in required:
                child_path = self._join_path(path, key)
                if key in actual:
                    score.add(1.0, 1.0)
                else:
                    self._add_difference(
                        differences,
                        Difference(
                            path=child_path,
                            difference_type=DifferenceType.MISSING_KEY.value,
                            expected="required",
                            actual=None,
                            message="Required schema key is missing.",
                            severity="high",
                            score_impact=0.1,
                        ),
                        options,
                    )
                    score.add(0.0, 1.0, critical_failures=1)

            if isinstance(properties, Mapping):
                for key, child_schema in properties.items():
                    child_path = self._join_path(path, key)
                    if key not in actual:
                        continue
                    child_score = self._compare_schema(
                        expected_schema=child_schema,
                        actual=actual[key],
                        path=child_path,
                        options=options,
                        differences=differences,
                        depth=depth + 1,
                    )
                    score.merge(child_score)

        if isinstance(actual, Sequence) and not isinstance(actual, (str, bytes, bytearray)) and items_schema:
            for index, item in enumerate(actual):
                child_score = self._compare_schema(
                    expected_schema=items_schema,
                    actual=item,
                    path=f"{path}[{index}]",
                    options=options,
                    differences=differences,
                    depth=depth + 1,
                )
                score.merge(child_score)

        if score.possible <= 0:
            score.add(1.0, 1.0)

        return score

    # ------------------------------------------------------------------
    # Context / Security / Memory / Event hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        William/Jarvis rule:
            Every user-specific execution must carry user_id and workspace_id.

        This validator is sometimes used for pure local tests, so it supports
        explicit non_user_context=True in context to allow test/system checks.
        """

        ctx = dict(context or {})
        non_user_context = bool(ctx.get("non_user_context", False) or ctx.get("system_context", False))

        if non_user_context:
            return self._safe_result(
                success=True,
                message="Task context validated for non-user/system context.",
                data={"context_valid": True},
            )

        missing = []
        if user_id is None or str(user_id).strip() == "":
            missing.append("user_id")
        if workspace_id is None or str(workspace_id).strip() == "":
            missing.append("workspace_id")

        if missing:
            return self._safe_result(
                success=False,
                message=f"Missing required SaaS isolation context: {', '.join(missing)}.",
                data={
                    "status": ValidationStatus.SKIPPED.value,
                    "context_valid": False,
                    "missing": missing,
                    "task_id": task_id,
                },
                error={
                    "code": "MISSING_TASK_CONTEXT",
                    "details": f"Missing required context fields: {', '.join(missing)}",
                },
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "context_valid": True,
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "task_id": task_id,
            },
        )

    def _requires_security_check(
        self,
        *,
        expected: Any,
        actual: Any,
        options: ValidationOptions,
    ) -> bool:
        """
        Determine whether validation touches sensitive-looking keys.

        This file does not execute sensitive actions. The security check hook is
        present for architecture compatibility and to avoid leaking sensitive
        values into audit/memory/report payloads.
        """

        return self._contains_sensitive_key(expected, options.sensitive_keys) or self._contains_sensitive_key(
            actual,
            options.sensitive_keys,
        )

    def _request_security_approval(
        self,
        *,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str],
        action: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when sensitive fields are detected.

        Safe default:
            If no security client is configured, approve validation but enforce
            redaction in outputs. Validation itself is read-only and non-destructive.
        """

        payload = {
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "requesting_agent": self.agent_name,
            "action": action,
            "metadata": dict(metadata or {}),
            "read_only": True,
            "destructive": False,
        }

        if self.security_client is None:
            return {
                "approved": True,
                "source": "safe_default_no_security_client",
                "payload": payload,
            }

        try:
            if hasattr(self.security_client, "approve"):
                response = self.security_client.approve(payload)
            elif hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(payload)
            else:
                response = {"approved": True, "source": "security_client_no_approval_method"}

            if isinstance(response, Mapping):
                return {
                    "approved": bool(response.get("approved", response.get("success", False))),
                    "source": response.get("source", "security_client"),
                    "payload": payload,
                    "raw": dict(response),
                }

            return {
                "approved": bool(response),
                "source": "security_client_bool",
                "payload": payload,
            }

        except Exception as exc:
            self.logger.warning("Security approval failed safely: %s", exc)
            return {
                "approved": False,
                "source": "security_client_error",
                "error": str(exc),
                "payload": payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        expected: Any,
        actual: Any,
        status: ValidationStatus,
        confidence: float,
        report: Mapping[str, Any],
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str],
        agent_name: Optional[str],
        action_name: Optional[str],
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent, Dashboard/API, task history,
        Retry Manager, and Master Agent routing.
        """

        return {
            "verification_type": "result_validation",
            "validator": self.agent_name,
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "source_agent": agent_name,
            "source_action": action_name,
            "status": status.value,
            "confidence": confidence,
            "passed": status == ValidationStatus.PASSED,
            "partial": status == ValidationStatus.PARTIAL,
            "failed": status == ValidationStatus.FAILED,
            "report": dict(report),
            "expected_preview": self.safe_preview_static(expected),
            "actual_preview": self.safe_preview_static(actual),
            "created_at": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        verification_payload: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Stores outcome summary only. Sensitive fields are redacted through preview
        methods to avoid leaking credentials/tokens into memory.
        """

        payload = dict(verification_payload)
        report = dict(payload.get("report", {}))

        memory_payload = {
            "memory_type": "verification_result",
            "importance": self._memory_importance(payload),
            "user_id": payload.get("user_id"),
            "workspace_id": payload.get("workspace_id"),
            "task_id": payload.get("task_id"),
            "source_agent": payload.get("source_agent"),
            "source_action": payload.get("source_action"),
            "status": payload.get("status"),
            "confidence": payload.get("confidence"),
            "summary": report.get("summary"),
            "recommendation": report.get("recommendation"),
            "created_at": self._utc_now_iso(),
            "context": dict(context or {}),
        }

        if self.memory_client is not None:
            try:
                if hasattr(self.memory_client, "prepare_payload"):
                    prepared = self.memory_client.prepare_payload(memory_payload)
                    if isinstance(prepared, Mapping):
                        return dict(prepared)
            except Exception as exc:
                self.logger.debug("Memory client prepare_payload failed safely: %s", exc)

        return memory_payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for MasterAgent, Dashboard, analytics, or registry listeners.
        """

        safe_payload = self._redact_sensitive(copy.deepcopy(payload))

        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            if hasattr(self, "emit_event"):
                method = getattr(self, "emit_event")
                if callable(method) and method.__qualname__.split(".")[0] != self.__class__.__name__:
                    method(event_name, safe_payload)

        except Exception as exc:
            self.logger.debug("Event emit failed safely: %s", exc)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Log audit event without exposing sensitive values.
        """

        safe_payload = self._redact_sensitive(copy.deepcopy(payload))

        try:
            if self.audit_logger:
                self.audit_logger(event_name, safe_payload)
                return

            if hasattr(super(), "log_audit_event"):
                try:
                    super().log_audit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.info("Audit event: %s %s", event_name, safe_payload)

        except Exception as exc:
            self.logger.debug("Audit logging failed safely: %s", exc)

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Union[Mapping[str, Any], str, Exception]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": self._format_error(error),
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[Exception, str, Mapping[str, Any]],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": str(message),
            "data": {
                "status": ValidationStatus.ERROR.value,
                "confidence": 0.0,
            },
            "error": self._format_error(error),
            "metadata": dict(metadata or {}),
        }

    def _format_error(self, error: Optional[Union[Mapping[str, Any], str, Exception]]) -> Optional[Dict[str, Any]]:
        if error is None:
            return None

        if isinstance(error, Mapping):
            return dict(error)

        if isinstance(error, Exception):
            return {
                "code": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(limit=5),
            }

        return {
            "code": "ERROR",
            "message": str(error),
        }

    def _metadata(
        self,
        *,
        started_at: float,
        validation_context: Optional[Mapping[str, Any]],
        options: ValidationOptions,
    ) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "module": self.module_name,
            "file": self.file_name,
            "duration_ms": round((time.time() - started_at) * 1000, 3),
            "created_at": self._utc_now_iso(),
            "context": dict(validation_context or {}),
            "options": {
                "comparison_mode": options.comparison_mode.value,
                "confidence_threshold": options.confidence_threshold,
                "partial_confidence_threshold": options.partial_confidence_threshold,
                "text_similarity_threshold": options.text_similarity_threshold,
                "numeric_tolerance": options.numeric_tolerance,
                "allow_extra_keys": options.allow_extra_keys,
                "ignore_order": options.ignore_order,
                "strict_types": options.strict_types,
                "ignored_paths": list(options.ignored_paths),
                "required_paths": list(options.required_paths),
                "optional_paths": list(options.optional_paths),
            },
        }

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _merge_options(
        self,
        options: Optional[Union[ValidationOptions, Mapping[str, Any]]],
        criteria: Optional[Mapping[str, Any]] = None,
    ) -> ValidationOptions:
        if isinstance(options, ValidationOptions):
            base = dataclasses.replace(options)
        elif isinstance(options, Mapping):
            base = ValidationOptions.from_dict(options)
        else:
            base = dataclasses.replace(self.default_options)

        if not criteria:
            return base

        criteria_dict = dict(criteria)

        option_updates: Dict[str, Any] = {}
        for key in (
            "comparison_mode",
            "mode",
            "confidence_threshold",
            "partial_confidence_threshold",
            "text_similarity_threshold",
            "numeric_tolerance",
            "allow_extra_keys",
            "allow_missing_optional_keys",
            "ignore_order",
            "case_sensitive",
            "trim_strings",
            "normalize_whitespace",
            "strict_types",
            "max_diff_items",
            "max_recursion_depth",
            "ignored_paths",
            "required_paths",
            "optional_paths",
            "sensitive_keys",
        ):
            if key in criteria_dict:
                option_updates[key] = criteria_dict[key]

        if not option_updates:
            return base

        merged = dataclasses.asdict(base)
        merged.update(option_updates)
        return ValidationOptions.from_dict(merged)

    def _status_from_confidence(
        self,
        *,
        confidence: float,
        critical_failures: int,
        options: ValidationOptions,
    ) -> ValidationStatus:
        if critical_failures > 0 and confidence < options.confidence_threshold:
            if confidence >= options.partial_confidence_threshold:
                return ValidationStatus.PARTIAL
            return ValidationStatus.FAILED

        if confidence >= options.confidence_threshold:
            return ValidationStatus.PASSED

        if confidence >= options.partial_confidence_threshold:
            return ValidationStatus.PARTIAL

        return ValidationStatus.FAILED

    def _message_for_status(
        self,
        status: ValidationStatus,
        confidence: float,
        comparison: Mapping[str, Any],
    ) -> str:
        difference_count = int(comparison.get("difference_count", 0))

        if status == ValidationStatus.PASSED:
            return f"Result validation passed with confidence {confidence:.2%}."
        if status == ValidationStatus.PARTIAL:
            return (
                f"Result validation partially matched with confidence {confidence:.2%}; "
                f"{difference_count} difference(s) found."
            )
        if status == ValidationStatus.FAILED:
            return (
                f"Result validation failed with confidence {confidence:.2%}; "
                f"{difference_count} difference(s) found."
            )
        if status == ValidationStatus.SKIPPED:
            return "Result validation was skipped."
        return "Result validation ended with an error."

    def _comparison_summary(
        self,
        *,
        confidence: float,
        difference_count: int,
        critical_failures: int,
        truncated: bool,
    ) -> str:
        parts = [
            f"confidence={confidence:.2%}",
            f"differences={difference_count}",
            f"critical_failures={critical_failures}",
        ]
        if truncated:
            parts.append("differences_truncated=true")
        return "Result comparison completed: " + ", ".join(parts) + "."

    def _recommendation_for_status(
        self,
        status: ValidationStatus,
        confidence: float,
        differences: Sequence[Mapping[str, Any]],
    ) -> str:
        if status == ValidationStatus.PASSED:
            return "Accept the result and continue the workflow."

        if status == ValidationStatus.PARTIAL:
            high_or_critical = [
                diff for diff in differences
                if str(diff.get("severity")) in {"high", "critical"}
            ]
            if high_or_critical:
                return "Review high-severity differences before marking the task complete."
            return "Review differences; result may be acceptable depending on task tolerance."

        if status == ValidationStatus.FAILED:
            return "Reject the result, collect proof, and consider retrying or escalating to the Verification Agent."

        if status == ValidationStatus.SKIPPED:
            return "Validation was skipped; verify required context and permissions."

        return "Inspect validation error logs and retry after fixing the underlying issue."

    def _memory_importance(self, verification_payload: Mapping[str, Any]) -> str:
        status = str(verification_payload.get("status", ""))
        confidence = float(verification_payload.get("confidence", 0.0) or 0.0)

        if status == ValidationStatus.FAILED.value:
            return "high"
        if status == ValidationStatus.PARTIAL.value:
            return "medium"
        if confidence < 0.9:
            return "medium"
        return "low"

    def _add_difference(
        self,
        differences: List[Difference],
        difference: Difference,
        options: ValidationOptions,
    ) -> None:
        if len(differences) < options.max_diff_items:
            differences.append(difference)
        else:
            # Keep count lightweight by appending only until max. The comparison
            # method still reports truncation based on actual collected count.
            differences.append(difference)

    def _check_required_paths(
        self,
        *,
        actual: Any,
        required_paths: Sequence[str],
        options: ValidationOptions,
        differences: List[Difference],
    ) -> int:
        failures = 0

        for path in required_paths:
            if self._is_ignored_path(path, options):
                continue

            exists, value = self._get_by_path(actual, path)
            if not exists or value is None:
                failures += 1
                self._add_difference(
                    differences,
                    Difference(
                        path=path,
                        difference_type=DifferenceType.MISSING_KEY.value,
                        expected="required_path",
                        actual=None,
                        message="Required validation path is missing or null in actual result.",
                        severity="high",
                        score_impact=0.1,
                    ),
                    options,
                )

        return failures

    def _get_by_path(self, data: Any, path: str) -> Tuple[bool, Any]:
        if not path:
            return True, data

        normalized = path
        if normalized.startswith("$."):
            normalized = normalized[2:]
        elif normalized == "$":
            return True, data

        current = data
        tokens = self._path_tokens(normalized)

        for token in tokens:
            if isinstance(token, int):
                if isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
                    if 0 <= token < len(current):
                        current = current[token]
                    else:
                        return False, None
                else:
                    return False, None
            else:
                if isinstance(current, Mapping) and token in current:
                    current = current[token]
                else:
                    return False, None

        return True, current

    def _path_tokens(self, path: str) -> List[Union[str, int]]:
        tokens: List[Union[str, int]] = []
        parts = path.split(".")

        for part in parts:
            if not part:
                continue

            name_match = re.match(r"^([^\[]+)", part)
            if name_match:
                tokens.append(name_match.group(1))

            for index_match in re.finditer(r"\[(\d+)\]", part):
                tokens.append(int(index_match.group(1)))

        return tokens

    def _join_path(self, parent: str, key: Any) -> str:
        safe_key = str(key)
        if parent == "$":
            return f"$.{safe_key}"
        return f"{parent}.{safe_key}"

    def _is_ignored_path(self, path: str, options: ValidationOptions) -> bool:
        return self._path_matches(path, options.ignored_paths)

    def _is_required_path(self, path: str, options: ValidationOptions) -> bool:
        return self._path_matches(path, options.required_paths)

    def _is_optional_path(self, path: str, options: ValidationOptions) -> bool:
        return self._path_matches(path, options.optional_paths)

    def _path_matches(self, path: str, patterns: Sequence[str]) -> bool:
        if not patterns:
            return False

        for pattern in patterns:
            pattern_str = str(pattern)
            if pattern_str == path:
                return True
            if pattern_str.endswith("*") and path.startswith(pattern_str[:-1]):
                return True
            if pattern_str.startswith("*.") and path.endswith(pattern_str[1:]):
                return True

        return False

    def _normalize_string(self, value: str, options: ValidationOptions) -> str:
        text = value

        if options.trim_strings:
            text = text.strip()

        if options.normalize_whitespace:
            text = re.sub(r"\s+", " ", text)

        if not options.case_sensitive:
            text = text.casefold()

        return text

    def _schema_type_matches(self, schema_type: Any, actual: Any) -> bool:
        normalized = str(schema_type).strip().lower()

        if normalized in {"str", "string", "text"}:
            return isinstance(actual, str)
        if normalized in {"int", "integer"}:
            return isinstance(actual, int) and not isinstance(actual, bool)
        if normalized in {"float", "number", "numeric"}:
            return self._is_number(actual)
        if normalized in {"bool", "boolean"}:
            return isinstance(actual, bool)
        if normalized in {"dict", "object", "mapping"}:
            return isinstance(actual, Mapping)
        if normalized in {"list", "array", "sequence"}:
            return isinstance(actual, Sequence) and not isinstance(actual, (str, bytes, bytearray))
        if normalized in {"none", "null"}:
            return actual is None
        if normalized in {"any", "*"}:
            return True

        return type(actual).__name__.lower() == normalized

    def _is_number(self, value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))

    def _contains_sensitive_key(self, data: Any, sensitive_keys: Sequence[str]) -> bool:
        lowered = {str(key).lower() for key in sensitive_keys}

        def walk(value: Any, depth: int = 0) -> bool:
            if depth > 20:
                return False

            if isinstance(value, Mapping):
                for key, child in value.items():
                    key_text = str(key).lower()
                    if any(sensitive in key_text for sensitive in lowered):
                        return True
                    if walk(child, depth + 1):
                        return True

            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                for child in value:
                    if walk(child, depth + 1):
                        return True

            return False

        return walk(data)

    def _redact_sensitive(self, data: Any) -> Any:
        sensitive_patterns = (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "private_key",
            "authorization",
            "cookie",
            "session",
        )

        def redact(value: Any, depth: int = 0) -> Any:
            if depth > 20:
                return "[MAX_DEPTH]"

            if isinstance(value, Mapping):
                result = {}
                for key, child in value.items():
                    key_text = str(key).lower()
                    if any(pattern in key_text for pattern in sensitive_patterns):
                        result[key] = "[REDACTED]"
                    else:
                        result[key] = redact(child, depth + 1)
                return result

            if isinstance(value, list):
                return [redact(item, depth + 1) for item in value]

            if isinstance(value, tuple):
                return tuple(redact(item, depth + 1) for item in value)

            return value

        return redact(data)

    def safe_preview(
        self,
        value: Any,
        *,
        options: Optional[ValidationOptions] = None,
    ) -> Any:
        return self.safe_preview_static(value)

    @staticmethod
    def safe_preview_static(value: Any) -> Any:
        """
        Return safe short preview for reports/logs/memory.

        Sensitive-looking keys are redacted. Long strings are truncated.
        """

        sensitive_patterns = (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "private_key",
            "authorization",
            "cookie",
            "session",
        )

        def preview(item: Any, depth: int = 0) -> Any:
            if depth > 8:
                return "[MAX_DEPTH]"

            if isinstance(item, Mapping):
                result: Dict[str, Any] = {}
                for key, child in list(item.items())[:50]:
                    key_text = str(key).lower()
                    if any(pattern in key_text for pattern in sensitive_patterns):
                        result[str(key)] = "[REDACTED]"
                    else:
                        result[str(key)] = preview(child, depth + 1)
                if len(item) > 50:
                    result["..."] = f"{len(item) - 50} more keys"
                return result

            if isinstance(item, list):
                shown = [preview(child, depth + 1) for child in item[:25]]
                if len(item) > 25:
                    shown.append(f"... {len(item) - 25} more items")
                return shown

            if isinstance(item, tuple):
                shown_tuple = tuple(preview(child, depth + 1) for child in item[:25])
                if len(item) > 25:
                    return shown_tuple + (f"... {len(item) - 25} more items",)
                return shown_tuple

            if isinstance(item, str):
                if len(item) > MAX_STRING_PREVIEW:
                    return item[:MAX_STRING_PREVIEW] + "...[TRUNCATED]"
                return item

            try:
                json.dumps(item)
                return item
            except Exception:
                return repr(item)

        return preview(value)

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Registry / Loader compatibility
    # ------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader compatible manifest.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module": self.module_name,
            "file": self.file_name,
            "class": self.__class__.__name__,
            "public_methods": [
                "validate_result",
                "validate_task_result",
                "compare",
                "calculate_confidence",
                "build_report",
                "get_agent_manifest",
                "health_check",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "performs_destructive_actions": False,
            "requires_security_for_sensitive_data": True,
            "compatible_with": [
                "BaseAgent",
                "MasterAgent",
                "AgentRegistry",
                "AgentLoader",
                "AgentRouter",
                "VerificationAgent",
                "MemoryAgent",
                "SecurityAgent",
                "DashboardAPI",
            ],
            "version": "1.0.0",
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for Dashboard/API and Agent Registry.
        """

        return self._safe_result(
            success=True,
            message="ResultValidator is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "module": self.module_name,
                "file": self.file_name,
                "default_mode": self.default_options.comparison_mode.value,
                "default_confidence_threshold": self.default_options.confidence_threshold,
            },
            metadata={
                "checked_at": self._utc_now_iso(),
            },
        )


# ---------------------------------------------------------------------------
# Convenience module-level functions
# ---------------------------------------------------------------------------

def validate_result(
    expected: Any,
    actual: Any,
    *,
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
    task_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    action_name: Optional[str] = None,
    options: Optional[Union[ValidationOptions, Mapping[str, Any]]] = None,
    criteria: Optional[Mapping[str, Any]] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience function for direct validation without manually instantiating
    ResultValidator.
    """

    validator = ResultValidator()
    return validator.validate_result(
        expected=expected,
        actual=actual,
        user_id=user_id,
        workspace_id=workspace_id,
        task_id=task_id,
        agent_name=agent_name,
        action_name=action_name,
        options=options,
        criteria=criteria,
        context=context,
    )


def compare_results(
    expected: Any,
    actual: Any,
    *,
    options: Optional[Union[ValidationOptions, Mapping[str, Any]]] = None,
    criteria: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience function for raw expected vs actual comparison.
    """

    validator = ResultValidator()
    return validator.compare(
        expected=expected,
        actual=actual,
        options=options,
        criteria=criteria,
    )


__all__ = [
    "ResultValidator",
    "ValidationStatus",
    "DifferenceType",
    "ComparisonMode",
    "Difference",
    "ValidationOptions",
    "ComparisonScore",
    "validate_result",
    "compare_results",
]


"""
Where to place it:
    agents/verification_agent/result_validator.py

Required dependencies:
    Python standard library only.
    Optional future project dependency:
        agents.base_agent.BaseAgent

How to test it:
    1. Import test:
        python -c "from agents.verification_agent.result_validator import ResultValidator; print(ResultValidator().health_check())"

    2. Simple validation:
        python - <<'PY'
        from agents.verification_agent.result_validator import ResultValidator

        validator = ResultValidator()
        result = validator.validate_result(
            expected={"success": True, "message": "done"},
            actual={"success": True, "message": "Done", "extra": 1},
            user_id="user_1",
            workspace_id="workspace_1",
            task_id="task_1",
            agent_name="demo_agent",
            action_name="demo_action",
        )
        print(result)
        PY

    3. Strict validation:
        python - <<'PY'
        from agents.verification_agent.result_validator import ResultValidator

        validator = ResultValidator()
        result = validator.validate_result(
            expected={"count": 10},
            actual={"count": 11},
            user_id="user_1",
            workspace_id="workspace_1",
            options={"comparison_mode": "strict", "numeric_tolerance": 0},
        )
        print(result["data"]["status"], result["data"]["confidence"])
        PY

Agent/Module: Verification Agent
File Completed: result_validator.py
Completion: 23.5%
Completed Files: ['verification_agent.py', 'state_checker.py', 'screenshot_checker.py', 'result_validator.py']
Remaining Files: ['app_state_checker.py', 'file_state_checker.py', 'browser_state_checker.py', 'code_state_checker.py', 'device_state_checker.py', 'ui_element_checker.py', 'action_replay_checker.py', 'error_detector.py', 'proof_collector.py', 'retry_manager.py', 'report_generator.py', 'verification_memory.py', 'config.py']
Next Recommended File: agents/verification_agent/app_state_checker.py
FILE COMPLETE
"""