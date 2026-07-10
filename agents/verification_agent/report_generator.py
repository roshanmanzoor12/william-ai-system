"""
agents/verification_agent/report_generator.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Creates task completion reports with proof, confidence, next actions.

This module is part of the Verification Agent layer. It converts raw verification
outputs from state checkers, proof collectors, result validators, retry managers,
error detectors, and action replay checkers into safe, structured, dashboard-ready
task completion reports.

Architecture compatibility:
    - Master Agent routing compatible
    - Agent Registry / Agent Loader compatible
    - BaseAgent compatible with fallback stub
    - SaaS user/workspace isolation enforced
    - Security Agent approval hook included
    - Memory Agent payload preparation included
    - Dashboard/API structured dict output included
    - Audit/event hooks included
    - Safe to import before future William modules exist
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import traceback
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe even when the full William/Jarvis agent
        framework has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": None,
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("VerificationReportGenerator")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPORT_SCHEMA_VERSION = "1.0.0"
DEFAULT_AGENT_NAME = "verification_report_generator"
DEFAULT_MODULE = "verification_agent"
MAX_INLINE_PROOF_ITEMS = 50
MAX_STRING_FIELD_LENGTH = 10_000
MAX_ERROR_TRACE_LENGTH = 8_000
MAX_NEXT_ACTIONS = 25
MAX_WARNINGS = 50
MAX_TAGS = 50
MAX_METADATA_DEPTH = 5


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VerificationStatus(str, Enum):
    """Normalized verification status values."""

    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    REVIEW = "review"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


class ReportAudience(str, Enum):
    """Supported report audiences."""

    INTERNAL = "internal"
    DASHBOARD = "dashboard"
    API = "api"
    MEMORY = "memory"
    AUDIT = "audit"


class ProofType(str, Enum):
    """Known proof artifact types."""

    SCREENSHOT = "screenshot"
    LOG = "log"
    FILE = "file"
    API_RESPONSE = "api_response"
    PROCESS_STATUS = "process_status"
    BROWSER_STATE = "browser_state"
    DEVICE_STATE = "device_state"
    CODE_STATE = "code_state"
    UI_STATE = "ui_state"
    ERROR_TRACE = "error_trace"
    METRIC = "metric"
    TEXT = "text"
    UNKNOWN = "unknown"


class NextActionPriority(str, Enum):
    """Priority levels for next actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ReportContext:
    """
    SaaS-safe report context.

    user_id and workspace_id are required for any user-specific execution.
    """

    user_id: str
    workspace_id: str
    task_id: str
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    actor_id: Optional[str] = None
    role: Optional[str] = None
    subscription_id: Optional[str] = None
    agent_name: str = DEFAULT_AGENT_NAME
    source_agent: Optional[str] = None
    route: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class ProofItem:
    """
    Proof artifact included in a verification report.

    The content field is sanitized and truncated before output.
    Sensitive values should never be inserted by callers.
    """

    proof_id: str
    proof_type: str
    title: str
    content: Any = None
    path: Optional[str] = None
    url: Optional[str] = None
    checksum: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    created_at: str = field(default_factory=lambda: VerificationReportGenerator.utcnow_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NextAction:
    """Recommended next action after verification."""

    action_id: str
    title: str
    description: str
    priority: str = NextActionPriority.MEDIUM.value
    owner_agent: Optional[str] = None
    requires_security_check: bool = False
    is_destructive: bool = False
    estimated_risk: str = "low"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfidenceBreakdown:
    """Confidence score and component explanation."""

    score: float
    label: str
    reasons: List[str] = field(default_factory=list)
    components: Dict[str, float] = field(default_factory=dict)


@dataclass
class VerificationReport:
    """Final task completion report data model."""

    report_id: str
    schema_version: str
    generated_at: str
    status: str
    confidence: ConfidenceBreakdown
    title: str
    summary: str
    message: str
    context: ReportContext
    task: Dict[str, Any]
    expected: Dict[str, Any]
    actual: Dict[str, Any]
    proof: List[ProofItem]
    errors: List[Dict[str, Any]]
    warnings: List[str]
    next_actions: List[NextAction]
    audit: Dict[str, Any]
    memory: Dict[str, Any]
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VerificationReportGenerator(BaseAgent):
    """
    Creates structured task completion reports for William/Jarvis Verification Agent.

    Public methods:
        - generate_report()
        - generate_report_from_payload()
        - render_markdown_report()
        - prepare_dashboard_report()
        - prepare_api_report()
        - calculate_confidence()
        - normalize_status()

    Required compatibility hooks:
        - _validate_task_context()
        - _requires_security_check()
        - _request_security_approval()
        - _prepare_verification_payload()
        - _prepare_memory_payload()
        - _emit_agent_event()
        - _log_audit_event()
        - _safe_result()
        - _error_result()
    """

    agent_type = DEFAULT_MODULE
    agent_name = DEFAULT_AGENT_NAME
    public_methods = (
        "generate_report",
        "generate_report_from_payload",
        "render_markdown_report",
        "prepare_dashboard_report",
        "prepare_api_report",
        "calculate_confidence",
        "normalize_status",
    )

    def __init__(
        self,
        *,
        agent_name: str = DEFAULT_AGENT_NAME,
        logger: Optional[logging.Logger] = None,
        strict_context: bool = True,
        max_inline_proof_items: int = MAX_INLINE_PROOF_ITEMS,
        redact_sensitive_keys: bool = True,
        enable_audit_events: bool = True,
        enable_memory_payloads: bool = True,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.logger = logger or logging.getLogger(agent_name)
        self.strict_context = strict_context
        self.max_inline_proof_items = max(1, int(max_inline_proof_items))
        self.redact_sensitive_keys = redact_sensitive_keys
        self.enable_audit_events = enable_audit_events
        self.enable_memory_payloads = enable_memory_payloads

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        *,
        context: Union[ReportContext, Mapping[str, Any]],
        task: Optional[Mapping[str, Any]] = None,
        expected: Optional[Mapping[str, Any]] = None,
        actual: Optional[Mapping[str, Any]] = None,
        status: Optional[Union[str, VerificationStatus]] = None,
        proof: Optional[Sequence[Union[ProofItem, Mapping[str, Any]]]] = None,
        errors: Optional[Sequence[Mapping[str, Any]]] = None,
        warnings: Optional[Sequence[str]] = None,
        confidence: Optional[Union[float, Mapping[str, Any], ConfidenceBreakdown]] = None,
        next_actions: Optional[Sequence[Union[NextAction, Mapping[str, Any]]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        title: Optional[str] = None,
        summary: Optional[str] = None,
        message: Optional[str] = None,
        emit_events: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a complete Verification Agent task completion report.

        Args:
            context: Required SaaS context containing user_id, workspace_id, task_id.
            task: Original task/request details.
            expected: Expected result definition.
            actual: Actual observed result details.
            status: Optional explicit status. If omitted, inferred.
            proof: Proof artifacts from ProofCollector/checkers.
            errors: Error records from ErrorDetector/checkers.
            warnings: Human-readable warnings.
            confidence: Optional explicit confidence or confidence breakdown.
            next_actions: Recommended next steps.
            metadata: Extra safe metadata.
            title: Optional report title.
            summary: Optional report summary.
            message: Optional user/dashboard message.
            emit_events: Whether to call audit/event hooks.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        try:
            parsed_context = self._coerce_context(context)
            context_validation = self._validate_task_context(parsed_context)

            if not context_validation["success"]:
                return context_validation

            safe_task = self._sanitize_mapping(task or {})
            safe_expected = self._sanitize_mapping(expected or {})
            safe_actual = self._sanitize_mapping(actual or {})
            safe_metadata = self._sanitize_mapping(metadata or {})

            normalized_errors = self._normalize_errors(errors or [])
            normalized_warnings = self._normalize_warnings(warnings or [])
            normalized_proof = self._normalize_proof_items(proof or [])
            normalized_next_actions = self._normalize_next_actions(next_actions or [])

            normalized_status = self.normalize_status(
                status=status,
                actual=safe_actual,
                errors=normalized_errors,
                proof=normalized_proof,
                warnings=normalized_warnings,
            )

            confidence_breakdown = self.calculate_confidence(
                explicit_confidence=confidence,
                status=normalized_status,
                expected=safe_expected,
                actual=safe_actual,
                proof=normalized_proof,
                errors=normalized_errors,
                warnings=normalized_warnings,
            )

            final_title = self._build_title(
                title=title,
                task=safe_task,
                status=normalized_status,
            )
            final_summary = self._build_summary(
                summary=summary,
                status=normalized_status,
                confidence=confidence_breakdown,
                proof=normalized_proof,
                errors=normalized_errors,
                warnings=normalized_warnings,
            )
            final_message = self._build_message(
                message=message,
                status=normalized_status,
                confidence=confidence_breakdown,
                errors=normalized_errors,
            )

            report_id = self._new_report_id(parsed_context)

            audit_payload = self._build_audit_payload(
                report_id=report_id,
                context=parsed_context,
                status=normalized_status,
                confidence=confidence_breakdown,
                proof_count=len(normalized_proof),
                error_count=len(normalized_errors),
                warning_count=len(normalized_warnings),
            )

            memory_payload = self._prepare_memory_payload(
                report_id=report_id,
                context=parsed_context,
                status=normalized_status,
                confidence=confidence_breakdown,
                task=safe_task,
                summary=final_summary,
                proof=normalized_proof,
                errors=normalized_errors,
                next_actions=normalized_next_actions,
            )

            report = VerificationReport(
                report_id=report_id,
                schema_version=REPORT_SCHEMA_VERSION,
                generated_at=self.utcnow_iso(),
                status=normalized_status.value,
                confidence=confidence_breakdown,
                title=final_title,
                summary=final_summary,
                message=final_message,
                context=parsed_context,
                task=safe_task,
                expected=safe_expected,
                actual=safe_actual,
                proof=normalized_proof[: self.max_inline_proof_items],
                errors=normalized_errors,
                warnings=normalized_warnings,
                next_actions=normalized_next_actions,
                audit=audit_payload,
                memory=memory_payload,
                metadata={
                    **safe_metadata,
                    "agent_name": self.agent_name,
                    "module": DEFAULT_MODULE,
                    "proof_total_count": len(normalized_proof),
                    "proof_inline_count": min(len(normalized_proof), self.max_inline_proof_items),
                    "report_schema_version": REPORT_SCHEMA_VERSION,
                    "security_check_required": self._requires_security_check(
                        {
                            "status": normalized_status.value,
                            "errors": normalized_errors,
                            "next_actions": [asdict(action) for action in normalized_next_actions],
                            "metadata": safe_metadata,
                        }
                    ),
                },
            )

            report_dict = self._report_to_dict(report)

            verification_payload = self._prepare_verification_payload(report_dict)

            if emit_events:
                self._emit_agent_event(
                    event_name="verification.report.generated",
                    payload=verification_payload,
                    context=parsed_context,
                )
                self._log_audit_event(
                    action="verification_report_generated",
                    payload=audit_payload,
                    context=parsed_context,
                )

            return self._safe_result(
                success=True,
                message=final_message,
                data={
                    "report": report_dict,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "dashboard_report": self.prepare_dashboard_report(report_dict)["data"],
                    "api_report": self.prepare_api_report(report_dict)["data"],
                },
                metadata={
                    "report_id": report_id,
                    "status": normalized_status.value,
                    "confidence_score": confidence_breakdown.score,
                    "proof_count": len(normalized_proof),
                    "next_action_count": len(normalized_next_actions),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to generate verification report.",
                error=exc,
                metadata={
                    "operation": "generate_report",
                    "agent_name": self.agent_name,
                },
            )

    def generate_report_from_payload(
        self,
        payload: Mapping[str, Any],
        *,
        emit_events: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a report from a single dict payload.

        Useful for Master Agent, API routes, dashboard actions, queue jobs,
        and future Agent Router calls.
        """

        try:
            safe_payload = self._sanitize_mapping(payload)

            return self.generate_report(
                context=safe_payload.get("context") or {},
                task=safe_payload.get("task") or {},
                expected=safe_payload.get("expected") or {},
                actual=safe_payload.get("actual") or {},
                status=safe_payload.get("status"),
                proof=safe_payload.get("proof") or safe_payload.get("proof_items") or [],
                errors=safe_payload.get("errors") or [],
                warnings=safe_payload.get("warnings") or [],
                confidence=safe_payload.get("confidence"),
                next_actions=safe_payload.get("next_actions") or [],
                metadata=safe_payload.get("metadata") or {},
                title=safe_payload.get("title"),
                summary=safe_payload.get("summary"),
                message=safe_payload.get("message"),
                emit_events=emit_events,
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to generate verification report from payload.",
                error=exc,
                metadata={"operation": "generate_report_from_payload"},
            )

    def render_markdown_report(
        self,
        report: Mapping[str, Any],
        *,
        audience: Union[str, ReportAudience] = ReportAudience.DASHBOARD,
        include_proof: bool = True,
        include_errors: bool = True,
        include_next_actions: bool = True,
    ) -> Dict[str, Any]:
        """
        Render a human-readable Markdown report.

        This is intended for dashboards, logs, downloadable reports, or admin UI.
        """

        try:
            safe_report = self._sanitize_mapping(report)
            audience_value = self._enum_value(audience)

            title = safe_report.get("title") or "Verification Report"
            status = safe_report.get("status") or VerificationStatus.UNKNOWN.value
            generated_at = safe_report.get("generated_at") or self.utcnow_iso()
            confidence = safe_report.get("confidence") or {}
            confidence_score = confidence.get("score", 0.0) if isinstance(confidence, dict) else 0.0
            confidence_label = confidence.get("label", "unknown") if isinstance(confidence, dict) else "unknown"

            context = safe_report.get("context") or {}
            task = safe_report.get("task") or {}
            summary = safe_report.get("summary") or ""
            proof = safe_report.get("proof") or []
            errors = safe_report.get("errors") or []
            warnings = safe_report.get("warnings") or []
            next_actions = safe_report.get("next_actions") or []

            lines: List[str] = [
                f"# {title}",
                "",
                f"**Status:** {status}",
                f"**Confidence:** {self._format_percent(confidence_score)} ({confidence_label})",
                f"**Generated At:** {generated_at}",
                f"**Audience:** {audience_value}",
                "",
                "## Summary",
                summary or "No summary was provided.",
                "",
                "## Context",
                f"- User ID: `{self._safe_inline(context.get('user_id'))}`",
                f"- Workspace ID: `{self._safe_inline(context.get('workspace_id'))}`",
                f"- Task ID: `{self._safe_inline(context.get('task_id'))}`",
                f"- Source Agent: `{self._safe_inline(context.get('source_agent'))}`",
                "",
                "## Task",
                f"- Name: {self._safe_inline(task.get('name') or task.get('title') or task.get('type') or 'Unknown task')}",
                f"- Description: {self._safe_inline(task.get('description') or task.get('prompt') or 'No description provided.')}",
                "",
            ]

            if warnings:
                lines.extend(["## Warnings"])
                for warning in warnings[:MAX_WARNINGS]:
                    lines.append(f"- {self._safe_inline(warning)}")
                lines.append("")

            if include_errors and errors:
                lines.extend(["## Errors"])
                for error in errors:
                    code = self._safe_inline(error.get("code") or "ERROR")
                    msg = self._safe_inline(error.get("message") or "No error message.")
                    severity = self._safe_inline(error.get("severity") or "unknown")
                    lines.append(f"- **{code}** ({severity}): {msg}")
                lines.append("")

            if include_proof and proof:
                lines.extend(["## Proof"])
                for item in proof[: self.max_inline_proof_items]:
                    proof_type = self._safe_inline(item.get("proof_type") or item.get("type") or "unknown")
                    proof_title = self._safe_inline(item.get("title") or "Untitled proof")
                    confidence_value = item.get("confidence")
                    confidence_part = (
                        f" — confidence {self._format_percent(float(confidence_value))}"
                        if isinstance(confidence_value, (int, float))
                        else ""
                    )
                    lines.append(f"- **{proof_title}** [{proof_type}]{confidence_part}")
                    if item.get("path"):
                        lines.append(f"  - Path: `{self._safe_inline(item.get('path'))}`")
                    if item.get("checksum"):
                        lines.append(f"  - Checksum: `{self._safe_inline(item.get('checksum'))}`")
                lines.append("")

            if include_next_actions and next_actions:
                lines.extend(["## Recommended Next Actions"])
                for action in next_actions[:MAX_NEXT_ACTIONS]:
                    priority = self._safe_inline(action.get("priority") or "medium")
                    title_value = self._safe_inline(action.get("title") or "Next action")
                    description = self._safe_inline(action.get("description") or "")
                    owner_agent = self._safe_inline(action.get("owner_agent") or "unassigned")
                    lines.append(f"- **{priority.upper()}**: {title_value} — {description} _(owner: {owner_agent})_")
                lines.append("")

            markdown = "\n".join(lines).strip() + "\n"

            return self._safe_result(
                success=True,
                message="Markdown verification report rendered.",
                data={
                    "markdown": markdown,
                    "audience": audience_value,
                    "report_id": safe_report.get("report_id"),
                },
                metadata={
                    "line_count": len(lines),
                    "include_proof": include_proof,
                    "include_errors": include_errors,
                    "include_next_actions": include_next_actions,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to render Markdown verification report.",
                error=exc,
                metadata={"operation": "render_markdown_report"},
            )

    def prepare_dashboard_report(self, report: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare a compact Dashboard/API card representation.

        Dashboard-safe output intentionally excludes large raw proof content.
        """

        try:
            safe_report = self._sanitize_mapping(report)
            proof = safe_report.get("proof") or []
            errors = safe_report.get("errors") or []
            warnings = safe_report.get("warnings") or []
            next_actions = safe_report.get("next_actions") or []
            confidence = safe_report.get("confidence") or {}

            cards = {
                "status_card": {
                    "status": safe_report.get("status", VerificationStatus.UNKNOWN.value),
                    "title": safe_report.get("title", "Verification Report"),
                    "summary": safe_report.get("summary", ""),
                    "message": safe_report.get("message", ""),
                    "generated_at": safe_report.get("generated_at"),
                },
                "confidence_card": {
                    "score": confidence.get("score", 0.0) if isinstance(confidence, dict) else 0.0,
                    "label": confidence.get("label", "unknown") if isinstance(confidence, dict) else "unknown",
                    "reasons": confidence.get("reasons", []) if isinstance(confidence, dict) else [],
                    "components": confidence.get("components", {}) if isinstance(confidence, dict) else {},
                },
                "proof_card": {
                    "total": len(proof),
                    "items": [
                        {
                            "proof_id": item.get("proof_id"),
                            "proof_type": item.get("proof_type"),
                            "title": item.get("title"),
                            "confidence": item.get("confidence"),
                            "source": item.get("source"),
                            "created_at": item.get("created_at"),
                            "path": item.get("path"),
                            "checksum": item.get("checksum"),
                        }
                        for item in proof[: self.max_inline_proof_items]
                        if isinstance(item, dict)
                    ],
                },
                "issues_card": {
                    "error_count": len(errors),
                    "warning_count": len(warnings),
                    "errors": errors,
                    "warnings": warnings[:MAX_WARNINGS],
                },
                "next_actions_card": {
                    "total": len(next_actions),
                    "items": next_actions[:MAX_NEXT_ACTIONS],
                },
            }

            return self._safe_result(
                success=True,
                message="Dashboard report prepared.",
                data={
                    "report_id": safe_report.get("report_id"),
                    "schema_version": safe_report.get("schema_version", REPORT_SCHEMA_VERSION),
                    "context": safe_report.get("context", {}),
                    "cards": cards,
                },
                metadata={"audience": ReportAudience.DASHBOARD.value},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare dashboard report.",
                error=exc,
                metadata={"operation": "prepare_dashboard_report"},
            )

    def prepare_api_report(self, report: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare API-safe report response.

        This keeps a stable envelope for FastAPI routes:
            success, message, data, error, metadata.
        """

        try:
            safe_report = self._sanitize_mapping(report)

            api_data = {
                "report_id": safe_report.get("report_id"),
                "schema_version": safe_report.get("schema_version", REPORT_SCHEMA_VERSION),
                "generated_at": safe_report.get("generated_at"),
                "status": safe_report.get("status", VerificationStatus.UNKNOWN.value),
                "confidence": safe_report.get("confidence", {}),
                "title": safe_report.get("title"),
                "summary": safe_report.get("summary"),
                "message": safe_report.get("message"),
                "context": safe_report.get("context", {}),
                "task": safe_report.get("task", {}),
                "expected": safe_report.get("expected", {}),
                "actual": safe_report.get("actual", {}),
                "proof": safe_report.get("proof", []),
                "errors": safe_report.get("errors", []),
                "warnings": safe_report.get("warnings", []),
                "next_actions": safe_report.get("next_actions", []),
                "metadata": safe_report.get("metadata", {}),
            }

            return self._safe_result(
                success=True,
                message="API report prepared.",
                data=api_data,
                metadata={"audience": ReportAudience.API.value},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare API report.",
                error=exc,
                metadata={"operation": "prepare_api_report"},
            )

    def calculate_confidence(
        self,
        *,
        explicit_confidence: Optional[Union[float, Mapping[str, Any], ConfidenceBreakdown]] = None,
        status: Union[str, VerificationStatus] = VerificationStatus.UNKNOWN,
        expected: Optional[Mapping[str, Any]] = None,
        actual: Optional[Mapping[str, Any]] = None,
        proof: Optional[Sequence[ProofItem]] = None,
        errors: Optional[Sequence[Mapping[str, Any]]] = None,
        warnings: Optional[Sequence[str]] = None,
    ) -> ConfidenceBreakdown:
        """
        Calculate confidence using explicit confidence if provided,
        otherwise infer it from status, proof, errors, warnings, and result match.
        """

        if isinstance(explicit_confidence, ConfidenceBreakdown):
            return self._normalize_confidence_breakdown(explicit_confidence)

        if isinstance(explicit_confidence, Mapping):
            return self._normalize_confidence_breakdown(
                ConfidenceBreakdown(
                    score=self._clamp_float(explicit_confidence.get("score", 0.0)),
                    label=str(explicit_confidence.get("label") or "custom"),
                    reasons=[
                        str(reason)
                        for reason in explicit_confidence.get("reasons", [])
                        if reason is not None
                    ],
                    components={
                        str(key): self._clamp_float(value)
                        for key, value in dict(explicit_confidence.get("components", {})).items()
                        if isinstance(value, (int, float))
                    },
                )
            )

        if isinstance(explicit_confidence, (int, float)):
            score = self._clamp_float(explicit_confidence)
            return ConfidenceBreakdown(
                score=score,
                label=self._confidence_label(score),
                reasons=["Explicit confidence score supplied by caller."],
                components={"explicit": score},
            )

        normalized_status = self._status_from_any(status)
        proof_items = list(proof or [])
        error_items = list(errors or [])
        warning_items = list(warnings or [])

        components: Dict[str, float] = {}
        reasons: List[str] = []

        status_component = {
            VerificationStatus.PASSED: 0.92,
            VerificationStatus.PARTIAL: 0.64,
            VerificationStatus.REVIEW: 0.48,
            VerificationStatus.SKIPPED: 0.38,
            VerificationStatus.FAILED: 0.28,
            VerificationStatus.UNKNOWN: 0.35,
        }.get(normalized_status, 0.35)
        components["status"] = status_component
        reasons.append(f"Status component based on '{normalized_status.value}'.")

        proof_component = self._proof_confidence_component(proof_items)
        components["proof"] = proof_component
        if proof_items:
            reasons.append(f"{len(proof_items)} proof item(s) included.")
        else:
            reasons.append("No proof artifacts were provided.")

        error_component = self._error_confidence_component(error_items)
        components["errors"] = error_component
        if error_items:
            reasons.append(f"{len(error_items)} error item(s) reduced confidence.")

        warning_component = self._warning_confidence_component(warning_items)
        components["warnings"] = warning_component
        if warning_items:
            reasons.append(f"{len(warning_items)} warning(s) reduced confidence.")

        match_component = self._expected_actual_match_component(expected or {}, actual or {})
        components["expected_actual_match"] = match_component
        reasons.append("Expected vs actual result consistency was evaluated.")

        weighted_score = (
            components["status"] * 0.35
            + components["proof"] * 0.25
            + components["errors"] * 0.15
            + components["warnings"] * 0.10
            + components["expected_actual_match"] * 0.15
        )

        score = self._clamp_float(weighted_score)

        return ConfidenceBreakdown(
            score=score,
            label=self._confidence_label(score),
            reasons=reasons,
            components=components,
        )

    def normalize_status(
        self,
        *,
        status: Optional[Union[str, VerificationStatus]] = None,
        actual: Optional[Mapping[str, Any]] = None,
        errors: Optional[Sequence[Mapping[str, Any]]] = None,
        proof: Optional[Sequence[ProofItem]] = None,
        warnings: Optional[Sequence[str]] = None,
    ) -> VerificationStatus:
        """
        Normalize or infer report status.

        Inference priority:
            1. Explicit caller status
            2. Critical errors
            3. Actual success/status fields
            4. Proof presence
            5. Warnings/review signals
        """

        if status is not None:
            return self._status_from_any(status)

        error_items = list(errors or [])
        actual_map = actual or {}
        proof_items = list(proof or [])
        warning_items = list(warnings or [])

        if error_items:
            has_critical = any(
                str(item.get("severity", "")).lower() in {"critical", "fatal", "high"}
                for item in error_items
                if isinstance(item, Mapping)
            )
            return VerificationStatus.FAILED if has_critical else VerificationStatus.REVIEW

        actual_status = actual_map.get("status") or actual_map.get("verification_status")
        actual_success = actual_map.get("success")

        if actual_status is not None:
            return self._status_from_any(actual_status)

        if isinstance(actual_success, bool):
            if actual_success and proof_items:
                return VerificationStatus.PASSED
            if actual_success and warning_items:
                return VerificationStatus.PARTIAL
            if actual_success:
                return VerificationStatus.PARTIAL
            return VerificationStatus.FAILED

        if proof_items and not warning_items:
            return VerificationStatus.PASSED

        if proof_items and warning_items:
            return VerificationStatus.PARTIAL

        if warning_items:
            return VerificationStatus.REVIEW

        return VerificationStatus.UNKNOWN

    async def run(self, payload: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Async-compatible BaseAgent entry point.

        Master Agent / Agent Router can call this with a payload.
        """

        final_payload: Dict[str, Any] = {}
        if payload:
            final_payload.update(dict(payload))
        if kwargs:
            final_payload.update(kwargs)

        return self.generate_report_from_payload(final_payload)

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[ReportContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Every user-specific verification report must have:
            - user_id
            - workspace_id
            - task_id
        """

        try:
            parsed = self._coerce_context(context)

            missing: List[str] = []
            for field_name in ("user_id", "workspace_id", "task_id"):
                value = getattr(parsed, field_name, None)
                if not isinstance(value, str) or not value.strip():
                    missing.append(field_name)

            if missing:
                return self._safe_result(
                    success=False,
                    message="Verification report context is missing required SaaS isolation fields.",
                    data=None,
                    error={
                        "code": "INVALID_TASK_CONTEXT",
                        "missing_fields": missing,
                    },
                    metadata={
                        "required_fields": ["user_id", "workspace_id", "task_id"],
                        "strict_context": self.strict_context,
                    },
                )

            if not self._is_safe_identifier(parsed.user_id):
                missing.append("user_id_format")
            if not self._is_safe_identifier(parsed.workspace_id):
                missing.append("workspace_id_format")
            if not self._is_safe_identifier(parsed.task_id):
                missing.append("task_id_format")

            if missing:
                return self._safe_result(
                    success=False,
                    message="Verification report context contains unsafe identifier values.",
                    data=None,
                    error={
                        "code": "UNSAFE_CONTEXT_IDENTIFIER",
                        "fields": missing,
                    },
                    metadata={},
                )

            return self._safe_result(
                success=True,
                message="Verification report context is valid.",
                data={"context": asdict(parsed)},
                metadata={},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate verification report context.",
                error=exc,
                metadata={"operation": "_validate_task_context"},
            )

    def _requires_security_check(self, payload: Mapping[str, Any]) -> bool:
        """
        Determine whether report generation requires Security Agent review.

        Report generation itself is non-destructive. However, next actions may
        recommend destructive or sensitive follow-up operations.
        """

        try:
            safe_payload = self._sanitize_mapping(payload)

            security_words = {
                "delete",
                "remove",
                "destroy",
                "financial",
                "payment",
                "invoice",
                "credentials",
                "password",
                "token",
                "secret",
                "call",
                "message",
                "email",
                "browser_action",
                "system_action",
                "device_action",
            }

            next_actions = safe_payload.get("next_actions") or []
            for action in next_actions:
                if not isinstance(action, Mapping):
                    continue

                if bool(action.get("requires_security_check")):
                    return True

                if bool(action.get("is_destructive")):
                    return True

                combined = " ".join(
                    str(action.get(key, ""))
                    for key in ("title", "description", "owner_agent", "estimated_risk")
                ).lower()

                if any(word in combined for word in security_words):
                    return True

            metadata = safe_payload.get("metadata") or {}
            if isinstance(metadata, Mapping):
                if bool(metadata.get("requires_security_check")):
                    return True
                if bool(metadata.get("sensitive_action_detected")):
                    return True

            return False

        except Exception:
            return True

    def _request_security_approval(
        self,
        *,
        context: Union[ReportContext, Mapping[str, Any]],
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        This file does not execute sensitive actions directly. In the complete
        William system, this method can be wired to Security Agent.
        """

        try:
            parsed_context = self._coerce_context(context)
            request_id = str(uuid.uuid4())

            approval_payload = {
                "request_id": request_id,
                "action": action,
                "context": asdict(parsed_context),
                "payload": self._sanitize_mapping(payload or {}),
                "requested_by": self.agent_name,
                "created_at": self.utcnow_iso(),
                "status": "approval_required",
            }

            return self._safe_result(
                success=False,
                message="Security approval is required before this sensitive next action can continue.",
                data=approval_payload,
                error={
                    "code": "SECURITY_APPROVAL_REQUIRED",
                    "request_id": request_id,
                },
                metadata={
                    "security_agent_route": "security_agent.approval.request",
                    "agent_name": self.agent_name,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create security approval request.",
                error=exc,
                metadata={"operation": "_request_security_approval"},
            )

    def _prepare_verification_payload(self, report: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare payload consumable by Verification Agent, Master Agent,
        dashboard, workflow engine, and task history.
        """

        safe_report = self._sanitize_mapping(report)

        return {
            "type": "verification_report",
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_id": safe_report.get("report_id"),
            "generated_at": safe_report.get("generated_at", self.utcnow_iso()),
            "status": safe_report.get("status", VerificationStatus.UNKNOWN.value),
            "confidence": safe_report.get("confidence", {}),
            "message": safe_report.get("message", ""),
            "summary": safe_report.get("summary", ""),
            "context": safe_report.get("context", {}),
            "proof_count": len(safe_report.get("proof") or []),
            "error_count": len(safe_report.get("errors") or []),
            "warning_count": len(safe_report.get("warnings") or []),
            "next_action_count": len(safe_report.get("next_actions") or []),
            "source": {
                "agent_name": self.agent_name,
                "module": DEFAULT_MODULE,
                "file": "report_generator.py",
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        report_id: str,
        context: ReportContext,
        status: VerificationStatus,
        confidence: ConfidenceBreakdown,
        task: Mapping[str, Any],
        summary: str,
        proof: Sequence[ProofItem],
        errors: Sequence[Mapping[str, Any]],
        next_actions: Sequence[NextAction],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Memory Agent should store useful task outcomes without mixing users or
        workspaces. The payload keeps user_id/workspace_id explicit.
        """

        if not self.enable_memory_payloads:
            return {
                "enabled": False,
                "reason": "Memory payload generation disabled for this report generator instance.",
            }

        task_name = task.get("name") or task.get("title") or task.get("type") or "verification_task"

        return {
            "enabled": True,
            "memory_type": "verification_task_report",
            "report_id": report_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "source_agent": context.source_agent or self.agent_name,
            "title": str(task_name),
            "summary": summary,
            "status": status.value,
            "confidence_score": confidence.score,
            "confidence_label": confidence.label,
            "proof_count": len(proof),
            "error_count": len(errors),
            "next_actions": [
                {
                    "title": action.title,
                    "priority": action.priority,
                    "owner_agent": action.owner_agent,
                    "requires_security_check": action.requires_security_check,
                }
                for action in next_actions[:MAX_NEXT_ACTIONS]
            ],
            "created_at": self.utcnow_iso(),
            "retention_hint": "task_history",
            "privacy_scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "isolation_required": True,
            },
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        payload: Mapping[str, Any],
        context: Union[ReportContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Agent event hook.

        In production, connect this to the William event bus, task history,
        WebSocket dashboard stream, or analytics service.
        """

        try:
            parsed_context = self._coerce_context(context)
            event = {
                "event_id": str(uuid.uuid4()),
                "event_name": event_name,
                "agent_name": self.agent_name,
                "module": DEFAULT_MODULE,
                "context": asdict(parsed_context),
                "payload": self._sanitize_mapping(payload),
                "created_at": self.utcnow_iso(),
            }

            self.logger.info(
                "Agent event emitted: %s user=%s workspace=%s task=%s",
                event_name,
                parsed_context.user_id,
                parsed_context.workspace_id,
                parsed_context.task_id,
            )

            return self._safe_result(
                success=True,
                message="Agent event emitted.",
                data=event,
                metadata={},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
                metadata={"operation": "_emit_agent_event", "event_name": event_name},
            )

    def _log_audit_event(
        self,
        *,
        action: str,
        payload: Mapping[str, Any],
        context: Union[ReportContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Audit logging hook.

        This method avoids external side effects by default. It returns a
        structured audit event that future audit services can persist.
        """

        try:
            parsed_context = self._coerce_context(context)

            audit_event = {
                "audit_id": str(uuid.uuid4()),
                "action": action,
                "agent_name": self.agent_name,
                "module": DEFAULT_MODULE,
                "user_id": parsed_context.user_id,
                "workspace_id": parsed_context.workspace_id,
                "task_id": parsed_context.task_id,
                "request_id": parsed_context.request_id,
                "correlation_id": parsed_context.correlation_id,
                "payload": self._sanitize_mapping(payload),
                "created_at": self.utcnow_iso(),
            }

            if self.enable_audit_events:
                self.logger.info(
                    "Audit event: %s user=%s workspace=%s task=%s",
                    action,
                    parsed_context.user_id,
                    parsed_context.workspace_id,
                    parsed_context.task_id,
                )

            return self._safe_result(
                success=True,
                message="Audit event prepared.",
                data=audit_event,
                metadata={"audit_enabled": self.enable_audit_events},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
                metadata={"operation": "_log_audit_event", "action": action},
            )

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Any = None,
        error: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis result envelope.
        """

        return {
            "success": bool(success),
            "message": str(message),
            "data": data,
            "error": self._sanitize_any(error),
            "metadata": self._sanitize_mapping(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[BaseException, Mapping[str, Any], str, None] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error result envelope.
        """

        error_payload: Dict[str, Any]

        if isinstance(error, BaseException):
            error_payload = {
                "code": error.__class__.__name__,
                "message": str(error),
                "trace": traceback.format_exc()[-MAX_ERROR_TRACE_LENGTH:],
            }
        elif isinstance(error, Mapping):
            error_payload = self._sanitize_mapping(error)
        elif error is None:
            error_payload = {"code": "UNKNOWN_ERROR", "message": "Unknown error."}
        else:
            error_payload = {"code": "ERROR", "message": str(error)}

        self.logger.error("%s | %s", message, error_payload.get("message"))

        return {
            "success": False,
            "message": str(message),
            "data": None,
            "error": error_payload,
            "metadata": self._sanitize_mapping(metadata or {}),
        }

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_title(
        self,
        *,
        title: Optional[str],
        task: Mapping[str, Any],
        status: VerificationStatus,
    ) -> str:
        if title:
            return self._truncate(str(title), 200)

        task_name = task.get("name") or task.get("title") or task.get("type") or "Task"
        return self._truncate(f"Verification Report: {task_name} ({status.value})", 200)

    def _build_summary(
        self,
        *,
        summary: Optional[str],
        status: VerificationStatus,
        confidence: ConfidenceBreakdown,
        proof: Sequence[ProofItem],
        errors: Sequence[Mapping[str, Any]],
        warnings: Sequence[str],
    ) -> str:
        if summary:
            return self._truncate(str(summary), MAX_STRING_FIELD_LENGTH)

        parts = [
            f"Verification completed with status '{status.value}'.",
            f"Confidence is {self._format_percent(confidence.score)} ({confidence.label}).",
            f"{len(proof)} proof item(s) collected.",
        ]

        if errors:
            parts.append(f"{len(errors)} error(s) detected.")
        if warnings:
            parts.append(f"{len(warnings)} warning(s) included.")

        return " ".join(parts)

    def _build_message(
        self,
        *,
        message: Optional[str],
        status: VerificationStatus,
        confidence: ConfidenceBreakdown,
        errors: Sequence[Mapping[str, Any]],
    ) -> str:
        if message:
            return self._truncate(str(message), 500)

        if status == VerificationStatus.PASSED:
            return f"Task verification passed with {self._format_percent(confidence.score)} confidence."

        if status == VerificationStatus.FAILED:
            return f"Task verification failed with {len(errors)} error(s)."

        if status == VerificationStatus.PARTIAL:
            return f"Task verification partially passed with {self._format_percent(confidence.score)} confidence."

        if status == VerificationStatus.REVIEW:
            return "Task verification needs review before it should be considered complete."

        if status == VerificationStatus.SKIPPED:
            return "Task verification was skipped."

        return "Task verification status is unknown."

    def _build_audit_payload(
        self,
        *,
        report_id: str,
        context: ReportContext,
        status: VerificationStatus,
        confidence: ConfidenceBreakdown,
        proof_count: int,
        error_count: int,
        warning_count: int,
    ) -> Dict[str, Any]:
        return {
            "report_id": report_id,
            "schema_version": REPORT_SCHEMA_VERSION,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "actor_id": context.actor_id,
            "agent_name": self.agent_name,
            "source_agent": context.source_agent,
            "status": status.value,
            "confidence_score": confidence.score,
            "confidence_label": confidence.label,
            "proof_count": proof_count,
            "error_count": error_count,
            "warning_count": warning_count,
            "created_at": self.utcnow_iso(),
            "event_category": "verification",
            "isolation_scope": f"{context.user_id}:{context.workspace_id}",
        }

    def _new_report_id(self, context: ReportContext) -> str:
        raw = f"{context.user_id}:{context.workspace_id}:{context.task_id}:{self.utcnow_iso()}:{uuid.uuid4()}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"vr_{digest}"

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _coerce_context(self, context: Union[ReportContext, Mapping[str, Any]]) -> ReportContext:
        if isinstance(context, ReportContext):
            return context

        if not isinstance(context, Mapping):
            raise ValueError("context must be a ReportContext or mapping.")

        return ReportContext(
            user_id=str(context.get("user_id") or "").strip(),
            workspace_id=str(context.get("workspace_id") or "").strip(),
            task_id=str(context.get("task_id") or context.get("id") or "").strip(),
            request_id=self._optional_str(context.get("request_id")),
            session_id=self._optional_str(context.get("session_id")),
            actor_id=self._optional_str(context.get("actor_id")),
            role=self._optional_str(context.get("role")),
            subscription_id=self._optional_str(context.get("subscription_id")),
            agent_name=self._optional_str(context.get("agent_name")) or self.agent_name,
            source_agent=self._optional_str(context.get("source_agent")),
            route=self._optional_str(context.get("route")),
            correlation_id=self._optional_str(context.get("correlation_id")),
        )

    def _normalize_proof_items(
        self,
        proof: Sequence[Union[ProofItem, Mapping[str, Any]]],
    ) -> List[ProofItem]:
        items: List[ProofItem] = []

        for raw_item in proof:
            try:
                if isinstance(raw_item, ProofItem):
                    item = copy.deepcopy(raw_item)
                elif isinstance(raw_item, Mapping):
                    proof_type = str(
                        raw_item.get("proof_type")
                        or raw_item.get("type")
                        or ProofType.UNKNOWN.value
                    )
                    item = ProofItem(
                        proof_id=str(raw_item.get("proof_id") or raw_item.get("id") or f"proof_{uuid.uuid4().hex[:12]}"),
                        proof_type=self._normalize_proof_type(proof_type),
                        title=str(raw_item.get("title") or raw_item.get("name") or "Proof item"),
                        content=self._sanitize_any(raw_item.get("content")),
                        path=self._optional_str(raw_item.get("path")),
                        url=self._optional_str(raw_item.get("url")),
                        checksum=self._optional_str(raw_item.get("checksum")),
                        confidence=self._optional_confidence(raw_item.get("confidence")),
                        source=self._optional_str(raw_item.get("source")),
                        created_at=self._optional_str(raw_item.get("created_at")) or self.utcnow_iso(),
                        metadata=self._sanitize_mapping(raw_item.get("metadata") or {}),
                    )
                else:
                    item = ProofItem(
                        proof_id=f"proof_{uuid.uuid4().hex[:12]}",
                        proof_type=ProofType.TEXT.value,
                        title="Raw proof item",
                        content=self._sanitize_any(raw_item),
                    )

                if not item.checksum:
                    item.checksum = self._checksum_proof_item(item)

                items.append(item)

            except Exception as exc:
                self.logger.warning("Skipped invalid proof item: %s", exc)

        return items

    def _normalize_next_actions(
        self,
        actions: Sequence[Union[NextAction, Mapping[str, Any]]],
    ) -> List[NextAction]:
        normalized: List[NextAction] = []

        for raw_action in list(actions)[:MAX_NEXT_ACTIONS]:
            try:
                if isinstance(raw_action, NextAction):
                    action = copy.deepcopy(raw_action)
                elif isinstance(raw_action, Mapping):
                    priority = str(raw_action.get("priority") or NextActionPriority.MEDIUM.value).lower()
                    if priority not in {item.value for item in NextActionPriority}:
                        priority = NextActionPriority.MEDIUM.value

                    action = NextAction(
                        action_id=str(raw_action.get("action_id") or raw_action.get("id") or f"act_{uuid.uuid4().hex[:12]}"),
                        title=str(raw_action.get("title") or "Recommended next action"),
                        description=str(raw_action.get("description") or raw_action.get("message") or ""),
                        priority=priority,
                        owner_agent=self._optional_str(raw_action.get("owner_agent")),
                        requires_security_check=bool(raw_action.get("requires_security_check", False)),
                        is_destructive=bool(raw_action.get("is_destructive", False)),
                        estimated_risk=str(raw_action.get("estimated_risk") or "low").lower(),
                        metadata=self._sanitize_mapping(raw_action.get("metadata") or {}),
                    )
                else:
                    action = NextAction(
                        action_id=f"act_{uuid.uuid4().hex[:12]}",
                        title="Recommended next action",
                        description=str(raw_action),
                    )

                normalized.append(action)

            except Exception as exc:
                self.logger.warning("Skipped invalid next action: %s", exc)

        return normalized

    def _normalize_errors(
        self,
        errors: Sequence[Mapping[str, Any]],
    ) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []

        for raw_error in errors:
            try:
                if isinstance(raw_error, Mapping):
                    code = str(raw_error.get("code") or raw_error.get("type") or "ERROR")
                    message = str(raw_error.get("message") or raw_error.get("detail") or "Unknown error.")
                    severity = str(raw_error.get("severity") or "medium").lower()

                    normalized.append(
                        {
                            "code": self._truncate(code, 120),
                            "message": self._truncate(message, 2_000),
                            "severity": severity,
                            "source": self._optional_str(raw_error.get("source")),
                            "created_at": self._optional_str(raw_error.get("created_at")) or self.utcnow_iso(),
                            "metadata": self._sanitize_mapping(raw_error.get("metadata") or {}),
                        }
                    )
                else:
                    normalized.append(
                        {
                            "code": "ERROR",
                            "message": self._truncate(str(raw_error), 2_000),
                            "severity": "medium",
                            "source": None,
                            "created_at": self.utcnow_iso(),
                            "metadata": {},
                        }
                    )
            except Exception as exc:
                self.logger.warning("Skipped invalid error item: %s", exc)

        return normalized

    def _normalize_warnings(self, warnings: Sequence[str]) -> List[str]:
        normalized: List[str] = []

        for warning in list(warnings)[:MAX_WARNINGS]:
            if warning is None:
                continue
            normalized.append(self._truncate(str(warning), 1_000))

        return normalized

    def _normalize_confidence_breakdown(
        self,
        confidence: ConfidenceBreakdown,
    ) -> ConfidenceBreakdown:
        score = self._clamp_float(confidence.score)
        label = confidence.label or self._confidence_label(score)

        return ConfidenceBreakdown(
            score=score,
            label=label,
            reasons=[self._truncate(str(reason), 500) for reason in confidence.reasons],
            components={
                str(key): self._clamp_float(value)
                for key, value in confidence.components.items()
                if isinstance(value, (int, float))
            },
        )

    def _normalize_proof_type(self, value: str) -> str:
        lowered = str(value or "").strip().lower()

        known = {item.value for item in ProofType}
        if lowered in known:
            return lowered

        aliases = {
            "screen": ProofType.SCREENSHOT.value,
            "image": ProofType.SCREENSHOT.value,
            "stdout": ProofType.LOG.value,
            "stderr": ProofType.LOG.value,
            "api": ProofType.API_RESPONSE.value,
            "http": ProofType.API_RESPONSE.value,
            "browser": ProofType.BROWSER_STATE.value,
            "device": ProofType.DEVICE_STATE.value,
            "code": ProofType.CODE_STATE.value,
            "ui": ProofType.UI_STATE.value,
            "error": ProofType.ERROR_TRACE.value,
        }

        return aliases.get(lowered, ProofType.UNKNOWN.value)

    def _status_from_any(self, value: Union[str, VerificationStatus]) -> VerificationStatus:
        if isinstance(value, VerificationStatus):
            return value

        normalized = str(value or "").strip().lower()

        aliases = {
            "success": VerificationStatus.PASSED,
            "succeeded": VerificationStatus.PASSED,
            "complete": VerificationStatus.PASSED,
            "completed": VerificationStatus.PASSED,
            "ok": VerificationStatus.PASSED,
            "true": VerificationStatus.PASSED,
            "pass": VerificationStatus.PASSED,
            "passed": VerificationStatus.PASSED,
            "fail": VerificationStatus.FAILED,
            "failed": VerificationStatus.FAILED,
            "error": VerificationStatus.FAILED,
            "false": VerificationStatus.FAILED,
            "partial": VerificationStatus.PARTIAL,
            "partially_completed": VerificationStatus.PARTIAL,
            "review": VerificationStatus.REVIEW,
            "needs_review": VerificationStatus.REVIEW,
            "manual_review": VerificationStatus.REVIEW,
            "skip": VerificationStatus.SKIPPED,
            "skipped": VerificationStatus.SKIPPED,
            "unknown": VerificationStatus.UNKNOWN,
            "none": VerificationStatus.UNKNOWN,
        }

        return aliases.get(normalized, VerificationStatus.UNKNOWN)

    # ------------------------------------------------------------------
    # Confidence helpers
    # ------------------------------------------------------------------

    def _proof_confidence_component(self, proof: Sequence[ProofItem]) -> float:
        if not proof:
            return 0.25

        confidence_values = [
            item.confidence
            for item in proof
            if isinstance(item.confidence, (int, float))
        ]

        if confidence_values:
            average = sum(self._clamp_float(value) for value in confidence_values) / len(confidence_values)
        else:
            average = 0.70

        count_bonus = min(0.15, len(proof) * 0.025)
        return self._clamp_float(average + count_bonus)

    def _error_confidence_component(self, errors: Sequence[Mapping[str, Any]]) -> float:
        if not errors:
            return 1.0

        penalty = 0.0
        for error in errors:
            severity = str(error.get("severity") or "medium").lower()
            if severity in {"critical", "fatal"}:
                penalty += 0.45
            elif severity == "high":
                penalty += 0.30
            elif severity == "medium":
                penalty += 0.18
            else:
                penalty += 0.08

        return self._clamp_float(1.0 - min(0.85, penalty))

    def _warning_confidence_component(self, warnings: Sequence[str]) -> float:
        if not warnings:
            return 1.0

        penalty = min(0.50, len(warnings) * 0.07)
        return self._clamp_float(1.0 - penalty)

    def _expected_actual_match_component(
        self,
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
    ) -> float:
        if not expected and not actual:
            return 0.50

        if not expected and actual:
            return 0.70

        if expected and not actual:
            return 0.30

        comparable_keys = [
            key
            for key in expected.keys()
            if key in actual and not isinstance(expected.get(key), (dict, list))
        ]

        if not comparable_keys:
            if actual.get("success") is True:
                return 0.75
            if actual.get("success") is False:
                return 0.35
            return 0.55

        matches = 0
        for key in comparable_keys:
            if str(expected.get(key)).strip().lower() == str(actual.get(key)).strip().lower():
                matches += 1

        return self._clamp_float(matches / max(1, len(comparable_keys)))

    def _confidence_label(self, score: float) -> str:
        score = self._clamp_float(score)

        if score >= 0.90:
            return "very_high"
        if score >= 0.75:
            return "high"
        if score >= 0.55:
            return "medium"
        if score >= 0.35:
            return "low"
        return "very_low"

    # ------------------------------------------------------------------
    # Serialization and sanitization
    # ------------------------------------------------------------------

    def _report_to_dict(self, report: VerificationReport) -> Dict[str, Any]:
        return {
            "report_id": report.report_id,
            "schema_version": report.schema_version,
            "generated_at": report.generated_at,
            "status": report.status,
            "confidence": asdict(report.confidence),
            "title": report.title,
            "summary": report.summary,
            "message": report.message,
            "context": asdict(report.context),
            "task": dict(report.task),
            "expected": dict(report.expected),
            "actual": dict(report.actual),
            "proof": [asdict(item) for item in report.proof],
            "errors": list(report.errors),
            "warnings": list(report.warnings),
            "next_actions": [asdict(action) for action in report.next_actions],
            "audit": dict(report.audit),
            "memory": dict(report.memory),
            "metadata": dict(report.metadata),
        }

    def _sanitize_mapping(
        self,
        value: Mapping[str, Any],
        *,
        depth: int = 0,
    ) -> Dict[str, Any]:
        if not isinstance(value, Mapping):
            return {}

        if depth > MAX_METADATA_DEPTH:
            return {"_truncated": "maximum_depth_reached"}

        sanitized: Dict[str, Any] = {}

        for key, raw_value in value.items():
            safe_key = str(key)

            if self.redact_sensitive_keys and self._is_sensitive_key(safe_key):
                sanitized[safe_key] = "[REDACTED]"
                continue

            sanitized[safe_key] = self._sanitize_any(raw_value, depth=depth + 1)

        return sanitized

    def _sanitize_any(self, value: Any, *, depth: int = 0) -> Any:
        if depth > MAX_METADATA_DEPTH:
            return "[TRUNCATED_MAX_DEPTH]"

        if value is None:
            return None

        if isinstance(value, (bool, int)):
            return value

        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                return None
            return value

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()

        if is_dataclass(value):
            return self._sanitize_mapping(asdict(value), depth=depth + 1)

        if isinstance(value, Mapping):
            return self._sanitize_mapping(value, depth=depth + 1)

        if isinstance(value, (list, tuple, set)):
            return [self._sanitize_any(item, depth=depth + 1) for item in list(value)[:500]]

        if isinstance(value, bytes):
            return {
                "type": "bytes",
                "length": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }

        text = str(value)
        return self._truncate(text, MAX_STRING_FIELD_LENGTH)

    def _is_sensitive_key(self, key: str) -> bool:
        lowered = key.lower()
        sensitive_fragments = {
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth_header",
            "cookie",
            "session_cookie",
            "private_key",
            "credential",
            "access_key",
            "refresh_token",
            "client_secret",
        }

        return any(fragment in lowered for fragment in sensitive_fragments)

    def _checksum_proof_item(self, item: ProofItem) -> str:
        payload = {
            "proof_type": item.proof_type,
            "title": item.title,
            "content": self._sanitize_any(item.content),
            "path": item.path,
            "url": item.url,
            "source": item.source,
        }
        raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def utcnow_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _clamp_float(self, value: Any, minimum: float = 0.0, maximum: float = 1.0) -> float:
        try:
            number = float(value)
        except Exception:
            number = minimum

        if math.isnan(number) or math.isinf(number):
            number = minimum

        return max(minimum, min(maximum, number))

    def _optional_confidence(self, value: Any) -> Optional[float]:
        if value is None:
            return None
        return self._clamp_float(value)

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None

        text = str(value).strip()
        if not text:
            return None

        return self._truncate(text, 1_000)

    def _truncate(self, value: str, max_length: int) -> str:
        text = str(value)
        if len(text) <= max_length:
            return text
        return text[: max(0, max_length - 15)] + "...[TRUNCATED]"

    def _safe_inline(self, value: Any) -> str:
        if value is None:
            return "N/A"

        text = str(value)
        text = text.replace("\n", " ").replace("\r", " ").strip()
        return self._truncate(text, 500)

    def _format_percent(self, value: Union[int, float]) -> str:
        score = self._clamp_float(value)
        return f"{score * 100:.1f}%"

    def _enum_value(self, value: Union[str, Enum]) -> str:
        if isinstance(value, Enum):
            return str(value.value)
        return str(value)

    def _is_safe_identifier(self, value: str) -> bool:
        if not isinstance(value, str):
            return False

        text = value.strip()
        if not text or len(text) > 180:
            return False

        unsafe = {"..", "/", "\\", "\x00", "\n", "\r", "\t"}
        return not any(fragment in text for fragment in unsafe)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_report_generator(**kwargs: Any) -> VerificationReportGenerator:
    """
    Factory for Agent Loader / Registry.

    Example:
        generator = create_report_generator()
    """

    return VerificationReportGenerator(**kwargs)


# ---------------------------------------------------------------------------
# Module metadata for Agent Registry / Agent Loader
# ---------------------------------------------------------------------------

AGENT_MODULE_INFO: Dict[str, Any] = {
    "module": DEFAULT_MODULE,
    "file": "report_generator.py",
    "class": "VerificationReportGenerator",
    "agent_name": DEFAULT_AGENT_NAME,
    "schema_version": REPORT_SCHEMA_VERSION,
    "purpose": "Creates task completion reports with proof, confidence, next actions.",
    "safe_to_import": True,
    "requires_user_context": True,
    "requires_workspace_context": True,
    "public_methods": list(VerificationReportGenerator.public_methods),
    "compatible_with": [
        "BaseAgent",
        "AgentRegistry",
        "AgentLoader",
        "AgentRouter",
        "MasterAgent",
        "VerificationAgent",
        "SecurityAgent",
        "MemoryAgent",
        "DashboardAPI",
        "AuditLog",
        "TaskHistory",
    ],
}


__all__ = [
    "VerificationReportGenerator",
    "VerificationReport",
    "ReportContext",
    "ProofItem",
    "NextAction",
    "ConfidenceBreakdown",
    "VerificationStatus",
    "ReportAudience",
    "ProofType",
    "NextActionPriority",
    "create_report_generator",
    "AGENT_MODULE_INFO",
]