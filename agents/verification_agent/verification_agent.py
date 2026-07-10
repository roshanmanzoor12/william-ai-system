"""
agents/verification_agent/verification_agent.py

Verification Agent for William / Jarvis Multi-Agent AI SaaS System
by Digital Promotix.

Purpose:
    Task confirmation brain for app/file/browser/device/code state checking,
    screenshots, validation, and proof reports.

This file is intentionally import-safe:
    - It does not require the rest of the William/Jarvis codebase to exist yet.
    - Optional imports use fallbacks.
    - No destructive, financial, browser, device, message, or system actions are
      executed directly.
    - All user/workspace scoped verification is validated for SaaS isolation.

Architecture connections:
    - Master Agent:
        Can route completed task payloads here for verification.
    - Security Agent:
        Sensitive verification requests can be approval-gated.
    - Memory Agent:
        Useful verification summaries can be converted into memory payloads.
    - Dashboard/API:
        All outputs are structured dict/JSON-style objects.
    - Agent Registry / Loader:
        VerificationAgent exposes stable metadata and public methods.

Required hooks included:
    - _validate_task_context()
    - _requires_security_check()
    - _request_security_approval()
    - _prepare_verification_payload()
    - _prepare_memory_payload()
    - _emit_agent_event()
    - _log_audit_event()
    - _safe_result()
    - _error_result()

Public methods:
    - verify_task()
    - verify_file_state()
    - verify_code_state()
    - verify_app_state()
    - verify_browser_state()
    - verify_device_state()
    - verify_ui_element_state()
    - verify_action_replay()
    - validate_result()
    - collect_proof()
    - generate_report()
    - get_agent_metadata()
    - health_check()
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import mimetypes
import os
import platform
import re
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Optional William/Jarvis imports with safe fallbacks
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback is intentionally broad for import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe before the real William/Jarvis BaseAgent exists.
        The real BaseAgent can later provide richer routing, event bus, permissions,
        telemetry, and registry hooks.
        """

        agent_name: str = "base_agent"
        agent_type: str = "base"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


try:
    from agents.verification_agent.config import VerificationConfig  # type: ignore
except Exception:
    VerificationConfig = None  # type: ignore


try:
    from agents.security_agent.policy_engine import PolicyDecision  # type: ignore
except Exception:
    PolicyDecision = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

LOGGER = logging.getLogger("william.verification_agent")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Constants
# ======================================================================================

AGENT_NAME = "verification_agent"
AGENT_DISPLAY_NAME = "Verification Agent"
AGENT_MODULE = "agents.verification_agent"
AGENT_FILE = "verification_agent.py"
AGENT_VERSION = "1.0.0"

DEFAULT_MAX_PROOF_ITEMS = 50
DEFAULT_MAX_FILE_READ_BYTES = 2_000_000
DEFAULT_MAX_DIFF_ITEMS = 100
DEFAULT_CONFIDENCE_THRESHOLD = 0.75
DEFAULT_ALLOWED_PROOF_TYPES = {
    "text",
    "json",
    "file_metadata",
    "checksum",
    "screenshot_reference",
    "browser_state",
    "device_state",
    "app_state",
    "code_analysis",
    "ui_element_state",
    "action_replay",
    "validation_summary",
}

SENSITIVE_VERIFICATION_TYPES = {
    "device_state",
    "browser_state",
    "screenshot",
    "screenshot_reference",
    "file_content",
    "system_state",
    "app_state",
    "action_replay",
}

PRIVATE_PATH_HINTS = {
    ".ssh",
    ".aws",
    ".azure",
    ".gcloud",
    ".gnupg",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "secrets",
    "secret",
    "token",
    "password",
    "credentials",
    ".env",
}

TEXT_EXTENSIONS = {
    ".py",
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".csv",
    ".html",
    ".css",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".xml",
    ".sql",
    ".sh",
    ".bat",
    ".ps1",
    ".env.example",
}


# ======================================================================================
# Enums and data structures
# ======================================================================================

class VerificationStatus(str, Enum):
    """Verification lifecycle/result status."""

    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"
    ERROR = "error"


class VerificationType(str, Enum):
    """Supported verification domains."""

    TASK = "task"
    RESULT = "result"
    FILE_STATE = "file_state"
    CODE_STATE = "code_state"
    APP_STATE = "app_state"
    BROWSER_STATE = "browser_state"
    DEVICE_STATE = "device_state"
    UI_ELEMENT = "ui_element"
    ACTION_REPLAY = "action_replay"
    SCREENSHOT = "screenshot"
    PROOF_REPORT = "proof_report"


class Severity(str, Enum):
    """Finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VerificationFinding:
    """A single verification finding."""

    check_name: str
    status: VerificationStatus
    message: str
    severity: Severity = Severity.INFO
    expected: Any = None
    actual: Any = None
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


@dataclass
class ProofItem:
    """A proof artifact collected during verification."""

    proof_id: str
    proof_type: str
    title: str
    data: Any
    created_at: str
    source: str = AGENT_NAME
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationContext:
    """
    SaaS-scoped task verification context.

    user_id and workspace_id are mandatory whenever verification belongs to a user
    or workspace. This prevents cross-tenant leakage.
    """

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    agent_name: Optional[str] = None
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationReport:
    """Complete verification report."""

    report_id: str
    status: VerificationStatus
    summary: str
    verification_type: VerificationType
    findings: List[VerificationFinding]
    proof_items: List[ProofItem]
    confidence: float
    created_at: str
    context: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "status": self.status.value,
            "summary": self.summary,
            "verification_type": self.verification_type.value,
            "findings": [item.to_dict() for item in self.findings],
            "proof_items": [item.to_dict() for item in self.proof_items],
            "confidence": self.confidence,
            "created_at": self.created_at,
            "context": self.context,
            "metadata": self.metadata,
        }


# ======================================================================================
# Helper functions
# ======================================================================================

def _utc_now() -> str:
    """Return ISO UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _safe_uuid(prefix: str = "ver") -> str:
    """Create a stable readable ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_safe(value: Any) -> Any:
    """Convert value to JSON-safe data where possible."""
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, Enum):
            return value.value
        if hasattr(value, "to_dict") and callable(value.to_dict):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            return dict(value.__dict__)
        return str(value)


def _normalize_string(value: Any) -> str:
    """Normalize arbitrary value into lowercase stripped string."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _safe_read_text(path: Path, max_bytes: int = DEFAULT_MAX_FILE_READ_BYTES) -> Tuple[Optional[str], Optional[str]]:
    """
    Safely read text-ish file content with a byte limit.

    Returns:
        (content, error)
    """
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None, f"File exceeds safe read limit: {size} bytes > {max_bytes} bytes"
        raw = path.read_bytes()
        try:
            return raw.decode("utf-8"), None
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace"), None
    except Exception as exc:
        return None, str(exc)


def _path_has_private_hint(path: Union[str, Path]) -> bool:
    raw = str(path).replace("\\", "/").lower()
    parts = set(part for part in raw.split("/") if part)
    return any(hint.lower() in raw or hint.lower() in parts for hint in PRIVATE_PATH_HINTS)


def _deep_get(mapping: Mapping[str, Any], dotted_key: str, default: Any = None) -> Any:
    """Get nested dict value using dot notation."""
    current: Any = mapping
    for part in dotted_key.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def _safe_compare(expected: Any, actual: Any, mode: str = "equals") -> bool:
    """Compare expected and actual values using supported modes."""
    if mode == "equals":
        return expected == actual
    if mode == "not_equals":
        return expected != actual
    if mode == "contains":
        return _normalize_string(expected) in _normalize_string(actual)
    if mode == "not_contains":
        return _normalize_string(expected) not in _normalize_string(actual)
    if mode == "case_insensitive_equals":
        return _normalize_string(expected) == _normalize_string(actual)
    if mode == "exists":
        return actual is not None
    if mode == "truthy":
        return bool(actual)
    if mode == "falsy":
        return not bool(actual)
    if mode == "regex":
        try:
            return bool(re.search(str(expected), str(actual or ""), re.IGNORECASE))
        except re.error:
            return False
    if mode == "gte":
        try:
            return float(actual) >= float(expected)
        except Exception:
            return False
    if mode == "lte":
        try:
            return float(actual) <= float(expected)
        except Exception:
            return False
    return expected == actual


# ======================================================================================
# Main agent
# ======================================================================================

class VerificationAgent(BaseAgent):
    """
    Main Verification Agent.

    This class confirms whether a requested task/action/result actually happened,
    using structured checks and proof collection. It avoids direct destructive actions
    and can be safely routed by the Master Agent after another agent completes a task.
    """

    agent_name = AGENT_NAME
    agent_type = "verification"
    agent_version = AGENT_VERSION
    display_name = AGENT_DISPLAY_NAME

    def __init__(
        self,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.config = config or self._load_default_config()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

        self.max_proof_items = int(getattr(self.config, "max_proof_items", DEFAULT_MAX_PROOF_ITEMS))
        self.max_file_read_bytes = int(getattr(self.config, "max_file_read_bytes", DEFAULT_MAX_FILE_READ_BYTES))
        self.default_confidence_threshold = float(
            getattr(self.config, "default_confidence_threshold", DEFAULT_CONFIDENCE_THRESHOLD)
        )
        self.allowed_proof_types = set(
            getattr(self.config, "allowed_proof_types", DEFAULT_ALLOWED_PROOF_TYPES)
        )

    # ----------------------------------------------------------------------------------
    # Metadata and health
    # ----------------------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """Return registry/loader compatible metadata."""
        return {
            "success": True,
            "message": "Verification Agent metadata loaded.",
            "data": {
                "agent_name": self.agent_name,
                "display_name": self.display_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "module": AGENT_MODULE,
                "file": AGENT_FILE,
                "public_methods": [
                    "verify_task",
                    "verify_file_state",
                    "verify_code_state",
                    "verify_app_state",
                    "verify_browser_state",
                    "verify_device_state",
                    "verify_ui_element_state",
                    "verify_action_replay",
                    "validate_result",
                    "collect_proof",
                    "generate_report",
                    "health_check",
                    "get_agent_metadata",
                ],
                "requires_saas_context": True,
                "supports_security_agent": True,
                "supports_memory_agent": True,
                "supports_dashboard_api": True,
                "safe_import": True,
            },
            "error": None,
            "metadata": {
                "created_at": _utc_now(),
            },
        }

    def health_check(self) -> Dict[str, Any]:
        """Return a lightweight health check."""
        return self._safe_result(
            message="Verification Agent is healthy.",
            data={
                "agent_name": self.agent_name,
                "version": self.agent_version,
                "python": platform.python_version(),
                "platform": platform.platform(),
                "security_agent_connected": self.security_agent is not None,
                "memory_agent_connected": self.memory_agent is not None,
                "allowed_proof_types": sorted(self.allowed_proof_types),
            },
            metadata={"checked_at": _utc_now()},
        )

    # ----------------------------------------------------------------------------------
    # Main verification orchestration
    # ----------------------------------------------------------------------------------

    def verify_task(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        task_payload: Mapping[str, Any],
        expected_state: Optional[Mapping[str, Any]] = None,
        actual_state: Optional[Mapping[str, Any]] = None,
        verification_plan: Optional[Sequence[Mapping[str, Any]]] = None,
        proof_inputs: Optional[Sequence[Mapping[str, Any]]] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Verify a completed task.

        Args:
            context:
                SaaS context with user_id and workspace_id.
            task_payload:
                Completed task metadata from Master Agent or another agent.
            expected_state:
                Optional expected final state.
            actual_state:
                Optional actual observed state.
            verification_plan:
                Optional list of structured checks.
            proof_inputs:
                Optional evidence/proof objects provided by caller.
            require_security:
                Override security gating. If None, agent decides based on type/sensitivity.

        Returns:
            Structured verification result.
        """
        started_at = time.time()
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result

            ctx = ctx_result["data"]["context"]
            verification_type = VerificationType.TASK

            sensitive = (
                bool(require_security)
                if require_security is not None
                else self._requires_security_check(
                    verification_type=verification_type.value,
                    payload={
                        "task_payload": task_payload,
                        "expected_state": expected_state,
                        "actual_state": actual_state,
                        "verification_plan": verification_plan,
                    },
                    context=ctx,
                )
            )

            if sensitive:
                approval = self._request_security_approval(
                    context=ctx,
                    action="verify_task",
                    payload={
                        "task_id": ctx.get("task_id"),
                        "task_payload": self._redact_sensitive_payload(dict(task_payload)),
                    },
                )
                if not approval.get("success"):
                    return approval

            findings: List[VerificationFinding] = []
            proof_items: List[ProofItem] = []

            task_status = task_payload.get("status") or task_payload.get("task_status")
            if task_status:
                passed = _normalize_string(task_status) in {"completed", "success", "succeeded", "done", "passed"}
                findings.append(
                    VerificationFinding(
                        check_name="task_status",
                        status=VerificationStatus.PASSED if passed else VerificationStatus.NEEDS_REVIEW,
                        message=f"Task status reported as '{task_status}'.",
                        expected="completed/success/succeeded/done/passed",
                        actual=task_status,
                        confidence=0.8 if passed else 0.55,
                        severity=Severity.INFO if passed else Severity.MEDIUM,
                    )
                )

            if expected_state is not None and actual_state is not None:
                validation = self.validate_result(
                    context=ctx,
                    expected=expected_state,
                    actual=actual_state,
                    checks=verification_plan,
                    verification_type=VerificationType.RESULT.value,
                )
                if validation["success"]:
                    for item in validation["data"].get("findings", []):
                        findings.append(self._finding_from_dict(item))
                    for proof in validation["data"].get("proof_items", []):
                        proof_items.append(self._proof_from_dict(proof))
                else:
                    findings.append(
                        VerificationFinding(
                            check_name="result_validation",
                            status=VerificationStatus.ERROR,
                            message=validation.get("message", "Result validation failed."),
                            severity=Severity.HIGH,
                            confidence=0.0,
                            evidence={"error": validation.get("error")},
                        )
                    )

            if proof_inputs:
                proof_result = self.collect_proof(ctx, proof_inputs)
                if proof_result["success"]:
                    for item in proof_result["data"].get("proof_items", []):
                        proof_items.append(self._proof_from_dict(item))
                else:
                    findings.append(
                        VerificationFinding(
                            check_name="proof_collection",
                            status=VerificationStatus.NEEDS_REVIEW,
                            message=proof_result.get("message", "Proof collection needs review."),
                            severity=Severity.MEDIUM,
                            confidence=0.4,
                            evidence={"error": proof_result.get("error")},
                        )
                    )

            if not findings:
                findings.append(
                    VerificationFinding(
                        check_name="task_payload_presence",
                        status=VerificationStatus.NEEDS_REVIEW,
                        message="Task payload received, but no explicit verification checks were provided.",
                        severity=Severity.MEDIUM,
                        expected="Verification plan or expected/actual state",
                        actual="No explicit checks",
                        confidence=0.45,
                        remediation="Provide expected_state, actual_state, or verification_plan for stronger verification.",
                    )
                )

            report = self._build_report(
                context=ctx,
                verification_type=verification_type,
                findings=findings,
                proof_items=proof_items,
                metadata={
                    "task_payload": self._redact_sensitive_payload(dict(task_payload)),
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                },
            )

            verification_payload = self._prepare_verification_payload(report, ctx)
            memory_payload = self._prepare_memory_payload(report, ctx)

            self._emit_agent_event(
                "verification.task.completed",
                {
                    "context": ctx,
                    "report_id": report.report_id,
                    "status": report.status.value,
                    "confidence": report.confidence,
                },
            )
            self._log_audit_event(
                {
                    "event": "verification_task_completed",
                    "context": ctx,
                    "report_id": report.report_id,
                    "status": report.status.value,
                    "confidence": report.confidence,
                    "created_at": report.created_at,
                }
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "findings": [finding.to_dict() for finding in findings],
                    "proof_items": [proof.to_dict() for proof in proof_items],
                },
                metadata={
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                    "agent": self.agent_name,
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Verification task failed unexpectedly.",
                error=exc,
                metadata={"duration_ms": round((time.time() - started_at) * 1000, 2)},
            )

    # ----------------------------------------------------------------------------------
    # Result validation
    # ----------------------------------------------------------------------------------

    def validate_result(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        checks: Optional[Sequence[Mapping[str, Any]]] = None,
        verification_type: str = "result",
    ) -> Dict[str, Any]:
        """
        Validate expected vs actual result.

        Supported check format:
            {
                "name": "status_check",
                "path": "status",
                "expected": "done",
                "mode": "case_insensitive_equals",
                "required": true,
                "severity": "high"
            }

        If checks are omitted, top-level expected keys are compared with equals mode.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            findings: List[VerificationFinding] = []
            proof_items: List[ProofItem] = []

            normalized_checks = list(checks or self._checks_from_expected(expected))

            for index, check in enumerate(normalized_checks):
                name = str(check.get("name") or check.get("check_name") or f"check_{index + 1}")
                path = str(check.get("path") or check.get("key") or "")
                mode = str(check.get("mode") or "equals")
                required = bool(check.get("required", True))
                severity = self._severity_from_string(str(check.get("severity") or "medium"))
                expected_value = check.get("expected", _deep_get(expected, path) if path else expected)
                actual_value = _deep_get(actual, path) if path else actual

                passed = _safe_compare(expected_value, actual_value, mode)
                finding_status = VerificationStatus.PASSED if passed else (
                    VerificationStatus.FAILED if required else VerificationStatus.NEEDS_REVIEW
                )

                findings.append(
                    VerificationFinding(
                        check_name=name,
                        status=finding_status,
                        message=(
                            f"Check '{name}' passed."
                            if passed
                            else f"Check '{name}' did not match expected value."
                        ),
                        severity=Severity.INFO if passed else severity,
                        expected=expected_value,
                        actual=actual_value,
                        confidence=0.95 if passed else 0.35,
                        evidence={
                            "path": path,
                            "mode": mode,
                            "required": required,
                        },
                        remediation=None if passed else "Review actual result or update expected verification criteria.",
                    )
                )

            summary_proof = ProofItem(
                proof_id=_safe_uuid("proof"),
                proof_type="validation_summary",
                title="Expected vs actual validation summary",
                data={
                    "checks_total": len(findings),
                    "checks_passed": sum(1 for item in findings if item.status == VerificationStatus.PASSED),
                    "checks_failed": sum(1 for item in findings if item.status == VerificationStatus.FAILED),
                    "checks_needs_review": sum(1 for item in findings if item.status == VerificationStatus.NEEDS_REVIEW),
                },
                created_at=_utc_now(),
                confidence=self._calculate_confidence(findings),
                metadata={"verification_type": verification_type},
            )
            proof_items.append(summary_proof)

            report = self._build_report(
                context=ctx,
                verification_type=self._verification_type_from_string(verification_type),
                findings=findings,
                proof_items=proof_items,
                metadata={"expected_keys": list(expected.keys()), "actual_keys": list(actual.keys())},
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "findings": [finding.to_dict() for finding in findings],
                    "proof_items": [proof.to_dict() for proof in proof_items],
                },
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("Result validation failed unexpectedly.", exc)

    # ----------------------------------------------------------------------------------
    # File state verification
    # ----------------------------------------------------------------------------------

    def verify_file_state(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        file_path: Union[str, Path],
        expected: Optional[Mapping[str, Any]] = None,
        allow_content_read: bool = False,
    ) -> Dict[str, Any]:
        """
        Verify file existence, metadata, checksum, optional content snippets.

        This is non-destructive. It reads metadata and optionally limited file content.
        Sensitive paths are not read unless the context explicitly allows it.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            path = Path(file_path).expanduser()
            expected = dict(expected or {})
            findings: List[VerificationFinding] = []
            proof_items: List[ProofItem] = []

            sensitive_path = _path_has_private_hint(path)
            can_read_sensitive = bool(ctx.get("permissions", {}).get("allow_sensitive_file_verification"))

            if sensitive_path and not can_read_sensitive:
                findings.append(
                    VerificationFinding(
                        check_name="sensitive_path_guard",
                        status=VerificationStatus.BLOCKED,
                        message="File path appears sensitive and content verification is blocked.",
                        severity=Severity.HIGH,
                        actual=str(path),
                        confidence=0.95,
                        remediation="Request Security Agent approval or verify using metadata only.",
                    )
                )
                allow_content_read = False

            exists = path.exists()
            expected_exists = expected.get("exists", True)
            findings.append(
                VerificationFinding(
                    check_name="file_exists",
                    status=VerificationStatus.PASSED if exists == expected_exists else VerificationStatus.FAILED,
                    message=f"File existence is {exists}.",
                    expected=expected_exists,
                    actual=exists,
                    severity=Severity.HIGH if expected_exists and not exists else Severity.INFO,
                    confidence=1.0,
                )
            )

            metadata: Dict[str, Any] = {
                "path": str(path),
                "exists": exists,
                "is_file": False,
                "is_dir": False,
                "size_bytes": None,
                "suffix": path.suffix,
                "mime_type": mimetypes.guess_type(str(path))[0],
                "sha256": None,
                "modified_at": None,
            }

            if exists:
                stat = path.stat()
                metadata.update(
                    {
                        "is_file": path.is_file(),
                        "is_dir": path.is_dir(),
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    }
                )

                if "is_file" in expected:
                    passed = path.is_file() == bool(expected["is_file"])
                    findings.append(
                        VerificationFinding(
                            check_name="file_is_file",
                            status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                            message=f"Path is_file={path.is_file()}.",
                            expected=bool(expected["is_file"]),
                            actual=path.is_file(),
                            confidence=1.0,
                        )
                    )

                if "min_size_bytes" in expected:
                    passed = stat.st_size >= int(expected["min_size_bytes"])
                    findings.append(
                        VerificationFinding(
                            check_name="file_min_size",
                            status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                            message=f"File size is {stat.st_size} bytes.",
                            expected=expected["min_size_bytes"],
                            actual=stat.st_size,
                            confidence=1.0,
                        )
                    )

                if "max_size_bytes" in expected:
                    passed = stat.st_size <= int(expected["max_size_bytes"])
                    findings.append(
                        VerificationFinding(
                            check_name="file_max_size",
                            status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                            message=f"File size is {stat.st_size} bytes.",
                            expected=expected["max_size_bytes"],
                            actual=stat.st_size,
                            confidence=1.0,
                        )
                    )

                if path.is_file():
                    try:
                        raw = path.read_bytes()
                        digest = _sha256_bytes(raw)
                        metadata["sha256"] = digest
                        if expected.get("sha256"):
                            passed = digest == expected["sha256"]
                            findings.append(
                                VerificationFinding(
                                    check_name="file_sha256",
                                    status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                                    message="File SHA256 checksum verified." if passed else "File SHA256 checksum mismatch.",
                                    expected=expected["sha256"],
                                    actual=digest,
                                    severity=Severity.HIGH if not passed else Severity.INFO,
                                    confidence=1.0,
                                )
                            )
                    except Exception as exc:
                        findings.append(
                            VerificationFinding(
                                check_name="file_checksum",
                                status=VerificationStatus.ERROR,
                                message="Could not calculate file checksum.",
                                severity=Severity.MEDIUM,
                                confidence=0.0,
                                evidence={"error": str(exc)},
                            )
                        )

                    should_read = allow_content_read and path.suffix.lower() in TEXT_EXTENSIONS
                    if should_read:
                        content, error = _safe_read_text(path, self.max_file_read_bytes)
                        if error:
                            findings.append(
                                VerificationFinding(
                                    check_name="file_content_read",
                                    status=VerificationStatus.NEEDS_REVIEW,
                                    message="File content could not be safely read.",
                                    severity=Severity.MEDIUM,
                                    confidence=0.4,
                                    evidence={"error": error},
                                )
                            )
                        else:
                            if expected.get("contains"):
                                contains_value = str(expected["contains"])
                                passed = contains_value in (content or "")
                                findings.append(
                                    VerificationFinding(
                                        check_name="file_contains",
                                        status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                                        message=(
                                            "Expected content was found."
                                            if passed
                                            else "Expected content was not found."
                                        ),
                                        expected=contains_value,
                                        actual="[content checked]",
                                        severity=Severity.MEDIUM if not passed else Severity.INFO,
                                        confidence=0.9,
                                    )
                                )
                            metadata["content_sha256"] = _sha256_text(content or "")
                            metadata["content_preview"] = (content or "")[:1000]

            proof_items.append(
                ProofItem(
                    proof_id=_safe_uuid("proof"),
                    proof_type="file_metadata",
                    title="File state metadata",
                    data=metadata,
                    created_at=_utc_now(),
                    confidence=self._calculate_confidence(findings),
                    metadata={"allow_content_read": allow_content_read, "sensitive_path": sensitive_path},
                )
            )

            report = self._build_report(
                context=ctx,
                verification_type=VerificationType.FILE_STATE,
                findings=findings,
                proof_items=proof_items,
                metadata={"file_path": str(path)},
            )

            return self._safe_result(
                message=report.summary,
                data={"report": report.to_dict(), "file_metadata": metadata},
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("File state verification failed unexpectedly.", exc)

    # ----------------------------------------------------------------------------------
    # Code state verification
    # ----------------------------------------------------------------------------------

    def verify_code_state(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        code: Optional[str] = None,
        file_path: Optional[Union[str, Path]] = None,
        language: str = "python",
        expected: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Verify code syntax/static properties.

        For Python:
            - Parses AST
            - Counts classes/functions/imports
            - Checks expected class/function names
            - Checks syntax without executing the code

        This method never runs user code.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            expected = dict(expected or {})
            findings: List[VerificationFinding] = []
            proof_items: List[ProofItem] = []
            source = code

            if source is None and file_path is not None:
                path = Path(file_path).expanduser()
                if not path.exists() or not path.is_file():
                    return self._error_result(
                        message="Code file does not exist or is not a file.",
                        error=f"Invalid file_path: {path}",
                    )
                source, read_error = _safe_read_text(path, self.max_file_read_bytes)
                if read_error:
                    return self._error_result(
                        message="Could not safely read code file.",
                        error=read_error,
                    )

            if source is None:
                return self._error_result(
                    message="No code or file_path provided for code verification.",
                    error="missing_code",
                )

            code_metadata: Dict[str, Any] = {
                "language": language,
                "length_chars": len(source),
                "line_count": source.count("\n") + 1 if source else 0,
                "sha256": _sha256_text(source),
                "file_path": str(file_path) if file_path else None,
                "syntax_valid": None,
                "classes": [],
                "functions": [],
                "imports": [],
            }

            if language.lower() in {"python", "py"}:
                try:
                    tree = ast.parse(source)
                    code_metadata["syntax_valid"] = True
                    findings.append(
                        VerificationFinding(
                            check_name="python_syntax",
                            status=VerificationStatus.PASSED,
                            message="Python syntax is valid.",
                            confidence=1.0,
                        )
                    )

                    classes: List[str] = []
                    functions: List[str] = []
                    imports: List[str] = []

                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            classes.append(node.name)
                        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            functions.append(node.name)
                        elif isinstance(node, ast.Import):
                            imports.extend(alias.name for alias in node.names)
                        elif isinstance(node, ast.ImportFrom):
                            module = node.module or ""
                            imports.append(module)

                    code_metadata["classes"] = sorted(set(classes))
                    code_metadata["functions"] = sorted(set(functions))
                    code_metadata["imports"] = sorted(set(item for item in imports if item))

                    for class_name in expected.get("required_classes", []):
                        passed = class_name in classes
                        findings.append(
                            VerificationFinding(
                                check_name=f"required_class:{class_name}",
                                status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                                message=(
                                    f"Required class '{class_name}' exists."
                                    if passed
                                    else f"Required class '{class_name}' is missing."
                                ),
                                expected=class_name,
                                actual=classes,
                                confidence=0.95 if passed else 0.2,
                                severity=Severity.HIGH if not passed else Severity.INFO,
                            )
                        )

                    for function_name in expected.get("required_functions", []):
                        passed = function_name in functions
                        findings.append(
                            VerificationFinding(
                                check_name=f"required_function:{function_name}",
                                status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                                message=(
                                    f"Required function '{function_name}' exists."
                                    if passed
                                    else f"Required function '{function_name}' is missing."
                                ),
                                expected=function_name,
                                actual=functions,
                                confidence=0.95 if passed else 0.2,
                                severity=Severity.HIGH if not passed else Severity.INFO,
                            )
                        )

                    if expected.get("must_not_execute"):
                        unsafe_patterns = self._detect_potential_execution_patterns(source)
                        passed = not unsafe_patterns
                        findings.append(
                            VerificationFinding(
                                check_name="unsafe_execution_patterns",
                                status=VerificationStatus.PASSED if passed else VerificationStatus.NEEDS_REVIEW,
                                message=(
                                    "No obvious direct execution/destructive patterns found."
                                    if passed
                                    else "Potential direct execution/destructive patterns found."
                                ),
                                expected="No unsafe execution patterns",
                                actual=unsafe_patterns,
                                severity=Severity.HIGH if unsafe_patterns else Severity.INFO,
                                confidence=0.7 if passed else 0.45,
                                remediation="Review flagged patterns manually; static detection can have false positives.",
                            )
                        )

                except SyntaxError as exc:
                    code_metadata["syntax_valid"] = False
                    findings.append(
                        VerificationFinding(
                            check_name="python_syntax",
                            status=VerificationStatus.FAILED,
                            message="Python syntax is invalid.",
                            severity=Severity.HIGH,
                            expected="valid syntax",
                            actual=f"{exc.msg} at line {exc.lineno}, offset {exc.offset}",
                            confidence=1.0,
                            evidence={
                                "lineno": exc.lineno,
                                "offset": exc.offset,
                                "text": exc.text,
                            },
                        )
                    )
            else:
                findings.append(
                    VerificationFinding(
                        check_name="language_support",
                        status=VerificationStatus.NEEDS_REVIEW,
                        message=f"Static syntax parser is not implemented for language '{language}'. Basic metadata only.",
                        severity=Severity.LOW,
                        confidence=0.4,
                    )
                )

            if expected.get("contains"):
                for text in expected["contains"]:
                    passed = str(text) in source
                    findings.append(
                        VerificationFinding(
                            check_name=f"code_contains:{str(text)[:50]}",
                            status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                            message="Required code text found." if passed else "Required code text missing.",
                            expected=text,
                            actual="[source checked]",
                            severity=Severity.MEDIUM if not passed else Severity.INFO,
                            confidence=0.9 if passed else 0.25,
                        )
                    )

            proof_items.append(
                ProofItem(
                    proof_id=_safe_uuid("proof"),
                    proof_type="code_analysis",
                    title="Code static analysis",
                    data=code_metadata,
                    created_at=_utc_now(),
                    confidence=self._calculate_confidence(findings),
                )
            )

            report = self._build_report(
                context=ctx,
                verification_type=VerificationType.CODE_STATE,
                findings=findings,
                proof_items=proof_items,
                metadata={"language": language, "file_path": str(file_path) if file_path else None},
            )

            return self._safe_result(
                message=report.summary,
                data={"report": report.to_dict(), "code_metadata": code_metadata},
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("Code state verification failed unexpectedly.", exc)

    # ----------------------------------------------------------------------------------
    # App/browser/device/UI/action state verification
    # ----------------------------------------------------------------------------------

    def verify_app_state(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        app_name: Optional[str] = None,
        checks: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Verify app state from caller-provided observed state."""
        return self._verify_state_domain(
            context=context,
            expected=expected,
            actual=actual,
            verification_type=VerificationType.APP_STATE,
            domain_name="app_state",
            domain_label=app_name or "application",
            checks=checks,
        )

    def verify_browser_state(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        checks: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Verify browser state from provided data.

        This method does not open/control a browser. Browser automation/checking can be
        implemented in browser_state_checker.py later and route observations here.
        """
        return self._verify_state_domain(
            context=context,
            expected=expected,
            actual=actual,
            verification_type=VerificationType.BROWSER_STATE,
            domain_name="browser_state",
            domain_label=str(actual.get("browser") or actual.get("url") or "browser"),
            checks=checks,
        )

    def verify_device_state(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        checks: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Verify device state from provided telemetry.

        This method does not control, lock, delete from, or modify any device.
        """
        return self._verify_state_domain(
            context=context,
            expected=expected,
            actual=actual,
            verification_type=VerificationType.DEVICE_STATE,
            domain_name="device_state",
            domain_label=str(actual.get("device_id") or actual.get("device_name") or "device"),
            checks=checks,
        )

    def verify_ui_element_state(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected_elements: Sequence[Mapping[str, Any]],
        actual_elements: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Verify UI element state using caller-provided element descriptions.

        Expected element example:
            {
                "id": "submit_button",
                "text": "Submit",
                "visible": true,
                "enabled": true
            }
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            findings: List[VerificationFinding] = []
            actual_by_id = {
                str(item.get("id") or item.get("selector") or item.get("text") or index): item
                for index, item in enumerate(actual_elements)
            }

            for expected in expected_elements:
                key = str(expected.get("id") or expected.get("selector") or expected.get("text") or "")
                actual = actual_by_id.get(key)
                exists = actual is not None

                findings.append(
                    VerificationFinding(
                        check_name=f"ui_element_exists:{key}",
                        status=VerificationStatus.PASSED if exists else VerificationStatus.FAILED,
                        message=f"UI element '{key}' exists." if exists else f"UI element '{key}' is missing.",
                        expected=expected,
                        actual=actual,
                        severity=Severity.HIGH if not exists else Severity.INFO,
                        confidence=0.9 if exists else 0.25,
                    )
                )

                if actual:
                    for attr in ("text", "visible", "enabled", "checked", "selected"):
                        if attr in expected:
                            passed = expected[attr] == actual.get(attr)
                            findings.append(
                                VerificationFinding(
                                    check_name=f"ui_element_{attr}:{key}",
                                    status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                                    message=(
                                        f"UI element '{key}' attribute '{attr}' matched."
                                        if passed
                                        else f"UI element '{key}' attribute '{attr}' did not match."
                                    ),
                                    expected=expected[attr],
                                    actual=actual.get(attr),
                                    severity=Severity.MEDIUM if not passed else Severity.INFO,
                                    confidence=0.85 if passed else 0.3,
                                )
                            )

            proof_items = [
                ProofItem(
                    proof_id=_safe_uuid("proof"),
                    proof_type="ui_element_state",
                    title="UI element verification state",
                    data={
                        "expected_elements": list(expected_elements),
                        "actual_elements": list(actual_elements),
                        "expected_count": len(expected_elements),
                        "actual_count": len(actual_elements),
                    },
                    created_at=_utc_now(),
                    confidence=self._calculate_confidence(findings),
                )
            ]

            report = self._build_report(
                context=ctx,
                verification_type=VerificationType.UI_ELEMENT,
                findings=findings,
                proof_items=proof_items,
                metadata={},
            )

            return self._safe_result(
                message=report.summary,
                data={"report": report.to_dict()},
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("UI element verification failed unexpectedly.", exc)

    def verify_action_replay(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected_steps: Sequence[Mapping[str, Any]],
        observed_steps: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Verify an action replay from logs/observations.

        This method compares provided step logs only. It does not replay actions on a
        live system/browser/device.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            findings: List[VerificationFinding] = []
            max_len = max(len(expected_steps), len(observed_steps))

            for index in range(max_len):
                expected = expected_steps[index] if index < len(expected_steps) else None
                observed = observed_steps[index] if index < len(observed_steps) else None

                if expected is None:
                    findings.append(
                        VerificationFinding(
                            check_name=f"unexpected_step_{index + 1}",
                            status=VerificationStatus.NEEDS_REVIEW,
                            message="Observed extra action step not present in expected replay.",
                            expected=None,
                            actual=observed,
                            severity=Severity.MEDIUM,
                            confidence=0.45,
                        )
                    )
                    continue

                if observed is None:
                    findings.append(
                        VerificationFinding(
                            check_name=f"missing_step_{index + 1}",
                            status=VerificationStatus.FAILED,
                            message="Expected action step was not observed.",
                            expected=expected,
                            actual=None,
                            severity=Severity.HIGH,
                            confidence=0.2,
                        )
                    )
                    continue

                expected_action = expected.get("action")
                observed_action = observed.get("action")
                passed = _normalize_string(expected_action) == _normalize_string(observed_action)

                findings.append(
                    VerificationFinding(
                        check_name=f"action_step_{index + 1}",
                        status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
                        message=(
                            f"Action step {index + 1} matched."
                            if passed
                            else f"Action step {index + 1} did not match."
                        ),
                        expected=expected,
                        actual=observed,
                        severity=Severity.HIGH if not passed else Severity.INFO,
                        confidence=0.85 if passed else 0.25,
                    )
                )

            proof_items = [
                ProofItem(
                    proof_id=_safe_uuid("proof"),
                    proof_type="action_replay",
                    title="Action replay verification",
                    data={
                        "expected_steps": list(expected_steps),
                        "observed_steps": list(observed_steps),
                        "expected_count": len(expected_steps),
                        "observed_count": len(observed_steps),
                    },
                    created_at=_utc_now(),
                    confidence=self._calculate_confidence(findings),
                )
            ]

            report = self._build_report(
                context=ctx,
                verification_type=VerificationType.ACTION_REPLAY,
                findings=findings,
                proof_items=proof_items,
                metadata={},
            )

            return self._safe_result(
                message=report.summary,
                data={"report": report.to_dict()},
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("Action replay verification failed unexpectedly.", exc)

    def _verify_state_domain(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        verification_type: VerificationType,
        domain_name: str,
        domain_label: str,
        checks: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Shared implementation for app/browser/device state verification."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            if self._requires_security_check(verification_type.value, {"expected": expected, "actual": actual}, ctx):
                approval = self._request_security_approval(
                    context=ctx,
                    action=f"verify_{domain_name}",
                    payload={"domain_label": domain_label},
                )
                if not approval.get("success"):
                    return approval

            validation = self.validate_result(
                context=ctx,
                expected=expected,
                actual=actual,
                checks=checks,
                verification_type=verification_type.value,
            )
            if not validation["success"]:
                return validation

            state_proof = ProofItem(
                proof_id=_safe_uuid("proof"),
                proof_type=domain_name,
                title=f"{domain_label} state observation",
                data={
                    "expected": dict(expected),
                    "actual": dict(actual),
                    "domain": domain_name,
                    "label": domain_label,
                },
                created_at=_utc_now(),
                confidence=validation["data"]["report"].get("confidence", 0.5),
            )

            report_data = validation["data"]["report"]
            report_data["proof_items"].append(state_proof.to_dict())
            report_data["metadata"]["domain_name"] = domain_name
            report_data["metadata"]["domain_label"] = domain_label

            return self._safe_result(
                message=report_data["summary"],
                data={
                    "report": report_data,
                    "state_proof": state_proof.to_dict(),
                },
                metadata={"agent": self.agent_name, "verification_type": verification_type.value},
            )
        except Exception as exc:
            return self._error_result(f"{domain_name} verification failed unexpectedly.", exc)

    # ----------------------------------------------------------------------------------
    # Proof and report handling
    # ----------------------------------------------------------------------------------

    def collect_proof(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        proof_inputs: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Normalize and collect proof items from provided proof inputs.

        This method does not capture screenshots itself. Screenshot checkers can later
        provide screenshot references, file metadata, hashes, or dashboard-safe URLs.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            proof_items: List[ProofItem] = []
            findings: List[VerificationFinding] = []

            if len(proof_inputs) > self.max_proof_items:
                findings.append(
                    VerificationFinding(
                        check_name="proof_count_limit",
                        status=VerificationStatus.PARTIAL,
                        message="Proof inputs exceeded max proof item limit; extra items were ignored.",
                        expected=f"<= {self.max_proof_items}",
                        actual=len(proof_inputs),
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                    )
                )

            for index, raw in enumerate(list(proof_inputs)[: self.max_proof_items]):
                proof_type = str(raw.get("proof_type") or raw.get("type") or "text")
                title = str(raw.get("title") or f"Proof item {index + 1}")
                data = raw.get("data", raw.get("value"))

                if proof_type not in self.allowed_proof_types:
                    findings.append(
                        VerificationFinding(
                            check_name=f"proof_type_allowed:{index + 1}",
                            status=VerificationStatus.NEEDS_REVIEW,
                            message=f"Proof type '{proof_type}' is not in allowed proof types.",
                            expected=sorted(self.allowed_proof_types),
                            actual=proof_type,
                            severity=Severity.MEDIUM,
                            confidence=0.35,
                        )
                    )
                    continue

                if proof_type in SENSITIVE_VERIFICATION_TYPES:
                    if self._requires_security_check(proof_type, {"proof": raw}, ctx):
                        approval = self._request_security_approval(
                            context=ctx,
                            action=f"collect_proof:{proof_type}",
                            payload={"title": title, "proof_type": proof_type},
                        )
                        if not approval.get("success"):
                            findings.append(
                                VerificationFinding(
                                    check_name=f"proof_security:{index + 1}",
                                    status=VerificationStatus.BLOCKED,
                                    message="Sensitive proof collection blocked by Security Agent.",
                                    expected="security approval",
                                    actual=approval.get("message"),
                                    severity=Severity.HIGH,
                                    confidence=0.9,
                                )
                            )
                            continue

                proof_items.append(
                    ProofItem(
                        proof_id=str(raw.get("proof_id") or _safe_uuid("proof")),
                        proof_type=proof_type,
                        title=title,
                        data=_json_safe(data),
                        created_at=str(raw.get("created_at") or _utc_now()),
                        source=str(raw.get("source") or AGENT_NAME),
                        confidence=float(raw.get("confidence", 1.0)),
                        metadata=dict(raw.get("metadata") or {}),
                    )
                )

            if not findings:
                findings.append(
                    VerificationFinding(
                        check_name="proof_collection",
                        status=VerificationStatus.PASSED,
                        message=f"Collected {len(proof_items)} proof item(s).",
                        confidence=0.95,
                    )
                )

            report = self._build_report(
                context=ctx,
                verification_type=VerificationType.PROOF_REPORT,
                findings=findings,
                proof_items=proof_items,
                metadata={"proof_input_count": len(proof_inputs)},
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "proof_items": [item.to_dict() for item in proof_items],
                    "findings": [finding.to_dict() for finding in findings],
                },
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("Proof collection failed unexpectedly.", exc)

    def generate_report(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
        verification_type: str,
        findings: Sequence[Union[VerificationFinding, Mapping[str, Any]]],
        proof_items: Optional[Sequence[Union[ProofItem, Mapping[str, Any]]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a structured verification report from findings and proof items."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            normalized_findings = [
                item if isinstance(item, VerificationFinding) else self._finding_from_dict(item)
                for item in findings
            ]
            normalized_proof = [
                item if isinstance(item, ProofItem) else self._proof_from_dict(item)
                for item in (proof_items or [])
            ]

            report = self._build_report(
                context=ctx,
                verification_type=self._verification_type_from_string(verification_type),
                findings=normalized_findings,
                proof_items=normalized_proof,
                metadata=dict(metadata or {}),
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "verification_payload": self._prepare_verification_payload(report, ctx),
                    "memory_payload": self._prepare_memory_payload(report, ctx),
                },
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result("Report generation failed unexpectedly.", exc)

    # ----------------------------------------------------------------------------------
    # Required compatibility hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[VerificationContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Every user-specific verification must include user_id and workspace_id.
        """
        try:
            if isinstance(context, VerificationContext):
                ctx = context.to_dict()
            elif isinstance(context, Mapping):
                ctx = dict(context)
            else:
                return self._error_result(
                    message="Invalid verification context.",
                    error="context must be VerificationContext or mapping",
                )

            user_id = ctx.get("user_id")
            workspace_id = ctx.get("workspace_id")

            if not _is_non_empty_string(user_id):
                return self._error_result(
                    message="Verification context missing user_id.",
                    error="missing_user_id",
                    metadata={"hook": "_validate_task_context"},
                )

            if not _is_non_empty_string(workspace_id):
                return self._error_result(
                    message="Verification context missing workspace_id.",
                    error="missing_workspace_id",
                    metadata={"hook": "_validate_task_context"},
                )

            ctx.setdefault("task_id", None)
            ctx.setdefault("request_id", _safe_uuid("req"))
            ctx.setdefault("session_id", None)
            ctx.setdefault("agent_name", self.agent_name)
            ctx.setdefault("permissions", {})
            ctx.setdefault("metadata", {})
            ctx["user_id"] = str(user_id)
            ctx["workspace_id"] = str(workspace_id)

            return self._safe_result(
                message="Verification context is valid.",
                data={"context": ctx},
                metadata={"hook": "_validate_task_context"},
            )
        except Exception as exc:
            return self._error_result("Context validation failed unexpectedly.", exc)

    def _requires_security_check(
        self,
        verification_type: str,
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a verification request requires Security Agent approval.

        Safe defaults:
            - Sensitive verification types require approval unless explicitly allowed.
            - Context permissions may include:
                allow_sensitive_verification: true
                allow_browser_verification: true
                allow_device_verification: true
                allow_app_verification: true
        """
        payload = payload or {}
        context = context or {}
        permissions = dict(context.get("permissions") or {})

        if permissions.get("allow_sensitive_verification") is True:
            return False

        vt = str(verification_type or "").lower()

        if vt in SENSITIVE_VERIFICATION_TYPES:
            specific_key = f"allow_{vt}_verification"
            if permissions.get(specific_key) is True:
                return False
            return True

        raw = json.dumps(_json_safe(payload), default=str).lower()
        if any(hint in raw for hint in PRIVATE_PATH_HINTS):
            return True

        return False

    def _request_security_approval(
        self,
        context: Mapping[str, Any],
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is connected:
            - Safe default is to block sensitive actions unless context permission
              allow_without_security_agent is true.
        """
        payload = dict(payload or {})
        permissions = dict(context.get("permissions") or {})

        if self.security_agent is None:
            if permissions.get("allow_without_security_agent") is True:
                return self._safe_result(
                    message="Security approval bypassed by explicit context permission.",
                    data={"approved": True, "source": "context_permission"},
                    metadata={"hook": "_request_security_approval", "action": action},
                )
            return self._error_result(
                message="Security approval required, but Security Agent is not connected.",
                error="security_agent_unavailable",
                metadata={
                    "hook": "_request_security_approval",
                    "action": action,
                    "blocked": True,
                },
            )

        try:
            if hasattr(self.security_agent, "approve_action"):
                decision = self.security_agent.approve_action(
                    user_id=context.get("user_id"),
                    workspace_id=context.get("workspace_id"),
                    action=action,
                    payload=payload,
                )
            elif hasattr(self.security_agent, "request_approval"):
                decision = self.security_agent.request_approval(
                    context=dict(context),
                    action=action,
                    payload=payload,
                )
            else:
                return self._error_result(
                    message="Connected Security Agent does not expose an approval method.",
                    error="security_agent_missing_approval_method",
                    metadata={"action": action},
                )

            if isinstance(decision, Mapping):
                approved = bool(
                    decision.get("approved")
                    or decision.get("success")
                    or decision.get("allow")
                    or decision.get("allowed")
                )
                if approved:
                    return self._safe_result(
                        message="Security Agent approved verification action.",
                        data={"approved": True, "decision": _json_safe(dict(decision))},
                        metadata={"hook": "_request_security_approval", "action": action},
                    )
                return self._error_result(
                    message="Security Agent blocked verification action.",
                    error=decision.get("error") or decision.get("reason") or "security_blocked",
                    metadata={"decision": _json_safe(dict(decision)), "action": action},
                )

            if bool(decision):
                return self._safe_result(
                    message="Security Agent approved verification action.",
                    data={"approved": True, "decision": bool(decision)},
                    metadata={"hook": "_request_security_approval", "action": action},
                )

            return self._error_result(
                message="Security Agent blocked verification action.",
                error="security_blocked",
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result("Security approval request failed.", exc)

    def _prepare_verification_payload(
        self,
        report: Union[VerificationReport, Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent payload for downstream routing/dashboard/API."""
        report_data = report.to_dict() if isinstance(report, VerificationReport) else dict(report)
        ctx = dict(context or report_data.get("context") or {})
        return {
            "agent": self.agent_name,
            "type": "verification_payload",
            "version": self.agent_version,
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "task_id": ctx.get("task_id"),
            "request_id": ctx.get("request_id"),
            "status": report_data.get("status"),
            "confidence": report_data.get("confidence"),
            "report_id": report_data.get("report_id"),
            "summary": report_data.get("summary"),
            "findings_count": len(report_data.get("findings") or []),
            "proof_count": len(report_data.get("proof_items") or []),
            "created_at": _utc_now(),
            "data": {
                "report": report_data,
            },
        }

    def _prepare_memory_payload(
        self,
        report: Union[VerificationReport, Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        It intentionally stores summaries and metadata, not raw sensitive proof data.
        """
        report_data = report.to_dict() if isinstance(report, VerificationReport) else dict(report)
        ctx = dict(context or report_data.get("context") or {})
        safe_findings = []
        for item in report_data.get("findings", [])[:10]:
            safe_findings.append(
                {
                    "check_name": item.get("check_name"),
                    "status": item.get("status"),
                    "message": item.get("message"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                }
            )

        return {
            "agent": self.agent_name,
            "type": "verification_memory",
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "task_id": ctx.get("task_id"),
            "memory_scope": "workspace",
            "importance": self._memory_importance_from_status(str(report_data.get("status"))),
            "summary": report_data.get("summary"),
            "facts": {
                "report_id": report_data.get("report_id"),
                "status": report_data.get("status"),
                "confidence": report_data.get("confidence"),
                "verification_type": report_data.get("verification_type"),
                "findings": safe_findings,
            },
            "created_at": _utc_now(),
            "metadata": {
                "source_agent": self.agent_name,
                "raw_proof_excluded": True,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Emit an agent event if an event bus/emitter exists."""
        try:
            safe_payload = _json_safe(payload)
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return
            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.debug("Agent event: %s %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit agent event '%s': %s", event_name, exc)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """Log audit event using configured logger or fallback."""
        try:
            safe_payload = _json_safe(payload)
            if self.audit_logger:
                self.audit_logger(safe_payload)
                return
            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.info("AUDIT %s", json.dumps(safe_payload, default=str))
        except Exception as exc:
            self.logger.warning("Failed to log audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized success result."""
        return {
            "success": True,
            "message": message,
            "data": _json_safe(data or {}),
            "error": None,
            "metadata": _json_safe(
                {
                    "agent": self.agent_name,
                    "agent_version": self.agent_version,
                    "timestamp": _utc_now(),
                    **(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized error result."""
        if isinstance(error, BaseException):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": _json_safe(data or {}),
            "error": _json_safe(error_payload),
            "metadata": _json_safe(
                {
                    "agent": self.agent_name,
                    "agent_version": self.agent_version,
                    "timestamp": _utc_now(),
                    **(metadata or {}),
                }
            ),
        }

    # ----------------------------------------------------------------------------------
    # Internal utilities
    # ----------------------------------------------------------------------------------

    def _load_default_config(self) -> Any:
        """Load config class if available; otherwise use lightweight fallback object."""
        if VerificationConfig is not None:
            try:
                return VerificationConfig()
            except Exception:
                pass

        class _FallbackConfig:
            max_proof_items = DEFAULT_MAX_PROOF_ITEMS
            max_file_read_bytes = DEFAULT_MAX_FILE_READ_BYTES
            default_confidence_threshold = DEFAULT_CONFIDENCE_THRESHOLD
            allowed_proof_types = DEFAULT_ALLOWED_PROOF_TYPES

        return _FallbackConfig()

    def _build_report(
        self,
        context: Mapping[str, Any],
        verification_type: VerificationType,
        findings: Sequence[VerificationFinding],
        proof_items: Sequence[ProofItem],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> VerificationReport:
        """Create a VerificationReport from findings/proof."""
        normalized_findings = list(findings)
        normalized_proof = list(proof_items)
        status = self._calculate_status(normalized_findings)
        confidence = self._calculate_confidence(normalized_findings)
        summary = self._build_summary(status, verification_type, normalized_findings, confidence)

        return VerificationReport(
            report_id=_safe_uuid("report"),
            status=status,
            summary=summary,
            verification_type=verification_type,
            findings=normalized_findings,
            proof_items=normalized_proof,
            confidence=confidence,
            created_at=_utc_now(),
            context=dict(context),
            metadata=dict(metadata or {}),
        )

    def _calculate_status(self, findings: Sequence[VerificationFinding]) -> VerificationStatus:
        """Calculate overall status from findings."""
        if not findings:
            return VerificationStatus.NEEDS_REVIEW

        statuses = [item.status for item in findings]

        if any(status == VerificationStatus.ERROR for status in statuses):
            return VerificationStatus.ERROR
        if any(status == VerificationStatus.BLOCKED for status in statuses):
            return VerificationStatus.BLOCKED
        if any(status == VerificationStatus.FAILED for status in statuses):
            passed_count = sum(1 for status in statuses if status == VerificationStatus.PASSED)
            return VerificationStatus.PARTIAL if passed_count else VerificationStatus.FAILED
        if any(status == VerificationStatus.NEEDS_REVIEW for status in statuses):
            passed_count = sum(1 for status in statuses if status == VerificationStatus.PASSED)
            return VerificationStatus.PARTIAL if passed_count else VerificationStatus.NEEDS_REVIEW
        if all(status == VerificationStatus.SKIPPED for status in statuses):
            return VerificationStatus.SKIPPED
        if all(status == VerificationStatus.PASSED for status in statuses):
            return VerificationStatus.PASSED
        return VerificationStatus.PARTIAL

    def _calculate_confidence(self, findings: Sequence[VerificationFinding]) -> float:
        """Calculate weighted confidence from findings."""
        if not findings:
            return 0.0

        severity_weight = {
            Severity.INFO: 1.0,
            Severity.LOW: 1.1,
            Severity.MEDIUM: 1.3,
            Severity.HIGH: 1.6,
            Severity.CRITICAL: 2.0,
        }
        total_weight = 0.0
        weighted_score = 0.0

        for finding in findings:
            weight = severity_weight.get(finding.severity, 1.0)
            total_weight += weight
            weighted_score += max(0.0, min(1.0, float(finding.confidence))) * weight

        return round(weighted_score / total_weight, 4) if total_weight else 0.0

    def _build_summary(
        self,
        status: VerificationStatus,
        verification_type: VerificationType,
        findings: Sequence[VerificationFinding],
        confidence: float,
    ) -> str:
        """Build human-readable report summary."""
        total = len(findings)
        passed = sum(1 for item in findings if item.status == VerificationStatus.PASSED)
        failed = sum(1 for item in findings if item.status == VerificationStatus.FAILED)
        review = sum(1 for item in findings if item.status == VerificationStatus.NEEDS_REVIEW)
        blocked = sum(1 for item in findings if item.status == VerificationStatus.BLOCKED)
        errors = sum(1 for item in findings if item.status == VerificationStatus.ERROR)

        return (
            f"{verification_type.value} verification {status.value}. "
            f"Checks: {passed}/{total} passed, {failed} failed, "
            f"{review} need review, {blocked} blocked, {errors} errors. "
            f"Confidence: {confidence:.2f}."
        )

    def _checks_from_expected(self, expected: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """Create basic equality checks from expected top-level keys."""
        checks: List[Dict[str, Any]] = []
        for key, value in expected.items():
            checks.append(
                {
                    "name": f"expected_{key}",
                    "path": str(key),
                    "expected": value,
                    "mode": "equals",
                    "required": True,
                    "severity": "medium",
                }
            )
        return checks

    def _finding_from_dict(self, item: Mapping[str, Any]) -> VerificationFinding:
        """Normalize mapping into VerificationFinding."""
        return VerificationFinding(
            check_name=str(item.get("check_name") or item.get("name") or "unnamed_check"),
            status=self._status_from_string(str(item.get("status") or VerificationStatus.NEEDS_REVIEW.value)),
            message=str(item.get("message") or ""),
            severity=self._severity_from_string(str(item.get("severity") or Severity.INFO.value)),
            expected=item.get("expected"),
            actual=item.get("actual"),
            confidence=float(item.get("confidence", 0.5)),
            evidence=dict(item.get("evidence") or {}),
            remediation=item.get("remediation"),
        )

    def _proof_from_dict(self, item: Mapping[str, Any]) -> ProofItem:
        """Normalize mapping into ProofItem."""
        return ProofItem(
            proof_id=str(item.get("proof_id") or _safe_uuid("proof")),
            proof_type=str(item.get("proof_type") or item.get("type") or "text"),
            title=str(item.get("title") or "Proof item"),
            data=item.get("data"),
            created_at=str(item.get("created_at") or _utc_now()),
            source=str(item.get("source") or self.agent_name),
            confidence=float(item.get("confidence", 1.0)),
            metadata=dict(item.get("metadata") or {}),
        )

    def _status_from_string(self, value: str) -> VerificationStatus:
        """Parse status string safely."""
        normalized = _normalize_string(value)
        for status in VerificationStatus:
            if status.value == normalized:
                return status
        return VerificationStatus.NEEDS_REVIEW

    def _severity_from_string(self, value: str) -> Severity:
        """Parse severity string safely."""
        normalized = _normalize_string(value)
        for severity in Severity:
            if severity.value == normalized:
                return severity
        return Severity.INFO

    def _verification_type_from_string(self, value: str) -> VerificationType:
        """Parse verification type safely."""
        normalized = _normalize_string(value)
        for item in VerificationType:
            if item.value == normalized:
                return item
        return VerificationType.RESULT

    def _memory_importance_from_status(self, status: str) -> str:
        """Map verification status to memory importance."""
        normalized = _normalize_string(status)
        if normalized in {"failed", "blocked", "error"}:
            return "high"
        if normalized in {"partial", "needs_review"}:
            return "medium"
        return "low"

    def _redact_sensitive_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Best-effort redaction for sensitive fields before audit/memory/event use."""
        sensitive_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "session",
            "credential",
            "private_key",
        }

        def redact(value: Any) -> Any:
            if isinstance(value, Mapping):
                cleaned: Dict[str, Any] = {}
                for key, item in value.items():
                    key_text = str(key).lower()
                    if any(sensitive in key_text for sensitive in sensitive_keys):
                        cleaned[str(key)] = "[REDACTED]"
                    else:
                        cleaned[str(key)] = redact(item)
                return cleaned
            if isinstance(value, list):
                return [redact(item) for item in value]
            if isinstance(value, tuple):
                return tuple(redact(item) for item in value)
            return value

        return redact(payload)

    def _detect_potential_execution_patterns(self, code: str) -> List[Dict[str, Any]]:
        """
        Static best-effort detection for patterns that may execute system/destructive actions.

        This is not a security scanner. It only helps Verification Agent flag code that
        deserves manual review.
        """
        patterns = {
            "os.system": r"\bos\.system\s*\(",
            "subprocess": r"\bsubprocess\.",
            "eval": r"\beval\s*\(",
            "exec": r"\bexec\s*\(",
            "shell_true": r"shell\s*=\s*True",
            "shutil.rmtree": r"\bshutil\.rmtree\s*\(",
            "unlink": r"\.unlink\s*\(",
            "remove": r"\bos\.remove\s*\(",
            "rmdir": r"\bos\.rmdir\s*\(",
            "network_request": r"\b(requests|urllib|httpx)\.",
        }

        findings: List[Dict[str, Any]] = []
        for name, pattern in patterns.items():
            for match in re.finditer(pattern, code):
                line = code.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "pattern": name,
                        "line": line,
                        "match": match.group(0),
                    }
                )

        return findings[:DEFAULT_MAX_DIFF_ITEMS]


# ======================================================================================
# Module-level factory for Agent Loader / Registry compatibility
# ======================================================================================

def create_agent(*args: Any, **kwargs: Any) -> VerificationAgent:
    """Factory used by future Agent Loader/Registry."""
    return VerificationAgent(*args, **kwargs)


def get_agent_class() -> type:
    """Return the agent class for registry discovery."""
    return VerificationAgent


__all__ = [
    "VerificationAgent",
    "VerificationStatus",
    "VerificationType",
    "Severity",
    "VerificationFinding",
    "ProofItem",
    "VerificationContext",
    "VerificationReport",
    "create_agent",
    "get_agent_class",
]


# ======================================================================================
# Completion tracking
# ======================================================================================
#
# Agent/Module: Verification Agent
# File Completed: verification_agent.py
# Completion: 5.9%
# Completed Files: ['verification_agent.py']
# Remaining Files: ['state_checker.py', 'screenshot_checker.py', 'result_validator.py', 'app_state_checker.py', 'file_state_checker.py', 'browser_state_checker.py', 'code_state_checker.py', 'device_state_checker.py', 'ui_element_checker.py', 'action_replay_checker.py', 'error_detector.py', 'proof_collector.py', 'retry_manager.py', 'report_generator.py', 'verification_memory.py', 'config.py']
# Next Recommended File: agents/verification_agent/state_checker.py
# FILE COMPLETE