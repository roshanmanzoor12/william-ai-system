"""
agents/verification_agent/error_detector.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix
Verification Agent Helper: Error Detector

Purpose:
    Detects app crashes, HTTP 404/500 errors, permission denied failures,
    timeouts, build failures, runtime exceptions, dependency failures, and
    other actionable error signals from logs, command outputs, HTTP responses,
    browser/app state payloads, and verification snapshots.

Architecture Notes:
    - Import-safe even when future William/Jarvis modules are not available.
    - Compatible with BaseAgent-style construction where available.
    - Uses SaaS isolation through required user_id/workspace_id task context.
    - Does not execute destructive/system/browser/network actions directly.
    - Emits structured verification, memory, audit, and dashboard-friendly payloads.
    - Designed to be called by Verification Agent, Master Agent, Agent Router,
      Dashboard/API endpoints, workflow runners, or retry/report helpers.

Public Class:
    VerificationErrorDetector
"""

from __future__ import annotations

import re
import time
import uuid
import logging
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated imports
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent can replace this without changing this file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name)
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from core.audit.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


try:
    from core.events.event_bus import EventBus  # type: ignore
except Exception:  # pragma: no cover
    EventBus = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

UTC = timezone.utc


class ErrorCategory(str, Enum):
    """High-level error categories used by Verification Agent and dashboard."""

    APP_CRASH = "app_crash"
    HTTP_CLIENT_ERROR = "http_client_error"
    HTTP_SERVER_ERROR = "http_server_error"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    BUILD_FAILURE = "build_failure"
    TEST_FAILURE = "test_failure"
    RUNTIME_EXCEPTION = "runtime_exception"
    DEPENDENCY_ERROR = "dependency_error"
    NETWORK_ERROR = "network_error"
    DATABASE_ERROR = "database_error"
    CONFIGURATION_ERROR = "configuration_error"
    AUTHENTICATION_ERROR = "authentication_error"
    RATE_LIMIT_ERROR = "rate_limit_error"
    RESOURCE_ERROR = "resource_error"
    UNKNOWN_ERROR = "unknown_error"


class ErrorSeverity(str, Enum):
    """Severity values suitable for API, dashboard, and report_generator."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorStatus(str, Enum):
    """Detector status for a single finding or aggregate result."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    INCONCLUSIVE = "inconclusive"


DEFAULT_AGENT_NAME = "VerificationErrorDetector"
DEFAULT_CONFIDENCE_THRESHOLD = 0.55
MAX_TEXT_CHARS_DEFAULT = 250_000
MAX_EVIDENCE_SNIPPET_CHARS = 700
MAX_FINDINGS_DEFAULT = 100


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ErrorPattern:
    """
    A compiled semantic error pattern.

    Attributes:
        name: Stable internal pattern name.
        category: Error category produced when matched.
        severity: Default severity for this pattern.
        regex: Case-insensitive regex pattern.
        confidence: Base confidence score for this pattern.
        description: Human-readable explanation.
        remediation_hint: Optional suggested repair direction.
    """

    name: str
    category: ErrorCategory
    severity: ErrorSeverity
    regex: str
    confidence: float
    description: str
    remediation_hint: str = ""


@dataclass
class ErrorFinding:
    """
    A single detected error finding.

    This is intentionally simple and JSON-serializable through to_dict().
    """

    finding_id: str
    category: str
    severity: str
    status: str
    confidence: float
    source: str
    pattern_name: str
    message: str
    evidence: str
    line_number: Optional[int] = None
    status_code: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    remediation_hint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe dict."""
        return asdict(self)


@dataclass
class ErrorDetectorConfig:
    """
    Runtime configuration for VerificationErrorDetector.

    This file does not require external config to import. A future
    agents/verification_agent/config.py can pass values into this dataclass.
    """

    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    max_text_chars: int = MAX_TEXT_CHARS_DEFAULT
    max_findings: int = MAX_FINDINGS_DEFAULT
    include_low_confidence: bool = False
    enable_audit_logging: bool = True
    enable_event_emit: bool = True
    require_user_workspace: bool = True
    detect_warnings_as_low: bool = False
    redact_sensitive_values: bool = True
    event_namespace: str = "verification.error_detector"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    """Safely convert any value to string."""
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert any value to float."""
    try:
        return float(value)
    except Exception:
        return default


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Clamp a float to a range."""
    return max(minimum, min(maximum, value))


def _normalize_source_name(source: Optional[str]) -> str:
    """Return a stable source name for findings."""
    source_text = _safe_str(source, "unknown").strip()
    return source_text or "unknown"


def _truncate_text(text: str, max_chars: int) -> str:
    """Truncate large text input to keep detection bounded and API-safe."""
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def _line_number_for_index(text: str, index: int) -> int:
    """Calculate 1-based line number for a character index."""
    if index <= 0:
        return 1
    return text.count("\n", 0, index) + 1


def _extract_line(text: str, index: int) -> str:
    """Extract the full line containing index."""
    start = text.rfind("\n", 0, index)
    end = text.find("\n", index)
    if start == -1:
        start = 0
    else:
        start += 1
    if end == -1:
        end = len(text)
    return text[start:end].strip()


def _snippet_around(text: str, start: int, end: int, window: int = 260) -> str:
    """Extract compact evidence around a regex match."""
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right].strip()
    if len(snippet) > MAX_EVIDENCE_SNIPPET_CHARS:
        snippet = snippet[:MAX_EVIDENCE_SNIPPET_CHARS].rstrip() + "..."
    return snippet


def _dedupe_key(finding: ErrorFinding) -> Tuple[str, str, str, Optional[int], Optional[int]]:
    """Stable duplicate key for error findings."""
    return (
        finding.category,
        finding.pattern_name,
        finding.source,
        finding.line_number,
        finding.status_code,
    )


def _looks_like_secret(token: str) -> bool:
    """Heuristic for token-like sensitive values."""
    if len(token) < 16:
        return False
    if re.fullmatch(r"[A-Za-z0-9_\-]{24,}", token):
        return True
    if re.fullmatch(r"[a-fA-F0-9]{32,}", token):
        return True
    return False


def _redact_text(text: str) -> str:
    """
    Redact common secrets from logs and evidence snippets.

    This avoids leaking tokens, credentials, cookies, and authorization headers
    into dashboard, memory, report, or audit payloads.
    """
    if not text:
        return text

    redacted = text

    redaction_patterns = [
        (r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(secret[_-]?key\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(access[_-]?token\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(refresh[_-]?token\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(password\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(passwd\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(cookie\s*:\s*)[^\n\r]+", r"\1[REDACTED]"),
        (r"(?i)(set-cookie\s*:\s*)[^\n\r]+", r"\1[REDACTED]"),
    ]

    for pattern, replacement in redaction_patterns:
        redacted = re.sub(pattern, replacement, redacted)

    words = redacted.split()
    safe_words = []
    for word in words:
        clean = word.strip(" ,;:'\"()[]{}")
        if _looks_like_secret(clean):
            safe_words.append(word.replace(clean, "[REDACTED]"))
        else:
            safe_words.append(word)

    return " ".join(safe_words)


def _json_safe(value: Any) -> Any:
    """
    Convert values to JSON-safe objects.

    The dashboard/API can serialize these results without custom encoders.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _json_safe(value.to_dict())
    if hasattr(value, "__dict__"):
        return _json_safe(vars(value))
    return _safe_str(value)


# ---------------------------------------------------------------------------
# Default detection patterns
# ---------------------------------------------------------------------------

DEFAULT_ERROR_PATTERNS: Tuple[ErrorPattern, ...] = (
    # App/runtime crash patterns
    ErrorPattern(
        name="process_crashed",
        category=ErrorCategory.APP_CRASH,
        severity=ErrorSeverity.CRITICAL,
        regex=r"\b(process|application|app|service)\s+(crashed|terminated unexpectedly|has stopped|stopped working|exited unexpectedly)\b",
        confidence=0.92,
        description="Application or service crash detected.",
        remediation_hint="Inspect crash stack trace, recent deployment changes, memory usage, and service restart logs.",
    ),
    ErrorPattern(
        name="segmentation_fault",
        category=ErrorCategory.APP_CRASH,
        severity=ErrorSeverity.CRITICAL,
        regex=r"\b(segmentation fault|sigsegv|fatal signal 11|access violation)\b",
        confidence=0.95,
        description="Native crash or memory access violation detected.",
        remediation_hint="Check native dependencies, C/C++ extensions, driver compatibility, and memory corruption sources.",
    ),
    ErrorPattern(
        name="uncaught_exception",
        category=ErrorCategory.RUNTIME_EXCEPTION,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(uncaught exception|unhandled exception|fatal exception|traceback \(most recent call last\))\b",
        confidence=0.9,
        description="Unhandled runtime exception detected.",
        remediation_hint="Review stack trace, add defensive handling, and fix the root exception.",
    ),
    ErrorPattern(
        name="python_exception",
        category=ErrorCategory.RUNTIME_EXCEPTION,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(ValueError|TypeError|KeyError|IndexError|AttributeError|RuntimeError|ImportError|ModuleNotFoundError|NameError|SyntaxError|IndentationError|RecursionError):\s+.+",
        confidence=0.86,
        description="Python exception detected.",
        remediation_hint="Fix the exception source shown in the stack trace and add tests around the failing path.",
    ),
    ErrorPattern(
        name="javascript_exception",
        category=ErrorCategory.RUNTIME_EXCEPTION,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(TypeError|ReferenceError|SyntaxError|RangeError|UnhandledPromiseRejection|Cannot read properties of undefined|is not a function)\b",
        confidence=0.84,
        description="JavaScript runtime exception detected.",
        remediation_hint="Inspect browser console/build logs, validate null checks, imports, and async promise handling.",
    ),

    # HTTP status patterns
    ErrorPattern(
        name="http_404",
        category=ErrorCategory.HTTP_CLIENT_ERROR,
        severity=ErrorSeverity.MEDIUM,
        regex=r"\b(404|HTTP\s*/?\s*1(?:\.1|\.0|\.x)?\s+404|status(?:_code)?\s*[=:]\s*404|not found)\b",
        confidence=0.8,
        description="HTTP 404 Not Found detected.",
        remediation_hint="Verify route path, endpoint registration, static file path, deployment rewrite rules, and resource existence.",
    ),
    ErrorPattern(
        name="http_403",
        category=ErrorCategory.PERMISSION_DENIED,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(403|HTTP\s*/?\s*1(?:\.1|\.0|\.x)?\s+403|forbidden|permission denied|access denied|operation not permitted)\b",
        confidence=0.86,
        description="Permission denied or HTTP 403 detected.",
        remediation_hint="Check user/workspace permissions, role policy, file permissions, API scopes, and Security Agent approval.",
    ),
    ErrorPattern(
        name="http_401",
        category=ErrorCategory.AUTHENTICATION_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(401|HTTP\s*/?\s*1(?:\.1|\.0|\.x)?\s+401|unauthorized|invalid token|token expired|authentication failed|not authenticated)\b",
        confidence=0.86,
        description="Authentication failure detected.",
        remediation_hint="Refresh credentials safely, verify auth middleware, token expiry, session state, and identity provider configuration.",
    ),
    ErrorPattern(
        name="http_429",
        category=ErrorCategory.RATE_LIMIT_ERROR,
        severity=ErrorSeverity.MEDIUM,
        regex=r"\b(429|too many requests|rate limit exceeded|quota exceeded|throttled)\b",
        confidence=0.86,
        description="Rate limit or quota failure detected.",
        remediation_hint="Add backoff, reduce request volume, verify quotas, and coordinate retry policy with Retry Manager.",
    ),
    ErrorPattern(
        name="http_500",
        category=ErrorCategory.HTTP_SERVER_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(500|HTTP\s*/?\s*1(?:\.1|\.0|\.x)?\s+500|internal server error)\b",
        confidence=0.84,
        description="HTTP 500 Internal Server Error detected.",
        remediation_hint="Inspect server logs, recent code changes, dependency health, database state, and exception traces.",
    ),
    ErrorPattern(
        name="http_502_503_504",
        category=ErrorCategory.HTTP_SERVER_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(502|503|504|bad gateway|service unavailable|gateway timeout)\b",
        confidence=0.84,
        description="Gateway/service availability HTTP error detected.",
        remediation_hint="Check upstream service health, reverse proxy configuration, load balancer routing, and timeout settings.",
    ),

    # Timeout/network
    ErrorPattern(
        name="timeout",
        category=ErrorCategory.TIMEOUT,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(timed out|timeout|request timeout|deadline exceeded|read timeout|connect timeout|execution exceeded|operation took too long)\b",
        confidence=0.86,
        description="Timeout detected.",
        remediation_hint="Check service latency, network connectivity, retry/backoff policy, worker limits, and long-running task boundaries.",
    ),
    ErrorPattern(
        name="network_connection_error",
        category=ErrorCategory.NETWORK_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(connection refused|connection reset|connection aborted|network unreachable|dns lookup failed|getaddrinfo failed|temporary failure in name resolution|ssl error|certificate verify failed)\b",
        confidence=0.86,
        description="Network or connection failure detected.",
        remediation_hint="Verify host, port, DNS, TLS certificates, firewall, proxy, and service availability.",
    ),

    # Build/test/dependency
    ErrorPattern(
        name="build_failed",
        category=ErrorCategory.BUILD_FAILURE,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(build failed|failed to build|compilation failed|compile error|webpack.*failed|vite.*error|npm ERR!|yarn error|gradle build failed|maven.*failure)\b",
        confidence=0.88,
        description="Build failure detected.",
        remediation_hint="Review compiler output, dependency versions, lock files, environment variables, and build scripts.",
    ),
    ErrorPattern(
        name="test_failed",
        category=ErrorCategory.TEST_FAILURE,
        severity=ErrorSeverity.MEDIUM,
        regex=r"\b(test failed|tests failed|assertionerror|failed assertions|pytest.*failed|jest.*failed|unit test failure|integration test failure)\b",
        confidence=0.84,
        description="Test failure detected.",
        remediation_hint="Open failing test details, compare expected vs actual values, and fix either code or test expectation.",
    ),
    ErrorPattern(
        name="dependency_missing",
        category=ErrorCategory.DEPENDENCY_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(module not found|cannot find module|no module named|package .* not found|dependency .* missing|missing dependency|could not resolve dependency|import could not be resolved)\b",
        confidence=0.88,
        description="Missing or unresolved dependency detected.",
        remediation_hint="Install or pin the dependency, verify virtual environment, package manager cache, and import path.",
    ),

    # Database/config/resource
    ErrorPattern(
        name="database_error",
        category=ErrorCategory.DATABASE_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(database error|db error|sql error|sqlite error|postgres error|mysql error|connection pool exhausted|deadlock detected|relation .* does not exist|table .* does not exist)\b",
        confidence=0.84,
        description="Database error detected.",
        remediation_hint="Check database connectivity, migrations, schema state, connection pool, locks, and query syntax.",
    ),
    ErrorPattern(
        name="configuration_error",
        category=ErrorCategory.CONFIGURATION_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(configuration error|config error|missing config|invalid config|environment variable .* not set|required setting .* missing|settings validation failed)\b",
        confidence=0.84,
        description="Configuration error detected.",
        remediation_hint="Verify environment variables, config files, secrets manager references, and safe defaults.",
    ),
    ErrorPattern(
        name="resource_error",
        category=ErrorCategory.RESOURCE_ERROR,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(out of memory|oom|memoryerror|disk full|no space left on device|too many open files|resource temporarily unavailable|cpu limit exceeded)\b",
        confidence=0.9,
        description="System resource failure detected.",
        remediation_hint="Check memory, disk, file descriptors, worker concurrency, and resource limits.",
    ),
    ErrorPattern(
        name="permission_denied_filesystem",
        category=ErrorCategory.PERMISSION_DENIED,
        severity=ErrorSeverity.HIGH,
        regex=r"\b(permission denied|access is denied|eacces|eperm|operation not permitted|read-only file system)\b",
        confidence=0.88,
        description="Filesystem or OS permission error detected.",
        remediation_hint="Check least-privilege permissions, workspace isolation paths, file owner/group, and Security Agent policy.",
    ),
)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VerificationErrorDetector(BaseAgent):
    """
    Detects error signals from text, logs, command outputs, HTTP responses,
    structured state payloads, and exception objects.

    How it connects:
        - Master Agent / Agent Router:
            Can call public methods like detect_errors(), detect_from_http_response(),
            detect_from_command_result(), or detect_from_exception().
        - Verification Agent:
            Consumes findings to determine whether a task failed and why.
        - Security Agent:
            _requires_security_check() and _request_security_approval() are provided
            so sensitive contexts can be protected before processing or reporting.
        - Memory Agent:
            _prepare_memory_payload() creates compact safe context for future task
            learning without leaking secrets.
        - Dashboard/API:
            _safe_result() and _error_result() return predictable dict structures.
        - Registry/Loader:
            Class name and constructor are stable; file is import-safe.
    """

    agent_type = "verification_agent_helper"
    capability = "error_detection"
    public_methods = (
        "detect_errors",
        "detect_from_text",
        "detect_from_logs",
        "detect_from_http_response",
        "detect_from_command_result",
        "detect_from_exception",
        "detect_from_state_payload",
        "has_blocking_error",
        "summarize_findings",
    )

    def __init__(
        self,
        config: Optional[Union[ErrorDetectorConfig, Mapping[str, Any]]] = None,
        security_agent: Any = None,
        audit_logger: Any = None,
        event_bus: Any = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the detector with safe optional integrations.

        Args:
            config: ErrorDetectorConfig or dict override.
            security_agent: Optional Security Agent instance.
            audit_logger: Optional audit logger.
            event_bus: Optional event emitter/bus.
            logger: Optional logger.
            **kwargs: Forward-compatible BaseAgent kwargs.
        """
        try:
            super().__init__(agent_name=DEFAULT_AGENT_NAME, **kwargs)
        except TypeError:
            try:
                super().__init__(**kwargs)
            except Exception:
                BaseAgent.__init__(self, agent_name=DEFAULT_AGENT_NAME)

        self.config = self._coerce_config(config)
        self.security_agent = security_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.logger = logger or getattr(self, "logger", logging.getLogger(DEFAULT_AGENT_NAME))
        self._compiled_patterns = self._compile_patterns(DEFAULT_ERROR_PATTERNS)

    # ------------------------------------------------------------------
    # Public detection methods
    # ------------------------------------------------------------------

    def detect_errors(
        self,
        task_context: Mapping[str, Any],
        *,
        text: Optional[str] = None,
        logs: Optional[Union[str, Sequence[str]]] = None,
        http_response: Optional[Mapping[str, Any]] = None,
        command_result: Optional[Mapping[str, Any]] = None,
        exception: Optional[BaseException] = None,
        state_payload: Optional[Mapping[str, Any]] = None,
        source: str = "mixed",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect all supported error types from mixed inputs.

        Args:
            task_context: Must include user_id and workspace_id when user-specific.
            text: Raw text or output.
            logs: Single log string or sequence of log lines.
            http_response: HTTP response-like dict.
            command_result: Command result dict with stdout/stderr/returncode.
            exception: Python exception object.
            state_payload: Structured app/browser/code/device verification state.
            source: Logical source name.
            metadata: Additional caller metadata.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)
        safe_metadata = dict(metadata or {})

        if self._requires_security_check(task_context, operation="detect_errors"):
            approval = self._request_security_approval(
                task_context,
                operation="detect_errors",
                metadata=safe_metadata,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for error detection.",
                    code="security_approval_denied",
                    data={"approved": False, "reason": approval.get("reason")},
                    metadata=self._base_metadata(task_context, request_id, started_at),
                )

        all_findings: List[ErrorFinding] = []

        try:
            if text is not None:
                result = self.detect_from_text(
                    task_context,
                    text=text,
                    source=source,
                    metadata=safe_metadata,
                )
                all_findings.extend(self._findings_from_result(result))

            if logs is not None:
                result = self.detect_from_logs(
                    task_context,
                    logs=logs,
                    source="logs",
                    metadata=safe_metadata,
                )
                all_findings.extend(self._findings_from_result(result))

            if http_response is not None:
                result = self.detect_from_http_response(
                    task_context,
                    http_response=http_response,
                    metadata=safe_metadata,
                )
                all_findings.extend(self._findings_from_result(result))

            if command_result is not None:
                result = self.detect_from_command_result(
                    task_context,
                    command_result=command_result,
                    metadata=safe_metadata,
                )
                all_findings.extend(self._findings_from_result(result))

            if exception is not None:
                result = self.detect_from_exception(
                    task_context,
                    exception=exception,
                    metadata=safe_metadata,
                )
                all_findings.extend(self._findings_from_result(result))

            if state_payload is not None:
                result = self.detect_from_state_payload(
                    task_context,
                    state_payload=state_payload,
                    metadata=safe_metadata,
                )
                all_findings.extend(self._findings_from_result(result))

            findings = self._dedupe_findings(all_findings)
            findings = self._sort_findings(findings)[: self.config.max_findings]
            summary = self.summarize_findings(findings)

            verification_payload = self._prepare_verification_payload(
                task_context,
                findings=findings,
                summary=summary,
                source=source,
            )
            memory_payload = self._prepare_memory_payload(
                task_context,
                findings=findings,
                summary=summary,
            )

            blocking = self.has_blocking_error(findings)
            message = (
                f"Detected {len(findings)} error finding(s)."
                if findings
                else "No matching error signals detected."
            )

            result = self._safe_result(
                success=True,
                message=message,
                data={
                    "status": ErrorStatus.DETECTED.value if findings else ErrorStatus.NOT_DETECTED.value,
                    "blocking_error": blocking,
                    "finding_count": len(findings),
                    "findings": [finding.to_dict() for finding in findings],
                    "summary": summary,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

            self._emit_agent_event(
                "errors_detected" if findings else "no_errors_detected",
                task_context,
                data={
                    "finding_count": len(findings),
                    "blocking_error": blocking,
                    "summary": summary,
                },
            )
            self._log_audit_event(
                task_context,
                action="detect_errors",
                outcome="success",
                data={"finding_count": len(findings), "blocking_error": blocking},
            )
            return result

        except Exception as exc:
            self.logger.exception("Error detection failed.")
            return self._error_result(
                message="Error detector failed while analyzing input.",
                code="error_detector_failure",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def detect_from_text(
        self,
        task_context: Mapping[str, Any],
        *,
        text: str,
        source: str = "text",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect errors from raw text, logs, terminal output, console output,
        browser console messages, or API response text.
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            clean_text = _safe_str(text)
            clean_text = _truncate_text(clean_text, self.config.max_text_chars)
            findings = self._scan_text_for_patterns(
                clean_text,
                source=_normalize_source_name(source),
                metadata=dict(metadata or {}),
            )
            findings = self._filter_findings(findings)
            findings = self._dedupe_findings(findings)
            findings = self._sort_findings(findings)[: self.config.max_findings]
            summary = self.summarize_findings(findings)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(findings)} error finding(s) from text."
                    if findings
                    else "No error signals detected from text."
                ),
                data={
                    "status": ErrorStatus.DETECTED.value if findings else ErrorStatus.NOT_DETECTED.value,
                    "finding_count": len(findings),
                    "findings": [finding.to_dict() for finding in findings],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to detect errors from text.",
                code="text_detection_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def detect_from_logs(
        self,
        task_context: Mapping[str, Any],
        *,
        logs: Union[str, Sequence[str]],
        source: str = "logs",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect errors from log content.

        Args:
            logs: A single string or a list/tuple of log lines.
        """
        if isinstance(logs, str):
            text = logs
        else:
            text = "\n".join(_safe_str(line) for line in logs)

        return self.detect_from_text(
            task_context,
            text=text,
            source=source,
            metadata=metadata,
        )

    def detect_from_http_response(
        self,
        task_context: Mapping[str, Any],
        *,
        http_response: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect HTTP errors from a response-like dict.

        Supported keys:
            status_code, code, status, url, method, reason, text, body, error,
            headers, elapsed_ms, timeout, ok
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)
        findings: List[ErrorFinding] = []

        try:
            status_code = self._extract_status_code(http_response)
            url = _safe_str(http_response.get("url", ""))
            method = _safe_str(http_response.get("method", ""))
            reason = _safe_str(http_response.get("reason", ""))
            body = _safe_str(
                http_response.get("text")
                or http_response.get("body")
                or http_response.get("response")
                or http_response.get("error")
                or ""
            )
            source = "http_response"
            response_metadata = {
                "url": url,
                "method": method,
                "reason": reason,
                "elapsed_ms": http_response.get("elapsed_ms"),
                "ok": http_response.get("ok"),
                **dict(metadata or {}),
            }

            if status_code is not None:
                finding = self._finding_from_status_code(
                    status_code=status_code,
                    source=source,
                    body=body,
                    metadata=response_metadata,
                )
                if finding is not None:
                    findings.append(finding)

            timeout_flag = bool(http_response.get("timeout", False))
            if timeout_flag:
                findings.append(
                    self._make_finding(
                        category=ErrorCategory.TIMEOUT,
                        severity=ErrorSeverity.HIGH,
                        confidence=0.92,
                        source=source,
                        pattern_name="http_timeout_flag",
                        message="HTTP request timeout detected.",
                        evidence=body or reason or f"{method} {url}".strip(),
                        status_code=status_code,
                        remediation_hint="Check endpoint latency, network path, timeout configuration, and retry policy.",
                        metadata=response_metadata,
                    )
                )

            if body:
                body_findings = self._scan_text_for_patterns(
                    body,
                    source=source,
                    metadata=response_metadata,
                )
                findings.extend(body_findings)

            findings = self._filter_findings(findings)
            findings = self._dedupe_findings(findings)
            findings = self._sort_findings(findings)[: self.config.max_findings]
            summary = self.summarize_findings(findings)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(findings)} HTTP error finding(s)."
                    if findings
                    else "No HTTP error detected."
                ),
                data={
                    "status": ErrorStatus.DETECTED.value if findings else ErrorStatus.NOT_DETECTED.value,
                    "status_code": status_code,
                    "finding_count": len(findings),
                    "findings": [finding.to_dict() for finding in findings],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to detect errors from HTTP response.",
                code="http_detection_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def detect_from_command_result(
        self,
        task_context: Mapping[str, Any],
        *,
        command_result: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect errors from command/build/test result payload.

        Supported keys:
            command, returncode, exit_code, stdout, stderr, output, duration_ms,
            timed_out, success
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)
        findings: List[ErrorFinding] = []

        try:
            command = _safe_str(command_result.get("command", ""))
            returncode = command_result.get("returncode", command_result.get("exit_code"))
            stdout = _safe_str(command_result.get("stdout", ""))
            stderr = _safe_str(command_result.get("stderr", ""))
            output = _safe_str(command_result.get("output", ""))
            timed_out = bool(command_result.get("timed_out", False))
            success = command_result.get("success")

            combined_text = "\n".join(part for part in [stdout, stderr, output] if part)
            source = "command_result"
            command_metadata = {
                "command": command,
                "returncode": returncode,
                "duration_ms": command_result.get("duration_ms"),
                "timed_out": timed_out,
                "reported_success": success,
                **dict(metadata or {}),
            }

            if timed_out:
                findings.append(
                    self._make_finding(
                        category=ErrorCategory.TIMEOUT,
                        severity=ErrorSeverity.HIGH,
                        confidence=0.94,
                        source=source,
                        pattern_name="command_timed_out",
                        message="Command execution timed out.",
                        evidence=combined_text or command,
                        remediation_hint="Increase timeout only if safe, optimize command, inspect blocking IO, and coordinate retry policy.",
                        metadata=command_metadata,
                    )
                )

            numeric_returncode = self._safe_int(returncode)
            if numeric_returncode is not None and numeric_returncode != 0:
                inferred_category = self._infer_command_failure_category(command, combined_text)
                findings.append(
                    self._make_finding(
                        category=inferred_category,
                        severity=ErrorSeverity.HIGH if inferred_category != ErrorCategory.TEST_FAILURE else ErrorSeverity.MEDIUM,
                        confidence=0.82,
                        source=source,
                        pattern_name="non_zero_exit_code",
                        message=f"Command failed with non-zero exit code {numeric_returncode}.",
                        evidence=combined_text or command,
                        remediation_hint=self._remediation_for_category(inferred_category),
                        metadata=command_metadata,
                    )
                )

            if combined_text:
                findings.extend(
                    self._scan_text_for_patterns(
                        combined_text,
                        source=source,
                        metadata=command_metadata,
                    )
                )

            findings = self._filter_findings(findings)
            findings = self._dedupe_findings(findings)
            findings = self._sort_findings(findings)[: self.config.max_findings]
            summary = self.summarize_findings(findings)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(findings)} command/build error finding(s)."
                    if findings
                    else "No command/build error detected."
                ),
                data={
                    "status": ErrorStatus.DETECTED.value if findings else ErrorStatus.NOT_DETECTED.value,
                    "returncode": numeric_returncode,
                    "finding_count": len(findings),
                    "findings": [finding.to_dict() for finding in findings],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to detect errors from command result.",
                code="command_detection_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def detect_from_exception(
        self,
        task_context: Mapping[str, Any],
        *,
        exception: BaseException,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect and structure a Python exception as an error finding.

        This does not re-raise the exception.
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            exc_type = exception.__class__.__name__
            exc_message = _safe_str(exception)
            tb = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
            category = self._category_for_exception(exception)
            severity = self._severity_for_exception(exception, category)
            evidence = tb or f"{exc_type}: {exc_message}"

            finding = self._make_finding(
                category=category,
                severity=severity,
                confidence=0.93,
                source="exception",
                pattern_name=f"exception_{exc_type}",
                message=f"{exc_type}: {exc_message}" if exc_message else exc_type,
                evidence=evidence,
                remediation_hint=self._remediation_for_category(category),
                metadata={
                    "exception_type": exc_type,
                    **dict(metadata or {}),
                },
            )

            findings = self._filter_findings([finding])
            summary = self.summarize_findings(findings)

            return self._safe_result(
                success=True,
                message="Detected exception error finding.",
                data={
                    "status": ErrorStatus.DETECTED.value,
                    "finding_count": len(findings),
                    "findings": [item.to_dict() for item in findings],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to detect errors from exception.",
                code="exception_detection_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def detect_from_state_payload(
        self,
        task_context: Mapping[str, Any],
        *,
        state_payload: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect errors from structured app/browser/code/device state payload.

        Useful with:
            app_state_checker.py
            browser_state_checker.py
            code_state_checker.py
            device_state_checker.py
            action_replay_checker.py
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)
        findings: List[ErrorFinding] = []

        try:
            source = _safe_str(state_payload.get("source", "state_payload"))
            state_metadata = {
                "state_type": state_payload.get("state_type"),
                "checker": state_payload.get("checker"),
                **dict(metadata or {}),
            }

            text_parts: List[str] = []
            for key in (
                "message",
                "error",
                "reason",
                "status",
                "details",
                "stdout",
                "stderr",
                "logs",
                "console",
                "traceback",
                "build_output",
                "test_output",
                "page_text",
                "response_text",
            ):
                value = state_payload.get(key)
                if isinstance(value, str):
                    text_parts.append(value)
                elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
                    text_parts.extend(_safe_str(item) for item in value)

            status_code = self._extract_status_code(state_payload)
            if status_code is not None:
                status_finding = self._finding_from_status_code(
                    status_code=status_code,
                    source=source,
                    body="\n".join(text_parts),
                    metadata=state_metadata,
                )
                if status_finding is not None:
                    findings.append(status_finding)

            crash_flags = (
                "crashed",
                "app_crashed",
                "process_crashed",
                "browser_crashed",
                "service_crashed",
            )
            if any(bool(state_payload.get(flag, False)) for flag in crash_flags):
                findings.append(
                    self._make_finding(
                        category=ErrorCategory.APP_CRASH,
                        severity=ErrorSeverity.CRITICAL,
                        confidence=0.94,
                        source=source,
                        pattern_name="state_crash_flag",
                        message="State payload indicates app/process/browser crash.",
                        evidence="\n".join(text_parts) or _safe_str(state_payload),
                        remediation_hint=self._remediation_for_category(ErrorCategory.APP_CRASH),
                        metadata=state_metadata,
                    )
                )

            timeout_flags = ("timed_out", "timeout", "deadline_exceeded")
            if any(bool(state_payload.get(flag, False)) for flag in timeout_flags):
                findings.append(
                    self._make_finding(
                        category=ErrorCategory.TIMEOUT,
                        severity=ErrorSeverity.HIGH,
                        confidence=0.92,
                        source=source,
                        pattern_name="state_timeout_flag",
                        message="State payload indicates timeout.",
                        evidence="\n".join(text_parts) or _safe_str(state_payload),
                        remediation_hint=self._remediation_for_category(ErrorCategory.TIMEOUT),
                        metadata=state_metadata,
                    )
                )

            permission_flags = ("permission_denied", "access_denied", "forbidden")
            if any(bool(state_payload.get(flag, False)) for flag in permission_flags):
                findings.append(
                    self._make_finding(
                        category=ErrorCategory.PERMISSION_DENIED,
                        severity=ErrorSeverity.HIGH,
                        confidence=0.92,
                        source=source,
                        pattern_name="state_permission_flag",
                        message="State payload indicates permission denied.",
                        evidence="\n".join(text_parts) or _safe_str(state_payload),
                        remediation_hint=self._remediation_for_category(ErrorCategory.PERMISSION_DENIED),
                        metadata=state_metadata,
                    )
                )

            build_flags = ("build_failed", "compile_failed", "tests_failed", "test_failed")
            if any(bool(state_payload.get(flag, False)) for flag in build_flags):
                category = (
                    ErrorCategory.TEST_FAILURE
                    if bool(state_payload.get("tests_failed") or state_payload.get("test_failed"))
                    else ErrorCategory.BUILD_FAILURE
                )
                findings.append(
                    self._make_finding(
                        category=category,
                        severity=ErrorSeverity.HIGH if category == ErrorCategory.BUILD_FAILURE else ErrorSeverity.MEDIUM,
                        confidence=0.9,
                        source=source,
                        pattern_name="state_build_or_test_flag",
                        message=f"State payload indicates {category.value.replace('_', ' ')}.",
                        evidence="\n".join(text_parts) or _safe_str(state_payload),
                        remediation_hint=self._remediation_for_category(category),
                        metadata=state_metadata,
                    )
                )

            combined_text = "\n".join(text_parts)
            if combined_text:
                findings.extend(
                    self._scan_text_for_patterns(
                        combined_text,
                        source=source,
                        metadata=state_metadata,
                    )
                )

            findings = self._filter_findings(findings)
            findings = self._dedupe_findings(findings)
            findings = self._sort_findings(findings)[: self.config.max_findings]
            summary = self.summarize_findings(findings)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(findings)} state error finding(s)."
                    if findings
                    else "No state error detected."
                ),
                data={
                    "status": ErrorStatus.DETECTED.value if findings else ErrorStatus.NOT_DETECTED.value,
                    "finding_count": len(findings),
                    "findings": [finding.to_dict() for finding in findings],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to detect errors from state payload.",
                code="state_detection_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def has_blocking_error(
        self,
        findings: Union[Sequence[ErrorFinding], Sequence[Mapping[str, Any]], Mapping[str, Any]],
        *,
        min_severity: ErrorSeverity = ErrorSeverity.HIGH,
    ) -> bool:
        """
        Return True when findings contain a blocking error.

        Blocking by default:
            - critical or high severity
            - app crash
            - server error
            - permission denied
            - timeout
            - build failure
            - runtime exception
        """
        normalized = self._normalize_findings_input(findings)
        severity_rank = {
            ErrorSeverity.INFO.value: 0,
            ErrorSeverity.LOW.value: 1,
            ErrorSeverity.MEDIUM.value: 2,
            ErrorSeverity.HIGH.value: 3,
            ErrorSeverity.CRITICAL.value: 4,
        }
        min_rank = severity_rank.get(min_severity.value, 3)

        blocking_categories = {
            ErrorCategory.APP_CRASH.value,
            ErrorCategory.HTTP_SERVER_ERROR.value,
            ErrorCategory.PERMISSION_DENIED.value,
            ErrorCategory.TIMEOUT.value,
            ErrorCategory.BUILD_FAILURE.value,
            ErrorCategory.RUNTIME_EXCEPTION.value,
            ErrorCategory.AUTHENTICATION_ERROR.value,
            ErrorCategory.DATABASE_ERROR.value,
            ErrorCategory.RESOURCE_ERROR.value,
        }

        for finding in normalized:
            severity = _safe_str(finding.get("severity", ""))
            category = _safe_str(finding.get("category", ""))
            status = _safe_str(finding.get("status", ""))
            if status and status != ErrorStatus.DETECTED.value:
                continue
            if severity_rank.get(severity, 0) >= min_rank:
                return True
            if category in blocking_categories:
                return True
        return False

    def summarize_findings(
        self,
        findings: Union[Sequence[ErrorFinding], Sequence[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build dashboard/report-friendly summary for findings.
        """
        normalized = self._normalize_findings_input(findings)
        by_category: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        top_messages: List[str] = []
        highest_severity = ErrorSeverity.INFO.value
        highest_rank = 0

        severity_rank = {
            ErrorSeverity.INFO.value: 0,
            ErrorSeverity.LOW.value: 1,
            ErrorSeverity.MEDIUM.value: 2,
            ErrorSeverity.HIGH.value: 3,
            ErrorSeverity.CRITICAL.value: 4,
        }

        for finding in normalized:
            category = _safe_str(finding.get("category", ErrorCategory.UNKNOWN_ERROR.value))
            severity = _safe_str(finding.get("severity", ErrorSeverity.INFO.value))
            message = _safe_str(finding.get("message", ""))

            by_category[category] = by_category.get(category, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

            rank = severity_rank.get(severity, 0)
            if rank > highest_rank:
                highest_rank = rank
                highest_severity = severity

            if message and message not in top_messages and len(top_messages) < 5:
                top_messages.append(message)

        return {
            "total": len(normalized),
            "blocking_error": self.has_blocking_error(normalized),
            "highest_severity": highest_severity if normalized else None,
            "by_category": by_category,
            "by_severity": by_severity,
            "top_messages": top_messages,
            "generated_at": _utc_now_iso(),
        }

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required for user-specific execution:
            - user_id
            - workspace_id

        Other useful optional keys:
            - task_id
            - request_id
            - role
            - permissions
            - agent_route
        """
        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="task_context must be a mapping/dict.",
                code="invalid_task_context",
                data={"required": ["user_id", "workspace_id"]},
            )

        user_id = _safe_str(task_context.get("user_id", "")).strip()
        workspace_id = _safe_str(task_context.get("workspace_id", "")).strip()

        if self.config.require_user_workspace:
            missing = []
            if not user_id:
                missing.append("user_id")
            if not workspace_id:
                missing.append("workspace_id")
            if missing:
                return self._error_result(
                    message="Missing required SaaS isolation context.",
                    code="missing_saas_context",
                    data={"missing": missing, "required": ["user_id", "workspace_id"]},
                    metadata={
                        "agent": DEFAULT_AGENT_NAME,
                        "timestamp": _utc_now_iso(),
                    },
                )

        return self._safe_result(
            success=True,
            message="Task context is valid.",
            data={
                "user_id": user_id or None,
                "workspace_id": workspace_id or None,
                "task_id": task_context.get("task_id"),
            },
            metadata={
                "agent": DEFAULT_AGENT_NAME,
                "timestamp": _utc_now_iso(),
            },
        )

    def _requires_security_check(
        self,
        task_context: Mapping[str, Any],
        *,
        operation: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is required.

        Error detection is read-only. However, approval is required when caller
        marks the context as sensitive or when metadata indicates private logs.
        """
        sensitive_flags = (
            task_context.get("requires_security_check"),
            task_context.get("sensitive"),
            task_context.get("contains_credentials"),
            task_context.get("private_logs"),
        )
        if any(bool(flag) for flag in sensitive_flags):
            return True

        if metadata:
            metadata_flags = (
                metadata.get("requires_security_check"),
                metadata.get("sensitive"),
                metadata.get("contains_credentials"),
                metadata.get("private_logs"),
            )
            if any(bool(flag) for flag in metadata_flags):
                return True

        return False

    def _request_security_approval(
        self,
        task_context: Mapping[str, Any],
        *,
        operation: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Safe fallback approves read-only error detection while preserving
        auditability. Future Security Agent can enforce stricter policy.
        """
        security_agent = self.security_agent

        if security_agent is not None:
            for method_name in ("approve_action", "request_approval", "validate_action", "authorize"):
                method = getattr(security_agent, method_name, None)
                if callable(method):
                    try:
                        response = method(
                            user_id=task_context.get("user_id"),
                            workspace_id=task_context.get("workspace_id"),
                            operation=operation,
                            agent=DEFAULT_AGENT_NAME,
                            metadata=dict(metadata or {}),
                        )
                        if isinstance(response, Mapping):
                            approved = bool(
                                response.get("approved", response.get("success", False))
                            )
                            return {
                                "approved": approved,
                                "reason": response.get("reason") or response.get("message"),
                                "raw": _json_safe(response),
                            }
                        return {"approved": bool(response), "reason": None}
                    except TypeError:
                        try:
                            response = method(task_context, operation, dict(metadata or {}))
                            if isinstance(response, Mapping):
                                return {
                                    "approved": bool(response.get("approved", response.get("success", False))),
                                    "reason": response.get("reason") or response.get("message"),
                                    "raw": _json_safe(response),
                                }
                            return {"approved": bool(response), "reason": None}
                        except Exception as exc:
                            return {
                                "approved": False,
                                "reason": f"Security approval method failed: {exc}",
                            }
                    except Exception as exc:
                        return {
                            "approved": False,
                            "reason": f"Security approval failed: {exc}",
                        }

        return {
            "approved": True,
            "reason": "Read-only detection approved by safe fallback policy.",
            "fallback": True,
        }

    def _prepare_verification_payload(
        self,
        task_context: Mapping[str, Any],
        *,
        findings: Sequence[ErrorFinding],
        summary: Mapping[str, Any],
        source: str,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent result confirmation.

        This can be attached to task history, action replay, report_generator,
        retry_manager, or dashboard state.
        """
        return {
            "payload_type": "verification_error_detection",
            "agent": DEFAULT_AGENT_NAME,
            "source": source,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "status": ErrorStatus.DETECTED.value if findings else ErrorStatus.NOT_DETECTED.value,
            "success": not self.has_blocking_error(findings),
            "blocking_error": self.has_blocking_error(findings),
            "finding_count": len(findings),
            "summary": _json_safe(summary),
            "findings": [finding.to_dict() for finding in findings],
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        task_context: Mapping[str, Any],
        *,
        findings: Sequence[ErrorFinding],
        summary: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare compact memory-compatible payload.

        Memory Agent should store only useful non-secret context. Evidence is
        intentionally shortened and redacted.
        """
        compact_findings = []
        for finding in findings[:10]:
            compact_findings.append(
                {
                    "category": finding.category,
                    "severity": finding.severity,
                    "message": finding.message,
                    "source": finding.source,
                    "pattern_name": finding.pattern_name,
                    "remediation_hint": finding.remediation_hint,
                    "confidence": finding.confidence,
                }
            )

        return {
            "payload_type": "verification_error_memory",
            "agent": DEFAULT_AGENT_NAME,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "should_store": bool(findings),
            "memory_scope": "workspace",
            "summary": _json_safe(summary),
            "findings": compact_findings,
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        task_context: Mapping[str, Any],
        *,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/router-friendly event if event bus exists.

        This method is intentionally non-throwing.
        """
        if not self.config.enable_event_emit:
            return

        payload = {
            "event": f"{self.config.event_namespace}.{event_name}",
            "agent": DEFAULT_AGENT_NAME,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "data": _json_safe(dict(data or {})),
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in ("emit", "publish", "send"):
                    method = getattr(self.event_bus, method_name, None)
                    if callable(method):
                        method(payload["event"], payload)
                        return

            self.logger.debug("Agent event: %s", payload)
        except Exception:
            self.logger.debug("Failed to emit agent event.", exc_info=True)

    def _log_audit_event(
        self,
        task_context: Mapping[str, Any],
        *,
        action: str,
        outcome: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Write audit event if audit logger exists.

        This supports SaaS compliance without making this file depend on a
        specific audit implementation.
        """
        if not self.config.enable_audit_logging:
            return

        payload = {
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "outcome": outcome,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "data": _json_safe(dict(data or {})),
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in ("log", "write", "record", "emit"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        method(payload)
                        return

            self.logger.debug("Audit event: %s", payload)
        except Exception:
            self.logger.debug("Failed to log audit event.", exc_info=True)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard William/Jarvis structured result.
        """
        return {
            "success": bool(success),
            "message": _safe_str(message),
            "data": _json_safe(dict(data or {})),
            "error": _json_safe(error) if error else None,
            "metadata": _json_safe(dict(metadata or {})),
        }

    def _error_result(
        self,
        *,
        message: str,
        code: str = "error",
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.
        """
        error_payload: Dict[str, Any] = {
            "code": code,
            "message": _safe_str(message),
        }

        if error is not None:
            error_payload.update(
                {
                    "type": error.__class__.__name__,
                    "details": _safe_str(error),
                }
            )

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error_payload,
            metadata=metadata or {
                "agent": DEFAULT_AGENT_NAME,
                "timestamp": _utc_now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Internal scanning and finding helpers
    # ------------------------------------------------------------------

    def _coerce_config(
        self,
        config: Optional[Union[ErrorDetectorConfig, Mapping[str, Any]]],
    ) -> ErrorDetectorConfig:
        """Convert config input to ErrorDetectorConfig."""
        if config is None:
            return ErrorDetectorConfig()
        if isinstance(config, ErrorDetectorConfig):
            return config
        if isinstance(config, Mapping):
            allowed = set(ErrorDetectorConfig.__dataclass_fields__.keys())
            values = {key: value for key, value in config.items() if key in allowed}
            return ErrorDetectorConfig(**values)
        return ErrorDetectorConfig()

    def _compile_patterns(
        self,
        patterns: Iterable[ErrorPattern],
    ) -> List[Tuple[ErrorPattern, re.Pattern[str]]]:
        """Compile regex patterns safely."""
        compiled: List[Tuple[ErrorPattern, re.Pattern[str]]] = []
        for pattern in patterns:
            try:
                compiled.append((pattern, re.compile(pattern.regex, re.IGNORECASE | re.MULTILINE)))
            except re.error:
                self.logger.warning("Invalid error regex skipped: %s", pattern.name, exc_info=True)
        return compiled

    def _scan_text_for_patterns(
        self,
        text: str,
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[ErrorFinding]:
        """Scan text using default compiled patterns."""
        if not text:
            return []

        text = _truncate_text(text, self.config.max_text_chars)
        findings: List[ErrorFinding] = []

        for pattern, compiled in self._compiled_patterns:
            for match in compiled.finditer(text):
                evidence = _snippet_around(text, match.start(), match.end())
                line_text = _extract_line(text, match.start())
                line_number = _line_number_for_index(text, match.start())

                message = pattern.description
                if line_text:
                    message = f"{pattern.description} Line: {line_text[:180]}"

                finding = self._make_finding(
                    category=pattern.category,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    source=source,
                    pattern_name=pattern.name,
                    message=message,
                    evidence=evidence,
                    line_number=line_number,
                    remediation_hint=pattern.remediation_hint,
                    metadata=dict(metadata or {}),
                )
                findings.append(finding)

                if len(findings) >= self.config.max_findings:
                    return findings

        if self.config.detect_warnings_as_low:
            findings.extend(self._scan_warnings(text, source=source, metadata=metadata))

        return findings

    def _scan_warnings(
        self,
        text: str,
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[ErrorFinding]:
        """Optionally scan warnings as low-severity findings."""
        findings: List[ErrorFinding] = []
        warning_regex = re.compile(r"\b(warning|deprecated|deprecationwarning)\b[:\s].+", re.IGNORECASE)
        for match in warning_regex.finditer(text):
            evidence = _snippet_around(text, match.start(), match.end())
            findings.append(
                self._make_finding(
                    category=ErrorCategory.UNKNOWN_ERROR,
                    severity=ErrorSeverity.LOW,
                    confidence=0.45,
                    source=source,
                    pattern_name="warning",
                    message="Warning detected.",
                    evidence=evidence,
                    line_number=_line_number_for_index(text, match.start()),
                    remediation_hint="Review warning and decide whether it should be fixed before production.",
                    metadata=dict(metadata or {}),
                )
            )
            if len(findings) >= self.config.max_findings:
                break
        return findings

    def _make_finding(
        self,
        *,
        category: ErrorCategory,
        severity: ErrorSeverity,
        confidence: float,
        source: str,
        pattern_name: str,
        message: str,
        evidence: str,
        line_number: Optional[int] = None,
        status_code: Optional[int] = None,
        remediation_hint: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ErrorFinding:
        """Create a sanitized finding."""
        safe_evidence = _safe_str(evidence)
        safe_message = _safe_str(message)

        if self.config.redact_sensitive_values:
            safe_evidence = _redact_text(safe_evidence)
            safe_message = _redact_text(safe_message)

        if len(safe_evidence) > MAX_EVIDENCE_SNIPPET_CHARS:
            safe_evidence = safe_evidence[:MAX_EVIDENCE_SNIPPET_CHARS].rstrip() + "..."

        return ErrorFinding(
            finding_id=str(uuid.uuid4()),
            category=category.value,
            severity=severity.value,
            status=ErrorStatus.DETECTED.value,
            confidence=_clamp(confidence),
            source=_normalize_source_name(source),
            pattern_name=_safe_str(pattern_name, "unknown_pattern"),
            message=safe_message,
            evidence=safe_evidence,
            line_number=line_number,
            status_code=status_code,
            remediation_hint=_safe_str(remediation_hint),
            metadata=_json_safe(dict(metadata or {})),
        )

    def _filter_findings(self, findings: Sequence[ErrorFinding]) -> List[ErrorFinding]:
        """Apply confidence filtering."""
        filtered: List[ErrorFinding] = []
        for finding in findings:
            if self.config.include_low_confidence:
                filtered.append(finding)
            elif finding.confidence >= self.config.confidence_threshold:
                filtered.append(finding)
        return filtered

    def _dedupe_findings(self, findings: Sequence[ErrorFinding]) -> List[ErrorFinding]:
        """Remove duplicate findings while keeping highest confidence evidence."""
        best_by_key: Dict[Tuple[str, str, str, Optional[int], Optional[int]], ErrorFinding] = {}
        for finding in findings:
            key = _dedupe_key(finding)
            existing = best_by_key.get(key)
            if existing is None or finding.confidence > existing.confidence:
                best_by_key[key] = finding
        return list(best_by_key.values())

    def _sort_findings(self, findings: Sequence[ErrorFinding]) -> List[ErrorFinding]:
        """Sort findings by severity and confidence."""
        severity_rank = {
            ErrorSeverity.CRITICAL.value: 5,
            ErrorSeverity.HIGH.value: 4,
            ErrorSeverity.MEDIUM.value: 3,
            ErrorSeverity.LOW.value: 2,
            ErrorSeverity.INFO.value: 1,
        }
        return sorted(
            findings,
            key=lambda item: (
                severity_rank.get(item.severity, 0),
                item.confidence,
                item.timestamp,
            ),
            reverse=True,
        )

    def _findings_from_result(self, result: Mapping[str, Any]) -> List[ErrorFinding]:
        """Extract ErrorFinding objects from structured result."""
        findings_data = (
            result.get("data", {}).get("findings", [])
            if isinstance(result.get("data"), Mapping)
            else []
        )
        findings: List[ErrorFinding] = []
        for item in findings_data:
            if isinstance(item, ErrorFinding):
                findings.append(item)
            elif isinstance(item, Mapping):
                try:
                    findings.append(
                        ErrorFinding(
                            finding_id=_safe_str(item.get("finding_id") or uuid.uuid4()),
                            category=_safe_str(item.get("category", ErrorCategory.UNKNOWN_ERROR.value)),
                            severity=_safe_str(item.get("severity", ErrorSeverity.INFO.value)),
                            status=_safe_str(item.get("status", ErrorStatus.DETECTED.value)),
                            confidence=_safe_float(item.get("confidence", 0.0)),
                            source=_safe_str(item.get("source", "unknown")),
                            pattern_name=_safe_str(item.get("pattern_name", "unknown_pattern")),
                            message=_safe_str(item.get("message", "")),
                            evidence=_safe_str(item.get("evidence", "")),
                            line_number=item.get("line_number"),
                            status_code=item.get("status_code"),
                            timestamp=_safe_str(item.get("timestamp", _utc_now_iso())),
                            remediation_hint=_safe_str(item.get("remediation_hint", "")),
                            metadata=dict(item.get("metadata", {}) or {}),
                        )
                    )
                except Exception:
                    self.logger.debug("Skipped malformed finding item.", exc_info=True)
        return findings

    def _normalize_findings_input(
        self,
        findings: Union[Sequence[ErrorFinding], Sequence[Mapping[str, Any]], Mapping[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Normalize findings or result dict to list of finding dicts."""
        if isinstance(findings, Mapping):
            if "data" in findings and isinstance(findings.get("data"), Mapping):
                raw = findings.get("data", {}).get("findings", [])
            elif "findings" in findings:
                raw = findings.get("findings", [])
            else:
                raw = [findings]
        else:
            raw = findings

        normalized: List[Dict[str, Any]] = []
        for item in raw:
            if isinstance(item, ErrorFinding):
                normalized.append(item.to_dict())
            elif isinstance(item, Mapping):
                normalized.append(dict(item))
        return normalized

    # ------------------------------------------------------------------
    # HTTP / command / exception inference helpers
    # ------------------------------------------------------------------

    def _extract_status_code(self, payload: Mapping[str, Any]) -> Optional[int]:
        """Extract HTTP-like status code from dict."""
        for key in ("status_code", "code", "status", "http_status"):
            value = payload.get(key)
            code = self._safe_int(value)
            if code is not None and 100 <= code <= 599:
                return code
        return None

    def _safe_int(self, value: Any) -> Optional[int]:
        """Safely parse int."""
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        try:
            return int(value)
        except Exception:
            text = _safe_str(value)
            match = re.search(r"\b([1-5][0-9]{2})\b", text)
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    return None
        return None

    def _finding_from_status_code(
        self,
        *,
        status_code: int,
        source: str,
        body: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Optional[ErrorFinding]:
        """Create finding for HTTP status code if it indicates error."""
        if status_code < 400:
            return None

        if status_code == 401:
            category = ErrorCategory.AUTHENTICATION_ERROR
            severity = ErrorSeverity.HIGH
            message = "HTTP 401 Unauthorized detected."
        elif status_code in (403,):
            category = ErrorCategory.PERMISSION_DENIED
            severity = ErrorSeverity.HIGH
            message = "HTTP 403 Forbidden / permission denied detected."
        elif status_code == 404:
            category = ErrorCategory.HTTP_CLIENT_ERROR
            severity = ErrorSeverity.MEDIUM
            message = "HTTP 404 Not Found detected."
        elif status_code == 408:
            category = ErrorCategory.TIMEOUT
            severity = ErrorSeverity.HIGH
            message = "HTTP 408 Request Timeout detected."
        elif status_code == 429:
            category = ErrorCategory.RATE_LIMIT_ERROR
            severity = ErrorSeverity.MEDIUM
            message = "HTTP 429 Rate Limit detected."
        elif 400 <= status_code <= 499:
            category = ErrorCategory.HTTP_CLIENT_ERROR
            severity = ErrorSeverity.MEDIUM
            message = f"HTTP client error {status_code} detected."
        elif 500 <= status_code <= 599:
            category = ErrorCategory.HTTP_SERVER_ERROR
            severity = ErrorSeverity.HIGH
            message = f"HTTP server error {status_code} detected."
        else:
            return None

        return self._make_finding(
            category=category,
            severity=severity,
            confidence=0.9,
            source=source,
            pattern_name=f"http_status_{status_code}",
            message=message,
            evidence=body or message,
            status_code=status_code,
            remediation_hint=self._remediation_for_category(category),
            metadata=dict(metadata or {}),
        )

    def _infer_command_failure_category(self, command: str, output: str) -> ErrorCategory:
        """Infer category from command name/output."""
        text = f"{command}\n{output}".lower()

        if any(token in text for token in ("pytest", "jest", "test", "unittest", "assertion")):
            return ErrorCategory.TEST_FAILURE
        if any(token in text for token in ("build", "webpack", "vite", "npm", "yarn", "gradle", "maven", "compile")):
            return ErrorCategory.BUILD_FAILURE
        if any(token in text for token in ("permission denied", "access denied", "eacces", "eperm")):
            return ErrorCategory.PERMISSION_DENIED
        if any(token in text for token in ("timeout", "timed out", "deadline exceeded")):
            return ErrorCategory.TIMEOUT
        if any(token in text for token in ("module not found", "no module named", "dependency")):
            return ErrorCategory.DEPENDENCY_ERROR
        return ErrorCategory.RUNTIME_EXCEPTION

    def _category_for_exception(self, exception: BaseException) -> ErrorCategory:
        """Map Python exception type to category."""
        name = exception.__class__.__name__.lower()
        text = _safe_str(exception).lower()

        if "timeout" in name or "timed out" in text or "deadline" in text:
            return ErrorCategory.TIMEOUT
        if "permission" in name or "permission denied" in text or "access denied" in text:
            return ErrorCategory.PERMISSION_DENIED
        if "connection" in name or "network" in name or "dns" in text:
            return ErrorCategory.NETWORK_ERROR
        if "import" in name or "module" in name:
            return ErrorCategory.DEPENDENCY_ERROR
        if "memory" in name or "no space left" in text:
            return ErrorCategory.RESOURCE_ERROR
        if "auth" in name or "unauthorized" in text or "token" in text:
            return ErrorCategory.AUTHENTICATION_ERROR
        if "database" in name or "sql" in name:
            return ErrorCategory.DATABASE_ERROR
        if "config" in name or "setting" in text:
            return ErrorCategory.CONFIGURATION_ERROR
        return ErrorCategory.RUNTIME_EXCEPTION

    def _severity_for_exception(
        self,
        exception: BaseException,
        category: ErrorCategory,
    ) -> ErrorSeverity:
        """Map exception category/type to severity."""
        if category in {
            ErrorCategory.APP_CRASH,
            ErrorCategory.RESOURCE_ERROR,
        }:
            return ErrorSeverity.CRITICAL
        if category in {
            ErrorCategory.RUNTIME_EXCEPTION,
            ErrorCategory.TIMEOUT,
            ErrorCategory.PERMISSION_DENIED,
            ErrorCategory.AUTHENTICATION_ERROR,
            ErrorCategory.DATABASE_ERROR,
            ErrorCategory.NETWORK_ERROR,
            ErrorCategory.DEPENDENCY_ERROR,
            ErrorCategory.CONFIGURATION_ERROR,
        }:
            return ErrorSeverity.HIGH
        return ErrorSeverity.MEDIUM

    def _remediation_for_category(self, category: ErrorCategory) -> str:
        """Default remediation hint for category."""
        hints = {
            ErrorCategory.APP_CRASH: "Inspect crash logs, stack traces, memory usage, dependencies, and recent deployments.",
            ErrorCategory.HTTP_CLIENT_ERROR: "Verify request URL, route registration, parameters, auth state, and resource existence.",
            ErrorCategory.HTTP_SERVER_ERROR: "Inspect server logs, upstream services, database health, and recent code changes.",
            ErrorCategory.PERMISSION_DENIED: "Check user/workspace role permissions, OS/file permissions, API scopes, and Security Agent policy.",
            ErrorCategory.TIMEOUT: "Check network/service latency, timeout values, worker limits, and retry/backoff policy.",
            ErrorCategory.BUILD_FAILURE: "Review compiler/build output, dependency versions, lock files, and environment configuration.",
            ErrorCategory.TEST_FAILURE: "Review failing assertions and compare expected vs actual behavior.",
            ErrorCategory.RUNTIME_EXCEPTION: "Inspect stack trace and fix the root exception path.",
            ErrorCategory.DEPENDENCY_ERROR: "Install, pin, or resolve missing dependencies and verify runtime environment.",
            ErrorCategory.NETWORK_ERROR: "Verify DNS, host, port, firewall, TLS, proxy, and upstream availability.",
            ErrorCategory.DATABASE_ERROR: "Verify DB connection, migrations, schema, query syntax, locks, and pool capacity.",
            ErrorCategory.CONFIGURATION_ERROR: "Verify required settings, environment variables, config files, and safe defaults.",
            ErrorCategory.AUTHENTICATION_ERROR: "Verify token/session state, identity provider configuration, and auth middleware.",
            ErrorCategory.RATE_LIMIT_ERROR: "Apply backoff, reduce request volume, and check quota limits.",
            ErrorCategory.RESOURCE_ERROR: "Check memory, disk, CPU, file descriptors, and worker concurrency limits.",
            ErrorCategory.UNKNOWN_ERROR: "Review full logs and reproduce the failing action with additional instrumentation.",
        }
        return hints.get(category, hints[ErrorCategory.UNKNOWN_ERROR])

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    def _request_id(self, task_context: Mapping[str, Any]) -> str:
        """Resolve or create request id."""
        return _safe_str(task_context.get("request_id") or task_context.get("trace_id") or uuid.uuid4())

    def _base_metadata(
        self,
        task_context: Mapping[str, Any],
        request_id: str,
        started_at: float,
    ) -> Dict[str, Any]:
        """Base metadata for all results."""
        return {
            "agent": DEFAULT_AGENT_NAME,
            "agent_type": self.agent_type,
            "capability": self.capability,
            "request_id": request_id,
            "task_id": task_context.get("task_id"),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "duration_ms": round((time.monotonic() - started_at) * 1000, 3),
            "timestamp": _utc_now_iso(),
        }


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def create_error_detector(
    config: Optional[Union[ErrorDetectorConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> VerificationErrorDetector:
    """
    Factory used by Agent Loader / Registry.

    Example:
        detector = create_error_detector()
    """
    return VerificationErrorDetector(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Return registry-friendly module metadata.

    Agent Registry can read this without instantiating the class.
    """
    return {
        "agent_module": "Verification Agent",
        "file": "agents/verification_agent/error_detector.py",
        "class_name": "VerificationErrorDetector",
        "agent_type": VerificationErrorDetector.agent_type,
        "capability": VerificationErrorDetector.capability,
        "public_methods": list(VerificationErrorDetector.public_methods),
        "import_safe": True,
        "requires_user_workspace": True,
        "destructive_actions": False,
        "security_sensitive": False,
        "version": "1.0.0",
    }


__all__ = [
    "VerificationErrorDetector",
    "ErrorDetectorConfig",
    "ErrorFinding",
    "ErrorPattern",
    "ErrorCategory",
    "ErrorSeverity",
    "ErrorStatus",
    "create_error_detector",
    "get_agent_metadata",
]


# ---------------------------------------------------------------------------
# Lightweight self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    detector = VerificationErrorDetector()
    context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
    }

    sample = """
    Traceback (most recent call last):
      File "app.py", line 10, in <module>
        raise RuntimeError("boom")
    RuntimeError: boom

    GET /missing-page HTTP/1.1 404 Not Found
    build failed: npm ERR! Cannot find module 'vite'
    """

    result = detector.detect_from_text(context, text=sample, source="self_test")
    print(result)


"""
William / Jarvis All-File Prompt Bible - Digital Promotix
Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.

Agent/Module: Verification Agent
File Completed: error_detector.py
Completion: 70.6%
Completed Files: ['verification_agent.py', 'state_checker.py', 'screenshot_checker.py', 'result_validator.py', 'app_state_checker.py', 'file_state_checker.py', 'browser_state_checker.py', 'code_state_checker.py', 'device_state_checker.py', 'ui_element_checker.py', 'action_replay_checker.py', 'error_detector.py']
Remaining Files: ['proof_collector.py', 'retry_manager.py', 'report_generator.py', 'verification_memory.py', 'config.py']
Next Recommended File: agents/verification_agent/proof_collector.py
FILE COMPLETE
"""