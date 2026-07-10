"""
agents/visual_agent/error_screen_detector.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detects visual errors and sends structured issue to the proper agent.

This module is part of the Visual Agent layer. It analyzes screen/OCR/UI context and
detects error states such as browser errors, permission blocks, login/session errors,
form validation errors, server errors, app crashes, empty states, loading stuck states,
network errors, visual blocking overlays, security warnings, and automation failures.

Important:
    - This file does not execute browser/system/message/call/financial/destructive actions.
    - It only detects, classifies, and prepares structured routing payloads.
    - It is safe to import even when other William/Jarvis files are not created yet.
    - Every user-scoped task requires user_id and workspace_id.
    - Every result follows dict/JSON style:
        success, message, data, error, metadata

Architecture Connections:
    - Master Agent:
        Can route screen-analysis tasks here and use the returned route_issue_to field.

    - Visual Agent:
        Uses this detector after screenshot_reader.py, ocr_engine.py, ui_mapper.py,
        image_analyzer.py, screen_context.py, and element_detector.py.

    - Security Agent:
        Sensitive visual states such as credential exposure, permission screens,
        suspicious security warnings, and private data screens can trigger security hooks.

    - Verification Agent:
        A completed detection prepares a verification payload.

    - Memory Agent:
        Useful visual error patterns are prepared as memory-compatible payloads
        scoped by user_id and workspace_id.

    - Dashboard/API:
        Output is ready for FastAPI, dashboard cards, issue tables, audit logs,
        task history, analytics, and future retry workflows.

Required class:
    ErrorScreenDetector
"""

from __future__ import annotations

import json
import logging
import math
import re
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe Optional Imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe while the William/Jarvis project is still
        being generated file-by-file.
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


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("william.visual.error_screen_detector")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

DEFAULT_AGENT_NAME = "ErrorScreenDetector"
DEFAULT_VERSION = "1.0.0"

MAX_TEXT_LENGTH = 25000
MAX_UI_ELEMENTS = 1000
MAX_EVIDENCE_ITEMS = 80
MAX_PATTERNS_PER_CATEGORY = 60

DEFAULT_CONFIDENCE_THRESHOLD = 0.52
DEFAULT_STRONG_CONFIDENCE_THRESHOLD = 0.78

SENSITIVE_KEYWORDS = {
    "password",
    "secret",
    "api key",
    "token",
    "private key",
    "credential",
    "card number",
    "cvv",
    "ssn",
    "social security",
    "bank",
    "account number",
    "2fa",
    "otp",
    "verification code",
    "recovery code",
    "permission",
    "admin access",
    "security warning",
    "unsafe",
    "malware",
    "phishing",
    "blocked",
}


# =============================================================================
# Enums
# =============================================================================

class ErrorCategory(str, Enum):
    """High-level visual error category."""

    NONE = "none"
    BROWSER_ERROR = "browser_error"
    NETWORK_ERROR = "network_error"
    SERVER_ERROR = "server_error"
    CLIENT_ERROR = "client_error"
    AUTH_ERROR = "auth_error"
    PERMISSION_ERROR = "permission_error"
    SECURITY_WARNING = "security_warning"
    FORM_VALIDATION_ERROR = "form_validation_error"
    APP_CRASH = "app_crash"
    CODE_RUNTIME_ERROR = "code_runtime_error"
    EMPTY_STATE = "empty_state"
    LOADING_STUCK = "loading_stuck"
    PAYMENT_OR_BILLING_ERROR = "payment_or_billing_error"
    RATE_LIMIT_ERROR = "rate_limit_error"
    CAPTCHA_OR_BOT_CHECK = "captcha_or_bot_check"
    AUTOMATION_BLOCKED = "automation_blocked"
    UI_BLOCKING_OVERLAY = "ui_blocking_overlay"
    NOT_FOUND = "not_found"
    UNKNOWN_ERROR = "unknown_error"


class ErrorSeverity(str, Enum):
    """Severity level for dashboard and routing."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RoutedAgent(str, Enum):
    """Agent route recommendation."""

    NONE = "none"
    MASTER_AGENT = "master_agent"
    VISUAL_AGENT = "visual_agent"
    VERIFICATION_AGENT = "verification_agent"
    BROWSER_AGENT = "browser_agent"
    CODE_AGENT = "code_agent"
    SYSTEM_AGENT = "system_agent"
    SECURITY_AGENT = "security_agent"
    WORKFLOW_AGENT = "workflow_agent"
    MEMORY_AGENT = "memory_agent"
    BUSINESS_AGENT = "business_agent"
    FINANCE_AGENT = "finance_agent"


class DetectionStatus(str, Enum):
    """Detector outcome status."""

    NO_ERROR = "no_error"
    ERROR_DETECTED = "error_detected"
    WARNING_DETECTED = "warning_detected"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(str, Enum):
    """Evidence source type."""

    OCR_TEXT = "ocr_text"
    UI_ELEMENT = "ui_element"
    SCREEN_CONTEXT = "screen_context"
    IMAGE_HINT = "image_hint"
    METADATA = "metadata"
    PATTERN_MATCH = "pattern_match"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class VisualErrorContext:
    """
    SaaS-safe visual error detection context.

    user_id and workspace_id are required for user/workspace isolation.
    """

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    screenshot_id: Optional[str] = None
    session_id: Optional[str] = None
    app_name: Optional[str] = None
    page_url: Optional[str] = None
    workflow_id: Optional[str] = None
    step_id: Optional[str] = None
    requested_by: Optional[str] = None
    source: str = "visual_agent"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorEvidence:
    """Evidence item supporting an error detection."""

    evidence_type: EvidenceType
    text: str
    confidence: float
    category: ErrorCategory
    severity: ErrorSeverity
    source: Optional[str] = None
    bounds: Optional[Dict[str, Any]] = None
    pattern: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectedVisualError:
    """Structured detected visual error."""

    detected: bool
    status: DetectionStatus
    category: ErrorCategory
    severity: ErrorSeverity
    route_issue_to: RoutedAgent
    title: str
    message: str
    confidence: float
    evidence: List[ErrorEvidence] = field(default_factory=list)
    suggested_actions: List[str] = field(default_factory=list)
    retryable: bool = False
    requires_security_review: bool = False
    requires_human_review: bool = False
    issue_code: str = "visual_error_unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorScreenDetectorConfig:
    """Configuration for visual error detection."""

    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    strong_confidence_threshold: float = DEFAULT_STRONG_CONFIDENCE_THRESHOLD
    max_text_length: int = MAX_TEXT_LENGTH
    max_ui_elements: int = MAX_UI_ELEMENTS
    include_raw_input: bool = False
    include_evidence: bool = True
    enable_security_check: bool = True
    enable_ui_element_analysis: bool = True
    enable_screen_context_analysis: bool = True
    enable_image_hint_analysis: bool = True
    fail_open_on_security_agent_missing: bool = True
    default_route: RoutedAgent = RoutedAgent.MASTER_AGENT


@dataclass(frozen=True)
class ErrorPattern:
    """Pattern rule for detecting visual errors."""

    category: ErrorCategory
    severity: ErrorSeverity
    route_to: RoutedAgent
    patterns: Tuple[str, ...]
    issue_code: str
    title: str
    suggestion: str
    retryable: bool = False
    requires_security_review: bool = False
    requires_human_review: bool = False
    weight: float = 1.0


# =============================================================================
# Utility Functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_jsonable(value: Any, max_string_length: int = 5000) -> Any:
    """Convert values into JSON-safe format."""
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        if len(value) > max_string_length:
            return value[:max_string_length] + "...[truncated]"
        return value

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Mapping):
        return {
            str(key): _safe_jsonable(item, max_string_length=max_string_length)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _safe_jsonable(item, max_string_length=max_string_length)
            for item in list(value)
        ]

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
    """Normalize text for matching."""
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple)):
        try:
            value = json.dumps(value, sort_keys=True, default=str)
        except Exception:
            value = str(value)

    text = str(value).lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text


def _clean_display_text(value: Any, max_length: int = 300) -> str:
    """Clean text for display."""
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > max_length:
        text = text[:max_length] + "...[truncated]"
    return text


def _clamp_confidence(value: float) -> float:
    """Clamp confidence into 0.0 to 1.0."""
    try:
        if math.isnan(value) or math.isinf(value):
            return 0.0
    except Exception:
        return 0.0

    return max(0.0, min(1.0, float(value)))


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Coerce mixed values into bool."""
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


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely parse a float."""
    try:
        parsed = float(value)
        if math.isnan(parsed) or math.isinf(parsed):
            return default
        return parsed
    except Exception:
        return default


def _as_list(value: Any) -> List[Any]:
    """Convert value into list safely."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


# =============================================================================
# Pattern Library
# =============================================================================

ERROR_PATTERNS: Tuple[ErrorPattern, ...] = (
    ErrorPattern(
        category=ErrorCategory.BROWSER_ERROR,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.BROWSER_AGENT,
        issue_code="browser_page_load_error",
        title="Browser page load error detected",
        suggestion="Ask Browser Agent to reload, inspect URL, check tab state, or retry navigation.",
        retryable=True,
        patterns=(
            r"this site can.?t be reached",
            r"this page isn.?t working",
            r"page unresponsive",
            r"aw, snap",
            r"err_[a-z0-9_]+",
            r"dns_probe_finished",
            r"connection timed out",
            r"connection reset",
            r"browser crashed",
            r"chrome didn.?t shut down correctly",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.NETWORK_ERROR,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.SYSTEM_AGENT,
        issue_code="network_connection_error",
        title="Network connection error detected",
        suggestion="Ask System Agent to check connectivity, DNS, proxy, VPN, and firewall status.",
        retryable=True,
        patterns=(
            r"no internet",
            r"network error",
            r"network unavailable",
            r"offline",
            r"check your connection",
            r"unable to connect",
            r"internet connection appears to be offline",
            r"temporary failure in name resolution",
            r"connection refused",
            r"network changed",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.SERVER_ERROR,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.CODE_AGENT,
        issue_code="server_error",
        title="Server error detected",
        suggestion="Ask Code Agent to inspect backend logs, API response, deployment, and server health.",
        retryable=True,
        patterns=(
            r"\b500 internal server error\b",
            r"\b502 bad gateway\b",
            r"\b503 service unavailable\b",
            r"\b504 gateway timeout\b",
            r"server error",
            r"application error",
            r"service temporarily unavailable",
            r"backend error",
            r"upstream error",
            r"nginx.*error",
            r"apache.*error",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.CLIENT_ERROR,
        severity=ErrorSeverity.MEDIUM,
        route_to=RoutedAgent.CODE_AGENT,
        issue_code="client_error",
        title="Client-side error detected",
        suggestion="Ask Code Agent to inspect frontend console, JavaScript bundle, and UI state.",
        retryable=True,
        patterns=(
            r"javascript error",
            r"script error",
            r"uncaught typeerror",
            r"uncaught referenceerror",
            r"uncaught exception",
            r"runtime error",
            r"failed to fetch",
            r"chunkloaderror",
            r"hydration failed",
            r"react error",
            r"vue error",
            r"angular error",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.CODE_RUNTIME_ERROR,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.CODE_AGENT,
        issue_code="code_runtime_error",
        title="Runtime/code error detected",
        suggestion="Ask Code Agent to inspect stack trace, failing file, function, and recent changes.",
        retryable=False,
        patterns=(
            r"traceback \(most recent call last\)",
            r"syntaxerror",
            r"importerror",
            r"modulenotfounderror",
            r"attributeerror",
            r"keyerror",
            r"valueerror",
            r"typeerror",
            r"nullpointerexception",
            r"segmentation fault",
            r"stack trace",
            r"fatal error",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.AUTH_ERROR,
        severity=ErrorSeverity.MEDIUM,
        route_to=RoutedAgent.SECURITY_AGENT,
        issue_code="authentication_error",
        title="Authentication/session error detected",
        suggestion="Ask Security Agent to verify session, auth state, permissions, and token safety.",
        retryable=True,
        requires_security_review=True,
        patterns=(
            r"login required",
            r"please sign in",
            r"session expired",
            r"invalid credentials",
            r"authentication failed",
            r"unauthorized",
            r"\b401\b",
            r"token expired",
            r"invalid token",
            r"access token",
            r"refresh token",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.PERMISSION_ERROR,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.SECURITY_AGENT,
        issue_code="permission_error",
        title="Permission/access error detected",
        suggestion="Ask Security Agent to check user role, workspace permission, and action policy.",
        retryable=False,
        requires_security_review=True,
        patterns=(
            r"access denied",
            r"permission denied",
            r"forbidden",
            r"\b403\b",
            r"you don.?t have permission",
            r"not allowed",
            r"administrator permission",
            r"requires admin",
            r"insufficient privileges",
            r"blocked by policy",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.SECURITY_WARNING,
        severity=ErrorSeverity.CRITICAL,
        route_to=RoutedAgent.SECURITY_AGENT,
        issue_code="security_warning",
        title="Security warning detected",
        suggestion="Ask Security Agent to review the screen before continuing.",
        retryable=False,
        requires_security_review=True,
        requires_human_review=True,
        patterns=(
            r"deceptive site ahead",
            r"malware",
            r"phishing",
            r"unsafe site",
            r"your connection is not private",
            r"certificate error",
            r"net::err_cert",
            r"security warning",
            r"dangerous",
            r"suspicious activity",
            r"blocked for your protection",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.FORM_VALIDATION_ERROR,
        severity=ErrorSeverity.MEDIUM,
        route_to=RoutedAgent.VISUAL_AGENT,
        issue_code="form_validation_error",
        title="Form validation error detected",
        suggestion="Ask Visual/Form Reader to identify invalid fields and required inputs.",
        retryable=True,
        patterns=(
            r"required field",
            r"this field is required",
            r"invalid email",
            r"invalid phone",
            r"please enter",
            r"must be",
            r"validation error",
            r"invalid value",
            r"field cannot be empty",
            r"please select",
            r"missing required",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.APP_CRASH,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.SYSTEM_AGENT,
        issue_code="application_crash",
        title="Application crash detected",
        suggestion="Ask System Agent to inspect app process, device state, memory, and crash logs.",
        retryable=True,
        patterns=(
            r"app has stopped",
            r"application has stopped",
            r"not responding",
            r"force close",
            r"crash",
            r"unexpectedly quit",
            r"program is not responding",
            r"close the program",
            r"wait for the program to respond",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.EMPTY_STATE,
        severity=ErrorSeverity.LOW,
        route_to=RoutedAgent.WORKFLOW_AGENT,
        issue_code="empty_state",
        title="Empty state detected",
        suggestion="Ask Workflow Agent to decide whether this is expected or next data/action is missing.",
        retryable=False,
        patterns=(
            r"no results found",
            r"nothing here",
            r"no data available",
            r"no records",
            r"empty",
            r"no items",
            r"no messages",
            r"no files",
            r"no tasks",
            r"start by creating",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.LOADING_STUCK,
        severity=ErrorSeverity.MEDIUM,
        route_to=RoutedAgent.BROWSER_AGENT,
        issue_code="loading_stuck",
        title="Possible stuck loading state detected",
        suggestion="Ask Browser Agent to wait/retry once, then ask Code/System Agent if still stuck.",
        retryable=True,
        patterns=(
            r"loading",
            r"please wait",
            r"processing",
            r"initializing",
            r"connecting",
            r"syncing",
            r"almost there",
            r"still working",
        ),
        weight=0.45,
    ),
    ErrorPattern(
        category=ErrorCategory.PAYMENT_OR_BILLING_ERROR,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.FINANCE_AGENT,
        issue_code="payment_billing_error",
        title="Payment or billing error detected",
        suggestion="Ask Finance Agent to review billing state without exposing sensitive payment data.",
        retryable=False,
        requires_security_review=True,
        patterns=(
            r"payment failed",
            r"billing error",
            r"card declined",
            r"insufficient funds",
            r"invoice overdue",
            r"subscription expired",
            r"payment method",
            r"transaction failed",
            r"unable to charge",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.RATE_LIMIT_ERROR,
        severity=ErrorSeverity.MEDIUM,
        route_to=RoutedAgent.WORKFLOW_AGENT,
        issue_code="rate_limit_error",
        title="Rate limit error detected",
        suggestion="Ask Workflow Agent to delay retry and reduce request frequency.",
        retryable=True,
        patterns=(
            r"rate limit",
            r"too many requests",
            r"\b429\b",
            r"quota exceeded",
            r"request limit",
            r"slow down",
            r"try again later",
            r"temporarily limited",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.CAPTCHA_OR_BOT_CHECK,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.SECURITY_AGENT,
        issue_code="captcha_or_bot_check",
        title="CAPTCHA or bot-check screen detected",
        suggestion="Ask Security Agent/Workflow Agent to pause automation and request human review if needed.",
        retryable=False,
        requires_security_review=True,
        requires_human_review=True,
        patterns=(
            r"captcha",
            r"recaptcha",
            r"verify you are human",
            r"are you a robot",
            r"security check",
            r"bot detection",
            r"unusual traffic",
            r"automated queries",
            r"prove you.?re not a robot",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.AUTOMATION_BLOCKED,
        severity=ErrorSeverity.HIGH,
        route_to=RoutedAgent.SECURITY_AGENT,
        issue_code="automation_blocked",
        title="Automation appears blocked",
        suggestion="Ask Security Agent to review compliance and ask Workflow Agent to stop/replan safely.",
        retryable=False,
        requires_security_review=True,
        requires_human_review=True,
        patterns=(
            r"automation blocked",
            r"automated activity",
            r"bot activity",
            r"your activity has been restricted",
            r"account temporarily locked",
            r"action blocked",
            r"we limit how often",
            r"suspicious login attempt",
            r"unusual activity",
        ),
    ),
    ErrorPattern(
        category=ErrorCategory.NOT_FOUND,
        severity=ErrorSeverity.MEDIUM,
        route_to=RoutedAgent.BROWSER_AGENT,
        issue_code="not_found",
        title="Not found screen detected",
        suggestion="Ask Browser Agent to verify URL/path and ask Code Agent if route is missing.",
        retryable=False,
        patterns=(
            r"\b404\b",
            r"page not found",
            r"not found",
            r"couldn.?t find",
            r"does not exist",
            r"broken link",
            r"route not found",
        ),
    ),
)


# =============================================================================
# Main Class
# =============================================================================

class ErrorScreenDetector(BaseAgent):
    """
    Detects visual errors and prepares structured issue routing.

    Public methods:
        - detect_error_screen(...)
        - detect(...)
        - classify_visual_error(...)
        - route_detected_issue(...)
        - prepare_dashboard_payload(...)

    This class analyzes screen data only. It does not execute the recovery action.
    """

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        config: Optional[Union[ErrorScreenDetectorConfig, Mapping[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize ErrorScreenDetector."""
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
            "visual_error_detection": True,
            "ocr_error_detection": True,
            "ui_element_error_detection": True,
            "screen_context_error_detection": True,
            "image_hint_error_detection": True,
            "issue_classification": True,
            "agent_routing_recommendation": True,
            "verification_payload": True,
            "memory_payload": True,
            "audit_events": True,
            "saas_isolation": True,
            "safe_import_fallbacks": True,
        }

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def detect_error_screen(
        self,
        ocr_text: Optional[Union[str, Sequence[str], Mapping[str, Any]]] = None,
        ui_elements: Optional[Sequence[Mapping[str, Any]]] = None,
        screen_context: Optional[Mapping[str, Any]] = None,
        image_hints: Optional[Mapping[str, Any]] = None,
        screenshot_metadata: Optional[Mapping[str, Any]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
        screenshot_id: Optional[str] = None,
        session_id: Optional[str] = None,
        app_name: Optional[str] = None,
        page_url: Optional[str] = None,
        workflow_id: Optional[str] = None,
        step_id: Optional[str] = None,
        context: Optional[Union[VisualErrorContext, Mapping[str, Any]]] = None,
        config: Optional[Union[ErrorScreenDetectorConfig, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Detect visual error screen from OCR/UI/context/image hints.

        Args:
            ocr_text:
                OCR string, list of text segments, or OCR result dict.

            ui_elements:
                UI element list from element_detector.py or ui_mapper.py.

            screen_context:
                Context from screen_context.py.

            image_hints:
                Optional image analyzer hints such as dominant states, labels,
                detected overlays, warning icons, or screenshot quality.

            screenshot_metadata:
                Optional screenshot metadata.

            user_id/workspace_id:
                Required SaaS isolation identifiers unless provided in context.

            context:
                Optional VisualErrorContext or dict.

            config:
                Optional per-call configuration.

        Returns:
            Structured dict with detection, issue, routing, verification, memory payload.
        """
        started_at = time.time()

        try:
            active_config = self._build_config(config, base=self.config)

            visual_context = self._coerce_context(
                context=context,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                screenshot_id=screenshot_id,
                session_id=session_id,
                app_name=app_name,
                page_url=page_url,
                workflow_id=workflow_id,
                step_id=step_id,
                screenshot_metadata=screenshot_metadata,
            )

            validation = self._validate_task_context(visual_context)
            if not validation.get("success"):
                return validation

            normalized_text = self._extract_text(ocr_text, active_config)
            normalized_elements = self._normalize_ui_elements(ui_elements, active_config)
            normalized_context = dict(screen_context or {})
            normalized_hints = dict(image_hints or {})
            normalized_metadata = dict(screenshot_metadata or {})

            if self._requires_security_check(
                context=visual_context,
                ocr_text=normalized_text,
                ui_elements=normalized_elements,
                screen_context=normalized_context,
                image_hints=normalized_hints,
            ):
                approval = self._request_security_approval(
                    action="visual.error_screen_detection",
                    context=visual_context,
                    payload={
                        "reason": "Sensitive visual content or security state may be present.",
                        "app_name": visual_context.app_name,
                        "page_url": visual_context.page_url,
                        "text_preview": normalized_text[:500],
                    },
                )

                if not approval.get("approved", False):
                    result = self._error_result(
                        message="Security approval denied for visual error detection.",
                        error={
                            "code": "security_approval_denied",
                            "approval": _safe_jsonable(approval),
                        },
                        metadata={
                            "agent": self.agent_name,
                            "version": self.version,
                            "context": asdict(visual_context),
                            "duration_ms": self._elapsed_ms(started_at),
                            "timestamp": _utc_now_iso(),
                        },
                    )
                    self._log_audit_event(
                        event_type="visual.error_screen_detector.security_denied",
                        context=visual_context,
                        result=result,
                    )
                    return result

            detected_error = self.classify_visual_error(
                ocr_text=normalized_text,
                ui_elements=normalized_elements,
                screen_context=normalized_context,
                image_hints=normalized_hints,
                screenshot_metadata=normalized_metadata,
                config=active_config,
            )

            routing_payload = self.route_detected_issue(
                detected_error=detected_error,
                context=visual_context,
            )

            verification_payload = self._prepare_verification_payload(
                context=visual_context,
                detected_error=detected_error,
                routing_payload=routing_payload,
            )

            memory_payload = self._prepare_memory_payload(
                context=visual_context,
                detected_error=detected_error,
            )

            dashboard_payload = self.prepare_dashboard_payload(
                detected_error=detected_error,
                context=visual_context,
                routing_payload=routing_payload,
            )

            data: Dict[str, Any] = {
                "detected": detected_error.detected,
                "status": detected_error.status.value,
                "category": detected_error.category.value,
                "severity": detected_error.severity.value,
                "confidence": round(detected_error.confidence, 4),
                "title": detected_error.title,
                "message": detected_error.message,
                "issue_code": detected_error.issue_code,
                "route_issue_to": detected_error.route_issue_to.value,
                "retryable": detected_error.retryable,
                "requires_security_review": detected_error.requires_security_review,
                "requires_human_review": detected_error.requires_human_review,
                "suggested_actions": detected_error.suggested_actions,
                "evidence": self._serialize_evidence(detected_error.evidence)
                if active_config.include_evidence
                else [],
                "routing_payload": routing_payload,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "dashboard_payload": dashboard_payload,
            }

            if active_config.include_raw_input:
                data["raw_input"] = {
                    "ocr_text": normalized_text,
                    "ui_elements": normalized_elements,
                    "screen_context": normalized_context,
                    "image_hints": normalized_hints,
                    "screenshot_metadata": normalized_metadata,
                }

            if detected_error.detected:
                message = (
                    f"Visual error detected: {detected_error.title}. "
                    f"Route to {detected_error.route_issue_to.value}."
                )
            elif detected_error.status == DetectionStatus.WARNING_DETECTED:
                message = (
                    f"Visual warning detected: {detected_error.title}. "
                    f"Route to {detected_error.route_issue_to.value}."
                )
            elif detected_error.status == DetectionStatus.INCONCLUSIVE:
                message = "Visual error detection is inconclusive. More screen evidence is needed."
            else:
                message = "No visual error screen detected."

            result = self._safe_result(
                success=True,
                message=message,
                data=data,
                metadata={
                    "agent": self.agent_name,
                    "version": self.version,
                    "context": asdict(visual_context),
                    "duration_ms": self._elapsed_ms(started_at),
                    "timestamp": _utc_now_iso(),
                },
            )

            self._emit_agent_event(
                event_type="visual.error_screen_detector.completed",
                context=visual_context,
                result=result,
            )
            self._log_audit_event(
                event_type="visual.error_screen_detector.completed",
                context=visual_context,
                result=result,
            )

            return result

        except Exception as exc:
            self.logger.exception("Visual error screen detection failed unexpectedly.")
            return self._error_result(
                message="Visual error screen detection failed unexpectedly.",
                error={
                    "exception": exc.__class__.__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
                metadata={
                    "agent": self.agent_name,
                    "version": self.version,
                    "duration_ms": self._elapsed_ms(started_at),
                    "timestamp": _utc_now_iso(),
                },
            )

    def detect(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Alias for detect_error_screen.

        Kept for Master Agent / Router method discovery.
        """
        return self.detect_error_screen(*args, **kwargs)

    def classify_visual_error(
        self,
        ocr_text: str,
        ui_elements: Sequence[Mapping[str, Any]],
        screen_context: Mapping[str, Any],
        image_hints: Mapping[str, Any],
        screenshot_metadata: Mapping[str, Any],
        config: Optional[ErrorScreenDetectorConfig] = None,
    ) -> DetectedVisualError:
        """
        Classify visual error from normalized data.

        This method is pure analysis and easy to unit test.
        """
        active_config = config or self.config
        evidence: List[ErrorEvidence] = []

        evidence.extend(self._detect_from_text(ocr_text))
        if active_config.enable_ui_element_analysis:
            evidence.extend(self._detect_from_ui_elements(ui_elements))

        if active_config.enable_screen_context_analysis:
            evidence.extend(self._detect_from_screen_context(screen_context))

        if active_config.enable_image_hint_analysis:
            evidence.extend(self._detect_from_image_hints(image_hints, screenshot_metadata))

        evidence = self._dedupe_evidence(evidence)[:MAX_EVIDENCE_ITEMS]

        if not evidence:
            if self._looks_inconclusive(ocr_text, ui_elements, screen_context, image_hints):
                return DetectedVisualError(
                    detected=False,
                    status=DetectionStatus.INCONCLUSIVE,
                    category=ErrorCategory.UNKNOWN_ERROR,
                    severity=ErrorSeverity.LOW,
                    route_issue_to=active_config.default_route,
                    title="Screen analysis inconclusive",
                    message="No strong error pattern was found, but screen data is too limited or unclear.",
                    confidence=0.35,
                    evidence=[],
                    suggested_actions=[
                        "Capture a clearer screenshot.",
                        "Run OCR again.",
                        "Ask Visual Agent to inspect screen context and UI elements.",
                    ],
                    retryable=True,
                    requires_security_review=False,
                    requires_human_review=False,
                    issue_code="visual_detection_inconclusive",
                    metadata={"reason": "limited_or_unclear_visual_input"},
                )

            return DetectedVisualError(
                detected=False,
                status=DetectionStatus.NO_ERROR,
                category=ErrorCategory.NONE,
                severity=ErrorSeverity.NONE,
                route_issue_to=RoutedAgent.NONE,
                title="No visual error detected",
                message="No visual error screen pattern was detected.",
                confidence=0.9,
                evidence=[],
                suggested_actions=[],
                retryable=False,
                requires_security_review=False,
                requires_human_review=False,
                issue_code="no_visual_error_detected",
                metadata={},
            )

        ranked = self._rank_evidence(evidence)
        top = ranked[0]
        confidence = self._calculate_overall_confidence(ranked)

        category = top.category
        severity = self._merge_severity(ranked)
        route_to = self._route_for_category(category, top)
        pattern_rule = self._find_pattern_rule_by_issue(top.metadata.get("issue_code"))

        if confidence < active_config.confidence_threshold:
            return DetectedVisualError(
                detected=False,
                status=DetectionStatus.INCONCLUSIVE,
                category=category,
                severity=severity,
                route_issue_to=route_to,
                title="Possible visual error detected",
                message=(
                    "A possible visual error pattern was found, but confidence is below "
                    "the configured detection threshold."
                ),
                confidence=confidence,
                evidence=ranked,
                suggested_actions=[
                    "Capture another screenshot.",
                    "Run OCR again with higher quality.",
                    "Ask Visual Agent to verify the screen manually.",
                ],
                retryable=True,
                requires_security_review=self._evidence_requires_security(ranked),
                requires_human_review=True,
                issue_code="possible_visual_error_low_confidence",
                metadata={"threshold": active_config.confidence_threshold},
            )

        status = DetectionStatus.ERROR_DETECTED
        if severity in {ErrorSeverity.LOW, ErrorSeverity.MEDIUM} and confidence < active_config.strong_confidence_threshold:
            status = DetectionStatus.WARNING_DETECTED

        title = pattern_rule.title if pattern_rule else self._default_title_for_category(category)
        suggestion = pattern_rule.suggestion if pattern_rule else self._default_suggestion_for_category(category, route_to)

        return DetectedVisualError(
            detected=status == DetectionStatus.ERROR_DETECTED,
            status=status,
            category=category,
            severity=severity,
            route_issue_to=route_to,
            title=title,
            message=self._build_detection_message(category, severity, route_to, confidence, ranked),
            confidence=confidence,
            evidence=ranked,
            suggested_actions=self._build_suggested_actions(
                category=category,
                route_to=route_to,
                suggestion=suggestion,
                evidence=ranked,
            ),
            retryable=self._is_retryable(category, ranked, pattern_rule),
            requires_security_review=self._evidence_requires_security(ranked),
            requires_human_review=self._requires_human_review(category, severity, ranked, pattern_rule),
            issue_code=top.metadata.get("issue_code") or self._issue_code_for_category(category),
            metadata={
                "top_evidence_type": top.evidence_type.value,
                "evidence_count": len(ranked),
                "matched_categories": sorted({item.category.value for item in ranked}),
                "matched_sources": sorted({item.source or "unknown" for item in ranked}),
            },
        )

    def route_detected_issue(
        self,
        detected_error: DetectedVisualError,
        context: VisualErrorContext,
    ) -> Dict[str, Any]:
        """
        Prepare structured issue payload for Master Agent / Router.

        This method does not send the issue itself. It returns a clean payload that
        the Master Agent, Agent Router, Dashboard, API, or Queue worker can use.
        """
        return {
            "issue_id": str(uuid.uuid4()),
            "issue_type": "visual_error_screen",
            "issue_code": detected_error.issue_code,
            "route_issue_to": detected_error.route_issue_to.value,
            "recommended_agent": detected_error.route_issue_to.value,
            "source_agent": self.agent_name,
            "source_module": "agents.visual_agent.error_screen_detector",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "screenshot_id": context.screenshot_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
            "app_name": context.app_name,
            "page_url": context.page_url,
            "correlation_id": context.correlation_id,
            "title": detected_error.title,
            "message": detected_error.message,
            "category": detected_error.category.value,
            "severity": detected_error.severity.value,
            "confidence": round(detected_error.confidence, 4),
            "retryable": detected_error.retryable,
            "requires_security_review": detected_error.requires_security_review,
            "requires_human_review": detected_error.requires_human_review,
            "suggested_actions": detected_error.suggested_actions,
            "evidence_summary": [
                {
                    "type": item.evidence_type.value,
                    "text": item.text,
                    "confidence": round(item.confidence, 4),
                    "category": item.category.value,
                    "severity": item.severity.value,
                    "source": item.source,
                    "pattern": item.pattern,
                }
                for item in detected_error.evidence[:10]
            ],
            "created_at": _utc_now_iso(),
            "metadata": {
                "context_metadata": _safe_jsonable(context.metadata),
                "detector_version": self.version,
            },
        }

    def prepare_dashboard_payload(
        self,
        detected_error: DetectedVisualError,
        context: VisualErrorContext,
        routing_payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare compact dashboard-friendly payload.
        """
        return {
            "detected": detected_error.detected,
            "status": detected_error.status.value,
            "title": detected_error.title,
            "category": detected_error.category.value,
            "severity": detected_error.severity.value,
            "confidence": round(detected_error.confidence, 4),
            "route_issue_to": detected_error.route_issue_to.value,
            "issue_code": detected_error.issue_code,
            "retryable": detected_error.retryable,
            "requires_security_review": detected_error.requires_security_review,
            "requires_human_review": detected_error.requires_human_review,
            "app_name": context.app_name,
            "page_url": context.page_url,
            "task_id": context.task_id,
            "screenshot_id": context.screenshot_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
            "evidence_count": len(detected_error.evidence),
            "top_evidence": detected_error.evidence[0].text if detected_error.evidence else None,
            "issue_id": None if routing_payload is None else routing_payload.get("issue_id"),
            "timestamp": _utc_now_iso(),
        }

    # -------------------------------------------------------------------------
    # Detection Methods
    # -------------------------------------------------------------------------

    def _detect_from_text(self, text: str) -> List[ErrorEvidence]:
        """Detect errors from OCR text."""
        normalized = _normalize_text(text)
        if not normalized:
            return []

        evidence: List[ErrorEvidence] = []

        for rule in ERROR_PATTERNS:
            for pattern in rule.patterns[:MAX_PATTERNS_PER_CATEGORY]:
                try:
                    match = re.search(pattern, normalized, flags=re.IGNORECASE)
                except re.error:
                    continue

                if match:
                    matched_text = _clean_display_text(match.group(0), max_length=220)
                    confidence = self._pattern_confidence(
                        pattern=pattern,
                        matched_text=matched_text,
                        full_text=normalized,
                        rule=rule,
                    )
                    evidence.append(
                        ErrorEvidence(
                            evidence_type=EvidenceType.PATTERN_MATCH,
                            text=matched_text,
                            confidence=confidence,
                            category=rule.category,
                            severity=rule.severity,
                            source="ocr_text",
                            pattern=pattern,
                            metadata={
                                "issue_code": rule.issue_code,
                                "title": rule.title,
                                "weight": rule.weight,
                            },
                        )
                    )

        return evidence

    def _detect_from_ui_elements(
        self,
        ui_elements: Sequence[Mapping[str, Any]],
    ) -> List[ErrorEvidence]:
        """Detect errors from UI element labels, text, roles, and metadata."""
        evidence: List[ErrorEvidence] = []

        for index, element in enumerate(ui_elements[:MAX_UI_ELEMENTS]):
            if not isinstance(element, Mapping):
                continue

            element_text = " ".join(
                _clean_display_text(element.get(key), max_length=500)
                for key in (
                    "text",
                    "label",
                    "aria_label",
                    "title",
                    "placeholder",
                    "value",
                    "role",
                    "type",
                    "class_name",
                    "id",
                    "description",
                )
                if element.get(key) is not None
            )

            normalized = _normalize_text(element_text)
            if not normalized:
                continue

            for rule in ERROR_PATTERNS:
                for pattern in rule.patterns[:MAX_PATTERNS_PER_CATEGORY]:
                    try:
                        match = re.search(pattern, normalized, flags=re.IGNORECASE)
                    except re.error:
                        continue

                    if match:
                        evidence.append(
                            ErrorEvidence(
                                evidence_type=EvidenceType.UI_ELEMENT,
                                text=_clean_display_text(element_text),
                                confidence=self._pattern_confidence(
                                    pattern=pattern,
                                    matched_text=match.group(0),
                                    full_text=normalized,
                                    rule=rule,
                                ),
                                category=rule.category,
                                severity=rule.severity,
                                source=f"ui_element:{index}",
                                bounds=self._extract_bounds(element),
                                pattern=pattern,
                                metadata={
                                    "issue_code": rule.issue_code,
                                    "element_index": index,
                                    "element_role": element.get("role"),
                                    "element_type": element.get("type"),
                                },
                            )
                        )

        evidence.extend(self._detect_visual_error_controls(ui_elements))
        return evidence

    def _detect_visual_error_controls(
        self,
        ui_elements: Sequence[Mapping[str, Any]],
    ) -> List[ErrorEvidence]:
        """
        Detect common visual error controls such as modal dialogs,
        alert boxes, disabled submit button, or blocking overlays.
        """
        evidence: List[ErrorEvidence] = []

        for index, element in enumerate(ui_elements[:MAX_UI_ELEMENTS]):
            if not isinstance(element, Mapping):
                continue

            role = _normalize_text(element.get("role") or element.get("type"))
            text = _normalize_text(
                element.get("text")
                or element.get("label")
                or element.get("aria_label")
                or element.get("title")
            )
            class_name = _normalize_text(element.get("class_name") or element.get("class"))
            visible = element.get("visible", True)

            if visible is False:
                continue

            if role in {"alert", "dialog", "alertdialog", "banner"} or "error" in class_name:
                category = ErrorCategory.UNKNOWN_ERROR
                severity = ErrorSeverity.MEDIUM
                route_to = RoutedAgent.VISUAL_AGENT

                if "permission" in text or "access" in text:
                    category = ErrorCategory.PERMISSION_ERROR
                    severity = ErrorSeverity.HIGH
                    route_to = RoutedAgent.SECURITY_AGENT
                elif "required" in text or "invalid" in text:
                    category = ErrorCategory.FORM_VALIDATION_ERROR
                    severity = ErrorSeverity.MEDIUM
                    route_to = RoutedAgent.VISUAL_AGENT
                elif "server" in text or "500" in text:
                    category = ErrorCategory.SERVER_ERROR
                    severity = ErrorSeverity.HIGH
                    route_to = RoutedAgent.CODE_AGENT

                evidence.append(
                    ErrorEvidence(
                        evidence_type=EvidenceType.UI_ELEMENT,
                        text=_clean_display_text(text or f"{role} element detected"),
                        confidence=0.68,
                        category=category,
                        severity=severity,
                        source=f"ui_control:{index}",
                        bounds=self._extract_bounds(element),
                        pattern="role/class visual error control",
                        metadata={
                            "issue_code": self._issue_code_for_category(category),
                            "route_to": route_to.value,
                            "role": role,
                            "class_name": class_name,
                        },
                    )
                )

        return evidence

    def _detect_from_screen_context(
        self,
        screen_context: Mapping[str, Any],
    ) -> List[ErrorEvidence]:
        """Detect errors from structured screen context."""
        if not screen_context:
            return []

        evidence: List[ErrorEvidence] = []

        context_text = _normalize_text(screen_context)
        explicit_status = _normalize_text(
            screen_context.get("status")
            or screen_context.get("state")
            or screen_context.get("page_state")
            or screen_context.get("screen_state")
        )
        app_type = _normalize_text(screen_context.get("app_type") or screen_context.get("app_name"))
        url = _normalize_text(screen_context.get("url") or screen_context.get("page_url"))

        if explicit_status in {
            "error",
            "failed",
            "crashed",
            "blocked",
            "permission_denied",
            "unauthorized",
            "offline",
        }:
            category = self._category_from_context_status(explicit_status, context_text)
            evidence.append(
                ErrorEvidence(
                    evidence_type=EvidenceType.SCREEN_CONTEXT,
                    text=f"Screen context status: {explicit_status}",
                    confidence=0.82,
                    category=category,
                    severity=self._severity_for_category(category),
                    source="screen_context.status",
                    metadata={
                        "issue_code": self._issue_code_for_category(category),
                        "app_type": app_type,
                        "url": url,
                    },
                )
            )

        for rule in ERROR_PATTERNS:
            for pattern in rule.patterns[:MAX_PATTERNS_PER_CATEGORY]:
                try:
                    if re.search(pattern, context_text, flags=re.IGNORECASE):
                        evidence.append(
                            ErrorEvidence(
                                evidence_type=EvidenceType.SCREEN_CONTEXT,
                                text=_clean_display_text(context_text),
                                confidence=0.64 * rule.weight,
                                category=rule.category,
                                severity=rule.severity,
                                source="screen_context",
                                pattern=pattern,
                                metadata={
                                    "issue_code": rule.issue_code,
                                    "title": rule.title,
                                },
                            )
                        )
                except re.error:
                    continue

        return evidence

    def _detect_from_image_hints(
        self,
        image_hints: Mapping[str, Any],
        screenshot_metadata: Mapping[str, Any],
    ) -> List[ErrorEvidence]:
        """Detect errors from image analyzer hints and screenshot metadata."""
        evidence: List[ErrorEvidence] = []

        combined_text = _normalize_text({
            "image_hints": image_hints,
            "screenshot_metadata": screenshot_metadata,
        })

        if not combined_text:
            return evidence

        hint_state = _normalize_text(
            image_hints.get("state")
            or image_hints.get("screen_state")
            or image_hints.get("visual_state")
            or screenshot_metadata.get("state")
        )

        if hint_state in {"error", "warning", "blocked", "crashed", "empty", "loading"}:
            category = self._category_from_context_status(hint_state, combined_text)
            severity = self._severity_for_category(category)
            confidence = 0.65 if hint_state != "error" else 0.74

            evidence.append(
                ErrorEvidence(
                    evidence_type=EvidenceType.IMAGE_HINT,
                    text=f"Image hint state: {hint_state}",
                    confidence=confidence,
                    category=category,
                    severity=severity,
                    source="image_hints.state",
                    metadata={
                        "issue_code": self._issue_code_for_category(category),
                    },
                )
            )

        visual_flags = image_hints.get("flags") or screenshot_metadata.get("flags")
        for flag in _as_list(visual_flags):
            flag_text = _normalize_text(flag)
            if not flag_text:
                continue

            if "warning" in flag_text or "error" in flag_text or "blocked" in flag_text:
                category = self._category_from_context_status(flag_text, combined_text)
                evidence.append(
                    ErrorEvidence(
                        evidence_type=EvidenceType.IMAGE_HINT,
                        text=_clean_display_text(flag_text),
                        confidence=0.62,
                        category=category,
                        severity=self._severity_for_category(category),
                        source="image_hints.flags",
                        metadata={
                            "issue_code": self._issue_code_for_category(category),
                        },
                    )
                )

        for rule in ERROR_PATTERNS:
            for pattern in rule.patterns[:MAX_PATTERNS_PER_CATEGORY]:
                try:
                    if re.search(pattern, combined_text, flags=re.IGNORECASE):
                        evidence.append(
                            ErrorEvidence(
                                evidence_type=EvidenceType.IMAGE_HINT,
                                text=_clean_display_text(combined_text),
                                confidence=0.58 * rule.weight,
                                category=rule.category,
                                severity=rule.severity,
                                source="image_hints",
                                pattern=pattern,
                                metadata={
                                    "issue_code": rule.issue_code,
                                    "title": rule.title,
                                },
                            )
                        )
                except re.error:
                    continue

        return evidence

    # -------------------------------------------------------------------------
    # Ranking / Classification Helpers
    # -------------------------------------------------------------------------

    def _rank_evidence(self, evidence: Sequence[ErrorEvidence]) -> List[ErrorEvidence]:
        """Rank evidence by severity and confidence."""
        severity_score = {
            ErrorSeverity.CRITICAL: 5,
            ErrorSeverity.HIGH: 4,
            ErrorSeverity.MEDIUM: 3,
            ErrorSeverity.LOW: 2,
            ErrorSeverity.NONE: 1,
        }

        return sorted(
            evidence,
            key=lambda item: (
                severity_score.get(item.severity, 0),
                item.confidence,
                1 if hasattr(item, "requires_security_review") and bool(getattr(item, "requires_security_review", False)) else 0,
            ),
            reverse=True,
        )

    def _calculate_overall_confidence(self, evidence: Sequence[ErrorEvidence]) -> float:
        """Calculate overall confidence from evidence."""
        if not evidence:
            return 0.0

        top_scores = [item.confidence for item in evidence[:8]]
        base = max(top_scores)

        if len(evidence) >= 2:
            base += 0.06
        if len(evidence) >= 4:
            base += 0.05
        if len({item.evidence_type for item in evidence}) >= 2:
            base += 0.07
        if len({item.category for item in evidence[:5]}) == 1:
            base += 0.05

        return _clamp_confidence(base)

    def _merge_severity(self, evidence: Sequence[ErrorEvidence]) -> ErrorSeverity:
        """Choose highest severity from evidence."""
        priority = [
            ErrorSeverity.CRITICAL,
            ErrorSeverity.HIGH,
            ErrorSeverity.MEDIUM,
            ErrorSeverity.LOW,
            ErrorSeverity.NONE,
        ]

        severities = {item.severity for item in evidence}
        for severity in priority:
            if severity in severities:
                return severity

        return ErrorSeverity.NONE

    def _route_for_category(
        self,
        category: ErrorCategory,
        top_evidence: Optional[ErrorEvidence] = None,
    ) -> RoutedAgent:
        """Route detected issue to proper agent."""
        if top_evidence and top_evidence.metadata.get("route_to"):
            try:
                return RoutedAgent(str(top_evidence.metadata["route_to"]))
            except Exception:
                pass

        route_map = {
            ErrorCategory.BROWSER_ERROR: RoutedAgent.BROWSER_AGENT,
            ErrorCategory.NETWORK_ERROR: RoutedAgent.SYSTEM_AGENT,
            ErrorCategory.SERVER_ERROR: RoutedAgent.CODE_AGENT,
            ErrorCategory.CLIENT_ERROR: RoutedAgent.CODE_AGENT,
            ErrorCategory.AUTH_ERROR: RoutedAgent.SECURITY_AGENT,
            ErrorCategory.PERMISSION_ERROR: RoutedAgent.SECURITY_AGENT,
            ErrorCategory.SECURITY_WARNING: RoutedAgent.SECURITY_AGENT,
            ErrorCategory.FORM_VALIDATION_ERROR: RoutedAgent.VISUAL_AGENT,
            ErrorCategory.APP_CRASH: RoutedAgent.SYSTEM_AGENT,
            ErrorCategory.CODE_RUNTIME_ERROR: RoutedAgent.CODE_AGENT,
            ErrorCategory.EMPTY_STATE: RoutedAgent.WORKFLOW_AGENT,
            ErrorCategory.LOADING_STUCK: RoutedAgent.BROWSER_AGENT,
            ErrorCategory.PAYMENT_OR_BILLING_ERROR: RoutedAgent.FINANCE_AGENT,
            ErrorCategory.RATE_LIMIT_ERROR: RoutedAgent.WORKFLOW_AGENT,
            ErrorCategory.CAPTCHA_OR_BOT_CHECK: RoutedAgent.SECURITY_AGENT,
            ErrorCategory.AUTOMATION_BLOCKED: RoutedAgent.SECURITY_AGENT,
            ErrorCategory.UI_BLOCKING_OVERLAY: RoutedAgent.VISUAL_AGENT,
            ErrorCategory.NOT_FOUND: RoutedAgent.BROWSER_AGENT,
            ErrorCategory.UNKNOWN_ERROR: RoutedAgent.MASTER_AGENT,
            ErrorCategory.NONE: RoutedAgent.NONE,
        }

        return route_map.get(category, self.config.default_route)

    def _severity_for_category(self, category: ErrorCategory) -> ErrorSeverity:
        """Default severity for a category."""
        severity_map = {
            ErrorCategory.SECURITY_WARNING: ErrorSeverity.CRITICAL,
            ErrorCategory.CAPTCHA_OR_BOT_CHECK: ErrorSeverity.HIGH,
            ErrorCategory.AUTOMATION_BLOCKED: ErrorSeverity.HIGH,
            ErrorCategory.PERMISSION_ERROR: ErrorSeverity.HIGH,
            ErrorCategory.SERVER_ERROR: ErrorSeverity.HIGH,
            ErrorCategory.NETWORK_ERROR: ErrorSeverity.HIGH,
            ErrorCategory.APP_CRASH: ErrorSeverity.HIGH,
            ErrorCategory.CODE_RUNTIME_ERROR: ErrorSeverity.HIGH,
            ErrorCategory.BROWSER_ERROR: ErrorSeverity.HIGH,
            ErrorCategory.PAYMENT_OR_BILLING_ERROR: ErrorSeverity.HIGH,
            ErrorCategory.AUTH_ERROR: ErrorSeverity.MEDIUM,
            ErrorCategory.FORM_VALIDATION_ERROR: ErrorSeverity.MEDIUM,
            ErrorCategory.RATE_LIMIT_ERROR: ErrorSeverity.MEDIUM,
            ErrorCategory.CLIENT_ERROR: ErrorSeverity.MEDIUM,
            ErrorCategory.LOADING_STUCK: ErrorSeverity.MEDIUM,
            ErrorCategory.NOT_FOUND: ErrorSeverity.MEDIUM,
            ErrorCategory.EMPTY_STATE: ErrorSeverity.LOW,
            ErrorCategory.UI_BLOCKING_OVERLAY: ErrorSeverity.MEDIUM,
            ErrorCategory.UNKNOWN_ERROR: ErrorSeverity.MEDIUM,
            ErrorCategory.NONE: ErrorSeverity.NONE,
        }
        return severity_map.get(category, ErrorSeverity.MEDIUM)

    def _category_from_context_status(
        self,
        status: str,
        context_text: str,
    ) -> ErrorCategory:
        """Infer category from generic screen context status."""
        combined = f"{status} {context_text}"

        if any(word in combined for word in ("security", "malware", "phishing", "certificate", "unsafe")):
            return ErrorCategory.SECURITY_WARNING
        if any(word in combined for word in ("permission", "forbidden", "access denied", "403")):
            return ErrorCategory.PERMISSION_ERROR
        if any(word in combined for word in ("login", "auth", "unauthorized", "session", "401")):
            return ErrorCategory.AUTH_ERROR
        if any(word in combined for word in ("network", "offline", "connection", "dns")):
            return ErrorCategory.NETWORK_ERROR
        if any(word in combined for word in ("server", "500", "502", "503", "504")):
            return ErrorCategory.SERVER_ERROR
        if any(word in combined for word in ("crash", "stopped", "not responding")):
            return ErrorCategory.APP_CRASH
        if any(word in combined for word in ("loading", "processing", "please wait")):
            return ErrorCategory.LOADING_STUCK
        if any(word in combined for word in ("empty", "no results", "no data")):
            return ErrorCategory.EMPTY_STATE
        if any(word in combined for word in ("404", "not found")):
            return ErrorCategory.NOT_FOUND
        if any(word in combined for word in ("captcha", "robot", "bot")):
            return ErrorCategory.CAPTCHA_OR_BOT_CHECK

        return ErrorCategory.UNKNOWN_ERROR

    def _pattern_confidence(
        self,
        pattern: str,
        matched_text: str,
        full_text: str,
        rule: ErrorPattern,
    ) -> float:
        """Estimate confidence for a pattern match."""
        confidence = 0.58 * rule.weight

        exact_terms = {
            "500 internal server error",
            "403",
            "404",
            "401",
            "captcha",
            "permission denied",
            "access denied",
            "your connection is not private",
            "this site can't be reached",
            "traceback",
            "syntaxerror",
            "modulenotfounderror",
        }

        matched_norm = _normalize_text(matched_text)
        if any(term in matched_norm for term in exact_terms):
            confidence += 0.22

        if len(matched_norm) >= 8:
            confidence += 0.06

        if "error" in matched_norm or "failed" in matched_norm or "denied" in matched_norm:
            confidence += 0.08

        if len(full_text) < 40:
            confidence -= 0.06

        return _clamp_confidence(confidence)

    def _evidence_requires_security(self, evidence: Sequence[ErrorEvidence]) -> bool:
        """Return true if evidence requires Security Agent review."""
        security_categories = {
            ErrorCategory.AUTH_ERROR,
            ErrorCategory.PERMISSION_ERROR,
            ErrorCategory.SECURITY_WARNING,
            ErrorCategory.CAPTCHA_OR_BOT_CHECK,
            ErrorCategory.AUTOMATION_BLOCKED,
            ErrorCategory.PAYMENT_OR_BILLING_ERROR,
        }

        if any(item.category in security_categories for item in evidence):
            return True

        combined = _normalize_text([item.text for item in evidence])
        return any(keyword in combined for keyword in SENSITIVE_KEYWORDS)

    def _requires_human_review(
        self,
        category: ErrorCategory,
        severity: ErrorSeverity,
        evidence: Sequence[ErrorEvidence],
        pattern_rule: Optional[ErrorPattern],
    ) -> bool:
        """Determine if issue needs human review."""
        if pattern_rule and pattern_rule.requires_human_review:
            return True

        if severity == ErrorSeverity.CRITICAL:
            return True

        if category in {
            ErrorCategory.SECURITY_WARNING,
            ErrorCategory.CAPTCHA_OR_BOT_CHECK,
            ErrorCategory.AUTOMATION_BLOCKED,
        }:
            return True

        return False

    def _is_retryable(
        self,
        category: ErrorCategory,
        evidence: Sequence[ErrorEvidence],
        pattern_rule: Optional[ErrorPattern],
    ) -> bool:
        """Determine whether retry is safe/reasonable."""
        if pattern_rule is not None:
            return pattern_rule.retryable

        retryable_categories = {
            ErrorCategory.BROWSER_ERROR,
            ErrorCategory.NETWORK_ERROR,
            ErrorCategory.SERVER_ERROR,
            ErrorCategory.CLIENT_ERROR,
            ErrorCategory.AUTH_ERROR,
            ErrorCategory.FORM_VALIDATION_ERROR,
            ErrorCategory.APP_CRASH,
            ErrorCategory.LOADING_STUCK,
            ErrorCategory.RATE_LIMIT_ERROR,
        }

        return category in retryable_categories

    def _looks_inconclusive(
        self,
        ocr_text: str,
        ui_elements: Sequence[Mapping[str, Any]],
        screen_context: Mapping[str, Any],
        image_hints: Mapping[str, Any],
    ) -> bool:
        """Detect if screen data is too limited for confident analysis."""
        if not ocr_text and not ui_elements and not screen_context and not image_hints:
            return True

        if len(_normalize_text(ocr_text)) < 8 and len(ui_elements) < 2:
            return True

        return False

    # -------------------------------------------------------------------------
    # Message / Suggestion Helpers
    # -------------------------------------------------------------------------

    def _build_detection_message(
        self,
        category: ErrorCategory,
        severity: ErrorSeverity,
        route_to: RoutedAgent,
        confidence: float,
        evidence: Sequence[ErrorEvidence],
    ) -> str:
        """Build clear detection message."""
        top_text = evidence[0].text if evidence else "No evidence text available"
        return (
            f"Detected {category.value} with {severity.value} severity. "
            f"Recommended route: {route_to.value}. "
            f"Confidence: {round(confidence, 4)}. "
            f"Top evidence: {top_text}"
        )

    def _build_suggested_actions(
        self,
        category: ErrorCategory,
        route_to: RoutedAgent,
        suggestion: str,
        evidence: Sequence[ErrorEvidence],
    ) -> List[str]:
        """Build suggested safe actions for next agent."""
        actions = [suggestion]

        if category == ErrorCategory.LOADING_STUCK:
            actions.append("Check whether the screen has been stuck for multiple observations before retrying.")
        elif category == ErrorCategory.FORM_VALIDATION_ERROR:
            actions.append("Inspect visible labels, required fields, and validation messages.")
        elif category in {ErrorCategory.SECURITY_WARNING, ErrorCategory.CAPTCHA_OR_BOT_CHECK, ErrorCategory.AUTOMATION_BLOCKED}:
            actions.append("Pause automation and request safe review before continuing.")
        elif category == ErrorCategory.SERVER_ERROR:
            actions.append("Attach page URL, timestamp, request context, and visible error text to Code Agent.")
        elif category == ErrorCategory.NETWORK_ERROR:
            actions.append("Check internet, DNS, VPN/proxy, firewall, and device connectivity.")
        elif category == ErrorCategory.BROWSER_ERROR:
            actions.append("Verify URL, reload once if safe, then inspect browser tab state.")
        else:
            actions.append(f"Send structured issue payload to {route_to.value} for next-step handling.")

        return actions

    def _default_title_for_category(self, category: ErrorCategory) -> str:
        """Default title if no pattern rule found."""
        return category.value.replace("_", " ").title()

    def _default_suggestion_for_category(
        self,
        category: ErrorCategory,
        route_to: RoutedAgent,
    ) -> str:
        """Default suggestion if no rule-specific suggestion found."""
        if route_to == RoutedAgent.NONE:
            return "No action required."
        return f"Route this structured visual issue to {route_to.value}."

    def _issue_code_for_category(self, category: ErrorCategory) -> str:
        """Default issue code."""
        return f"visual_{category.value}"

    def _find_pattern_rule_by_issue(self, issue_code: Optional[str]) -> Optional[ErrorPattern]:
        """Find pattern rule by issue code."""
        if not issue_code:
            return None

        for rule in ERROR_PATTERNS:
            if rule.issue_code == issue_code:
                return rule

        return None

    # -------------------------------------------------------------------------
    # Input Normalization
    # -------------------------------------------------------------------------

    def _extract_text(
        self,
        ocr_text: Optional[Union[str, Sequence[str], Mapping[str, Any]]],
        config: ErrorScreenDetectorConfig,
    ) -> str:
        """Extract text from OCR result formats."""
        if ocr_text is None:
            return ""

        parts: List[str] = []

        if isinstance(ocr_text, str):
            parts.append(ocr_text)

        elif isinstance(ocr_text, Mapping):
            for key in ("text", "raw_text", "clean_text", "full_text", "content", "ocr_text"):
                if ocr_text.get(key):
                    parts.append(str(ocr_text.get(key)))

            blocks = ocr_text.get("blocks") or ocr_text.get("lines") or ocr_text.get("items")
            for item in _as_list(blocks):
                if isinstance(item, Mapping):
                    value = item.get("text") or item.get("value") or item.get("label")
                    if value:
                        parts.append(str(value))
                elif item is not None:
                    parts.append(str(item))

        elif isinstance(ocr_text, Sequence):
            for item in ocr_text:
                if isinstance(item, Mapping):
                    value = item.get("text") or item.get("value") or item.get("label")
                    if value:
                        parts.append(str(value))
                elif item is not None:
                    parts.append(str(item))

        combined = "\n".join(parts)
        if len(combined) > config.max_text_length:
            combined = combined[: config.max_text_length] + "\n...[truncated]"

        return combined

    def _normalize_ui_elements(
        self,
        ui_elements: Optional[Sequence[Mapping[str, Any]]],
        config: ErrorScreenDetectorConfig,
    ) -> List[Dict[str, Any]]:
        """Normalize UI elements safely."""
        normalized: List[Dict[str, Any]] = []

        for item in list(ui_elements or [])[: config.max_ui_elements]:
            if not isinstance(item, Mapping):
                continue

            safe_item = _safe_jsonable(dict(item))
            if isinstance(safe_item, dict):
                normalized.append(safe_item)

        return normalized

    def _extract_bounds(self, element: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract bounds from UI element."""
        bounds = element.get("bounds") or element.get("bbox") or element.get("rect")
        if isinstance(bounds, Mapping):
            return _safe_jsonable(dict(bounds))

        keys = ("x", "y", "width", "height", "left", "top", "right", "bottom")
        found = {key: element.get(key) for key in keys if element.get(key) is not None}

        return _safe_jsonable(found) if found else None

    def _dedupe_evidence(self, evidence: Sequence[ErrorEvidence]) -> List[ErrorEvidence]:
        """Remove duplicate evidence entries."""
        seen = set()
        deduped: List[ErrorEvidence] = []

        for item in evidence:
            key = (
                item.evidence_type.value,
                item.category.value,
                item.pattern,
                _normalize_text(item.text)[:160],
                item.source,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        return deduped

    def _serialize_evidence(self, evidence: Sequence[ErrorEvidence]) -> List[Dict[str, Any]]:
        """Serialize evidence list."""
        output: List[Dict[str, Any]] = []

        for item in evidence[:MAX_EVIDENCE_ITEMS]:
            item_dict = asdict(item)
            item_dict["evidence_type"] = item.evidence_type.value
            item_dict["category"] = item.category.value
            item_dict["severity"] = item.severity.value
            item_dict["confidence"] = round(item.confidence, 4)
            output.append(_safe_jsonable(item_dict))

        return output

    # -------------------------------------------------------------------------
    # Context / Config / Security Hooks
    # -------------------------------------------------------------------------

    def _build_config(
        self,
        config: Optional[Union[ErrorScreenDetectorConfig, Mapping[str, Any]]],
        base: Optional[ErrorScreenDetectorConfig] = None,
    ) -> ErrorScreenDetectorConfig:
        """Build config from default/base/dict."""
        if config is None and base is not None:
            return ErrorScreenDetectorConfig(**asdict(base))

        if config is None:
            return ErrorScreenDetectorConfig()

        if isinstance(config, ErrorScreenDetectorConfig):
            return ErrorScreenDetectorConfig(**asdict(config))

        base_dict = asdict(base) if base is not None else asdict(ErrorScreenDetectorConfig())

        for key, value in dict(config).items():
            if key not in base_dict:
                continue

            if key == "default_route":
                try:
                    value = RoutedAgent(str(value))
                except Exception:
                    value = base_dict[key]

            base_dict[key] = value

        try:
            return ErrorScreenDetectorConfig(**base_dict)
        except Exception:
            self.logger.warning("Invalid ErrorScreenDetector config. Falling back to defaults.")
            return ErrorScreenDetectorConfig()

    def _coerce_context(
        self,
        context: Optional[Union[VisualErrorContext, Mapping[str, Any]]],
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str],
        screenshot_id: Optional[str],
        session_id: Optional[str],
        app_name: Optional[str],
        page_url: Optional[str],
        workflow_id: Optional[str],
        step_id: Optional[str],
        screenshot_metadata: Optional[Mapping[str, Any]],
    ) -> VisualErrorContext:
        """Coerce context into VisualErrorContext."""
        if isinstance(context, VisualErrorContext):
            if user_id:
                context.user_id = user_id
            if workspace_id:
                context.workspace_id = workspace_id
            if task_id:
                context.task_id = task_id
            if screenshot_id:
                context.screenshot_id = screenshot_id
            if session_id:
                context.session_id = session_id
            if app_name:
                context.app_name = app_name
            if page_url:
                context.page_url = page_url
            if workflow_id:
                context.workflow_id = workflow_id
            if step_id:
                context.step_id = step_id
            return context

        context_dict = dict(context or {})
        metadata = dict(context_dict.get("metadata") or {})
        if screenshot_metadata:
            metadata["screenshot_metadata"] = _safe_jsonable(dict(screenshot_metadata))

        return VisualErrorContext(
            user_id=str(user_id or context_dict.get("user_id") or ""),
            workspace_id=str(workspace_id or context_dict.get("workspace_id") or ""),
            task_id=task_id or context_dict.get("task_id"),
            screenshot_id=screenshot_id or context_dict.get("screenshot_id"),
            session_id=session_id or context_dict.get("session_id"),
            app_name=app_name or context_dict.get("app_name"),
            page_url=page_url or context_dict.get("page_url") or context_dict.get("url"),
            workflow_id=workflow_id or context_dict.get("workflow_id"),
            step_id=step_id or context_dict.get("step_id"),
            requested_by=context_dict.get("requested_by"),
            source=context_dict.get("source", "visual_agent"),
            correlation_id=context_dict.get("correlation_id") or str(uuid.uuid4()),
            metadata=_safe_jsonable(metadata),
        )

    def _validate_task_context(self, context: VisualErrorContext) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required compatibility hook.
        """
        errors: List[str] = []

        if not context.user_id or not str(context.user_id).strip():
            errors.append("user_id is required for visual error detection.")

        if not context.workspace_id or not str(context.workspace_id).strip():
            errors.append("workspace_id is required for visual error detection.")

        if errors:
            return self._error_result(
                message="Invalid visual error detection context.",
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
                "screenshot_id": context.screenshot_id,
                "session_id": context.session_id,
            },
            metadata={
                "agent": self.agent_name,
                "timestamp": _utc_now_iso(),
            },
        )

    def _requires_security_check(
        self,
        context: VisualErrorContext,
        ocr_text: str,
        ui_elements: Sequence[Mapping[str, Any]],
        screen_context: Mapping[str, Any],
        image_hints: Mapping[str, Any],
    ) -> bool:
        """
        Decide if Security Agent approval is required.

        Required compatibility hook.
        """
        if not self.config.enable_security_check:
            return False

        if _coerce_bool(context.metadata.get("force_security_check"), default=False):
            return True

        combined = _normalize_text({
            "ocr_text": ocr_text[:2000],
            "ui_elements": ui_elements[:20],
            "screen_context": screen_context,
            "image_hints": image_hints,
            "page_url": context.page_url,
            "app_name": context.app_name,
        })

        return any(keyword in combined for keyword in SENSITIVE_KEYWORDS)

    def _request_security_approval(
        self,
        action: str,
        context: VisualErrorContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Required compatibility hook.
        """
        approval_payload = {
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "screenshot_id": context.screenshot_id,
            "session_id": context.session_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
            "payload": _safe_jsonable(payload),
            "analysis_only": True,
            "requested_at": _utc_now_iso(),
        }

        agent = self.security_agent

        if agent is not None:
            for method_name in ("approve_action", "request_approval", "check_permission", "authorize"):
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
                        self.logger.warning("Security approval failed through %s: %s", method_name, exc)
                        return {
                            "approved": False,
                            "source": f"security_agent.{method_name}",
                            "error": str(exc),
                        }

        return {
            "approved": bool(self.config.fail_open_on_security_agent_missing),
            "source": "local_analysis_only_policy",
            "reason": (
                "Detector performs analysis only and does not expose or act on sensitive data."
            ),
        }

    # -------------------------------------------------------------------------
    # Verification / Memory / Event / Audit Hooks
    # -------------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        context: VisualErrorContext,
        detected_error: DetectedVisualError,
        routing_payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required compatibility hook.
        """
        return {
            "type": "visual_error_screen_detection",
            "agent": self.agent_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "screenshot_id": context.screenshot_id,
            "session_id": context.session_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
            "correlation_id": context.correlation_id,
            "detected": detected_error.detected,
            "status": detected_error.status.value,
            "category": detected_error.category.value,
            "severity": detected_error.severity.value,
            "confidence": round(detected_error.confidence, 4),
            "route_issue_to": detected_error.route_issue_to.value,
            "issue_code": detected_error.issue_code,
            "requires_security_review": detected_error.requires_security_review,
            "requires_human_review": detected_error.requires_human_review,
            "evidence_count": len(detected_error.evidence),
            "top_evidence": None if not detected_error.evidence else {
                "type": detected_error.evidence[0].evidence_type.value,
                "text": detected_error.evidence[0].text,
                "confidence": round(detected_error.evidence[0].confidence, 4),
            },
            "routing_issue_id": routing_payload.get("issue_id"),
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: VisualErrorContext,
        detected_error: DetectedVisualError,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Required compatibility hook.
        """
        return {
            "memory_type": "visual_error_screen_pattern",
            "scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "task_id": context.task_id,
            "session_id": context.session_id,
            "screenshot_id": context.screenshot_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
            "app_name": context.app_name,
            "page_url": context.page_url,
            "summary": {
                "detected": detected_error.detected,
                "status": detected_error.status.value,
                "category": detected_error.category.value,
                "severity": detected_error.severity.value,
                "confidence": round(detected_error.confidence, 4),
                "issue_code": detected_error.issue_code,
                "route_issue_to": detected_error.route_issue_to.value,
                "title": detected_error.title,
            },
            "importance": self._memory_importance(detected_error),
            "created_at": _utc_now_iso(),
        }

    def _memory_importance(self, detected_error: DetectedVisualError) -> str:
        """Determine memory importance."""
        if detected_error.severity in {ErrorSeverity.CRITICAL, ErrorSeverity.HIGH}:
            return "high"
        if detected_error.detected or detected_error.status == DetectionStatus.WARNING_DETECTED:
            return "medium"
        return "low"

    def _emit_agent_event(
        self,
        event_type: str,
        context: VisualErrorContext,
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
            "screenshot_id": context.screenshot_id,
            "session_id": context.session_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
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

        self.logger.debug("Agent event emitted locally: %s", _safe_jsonable(payload))

    def _log_audit_event(
        self,
        event_type: str,
        context: VisualErrorContext,
        result: Mapping[str, Any],
    ) -> None:
        """
        Log audit event.

        Required compatibility hook.
        """
        payload = {
            "event_type": event_type,
            "agent": self.agent_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "screenshot_id": context.screenshot_id,
            "session_id": context.session_id,
            "workflow_id": context.workflow_id,
            "step_id": context.step_id,
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

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standardized structured result.

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
        Return standardized structured error.

        Required compatibility hook.
        """
        return {
            "success": False,
            "message": str(message),
            "data": _safe_jsonable(data if data is not None else {}),
            "error": _safe_jsonable(error),
            "metadata": _safe_jsonable(metadata if metadata is not None else {}),
        }

    # -------------------------------------------------------------------------
    # Registry / Health
    # -------------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry compatible metadata."""
        return {
            "name": self.agent_name,
            "class_name": self.__class__.__name__,
            "version": self.version,
            "module": "agents.visual_agent.error_screen_detector",
            "capabilities": self.capabilities,
            "public_methods": [
                "detect_error_screen",
                "detect",
                "classify_visual_error",
                "route_detected_issue",
                "prepare_dashboard_payload",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "executes_real_actions": False,
            "safe_to_import": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """Lightweight health check for API/dashboard readiness."""
        return self._safe_result(
            success=True,
            message="ErrorScreenDetector is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.version,
                "capabilities": self.capabilities,
                "pattern_count": len(ERROR_PATTERNS),
                "config": _safe_jsonable(asdict(self.config)),
            },
            metadata={
                "timestamp": _utc_now_iso(),
            },
        )

    def _elapsed_ms(self, started_at: float) -> float:
        """Return elapsed milliseconds."""
        return round((time.time() - started_at) * 1000.0, 3)


# =============================================================================
# Module-Level Convenience Function
# =============================================================================

def detect_error_screen(
    ocr_text: Optional[Union[str, Sequence[str], Mapping[str, Any]]] = None,
    ui_elements: Optional[Sequence[Mapping[str, Any]]] = None,
    screen_context: Optional[Mapping[str, Any]] = None,
    image_hints: Optional[Mapping[str, Any]] = None,
    screenshot_metadata: Optional[Mapping[str, Any]] = None,
    user_id: str = "",
    workspace_id: str = "",
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Convenience function for direct module usage.

    Example:
        result = detect_error_screen(
            ocr_text="500 Internal Server Error",
            user_id="user_123",
            workspace_id="workspace_123",
        )
    """
    detector = ErrorScreenDetector()
    return detector.detect_error_screen(
        ocr_text=ocr_text,
        ui_elements=ui_elements,
        screen_context=screen_context,
        image_hints=image_hints,
        screenshot_metadata=screenshot_metadata,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


__all__ = [
    "ErrorScreenDetector",
    "VisualErrorContext",
    "ErrorEvidence",
    "DetectedVisualError",
    "ErrorScreenDetectorConfig",
    "ErrorPattern",
    "ErrorCategory",
    "ErrorSeverity",
    "RoutedAgent",
    "DetectionStatus",
    "EvidenceType",
    "detect_error_screen",
]


# =============================================================================
# Safe Manual Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    detector = ErrorScreenDetector()

    demo_result = detector.detect_error_screen(
        ocr_text="""
        This page isn't working.
        example.com is currently unable to handle this request.
        HTTP ERROR 500
        """,
        ui_elements=[
            {
                "text": "HTTP ERROR 500",
                "role": "alert",
                "bounds": {"x": 100, "y": 200, "width": 500, "height": 60},
                "visible": True,
            }
        ],
        screen_context={
            "app_name": "Chrome",
            "url": "https://example.com/dashboard",
            "status": "error",
        },
        image_hints={
            "state": "error",
            "flags": ["warning_icon_visible"],
        },
        screenshot_metadata={
            "width": 1920,
            "height": 1080,
        },
        user_id="demo_user",
        workspace_id="demo_workspace",
        task_id="demo_task",
        screenshot_id="demo_screenshot",
        app_name="Chrome",
        page_url="https://example.com/dashboard",
    )

    print(json.dumps(demo_result, indent=2, default=str))