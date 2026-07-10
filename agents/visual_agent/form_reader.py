"""
agents/visual_agent/form_reader.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix
Visual Agent Helper: Form Reader

Purpose:
    Reads forms, labels, required fields, validation errors, submit controls,
    reset controls, input types, field groups, and form completion state from
    OCR text, UI element maps, screenshots metadata, browser DOM-like payloads,
    and structured visual analysis results.

Architecture Notes:
    - Import-safe even when future William/Jarvis modules are not available.
    - Compatible with BaseAgent-style construction where available.
    - Enforces SaaS user/workspace isolation through task context validation.
    - Does not perform real clicks, typing, browser actions, file actions,
      calls, messages, financial actions, or destructive actions.
    - Prepares Verification Agent and Memory Agent compatible payloads.
    - Emits audit/event payloads for dashboard/API integration.
    - Designed for Master Agent, Visual Agent, Workflow Agent, Browser Agent,
      Verification Agent, and Agent Registry usage.

Public Class:
    FormReader
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent can replace this automatically later.
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
# Constants
# ---------------------------------------------------------------------------

UTC = timezone.utc

DEFAULT_AGENT_NAME = "FormReader"
DEFAULT_CONFIDENCE_THRESHOLD = 0.45
MAX_TEXT_CHARS_DEFAULT = 180_000
MAX_FORMS_DEFAULT = 50
MAX_FIELDS_DEFAULT = 300
MAX_ERRORS_DEFAULT = 100
MAX_EVIDENCE_CHARS = 800


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FormReadStatus(str, Enum):
    """High-level status for form reading result."""

    FORM_DETECTED = "form_detected"
    NO_FORM_DETECTED = "no_form_detected"
    PARTIAL_FORM_DETECTED = "partial_form_detected"
    INCONCLUSIVE = "inconclusive"


class FormFieldType(str, Enum):
    """Normalized form field types."""

    TEXT = "text"
    EMAIL = "email"
    PHONE = "phone"
    PASSWORD = "password"
    NUMBER = "number"
    DATE = "date"
    TIME = "time"
    DATETIME = "datetime"
    URL = "url"
    SEARCH = "search"
    TEXTAREA = "textarea"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    FILE = "file"
    HIDDEN = "hidden"
    OTP = "otp"
    CAPTCHA = "captcha"
    CONSENT = "consent"
    ADDRESS = "address"
    CITY = "city"
    STATE = "state"
    ZIP = "zip"
    COUNTRY = "country"
    NAME = "name"
    FIRST_NAME = "first_name"
    LAST_NAME = "last_name"
    COMPANY = "company"
    UNKNOWN = "unknown"


class FormControlType(str, Enum):
    """Normalized form control types."""

    SUBMIT = "submit"
    RESET = "reset"
    CANCEL = "cancel"
    NEXT = "next"
    BACK = "back"
    SAVE = "save"
    CONTINUE = "continue"
    UNKNOWN = "unknown"


class ValidationSeverity(str, Enum):
    """Validation issue severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Rect:
    """
    UI rectangle/bounds.

    Coordinates are intentionally generic so this file works with screenshots,
    web DOM, mobile UI dumps, OCR boxes, or element detector output.
    """

    x: Optional[float] = None
    y: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None
    left: Optional[float] = None
    top: Optional[float] = None
    right: Optional[float] = None
    bottom: Optional[float] = None

    def to_dict(self) -> Dict[str, Optional[float]]:
        """Return JSON-safe rectangle."""
        return asdict(self)


@dataclass
class FormField:
    """Detected form field."""

    field_id: str
    label: str
    field_type: str
    required: bool = False
    visible: bool = True
    enabled: bool = True
    placeholder: str = ""
    value_preview: str = ""
    name: str = ""
    element_id: str = ""
    autocomplete: str = ""
    aria_label: str = ""
    help_text: str = ""
    validation_error: str = ""
    confidence: float = 0.0
    bounds: Optional[Rect] = None
    source: str = "unknown"
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-safe dict."""
        data = asdict(self)
        if self.bounds:
            data["bounds"] = self.bounds.to_dict()
        return data


@dataclass
class SubmitControl:
    """Detected submit/reset/navigation control."""

    control_id: str
    text: str
    control_type: str
    enabled: bool = True
    visible: bool = True
    confidence: float = 0.0
    bounds: Optional[Rect] = None
    source: str = "unknown"
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-safe dict."""
        data = asdict(self)
        if self.bounds:
            data["bounds"] = self.bounds.to_dict()
        return data


@dataclass
class ValidationIssue:
    """Detected form validation issue."""

    issue_id: str
    message: str
    severity: str
    related_label: str = ""
    related_field_id: str = ""
    confidence: float = 0.0
    source: str = "unknown"
    evidence: str = ""
    bounds: Optional[Rect] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-safe dict."""
        data = asdict(self)
        if self.bounds:
            data["bounds"] = self.bounds.to_dict()
        return data


@dataclass
class FormStructure:
    """Detected form structure."""

    form_id: str
    title: str = ""
    description: str = ""
    fields: List[FormField] = field(default_factory=list)
    submit_controls: List[SubmitControl] = field(default_factory=list)
    validation_issues: List[ValidationIssue] = field(default_factory=list)
    required_field_count: int = 0
    missing_required_count: int = 0
    has_submit: bool = False
    has_validation_errors: bool = False
    confidence: float = 0.0
    source: str = "unknown"
    bounds: Optional[Rect] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-safe dict."""
        data = asdict(self)
        data["fields"] = [field_item.to_dict() for field_item in self.fields]
        data["submit_controls"] = [control.to_dict() for control in self.submit_controls]
        data["validation_issues"] = [issue.to_dict() for issue in self.validation_issues]
        if self.bounds:
            data["bounds"] = self.bounds.to_dict()
        return data


@dataclass
class FormReaderConfig:
    """Runtime configuration for FormReader."""

    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    max_text_chars: int = MAX_TEXT_CHARS_DEFAULT
    max_forms: int = MAX_FORMS_DEFAULT
    max_fields: int = MAX_FIELDS_DEFAULT
    max_errors: int = MAX_ERRORS_DEFAULT
    require_user_workspace: bool = True
    enable_audit_logging: bool = True
    enable_event_emit: bool = True
    redact_sensitive_values: bool = True
    include_low_confidence: bool = False
    infer_required_from_asterisk: bool = True
    infer_field_type_from_label: bool = True
    infer_submit_from_button_text: bool = True
    event_namespace: str = "visual.form_reader"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp."""
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
    """Safely convert value to float."""
    try:
        return float(value)
    except Exception:
        return default


def _safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert common bool-like values."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = _safe_str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "required", "checked", "selected", "enabled"}:
        return True
    if text in {"false", "0", "no", "n", "disabled", "unchecked", "none"}:
        return False
    return default


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Clamp float into a range."""
    return max(minimum, min(maximum, value))


def _truncate(text: str, max_chars: int) -> str:
    """Truncate text safely."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars]


def _normalize_space(text: str) -> str:
    """Normalize whitespace."""
    return re.sub(r"\s+", " ", _safe_str(text)).strip()


def _clean_label(text: str) -> str:
    """Clean label-like text."""
    cleaned = _normalize_space(text)
    cleaned = re.sub(r"[:：]+$", "", cleaned).strip()
    cleaned = re.sub(r"\s+\*$", " *", cleaned).strip()
    return cleaned


def _looks_sensitive_key(key: str) -> bool:
    """Detect sensitive key names."""
    key_l = key.lower()
    return any(
        token in key_l
        for token in (
            "password",
            "passcode",
            "secret",
            "token",
            "authorization",
            "cookie",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "card_number",
            "cvv",
            "ssn",
        )
    )


def _redact_text(text: str) -> str:
    """Redact sensitive values from evidence and previews."""
    if not text:
        return text

    redacted = text

    patterns = [
        (r"(?i)(password\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(passcode\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(token\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,'\"]+", r"\1[REDACTED]"),
        (r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+", r"\1[REDACTED]"),
        (r"(?i)(cookie\s*:\s*)[^\n\r]+", r"\1[REDACTED]"),
        (r"\b\d{13,19}\b", "[REDACTED_CARD_LIKE_NUMBER]"),
    ]

    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted)

    return redacted


def _json_safe(value: Any) -> Any:
    """Convert arbitrary values to JSON-safe structures."""
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


def _dedupe_text_key(text: str) -> str:
    """Create simple dedupe key from text."""
    return re.sub(r"[^a-z0-9]+", "", _safe_str(text).lower())


def _extract_rect(payload: Mapping[str, Any]) -> Optional[Rect]:
    """
    Extract rectangle from common UI-map/DOM/OCR payload formats.

    Supported:
        bounds: {x, y, width, height}
        bbox: [x, y, w, h]
        rect: {left, top, right, bottom}
        x/y/width/height
        left/top/right/bottom
    """
    if not isinstance(payload, Mapping):
        return None

    candidate = None
    for key in ("bounds", "bbox", "box", "rect", "bounding_box"):
        if key in payload:
            candidate = payload.get(key)
            break

    if isinstance(candidate, Mapping):
        x = candidate.get("x")
        y = candidate.get("y")
        width = candidate.get("width", candidate.get("w"))
        height = candidate.get("height", candidate.get("h"))
        left = candidate.get("left", x)
        top = candidate.get("top", y)
        right = candidate.get("right")
        bottom = candidate.get("bottom")

        if right is None and x is not None and width is not None:
            right = _safe_float(x) + _safe_float(width)
        if bottom is None and y is not None and height is not None:
            bottom = _safe_float(y) + _safe_float(height)

        return Rect(
            x=_optional_float(x),
            y=_optional_float(y),
            width=_optional_float(width),
            height=_optional_float(height),
            left=_optional_float(left),
            top=_optional_float(top),
            right=_optional_float(right),
            bottom=_optional_float(bottom),
        )

    if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes, bytearray)):
        values = list(candidate)
        if len(values) >= 4:
            x = _optional_float(values[0])
            y = _optional_float(values[1])
            width = _optional_float(values[2])
            height = _optional_float(values[3])
            return Rect(
                x=x,
                y=y,
                width=width,
                height=height,
                left=x,
                top=y,
                right=(x + width) if x is not None and width is not None else None,
                bottom=(y + height) if y is not None and height is not None else None,
            )

    direct_keys = ("x", "y", "width", "height", "left", "top", "right", "bottom")
    if any(key in payload for key in direct_keys):
        x = _optional_float(payload.get("x"))
        y = _optional_float(payload.get("y"))
        width = _optional_float(payload.get("width", payload.get("w")))
        height = _optional_float(payload.get("height", payload.get("h")))
        left = _optional_float(payload.get("left", x))
        top = _optional_float(payload.get("top", y))
        right = _optional_float(payload.get("right"))
        bottom = _optional_float(payload.get("bottom"))

        if right is None and x is not None and width is not None:
            right = x + width
        if bottom is None and y is not None and height is not None:
            bottom = y + height

        return Rect(
            x=x,
            y=y,
            width=width,
            height=height,
            left=left,
            top=top,
            right=right,
            bottom=bottom,
        )

    return None


def _optional_float(value: Any) -> Optional[float]:
    """Return float or None."""
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

REQUIRED_WORDS = (
    "required",
    "mandatory",
    "must be filled",
    "cannot be blank",
    "can't be blank",
    "is needed",
    "is required",
)

VALIDATION_ERROR_PATTERNS: Tuple[Tuple[str, str, ValidationSeverity, float], ...] = (
    (r"\b(required field|required|this field is required|please fill out this field|must be filled)\b", "Required field validation error.", ValidationSeverity.HIGH, 0.88),
    (r"\b(invalid email|email is invalid|enter a valid email|valid email address)\b", "Invalid email validation error.", ValidationSeverity.HIGH, 0.9),
    (r"\b(invalid phone|phone is invalid|enter a valid phone|valid phone number)\b", "Invalid phone validation error.", ValidationSeverity.HIGH, 0.88),
    (r"\b(password.*too short|password.*minimum|passwords do not match|confirm password)\b", "Password validation error.", ValidationSeverity.HIGH, 0.86),
    (r"\b(invalid url|enter a valid url|valid website|valid link)\b", "URL validation error.", ValidationSeverity.MEDIUM, 0.84),
    (r"\b(invalid date|date is invalid|select a date|choose a date)\b", "Date validation error.", ValidationSeverity.MEDIUM, 0.82),
    (r"\b(please select|select an option|choose an option|must select)\b", "Select/dropdown validation error.", ValidationSeverity.MEDIUM, 0.82),
    (r"\b(file.*required|upload.*required|please upload|invalid file type|file too large)\b", "File upload validation error.", ValidationSeverity.MEDIUM, 0.84),
    (r"\b(captcha|recaptcha|verify that you are human|human verification)\b", "CAPTCHA or human verification prompt detected.", ValidationSeverity.MEDIUM, 0.78),
    (r"\b(terms.*required|accept.*terms|agree.*terms|privacy policy.*required)\b", "Consent/terms validation error.", ValidationSeverity.HIGH, 0.86),
)

SUBMIT_TEXT_PATTERNS: Tuple[Tuple[str, FormControlType, float], ...] = (
    (r"^\s*(submit|send|send message|save|save changes|create|update|apply|confirm|register|sign up|signup|log in|login|continue|next|finish|complete|book now|get quote|request quote|start|search|place order|checkout|pay now)\s*$", FormControlType.SUBMIT, 0.88),
    (r"^\s*(reset|clear|clear form|start over)\s*$", FormControlType.RESET, 0.86),
    (r"^\s*(cancel|close|discard)\s*$", FormControlType.CANCEL, 0.8),
    (r"^\s*(next|continue)\s*$", FormControlType.NEXT, 0.82),
    (r"^\s*(back|previous)\s*$", FormControlType.BACK, 0.8),
)

FIELD_TYPE_KEYWORDS: Tuple[Tuple[FormFieldType, Tuple[str, ...]], ...] = (
    (FormFieldType.EMAIL, ("email", "e-mail")),
    (FormFieldType.PHONE, ("phone", "mobile", "tel", "telephone", "contact number", "whatsapp")),
    (FormFieldType.PASSWORD, ("password", "passcode", "pin")),
    (FormFieldType.NUMBER, ("number", "quantity", "amount", "price", "budget", "age")),
    (FormFieldType.DATE, ("date", "dob", "birth date", "birthday")),
    (FormFieldType.TIME, ("time",)),
    (FormFieldType.URL, ("website", "url", "link", "domain")),
    (FormFieldType.SEARCH, ("search",)),
    (FormFieldType.TEXTAREA, ("message", "comment", "description", "details", "notes", "project message")),
    (FormFieldType.SELECT, ("select", "choose", "dropdown", "option")),
    (FormFieldType.CHECKBOX, ("checkbox", "agree", "terms", "consent")),
    (FormFieldType.RADIO, ("radio",)),
    (FormFieldType.FILE, ("file", "upload", "attachment", "resume", "cv")),
    (FormFieldType.OTP, ("otp", "verification code", "one time password")),
    (FormFieldType.CAPTCHA, ("captcha", "recaptcha", "human verification")),
    (FormFieldType.ADDRESS, ("address", "street")),
    (FormFieldType.CITY, ("city",)),
    (FormFieldType.STATE, ("state", "province", "region")),
    (FormFieldType.ZIP, ("zip", "postal", "postcode")),
    (FormFieldType.COUNTRY, ("country",)),
    (FormFieldType.FIRST_NAME, ("first name", "firstname")),
    (FormFieldType.LAST_NAME, ("last name", "lastname")),
    (FormFieldType.NAME, ("name", "full name")),
    (FormFieldType.COMPANY, ("company", "business name", "organization", "organisation")),
)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class FormReader(BaseAgent):
    """
    Reads and summarizes form structures from visual/DOM/OCR payloads.

    How it connects:
        - Master Agent:
            Can route visual form understanding tasks to this class.
        - Visual Agent:
            Uses this helper after OCR, UI mapping, element detection, image
            analysis, or screen context detection.
        - Browser Agent:
            Can pass DOM-like element payloads for form reading.
        - Workflow Agent:
            Can use detected form fields to build safe automation recipes.
        - Security Agent:
            Approval hook exists for sensitive form data contexts.
        - Verification Agent:
            Receives verification payload to confirm whether a form was found
            and whether validation errors/blocking issues exist.
        - Memory Agent:
            Receives compact, redacted form schema context for future workflows.
        - Dashboard/API:
            Structured JSON result is ready for FastAPI responses.
        - Registry/Loader:
            Stable class name and metadata factory are included.
    """

    agent_type = "visual_agent_helper"
    capability = "form_reading"
    public_methods = (
        "read_form",
        "read_from_text",
        "read_from_elements",
        "read_from_dom",
        "read_from_visual_payload",
        "extract_validation_errors",
        "extract_submit_controls",
        "summarize_forms",
    )

    def __init__(
        self,
        config: Optional[Union[FormReaderConfig, Mapping[str, Any]]] = None,
        security_agent: Any = None,
        audit_logger: Any = None,
        event_bus: Any = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize FormReader.

        Args:
            config: Optional FormReaderConfig or dict.
            security_agent: Optional Security Agent instance.
            audit_logger: Optional audit logger instance.
            event_bus: Optional event bus instance.
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read_form(
        self,
        task_context: Mapping[str, Any],
        *,
        text: Optional[str] = None,
        elements: Optional[Sequence[Mapping[str, Any]]] = None,
        dom: Optional[Mapping[str, Any]] = None,
        visual_payload: Optional[Mapping[str, Any]] = None,
        source: str = "mixed",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read forms from mixed input sources.

        Args:
            task_context: Must include user_id/workspace_id for SaaS isolation.
            text: OCR or page text.
            elements: UI element detector / UI mapper list.
            dom: Browser/DOM-like payload.
            visual_payload: Combined output from Visual Agent helpers.
            source: Logical source name.
            metadata: Extra dashboard/API metadata.

        Returns:
            Standard William/Jarvis structured result.
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)
        safe_metadata = dict(metadata or {})

        if self._requires_security_check(task_context, operation="read_form", metadata=safe_metadata):
            approval = self._request_security_approval(
                task_context,
                operation="read_form",
                metadata=safe_metadata,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for form reading.",
                    code="security_approval_denied",
                    data={"approved": False, "reason": approval.get("reason")},
                    metadata=self._base_metadata(task_context, request_id, started_at),
                )

        try:
            all_forms: List[FormStructure] = []
            all_fields: List[FormField] = []
            all_controls: List[SubmitControl] = []
            all_issues: List[ValidationIssue] = []

            if text is not None:
                result = self.read_from_text(
                    task_context,
                    text=text,
                    source=source if source != "mixed" else "text",
                    metadata=safe_metadata,
                )
                forms = self._forms_from_result(result)
                all_forms.extend(forms)

            if elements is not None:
                result = self.read_from_elements(
                    task_context,
                    elements=elements,
                    source=source if source != "mixed" else "elements",
                    metadata=safe_metadata,
                )
                forms = self._forms_from_result(result)
                all_forms.extend(forms)

            if dom is not None:
                result = self.read_from_dom(
                    task_context,
                    dom=dom,
                    source=source if source != "mixed" else "dom",
                    metadata=safe_metadata,
                )
                forms = self._forms_from_result(result)
                all_forms.extend(forms)

            if visual_payload is not None:
                result = self.read_from_visual_payload(
                    task_context,
                    visual_payload=visual_payload,
                    source=source if source != "mixed" else "visual_payload",
                    metadata=safe_metadata,
                )
                forms = self._forms_from_result(result)
                all_forms.extend(forms)

            all_forms = self._merge_forms(all_forms, source=source)
            all_forms = self._filter_forms(all_forms)[: self.config.max_forms]

            for form in all_forms:
                all_fields.extend(form.fields)
                all_controls.extend(form.submit_controls)
                all_issues.extend(form.validation_issues)

            summary = self.summarize_forms(all_forms)
            status = self._status_for_forms(all_forms)

            verification_payload = self._prepare_verification_payload(
                task_context,
                forms=all_forms,
                summary=summary,
                source=source,
            )
            memory_payload = self._prepare_memory_payload(
                task_context,
                forms=all_forms,
                summary=summary,
            )

            result = self._safe_result(
                success=True,
                message=(
                    f"Detected {len(all_forms)} form structure(s)."
                    if all_forms
                    else "No form structure detected."
                ),
                data={
                    "status": status.value,
                    "form_count": len(all_forms),
                    "field_count": len(all_fields),
                    "submit_control_count": len(all_controls),
                    "validation_issue_count": len(all_issues),
                    "forms": [form.to_dict() for form in all_forms],
                    "summary": summary,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

            self._emit_agent_event(
                "forms_read",
                task_context,
                data={
                    "status": status.value,
                    "form_count": len(all_forms),
                    "field_count": len(all_fields),
                    "validation_issue_count": len(all_issues),
                },
            )
            self._log_audit_event(
                task_context,
                action="read_form",
                outcome="success",
                data={
                    "form_count": len(all_forms),
                    "field_count": len(all_fields),
                    "validation_issue_count": len(all_issues),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Form reading failed.")
            return self._error_result(
                message="FormReader failed while reading form data.",
                code="form_reader_failure",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def read_from_text(
        self,
        task_context: Mapping[str, Any],
        *,
        text: str,
        source: str = "text",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read form structure from OCR/page text.

        This method is useful when screenshot_reader.py or ocr_engine.py returns
        text but not element bounds.
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            clean_text = _truncate(_safe_str(text), self.config.max_text_chars)
            if self.config.redact_sensitive_values:
                clean_text_for_evidence = _redact_text(clean_text)
            else:
                clean_text_for_evidence = clean_text

            fields = self._extract_fields_from_text(clean_text_for_evidence, source=source, metadata=metadata)
            controls = self._extract_submit_controls_from_text(clean_text_for_evidence, source=source, metadata=metadata)
            issues = self._extract_validation_errors_from_text(clean_text_for_evidence, source=source, metadata=metadata)

            forms: List[FormStructure] = []
            if fields or controls or issues:
                forms.append(
                    self._build_form_structure(
                        fields=fields,
                        controls=controls,
                        issues=issues,
                        title=self._infer_form_title_from_text(clean_text_for_evidence),
                        description="",
                        source=source,
                        confidence=self._estimate_form_confidence(fields, controls, issues),
                        metadata=dict(metadata or {}),
                    )
                )

            forms = self._filter_forms(forms)
            summary = self.summarize_forms(forms)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(forms)} form structure(s) from text."
                    if forms
                    else "No form structure detected from text."
                ),
                data={
                    "status": self._status_for_forms(forms).value,
                    "form_count": len(forms),
                    "forms": [form.to_dict() for form in forms],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to read form from text.",
                code="text_form_read_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def read_from_elements(
        self,
        task_context: Mapping[str, Any],
        *,
        elements: Sequence[Mapping[str, Any]],
        source: str = "elements",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read form structure from UI mapper / element detector output.

        Expected element keys may include:
            text, label, type, role, tag, input_type, required, placeholder,
            value, aria_label, id, name, bounds, enabled, visible, error
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            normalized_elements = self._normalize_elements(elements)
            fields = self._extract_fields_from_elements(normalized_elements, source=source, metadata=metadata)
            controls = self._extract_submit_controls_from_elements(normalized_elements, source=source, metadata=metadata)
            issues = self._extract_validation_errors_from_elements(normalized_elements, source=source, metadata=metadata)

            grouped_forms = self._group_forms_from_elements(
                normalized_elements,
                fields=fields,
                controls=controls,
                issues=issues,
                source=source,
                metadata=dict(metadata or {}),
            )

            grouped_forms = self._filter_forms(grouped_forms)
            summary = self.summarize_forms(grouped_forms)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(grouped_forms)} form structure(s) from UI elements."
                    if grouped_forms
                    else "No form structure detected from UI elements."
                ),
                data={
                    "status": self._status_for_forms(grouped_forms).value,
                    "form_count": len(grouped_forms),
                    "forms": [form.to_dict() for form in grouped_forms],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to read form from UI elements.",
                code="element_form_read_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def read_from_dom(
        self,
        task_context: Mapping[str, Any],
        *,
        dom: Mapping[str, Any],
        source: str = "dom",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read form structure from DOM-like browser payload.

        Supported payload shapes:
            {
                "forms": [
                    {
                        "title": "...",
                        "fields": [...],
                        "buttons": [...],
                        "errors": [...]
                    }
                ]
            }

            or

            {
                "elements": [...]
            }
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            forms: List[FormStructure] = []

            raw_forms = dom.get("forms")
            if isinstance(raw_forms, Sequence) and not isinstance(raw_forms, (str, bytes, bytearray)):
                for raw_form in raw_forms:
                    if not isinstance(raw_form, Mapping):
                        continue

                    form_fields_raw = raw_form.get("fields") or raw_form.get("inputs") or raw_form.get("controls") or []
                    form_buttons_raw = raw_form.get("buttons") or raw_form.get("submit_controls") or []
                    form_errors_raw = raw_form.get("errors") or raw_form.get("validation_errors") or []

                    fields = self._extract_fields_from_elements(
                        self._normalize_elements(form_fields_raw),
                        source=source,
                        metadata=metadata,
                    )
                    controls = self._extract_submit_controls_from_elements(
                        self._normalize_elements(form_buttons_raw),
                        source=source,
                        metadata=metadata,
                    )
                    issues = self._extract_validation_errors_from_elements(
                        self._normalize_elements(form_errors_raw),
                        source=source,
                        metadata=metadata,
                    )

                    form = self._build_form_structure(
                        fields=fields,
                        controls=controls,
                        issues=issues,
                        title=_safe_str(raw_form.get("title") or raw_form.get("name") or raw_form.get("aria_label") or ""),
                        description=_safe_str(raw_form.get("description") or ""),
                        source=source,
                        confidence=self._estimate_form_confidence(fields, controls, issues, dom_hint=True),
                        bounds=_extract_rect(raw_form),
                        metadata={
                            "form_dom_id": raw_form.get("id"),
                            "form_name": raw_form.get("name"),
                            "action": raw_form.get("action"),
                            "method": raw_form.get("method"),
                            **dict(metadata or {}),
                        },
                    )
                    forms.append(form)

            if not forms and isinstance(dom.get("elements"), Sequence):
                element_result = self.read_from_elements(
                    task_context,
                    elements=dom.get("elements", []),
                    source=source,
                    metadata=metadata,
                )
                forms = self._forms_from_result(element_result)

            if not forms and isinstance(dom.get("text"), str):
                text_result = self.read_from_text(
                    task_context,
                    text=_safe_str(dom.get("text")),
                    source=source,
                    metadata=metadata,
                )
                forms = self._forms_from_result(text_result)

            forms = self._filter_forms(forms)
            summary = self.summarize_forms(forms)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(forms)} form structure(s) from DOM payload."
                    if forms
                    else "No form structure detected from DOM payload."
                ),
                data={
                    "status": self._status_for_forms(forms).value,
                    "form_count": len(forms),
                    "forms": [form.to_dict() for form in forms],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to read form from DOM payload.",
                code="dom_form_read_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def read_from_visual_payload(
        self,
        task_context: Mapping[str, Any],
        *,
        visual_payload: Mapping[str, Any],
        source: str = "visual_payload",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read forms from a combined Visual Agent payload.

        Supports payloads from screenshot_reader, ocr_engine, ui_mapper,
        element_detector, screen_context, image_analyzer, or visual_agent.
        """
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            forms: List[FormStructure] = []

            candidate_text = (
                visual_payload.get("text")
                or visual_payload.get("ocr_text")
                or visual_payload.get("screen_text")
                or visual_payload.get("page_text")
                or visual_payload.get("extracted_text")
            )
            candidate_elements = (
                visual_payload.get("elements")
                or visual_payload.get("ui_elements")
                or visual_payload.get("detected_elements")
                or visual_payload.get("nodes")
                or visual_payload.get("components")
            )
            candidate_dom = visual_payload.get("dom") or visual_payload.get("browser_dom")

            if isinstance(candidate_dom, Mapping):
                dom_result = self.read_from_dom(
                    task_context,
                    dom=candidate_dom,
                    source=source,
                    metadata=metadata,
                )
                forms.extend(self._forms_from_result(dom_result))

            if isinstance(candidate_elements, Sequence) and not isinstance(candidate_elements, (str, bytes, bytearray)):
                elements_result = self.read_from_elements(
                    task_context,
                    elements=candidate_elements,
                    source=source,
                    metadata=metadata,
                )
                forms.extend(self._forms_from_result(elements_result))

            if isinstance(candidate_text, str):
                text_result = self.read_from_text(
                    task_context,
                    text=candidate_text,
                    source=source,
                    metadata=metadata,
                )
                forms.extend(self._forms_from_result(text_result))

            forms = self._merge_forms(forms, source=source)
            forms = self._filter_forms(forms)
            summary = self.summarize_forms(forms)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(forms)} form structure(s) from visual payload."
                    if forms
                    else "No form structure detected from visual payload."
                ),
                data={
                    "status": self._status_for_forms(forms).value,
                    "form_count": len(forms),
                    "forms": [form.to_dict() for form in forms],
                    "summary": summary,
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to read form from visual payload.",
                code="visual_payload_form_read_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def extract_validation_errors(
        self,
        task_context: Mapping[str, Any],
        *,
        text: Optional[str] = None,
        elements: Optional[Sequence[Mapping[str, Any]]] = None,
        source: str = "validation",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Extract only validation errors from text and/or elements."""
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            issues: List[ValidationIssue] = []

            if text:
                issues.extend(
                    self._extract_validation_errors_from_text(
                        _safe_str(text),
                        source=source,
                        metadata=metadata,
                    )
                )

            if elements:
                issues.extend(
                    self._extract_validation_errors_from_elements(
                        self._normalize_elements(elements),
                        source=source,
                        metadata=metadata,
                    )
                )

            issues = self._dedupe_issues(issues)[: self.config.max_errors]

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(issues)} validation issue(s)."
                    if issues
                    else "No validation errors detected."
                ),
                data={
                    "validation_issue_count": len(issues),
                    "validation_issues": [issue.to_dict() for issue in issues],
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to extract validation errors.",
                code="validation_error_extract_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def extract_submit_controls(
        self,
        task_context: Mapping[str, Any],
        *,
        text: Optional[str] = None,
        elements: Optional[Sequence[Mapping[str, Any]]] = None,
        source: str = "submit_controls",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Extract submit/reset/navigation controls only."""
        started_at = time.monotonic()
        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        request_id = self._request_id(task_context)

        try:
            controls: List[SubmitControl] = []

            if text:
                controls.extend(
                    self._extract_submit_controls_from_text(
                        _safe_str(text),
                        source=source,
                        metadata=metadata,
                    )
                )

            if elements:
                controls.extend(
                    self._extract_submit_controls_from_elements(
                        self._normalize_elements(elements),
                        source=source,
                        metadata=metadata,
                    )
                )

            controls = self._dedupe_controls(controls)

            return self._safe_result(
                success=True,
                message=(
                    f"Detected {len(controls)} submit/control button(s)."
                    if controls
                    else "No submit/control button detected."
                ),
                data={
                    "submit_control_count": len(controls),
                    "submit_controls": [control.to_dict() for control in controls],
                },
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to extract submit controls.",
                code="submit_control_extract_failed",
                error=exc,
                metadata=self._base_metadata(task_context, request_id, started_at),
            )

    def summarize_forms(
        self,
        forms: Union[Sequence[FormStructure], Sequence[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Create compact summary for dashboard, Memory Agent, and Verification Agent."""
        normalized = self._normalize_forms_input(forms)

        total_fields = 0
        required_fields = 0
        missing_required = 0
        submit_controls = 0
        validation_issues = 0
        field_types: Dict[str, int] = {}
        labels: List[str] = []
        error_messages: List[str] = []

        highest_confidence = 0.0
        has_submit = False
        has_validation_errors = False

        for form in normalized:
            form_fields = form.get("fields", []) or []
            form_controls = form.get("submit_controls", []) or []
            form_issues = form.get("validation_issues", []) or []

            total_fields += len(form_fields)
            submit_controls += len(form_controls)
            validation_issues += len(form_issues)
            highest_confidence = max(highest_confidence, _safe_float(form.get("confidence", 0.0)))

            if form_controls or form.get("has_submit"):
                has_submit = True
            if form_issues or form.get("has_validation_errors"):
                has_validation_errors = True

            for field_item in form_fields:
                if not isinstance(field_item, Mapping):
                    continue
                field_type = _safe_str(field_item.get("field_type", FormFieldType.UNKNOWN.value))
                field_types[field_type] = field_types.get(field_type, 0) + 1
                if field_item.get("required"):
                    required_fields += 1
                label = _safe_str(field_item.get("label", ""))
                if label and label not in labels and len(labels) < 30:
                    labels.append(label)
                if field_item.get("required") and not _safe_str(field_item.get("value_preview", "")).strip():
                    missing_required += 1

            for issue in form_issues:
                if not isinstance(issue, Mapping):
                    continue
                message = _safe_str(issue.get("message", ""))
                if message and message not in error_messages and len(error_messages) < 10:
                    error_messages.append(message)

        return {
            "total_forms": len(normalized),
            "total_fields": total_fields,
            "required_fields": required_fields,
            "missing_required_fields": missing_required,
            "submit_controls": submit_controls,
            "validation_issues": validation_issues,
            "has_submit": has_submit,
            "has_validation_errors": has_validation_errors,
            "field_types": field_types,
            "labels": labels,
            "top_validation_messages": error_messages,
            "highest_confidence": round(highest_confidence, 4) if normalized else None,
            "generated_at": _utc_now_iso(),
        }

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required where user-specific execution is involved:
            - user_id
            - workspace_id
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
        Determine whether Security Agent approval is needed.

        Form reading is read-only, but form payloads can include sensitive fields
        like passwords, tokens, card-like numbers, or private customer data.
        """
        flags = (
            task_context.get("requires_security_check"),
            task_context.get("sensitive"),
            task_context.get("contains_credentials"),
            task_context.get("contains_pii"),
            task_context.get("private_screen"),
        )
        if any(bool(flag) for flag in flags):
            return True

        if metadata:
            meta_flags = (
                metadata.get("requires_security_check"),
                metadata.get("sensitive"),
                metadata.get("contains_credentials"),
                metadata.get("contains_pii"),
                metadata.get("private_screen"),
            )
            if any(bool(flag) for flag in meta_flags):
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
        Request Security Agent approval if available.

        Safe fallback approves read-only analysis while keeping the action
        auditable. Real Security Agent can override this behavior.
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
                            approved = bool(response.get("approved", response.get("success", False)))
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
            "reason": "Read-only form reading approved by safe fallback policy.",
            "fallback": True,
        }

    def _prepare_verification_payload(
        self,
        task_context: Mapping[str, Any],
        *,
        forms: Sequence[FormStructure],
        summary: Mapping[str, Any],
        source: str,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        Verification Agent can use this to confirm:
            - form was found
            - submit control exists
            - required fields were identified
            - validation errors are present
        """
        return {
            "payload_type": "visual_form_reading_verification",
            "agent": DEFAULT_AGENT_NAME,
            "source": source,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "status": self._status_for_forms(forms).value,
            "success": bool(forms),
            "form_count": len(forms),
            "summary": _json_safe(summary),
            "forms": [form.to_dict() for form in forms],
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        task_context: Mapping[str, Any],
        *,
        forms: Sequence[FormStructure],
        summary: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Stores compact schema-like information only. Sensitive values are not
        stored. This helps Workflow Agent learn repeated form layouts.
        """
        compact_forms = []
        for form in forms[:10]:
            compact_forms.append(
                {
                    "title": form.title,
                    "field_labels": [field_item.label for field_item in form.fields[:30]],
                    "field_types": [field_item.field_type for field_item in form.fields[:30]],
                    "required_labels": [field_item.label for field_item in form.fields if field_item.required][:30],
                    "submit_texts": [control.text for control in form.submit_controls[:10]],
                    "has_validation_errors": form.has_validation_errors,
                    "source": form.source,
                    "confidence": form.confidence,
                }
            )

        return {
            "payload_type": "visual_form_reader_memory",
            "agent": DEFAULT_AGENT_NAME,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "memory_scope": "workspace",
            "should_store": bool(forms),
            "summary": _json_safe(summary),
            "forms": compact_forms,
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        task_context: Mapping[str, Any],
        *,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Emit event to dashboard/router if event bus is available."""
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
            self.logger.debug("Failed to emit FormReader event.", exc_info=True)

    def _log_audit_event(
        self,
        task_context: Mapping[str, Any],
        *,
        action: str,
        outcome: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Log audit event if audit logger is available."""
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
            self.logger.debug("Failed to log FormReader audit event.", exc_info=True)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis result dict."""
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
        """Return standard William/Jarvis error result."""
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
    # Extraction internals
    # ------------------------------------------------------------------

    def _extract_fields_from_text(
        self,
        text: str,
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[FormField]:
        """Extract likely form fields from OCR/page text."""
        lines = [_normalize_space(line) for line in text.splitlines()]
        lines = [line for line in lines if line]

        fields: List[FormField] = []
        seen: set[str] = set()

        label_patterns = [
            r"^([A-Za-z][A-Za-z0-9\s/\-&().]{1,80})(\s*\*)?\s*[:：]\s*$",
            r"^([A-Za-z][A-Za-z0-9\s/\-&().]{1,80})(\s*\*)?\s*[:：]\s*(\[.*\]|_{2,}|-{2,}|input|select|choose)?$",
            r"^(enter|your|select|choose|upload)\s+([A-Za-z0-9\s/\-&().]{2,80})(\s*\*)?$",
        ]

        for index, line in enumerate(lines):
            lower_line = line.lower()

            if self._is_validation_line(line) or self._is_submit_text(line):
                continue

            label_candidate = ""

            for pattern in label_patterns:
                match = re.match(pattern, line, flags=re.IGNORECASE)
                if match:
                    if pattern.startswith("^(enter"):
                        label_candidate = f"{match.group(1)} {match.group(2)}"
                    else:
                        label_candidate = match.group(1)
                    break

            if not label_candidate:
                if self._looks_like_field_label(line):
                    label_candidate = line

            if not label_candidate:
                continue

            label = _clean_label(label_candidate)
            if not label or len(label) > 90:
                continue

            dedupe = _dedupe_text_key(label)
            if not dedupe or dedupe in seen:
                continue
            seen.add(dedupe)

            evidence_window = "\n".join(lines[max(0, index - 1): min(len(lines), index + 3)])
            required = self._infer_required(label, evidence_window)
            field_type = self._infer_field_type(label, "", "", "")

            fields.append(
                FormField(
                    field_id=str(uuid.uuid4()),
                    label=label.replace(" *", "").strip(),
                    field_type=field_type.value,
                    required=required,
                    visible=True,
                    enabled=True,
                    placeholder="",
                    value_preview="",
                    confidence=self._field_confidence_from_text(label, evidence_window),
                    source=source,
                    evidence=self._safe_evidence(evidence_window),
                    metadata={
                        "line_index": index,
                        "detection_method": "text_pattern",
                        **dict(metadata or {}),
                    },
                )
            )

            if len(fields) >= self.config.max_fields:
                break

        return self._dedupe_fields(fields)

    def _extract_fields_from_elements(
        self,
        elements: Sequence[Mapping[str, Any]],
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[FormField]:
        """Extract form fields from normalized elements."""
        fields: List[FormField] = []
        label_elements = self._label_elements(elements)

        for element in elements:
            if not self._is_field_element(element):
                continue

            text = _safe_str(element.get("text") or element.get("label") or "")
            explicit_label = _safe_str(
                element.get("label")
                or element.get("aria_label")
                or element.get("accessible_name")
                or element.get("name")
                or element.get("placeholder")
                or ""
            )

            nearby_label = self._find_nearby_label(element, label_elements)
            label = _clean_label(explicit_label or nearby_label or text or "Unlabeled field")

            element_type = _safe_str(
                element.get("input_type")
                or element.get("type")
                or element.get("field_type")
                or element.get("role")
                or element.get("tag")
                or ""
            )

            placeholder = _safe_str(element.get("placeholder", ""))
            name = _safe_str(element.get("name", ""))
            element_id = _safe_str(element.get("id", element.get("element_id", "")))
            aria_label = _safe_str(element.get("aria_label", element.get("accessible_name", "")))
            value_preview = self._safe_value_preview(element)

            field_type = self._infer_field_type(
                label=label,
                element_type=element_type,
                placeholder=placeholder,
                name=name,
            )

            required = self._infer_required_from_element(element, label=label)
            visible = not _safe_bool(element.get("hidden", False), False)
            if "visible" in element:
                visible = _safe_bool(element.get("visible"), True)
            enabled = not _safe_bool(element.get("disabled", False), False)
            if "enabled" in element:
                enabled = _safe_bool(element.get("enabled"), True)

            validation_error = _safe_str(element.get("validation_error") or element.get("error") or "")

            evidence_parts = [
                label,
                element_type,
                placeholder,
                name,
                aria_label,
                validation_error,
            ]
            evidence = " | ".join(part for part in evidence_parts if part)

            confidence = self._field_confidence_from_element(
                element=element,
                label=label,
                field_type=field_type,
                nearby_label=nearby_label,
            )

            fields.append(
                FormField(
                    field_id=str(uuid.uuid4()),
                    label=label,
                    field_type=field_type.value,
                    required=required,
                    visible=visible,
                    enabled=enabled,
                    placeholder=placeholder,
                    value_preview=value_preview,
                    name=name,
                    element_id=element_id,
                    autocomplete=_safe_str(element.get("autocomplete", "")),
                    aria_label=aria_label,
                    help_text=_safe_str(element.get("help_text", element.get("description", ""))),
                    validation_error=validation_error,
                    confidence=confidence,
                    bounds=_extract_rect(element),
                    source=source,
                    evidence=self._safe_evidence(evidence),
                    metadata={
                        "role": element.get("role"),
                        "tag": element.get("tag"),
                        "input_type": element.get("input_type"),
                        "detection_method": "element_field",
                        **dict(metadata or {}),
                    },
                )
            )

            if len(fields) >= self.config.max_fields:
                break

        return self._dedupe_fields(fields)

    def _extract_submit_controls_from_text(
        self,
        text: str,
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[SubmitControl]:
        """Extract submit/reset controls from text."""
        lines = [_normalize_space(line) for line in text.splitlines()]
        controls: List[SubmitControl] = []

        for index, line in enumerate(lines):
            if not line:
                continue

            control_type, confidence = self._infer_control_type(line)
            if control_type == FormControlType.UNKNOWN:
                continue

            controls.append(
                SubmitControl(
                    control_id=str(uuid.uuid4()),
                    text=line,
                    control_type=control_type.value,
                    enabled=True,
                    visible=True,
                    confidence=confidence,
                    source=source,
                    evidence=self._safe_evidence(line),
                    metadata={
                        "line_index": index,
                        "detection_method": "text_control",
                        **dict(metadata or {}),
                    },
                )
            )

        return self._dedupe_controls(controls)

    def _extract_submit_controls_from_elements(
        self,
        elements: Sequence[Mapping[str, Any]],
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[SubmitControl]:
        """Extract submit/reset/navigation controls from elements."""
        controls: List[SubmitControl] = []

        for element in elements:
            role = _safe_str(element.get("role", "")).lower()
            tag = _safe_str(element.get("tag", "")).lower()
            element_type = _safe_str(element.get("type") or element.get("input_type") or "").lower()
            text = _normalize_space(
                _safe_str(
                    element.get("text")
                    or element.get("label")
                    or element.get("aria_label")
                    or element.get("accessible_name")
                    or element.get("value")
                    or ""
                )
            )

            is_buttonish = (
                role in {"button", "submit", "link", "menuitem"}
                or tag in {"button", "a"}
                or element_type in {"submit", "button", "reset"}
                or _safe_bool(element.get("clickable", False), False)
            )

            if not is_buttonish and not self._is_submit_text(text):
                continue

            control_type, confidence = self._infer_control_type(text or element_type)
            if element_type == "submit":
                control_type = FormControlType.SUBMIT
                confidence = max(confidence, 0.93)
            elif element_type == "reset":
                control_type = FormControlType.RESET
                confidence = max(confidence, 0.9)

            if control_type == FormControlType.UNKNOWN:
                continue

            visible = not _safe_bool(element.get("hidden", False), False)
            if "visible" in element:
                visible = _safe_bool(element.get("visible"), True)

            enabled = not _safe_bool(element.get("disabled", False), False)
            if "enabled" in element:
                enabled = _safe_bool(element.get("enabled"), True)

            controls.append(
                SubmitControl(
                    control_id=str(uuid.uuid4()),
                    text=text or element_type,
                    control_type=control_type.value,
                    enabled=enabled,
                    visible=visible,
                    confidence=confidence,
                    bounds=_extract_rect(element),
                    source=source,
                    evidence=self._safe_evidence(text or element_type),
                    metadata={
                        "role": role,
                        "tag": tag,
                        "type": element_type,
                        "detection_method": "element_control",
                        **dict(metadata or {}),
                    },
                )
            )

        return self._dedupe_controls(controls)

    def _extract_validation_errors_from_text(
        self,
        text: str,
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[ValidationIssue]:
        """Extract validation errors from OCR/page text."""
        issues: List[ValidationIssue] = []
        clean_text = _truncate(_safe_str(text), self.config.max_text_chars)

        for pattern, message, severity, confidence in VALIDATION_ERROR_PATTERNS:
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for match in regex.finditer(clean_text):
                evidence = self._safe_evidence(self._snippet_around(clean_text, match.start(), match.end()))
                related = self._infer_related_label_from_context(clean_text, match.start())

                issues.append(
                    ValidationIssue(
                        issue_id=str(uuid.uuid4()),
                        message=message,
                        severity=severity.value,
                        related_label=related,
                        confidence=confidence,
                        source=source,
                        evidence=evidence,
                        metadata={
                            "detection_method": "text_validation_pattern",
                            **dict(metadata or {}),
                        },
                    )
                )

                if len(issues) >= self.config.max_errors:
                    return self._dedupe_issues(issues)

        return self._dedupe_issues(issues)

    def _extract_validation_errors_from_elements(
        self,
        elements: Sequence[Mapping[str, Any]],
        *,
        source: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> List[ValidationIssue]:
        """Extract validation errors from UI elements."""
        issues: List[ValidationIssue] = []

        for element in elements:
            role = _safe_str(element.get("role", "")).lower()
            classes = _safe_str(element.get("class", element.get("classes", ""))).lower()
            element_type = _safe_str(element.get("type", "")).lower()
            text = _normalize_space(
                _safe_str(
                    element.get("error")
                    or element.get("validation_error")
                    or element.get("text")
                    or element.get("aria_label")
                    or element.get("message")
                    or ""
                )
            )

            error_hint = (
                role in {"alert", "error", "status"}
                or element_type in {"error", "validation"}
                or "error" in classes
                or "invalid" in classes
                or bool(element.get("invalid"))
                or bool(element.get("aria_invalid"))
                or self._is_validation_line(text)
            )

            if not error_hint:
                continue

            issue_message = text or "Validation error detected."
            severity = ValidationSeverity.HIGH if self._is_required_error(issue_message) else ValidationSeverity.MEDIUM
            confidence = 0.9 if role in {"alert", "error"} or bool(element.get("aria_invalid")) else 0.76

            issues.append(
                ValidationIssue(
                    issue_id=str(uuid.uuid4()),
                    message=issue_message,
                    severity=severity.value,
                    related_label=_safe_str(element.get("label", "")),
                    related_field_id=_safe_str(element.get("field_id", element.get("for", ""))),
                    confidence=confidence,
                    source=source,
                    evidence=self._safe_evidence(issue_message),
                    bounds=_extract_rect(element),
                    metadata={
                        "role": role,
                        "type": element_type,
                        "classes": classes,
                        "detection_method": "element_validation",
                        **dict(metadata or {}),
                    },
                )
            )

            if len(issues) >= self.config.max_errors:
                break

        return self._dedupe_issues(issues)

    # ------------------------------------------------------------------
    # Form grouping and merging
    # ------------------------------------------------------------------

    def _build_form_structure(
        self,
        *,
        fields: Sequence[FormField],
        controls: Sequence[SubmitControl],
        issues: Sequence[ValidationIssue],
        title: str,
        description: str,
        source: str,
        confidence: float,
        bounds: Optional[Rect] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> FormStructure:
        """Build FormStructure from parts."""
        deduped_fields = self._dedupe_fields(fields)
        deduped_controls = self._dedupe_controls(controls)
        deduped_issues = self._dedupe_issues(issues)

        required_count = sum(1 for item in deduped_fields if item.required)
        missing_required = sum(
            1
            for item in deduped_fields
            if item.required and not _safe_str(item.value_preview).strip()
        )

        return FormStructure(
            form_id=str(uuid.uuid4()),
            title=_clean_label(title),
            description=_normalize_space(description),
            fields=deduped_fields,
            submit_controls=deduped_controls,
            validation_issues=deduped_issues,
            required_field_count=required_count,
            missing_required_count=missing_required,
            has_submit=bool(deduped_controls),
            has_validation_errors=bool(deduped_issues),
            confidence=_clamp(confidence),
            source=source,
            bounds=bounds,
            metadata=dict(metadata or {}),
        )

    def _group_forms_from_elements(
        self,
        elements: Sequence[Mapping[str, Any]],
        *,
        fields: Sequence[FormField],
        controls: Sequence[SubmitControl],
        issues: Sequence[ValidationIssue],
        source: str,
        metadata: Mapping[str, Any],
    ) -> List[FormStructure]:
        """
        Group detected fields/controls/issues into forms.

        If explicit form containers exist, grouping is based on bounds.
        Otherwise a single practical form structure is produced.
        """
        form_containers = [
            element for element in elements
            if _safe_str(element.get("tag", "")).lower() == "form"
            or _safe_str(element.get("role", "")).lower() == "form"
            or _safe_str(element.get("type", "")).lower() == "form"
            or _safe_bool(element.get("is_form", False), False)
        ]

        if not form_containers:
            if fields or controls or issues:
                return [
                    self._build_form_structure(
                        fields=fields,
                        controls=controls,
                        issues=issues,
                        title=self._infer_form_title_from_elements(elements),
                        description="",
                        source=source,
                        confidence=self._estimate_form_confidence(fields, controls, issues),
                        metadata={
                            "grouping": "single_form_fallback",
                            **dict(metadata),
                        },
                    )
                ]
            return []

        forms: List[FormStructure] = []
        used_field_ids: set[str] = set()
        used_control_ids: set[str] = set()
        used_issue_ids: set[str] = set()

        for container in form_containers[: self.config.max_forms]:
            container_rect = _extract_rect(container)

            grouped_fields = [
                field_item for field_item in fields
                if self._rect_contains(container_rect, field_item.bounds)
            ]
            grouped_controls = [
                control for control in controls
                if self._rect_contains(container_rect, control.bounds)
            ]
            grouped_issues = [
                issue for issue in issues
                if self._rect_contains(container_rect, issue.bounds)
            ]

            for item in grouped_fields:
                used_field_ids.add(item.field_id)
            for item in grouped_controls:
                used_control_ids.add(item.control_id)
            for item in grouped_issues:
                used_issue_ids.add(item.issue_id)

            if grouped_fields or grouped_controls or grouped_issues:
                forms.append(
                    self._build_form_structure(
                        fields=grouped_fields,
                        controls=grouped_controls,
                        issues=grouped_issues,
                        title=_safe_str(container.get("title") or container.get("name") or container.get("aria_label") or ""),
                        description=_safe_str(container.get("description") or ""),
                        source=source,
                        confidence=self._estimate_form_confidence(grouped_fields, grouped_controls, grouped_issues, dom_hint=True),
                        bounds=container_rect,
                        metadata={
                            "grouping": "form_container",
                            "container_id": container.get("id", container.get("element_id")),
                            **dict(metadata),
                        },
                    )
                )

        leftover_fields = [item for item in fields if item.field_id not in used_field_ids]
        leftover_controls = [item for item in controls if item.control_id not in used_control_ids]
        leftover_issues = [item for item in issues if item.issue_id not in used_issue_ids]

        if leftover_fields or leftover_controls or leftover_issues:
            forms.append(
                self._build_form_structure(
                    fields=leftover_fields,
                    controls=leftover_controls,
                    issues=leftover_issues,
                    title="",
                    description="",
                    source=source,
                    confidence=self._estimate_form_confidence(leftover_fields, leftover_controls, leftover_issues),
                    metadata={
                        "grouping": "leftover_elements",
                        **dict(metadata),
                    },
                )
            )

        return forms

    def _merge_forms(self, forms: Sequence[FormStructure], *, source: str) -> List[FormStructure]:
        """
        Merge duplicate forms from multiple sources.

        When OCR and elements both detect the same labels/buttons, this creates
        a cleaner combined result.
        """
        if not forms:
            return []

        if len(forms) == 1:
            return list(forms)

        all_fields: List[FormField] = []
        all_controls: List[SubmitControl] = []
        all_issues: List[ValidationIssue] = []
        titles: List[str] = []
        descriptions: List[str] = []
        confidence_values: List[float] = []

        for form in forms:
            all_fields.extend(form.fields)
            all_controls.extend(form.submit_controls)
            all_issues.extend(form.validation_issues)
            if form.title and form.title not in titles:
                titles.append(form.title)
            if form.description and form.description not in descriptions:
                descriptions.append(form.description)
            confidence_values.append(form.confidence)

        merged_form = self._build_form_structure(
            fields=self._dedupe_fields(all_fields),
            controls=self._dedupe_controls(all_controls),
            issues=self._dedupe_issues(all_issues),
            title=titles[0] if titles else "",
            description=descriptions[0] if descriptions else "",
            source=source,
            confidence=max(confidence_values) if confidence_values else 0.0,
            metadata={
                "merged_from_forms": len(forms),
                "merge_strategy": "label_control_issue_dedupe",
            },
        )

        return [merged_form] if merged_form.fields or merged_form.submit_controls or merged_form.validation_issues else []

    # ------------------------------------------------------------------
    # Inference helpers
    # ------------------------------------------------------------------

    def _infer_field_type(
        self,
        *,
        label: str,
        element_type: str,
        placeholder: str,
        name: str,
    ) -> FormFieldType:
        """Infer normalized field type."""
        type_l = _safe_str(element_type).lower().strip()
        label_blob = f"{label} {placeholder} {name}".lower()

        direct_map = {
            "text": FormFieldType.TEXT,
            "email": FormFieldType.EMAIL,
            "tel": FormFieldType.PHONE,
            "phone": FormFieldType.PHONE,
            "password": FormFieldType.PASSWORD,
            "number": FormFieldType.NUMBER,
            "date": FormFieldType.DATE,
            "time": FormFieldType.TIME,
            "datetime": FormFieldType.DATETIME,
            "datetime-local": FormFieldType.DATETIME,
            "url": FormFieldType.URL,
            "search": FormFieldType.SEARCH,
            "textarea": FormFieldType.TEXTAREA,
            "select": FormFieldType.SELECT,
            "select-one": FormFieldType.SELECT,
            "select-multiple": FormFieldType.SELECT,
            "checkbox": FormFieldType.CHECKBOX,
            "radio": FormFieldType.RADIO,
            "file": FormFieldType.FILE,
            "hidden": FormFieldType.HIDDEN,
        }

        if type_l in direct_map:
            return direct_map[type_l]

        if self.config.infer_field_type_from_label:
            for field_type, keywords in FIELD_TYPE_KEYWORDS:
                for keyword in keywords:
                    if keyword in label_blob:
                        return field_type

        return FormFieldType.TEXT if label_blob else FormFieldType.UNKNOWN

    def _infer_required(self, label: str, context: str) -> bool:
        """Infer required field from label/context."""
        blob = f"{label} {context}".lower()
        if self.config.infer_required_from_asterisk and "*" in label:
            return True
        return any(word in blob for word in REQUIRED_WORDS)

    def _infer_required_from_element(self, element: Mapping[str, Any], *, label: str) -> bool:
        """Infer required from element attributes."""
        for key in ("required", "aria_required", "is_required", "mandatory"):
            if key in element and _safe_bool(element.get(key), False):
                return True

        classes = _safe_str(element.get("class", element.get("classes", ""))).lower()
        if "required" in classes:
            return True

        required_text = " ".join(
            _safe_str(element.get(key, ""))
            for key in ("text", "label", "placeholder", "aria_label", "validation_error", "help_text")
        )
        return self._infer_required(label, required_text)

    def _infer_control_type(self, text: str) -> Tuple[FormControlType, float]:
        """Infer submit/reset/control type from text."""
        clean = _normalize_space(text).lower()
        if not clean:
            return FormControlType.UNKNOWN, 0.0

        for pattern, control_type, confidence in SUBMIT_TEXT_PATTERNS:
            if re.match(pattern, clean, flags=re.IGNORECASE):
                return control_type, confidence

        if self.config.infer_submit_from_button_text:
            if any(token in clean for token in ("submit", "send", "save", "continue", "next", "confirm")):
                return FormControlType.SUBMIT, 0.72

        return FormControlType.UNKNOWN, 0.0

    def _is_submit_text(self, text: str) -> bool:
        """Check whether text looks like a submit/control label."""
        control_type, confidence = self._infer_control_type(text)
        return control_type != FormControlType.UNKNOWN and confidence >= 0.7

    def _is_validation_line(self, text: str) -> bool:
        """Check whether a text line is likely a validation error."""
        lower = _safe_str(text).lower()
        if not lower:
            return False
        for pattern, _, _, _ in VALIDATION_ERROR_PATTERNS:
            if re.search(pattern, lower, flags=re.IGNORECASE):
                return True
        return any(word in lower for word in REQUIRED_WORDS) and len(lower) < 160

    def _is_required_error(self, text: str) -> bool:
        """Check whether validation text indicates required field."""
        lower = _safe_str(text).lower()
        return any(word in lower for word in REQUIRED_WORDS)

    def _looks_like_field_label(self, text: str) -> bool:
        """Heuristic for OCR line that looks like a field label."""
        clean = _clean_label(text)
        lower = clean.lower()

        if len(clean) < 2 or len(clean) > 90:
            return False
        if self._is_submit_text(clean) or self._is_validation_line(clean):
            return False
        if re.search(r"https?://|www\.|@\w+", lower):
            return False
        if re.fullmatch(r"[\W_]+", clean):
            return False

        strong_keywords = []
        for _, keywords in FIELD_TYPE_KEYWORDS:
            strong_keywords.extend(keywords)

        if any(keyword in lower for keyword in strong_keywords):
            return True

        if clean.endswith("*"):
            return True

        if re.match(r"^(enter|your|select|choose|upload)\s+\w+", lower):
            return True

        return False

    def _is_field_element(self, element: Mapping[str, Any]) -> bool:
        """Check whether element is an input/select/textarea-like field."""
        role = _safe_str(element.get("role", "")).lower()
        tag = _safe_str(element.get("tag", "")).lower()
        element_type = _safe_str(element.get("type") or element.get("input_type") or "").lower()
        classes = _safe_str(element.get("class", element.get("classes", ""))).lower()

        if tag in {"input", "select", "textarea"}:
            return True
        if role in {"textbox", "combobox", "checkbox", "radio", "searchbox", "spinbutton", "switch"}:
            return True
        if element_type in {
            "text",
            "email",
            "tel",
            "phone",
            "password",
            "number",
            "date",
            "time",
            "datetime",
            "datetime-local",
            "url",
            "search",
            "textarea",
            "select",
            "checkbox",
            "radio",
            "file",
            "hidden",
        }:
            return True
        if _safe_bool(element.get("is_input", False), False):
            return True
        if "input" in classes or "field" in classes or "form-control" in classes:
            return True

        return False

    def _label_elements(self, elements: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
        """Return elements likely to be labels."""
        labels = []
        for element in elements:
            role = _safe_str(element.get("role", "")).lower()
            tag = _safe_str(element.get("tag", "")).lower()
            text = _normalize_space(_safe_str(element.get("text") or element.get("label") or ""))
            if tag == "label" or role == "label" or self._looks_like_field_label(text):
                labels.append(element)
        return labels

    def _find_nearby_label(
        self,
        field_element: Mapping[str, Any],
        label_elements: Sequence[Mapping[str, Any]],
    ) -> str:
        """Find nearest label element above/left of field by bounds."""
        field_rect = _extract_rect(field_element)
        if field_rect is None:
            return ""

        best_label = ""
        best_score = float("inf")

        field_left = field_rect.left if field_rect.left is not None else field_rect.x
        field_top = field_rect.top if field_rect.top is not None else field_rect.y

        if field_left is None or field_top is None:
            return ""

        for label_element in label_elements:
            label_text = _normalize_space(
                _safe_str(label_element.get("text") or label_element.get("label") or "")
            )
            if not label_text:
                continue

            label_rect = _extract_rect(label_element)
            if label_rect is None:
                continue

            label_left = label_rect.left if label_rect.left is not None else label_rect.x
            label_top = label_rect.top if label_rect.top is not None else label_rect.y
            label_right = label_rect.right
            label_bottom = label_rect.bottom

            if label_left is None or label_top is None:
                continue

            horizontal_distance = abs(field_left - label_left)
            vertical_distance = abs(field_top - label_top)

            is_above = label_bottom is not None and label_bottom <= field_top + 10
            is_left = label_right is not None and label_right <= field_left + 20

            if not is_above and not is_left:
                continue

            score = vertical_distance + (horizontal_distance * 0.35)
            if score < best_score and score < 220:
                best_score = score
                best_label = label_text

        return best_label

    def _field_confidence_from_text(self, label: str, evidence: str) -> float:
        """Estimate confidence for text-based field detection."""
        confidence = 0.48
        lower = f"{label} {evidence}".lower()

        if ":" in evidence or "*" in evidence:
            confidence += 0.08
        if any(keyword in lower for _, keywords in FIELD_TYPE_KEYWORDS for keyword in keywords):
            confidence += 0.16
        if any(token in lower for token in ("input", "select", "choose", "enter", "upload")):
            confidence += 0.1
        if self._is_validation_line(evidence):
            confidence += 0.04

        return _clamp(confidence)

    def _field_confidence_from_element(
        self,
        *,
        element: Mapping[str, Any],
        label: str,
        field_type: FormFieldType,
        nearby_label: str,
    ) -> float:
        """Estimate confidence for element-based field detection."""
        confidence = 0.62

        tag = _safe_str(element.get("tag", "")).lower()
        role = _safe_str(element.get("role", "")).lower()

        if tag in {"input", "select", "textarea"}:
            confidence += 0.18
        if role in {"textbox", "combobox", "checkbox", "radio", "searchbox"}:
            confidence += 0.12
        if label and label != "Unlabeled field":
            confidence += 0.08
        if nearby_label:
            confidence += 0.06
        if field_type != FormFieldType.UNKNOWN:
            confidence += 0.05
        if _extract_rect(element):
            confidence += 0.04

        return _clamp(confidence)

    def _estimate_form_confidence(
        self,
        fields: Sequence[FormField],
        controls: Sequence[SubmitControl],
        issues: Sequence[ValidationIssue],
        *,
        dom_hint: bool = False,
    ) -> float:
        """Estimate overall form confidence."""
        if not fields and not controls and not issues:
            return 0.0

        confidence = 0.25
        if fields:
            confidence += min(0.38, len(fields) * 0.06)
            confidence += max((field_item.confidence for field_item in fields), default=0.0) * 0.18
        if controls:
            confidence += 0.16
        if issues:
            confidence += 0.08
        if dom_hint:
            confidence += 0.15

        return _clamp(confidence)

    def _infer_form_title_from_text(self, text: str) -> str:
        """Infer form title from text lines."""
        lines = [_normalize_space(line) for line in text.splitlines()]
        lines = [line for line in lines if line]

        title_keywords = (
            "contact",
            "login",
            "sign up",
            "register",
            "quote",
            "application",
            "checkout",
            "payment",
            "booking",
            "search",
            "subscribe",
            "lead",
            "form",
        )

        for line in lines[:12]:
            lower = line.lower()
            if any(keyword in lower for keyword in title_keywords) and len(line) <= 90:
                return line

        return ""

    def _infer_form_title_from_elements(self, elements: Sequence[Mapping[str, Any]]) -> str:
        """Infer form title from nearby heading elements."""
        for element in elements[:30]:
            tag = _safe_str(element.get("tag", "")).lower()
            role = _safe_str(element.get("role", "")).lower()
            text = _normalize_space(_safe_str(element.get("text") or element.get("label") or ""))
            if not text:
                continue
            if tag in {"h1", "h2", "h3", "legend"} or role in {"heading", "legend"}:
                return text
        return ""

    def _infer_related_label_from_context(self, text: str, index: int) -> str:
        """Infer related label near validation message."""
        before = text[max(0, index - 300): index]
        lines = [_normalize_space(line) for line in before.splitlines()]
        lines = [line for line in lines if line]

        for line in reversed(lines[-6:]):
            if self._looks_like_field_label(line):
                return _clean_label(line)

        return ""

    def _safe_value_preview(self, element: Mapping[str, Any]) -> str:
        """Return safe preview of field value without leaking sensitive data."""
        value = _safe_str(element.get("value") or element.get("text_value") or "")
        label_blob = " ".join(
            _safe_str(element.get(key, ""))
            for key in ("name", "id", "label", "aria_label", "placeholder", "type", "input_type")
        )

        if any(_looks_sensitive_key(part) for part in label_blob.split()):
            return "[REDACTED]"

        if self.config.redact_sensitive_values:
            value = _redact_text(value)

        if len(value) > 80:
            value = value[:80].rstrip() + "..."

        return value

    def _safe_evidence(self, evidence: str) -> str:
        """Redact and truncate evidence."""
        safe = _safe_str(evidence)
        if self.config.redact_sensitive_values:
            safe = _redact_text(safe)
        if len(safe) > MAX_EVIDENCE_CHARS:
            safe = safe[:MAX_EVIDENCE_CHARS].rstrip() + "..."
        return safe

    def _snippet_around(self, text: str, start: int, end: int, window: int = 180) -> str:
        """Return evidence snippet around character range."""
        left = max(0, start - window)
        right = min(len(text), end + window)
        return text[left:right].strip()

    # ------------------------------------------------------------------
    # Normalization / dedupe / filters
    # ------------------------------------------------------------------

    def _coerce_config(self, config: Optional[Union[FormReaderConfig, Mapping[str, Any]]]) -> FormReaderConfig:
        """Convert config input into FormReaderConfig."""
        if config is None:
            return FormReaderConfig()
        if isinstance(config, FormReaderConfig):
            return config
        if isinstance(config, Mapping):
            allowed = set(FormReaderConfig.__dataclass_fields__.keys())
            values = {key: value for key, value in config.items() if key in allowed}
            return FormReaderConfig(**values)
        return FormReaderConfig()

    def _normalize_elements(self, elements: Any) -> List[Mapping[str, Any]]:
        """Normalize arbitrary element list into list of mappings."""
        if not isinstance(elements, Sequence) or isinstance(elements, (str, bytes, bytearray)):
            return []

        normalized: List[Mapping[str, Any]] = []
        for element in elements:
            if isinstance(element, Mapping):
                normalized.append(element)
            elif hasattr(element, "to_dict") and callable(element.to_dict):
                maybe = element.to_dict()
                if isinstance(maybe, Mapping):
                    normalized.append(maybe)
            elif hasattr(element, "__dict__"):
                normalized.append(vars(element))

        return normalized

    def _dedupe_fields(self, fields: Sequence[FormField]) -> List[FormField]:
        """Dedupe fields by label/type/name/id."""
        best: Dict[str, FormField] = {}
        for field_item in fields:
            key = "|".join(
                [
                    _dedupe_text_key(field_item.element_id),
                    _dedupe_text_key(field_item.name),
                    _dedupe_text_key(field_item.label),
                    field_item.field_type,
                ]
            )
            if key == "|||":
                key = field_item.field_id

            existing = best.get(key)
            if existing is None or field_item.confidence > existing.confidence:
                best[key] = field_item

        return sorted(best.values(), key=lambda item: self._sort_key_for_bounds(item.bounds))

    def _dedupe_controls(self, controls: Sequence[SubmitControl]) -> List[SubmitControl]:
        """Dedupe controls by text/type."""
        best: Dict[str, SubmitControl] = {}
        for control in controls:
            key = f"{_dedupe_text_key(control.text)}|{control.control_type}"
            if key == "|":
                key = control.control_id

            existing = best.get(key)
            if existing is None or control.confidence > existing.confidence:
                best[key] = control

        return sorted(best.values(), key=lambda item: self._sort_key_for_bounds(item.bounds))

    def _dedupe_issues(self, issues: Sequence[ValidationIssue]) -> List[ValidationIssue]:
        """Dedupe validation issues by message/related label."""
        best: Dict[str, ValidationIssue] = {}
        for issue in issues:
            key = f"{_dedupe_text_key(issue.message)}|{_dedupe_text_key(issue.related_label)}"
            if key == "|":
                key = issue.issue_id

            existing = best.get(key)
            if existing is None or issue.confidence > existing.confidence:
                best[key] = issue

        return sorted(best.values(), key=lambda item: self._sort_key_for_bounds(item.bounds))

    def _filter_forms(self, forms: Sequence[FormStructure]) -> List[FormStructure]:
        """Filter forms by confidence and usefulness."""
        filtered: List[FormStructure] = []
        for form in forms:
            useful = bool(form.fields or form.submit_controls or form.validation_issues)
            if not useful:
                continue
            if self.config.include_low_confidence or form.confidence >= self.config.confidence_threshold:
                filtered.append(form)
        return filtered

    def _forms_from_result(self, result: Mapping[str, Any]) -> List[FormStructure]:
        """Extract FormStructure objects from structured result."""
        if not isinstance(result, Mapping):
            return []

        data = result.get("data", {})
        if not isinstance(data, Mapping):
            return []

        raw_forms = data.get("forms", [])
        if not isinstance(raw_forms, Sequence):
            return []

        forms: List[FormStructure] = []
        for raw in raw_forms:
            if isinstance(raw, FormStructure):
                forms.append(raw)
            elif isinstance(raw, Mapping):
                try:
                    fields = [
                        self._field_from_mapping(item)
                        for item in raw.get("fields", [])
                        if isinstance(item, Mapping)
                    ]
                    controls = [
                        self._control_from_mapping(item)
                        for item in raw.get("submit_controls", [])
                        if isinstance(item, Mapping)
                    ]
                    issues = [
                        self._issue_from_mapping(item)
                        for item in raw.get("validation_issues", [])
                        if isinstance(item, Mapping)
                    ]

                    forms.append(
                        FormStructure(
                            form_id=_safe_str(raw.get("form_id") or uuid.uuid4()),
                            title=_safe_str(raw.get("title", "")),
                            description=_safe_str(raw.get("description", "")),
                            fields=fields,
                            submit_controls=controls,
                            validation_issues=issues,
                            required_field_count=int(raw.get("required_field_count", 0) or 0),
                            missing_required_count=int(raw.get("missing_required_count", 0) or 0),
                            has_submit=_safe_bool(raw.get("has_submit", bool(controls))),
                            has_validation_errors=_safe_bool(raw.get("has_validation_errors", bool(issues))),
                            confidence=_safe_float(raw.get("confidence", 0.0)),
                            source=_safe_str(raw.get("source", "unknown")),
                            bounds=self._rect_from_mapping(raw.get("bounds")),
                            metadata=dict(raw.get("metadata", {}) or {}),
                        )
                    )
                except Exception:
                    self.logger.debug("Skipped malformed form mapping.", exc_info=True)

        return forms

    def _field_from_mapping(self, raw: Mapping[str, Any]) -> FormField:
        """Create FormField from mapping."""
        return FormField(
            field_id=_safe_str(raw.get("field_id") or uuid.uuid4()),
            label=_safe_str(raw.get("label", "")),
            field_type=_safe_str(raw.get("field_type", FormFieldType.UNKNOWN.value)),
            required=_safe_bool(raw.get("required", False)),
            visible=_safe_bool(raw.get("visible", True), True),
            enabled=_safe_bool(raw.get("enabled", True), True),
            placeholder=_safe_str(raw.get("placeholder", "")),
            value_preview=_safe_str(raw.get("value_preview", "")),
            name=_safe_str(raw.get("name", "")),
            element_id=_safe_str(raw.get("element_id", "")),
            autocomplete=_safe_str(raw.get("autocomplete", "")),
            aria_label=_safe_str(raw.get("aria_label", "")),
            help_text=_safe_str(raw.get("help_text", "")),
            validation_error=_safe_str(raw.get("validation_error", "")),
            confidence=_safe_float(raw.get("confidence", 0.0)),
            bounds=self._rect_from_mapping(raw.get("bounds")),
            source=_safe_str(raw.get("source", "unknown")),
            evidence=_safe_str(raw.get("evidence", "")),
            metadata=dict(raw.get("metadata", {}) or {}),
        )

    def _control_from_mapping(self, raw: Mapping[str, Any]) -> SubmitControl:
        """Create SubmitControl from mapping."""
        return SubmitControl(
            control_id=_safe_str(raw.get("control_id") or uuid.uuid4()),
            text=_safe_str(raw.get("text", "")),
            control_type=_safe_str(raw.get("control_type", FormControlType.UNKNOWN.value)),
            enabled=_safe_bool(raw.get("enabled", True), True),
            visible=_safe_bool(raw.get("visible", True), True),
            confidence=_safe_float(raw.get("confidence", 0.0)),
            bounds=self._rect_from_mapping(raw.get("bounds")),
            source=_safe_str(raw.get("source", "unknown")),
            evidence=_safe_str(raw.get("evidence", "")),
            metadata=dict(raw.get("metadata", {}) or {}),
        )

    def _issue_from_mapping(self, raw: Mapping[str, Any]) -> ValidationIssue:
        """Create ValidationIssue from mapping."""
        return ValidationIssue(
            issue_id=_safe_str(raw.get("issue_id") or uuid.uuid4()),
            message=_safe_str(raw.get("message", "")),
            severity=_safe_str(raw.get("severity", ValidationSeverity.MEDIUM.value)),
            related_label=_safe_str(raw.get("related_label", "")),
            related_field_id=_safe_str(raw.get("related_field_id", "")),
            confidence=_safe_float(raw.get("confidence", 0.0)),
            source=_safe_str(raw.get("source", "unknown")),
            evidence=_safe_str(raw.get("evidence", "")),
            bounds=self._rect_from_mapping(raw.get("bounds")),
            metadata=dict(raw.get("metadata", {}) or {}),
        )

    def _rect_from_mapping(self, raw: Any) -> Optional[Rect]:
        """Create Rect from mapping/list or None."""
        if raw is None:
            return None
        if isinstance(raw, Rect):
            return raw
        if isinstance(raw, Mapping):
            return _extract_rect(raw) or Rect(
                x=_optional_float(raw.get("x")),
                y=_optional_float(raw.get("y")),
                width=_optional_float(raw.get("width")),
                height=_optional_float(raw.get("height")),
                left=_optional_float(raw.get("left")),
                top=_optional_float(raw.get("top")),
                right=_optional_float(raw.get("right")),
                bottom=_optional_float(raw.get("bottom")),
            )
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            return _extract_rect({"bbox": raw})
        return None

    def _normalize_forms_input(
        self,
        forms: Union[Sequence[FormStructure], Sequence[Mapping[str, Any]], Mapping[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Normalize forms or result dict to list of form dicts."""
        if isinstance(forms, Mapping):
            if "data" in forms and isinstance(forms.get("data"), Mapping):
                raw = forms.get("data", {}).get("forms", [])
            elif "forms" in forms:
                raw = forms.get("forms", [])
            else:
                raw = [forms]
        else:
            raw = forms

        normalized: List[Dict[str, Any]] = []
        for item in raw:
            if isinstance(item, FormStructure):
                normalized.append(item.to_dict())
            elif isinstance(item, Mapping):
                normalized.append(dict(item))

        return normalized

    def _status_for_forms(self, forms: Sequence[FormStructure]) -> FormReadStatus:
        """Return high-level detection status."""
        if not forms:
            return FormReadStatus.NO_FORM_DETECTED

        has_fields = any(form.fields for form in forms)
        has_controls = any(form.submit_controls for form in forms)

        if has_fields and has_controls:
            return FormReadStatus.FORM_DETECTED
        if has_fields or has_controls:
            return FormReadStatus.PARTIAL_FORM_DETECTED
        return FormReadStatus.INCONCLUSIVE

    def _rect_contains(self, outer: Optional[Rect], inner: Optional[Rect]) -> bool:
        """Return True if outer rectangle contains inner rectangle."""
        if outer is None or inner is None:
            return False

        outer_left = outer.left if outer.left is not None else outer.x
        outer_top = outer.top if outer.top is not None else outer.y
        outer_right = outer.right
        outer_bottom = outer.bottom

        inner_left = inner.left if inner.left is not None else inner.x
        inner_top = inner.top if inner.top is not None else inner.y
        inner_right = inner.right
        inner_bottom = inner.bottom

        if None in (outer_left, outer_top, outer_right, outer_bottom, inner_left, inner_top, inner_right, inner_bottom):
            return False

        return (
            outer_left <= inner_left
            and outer_top <= inner_top
            and outer_right >= inner_right
            and outer_bottom >= inner_bottom
        )

    def _sort_key_for_bounds(self, rect: Optional[Rect]) -> Tuple[float, float]:
        """Sort by visual top-left where available."""
        if rect is None:
            return (999999.0, 999999.0)

        top = rect.top if rect.top is not None else rect.y
        left = rect.left if rect.left is not None else rect.x

        return (
            top if top is not None else 999999.0,
            left if left is not None else 999999.0,
        )

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
        """Build base result metadata."""
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
# Registry helpers
# ---------------------------------------------------------------------------

def create_form_reader(
    config: Optional[Union[FormReaderConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> FormReader:
    """
    Factory for Agent Loader / Agent Registry.

    Example:
        reader = create_form_reader()
    """
    return FormReader(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Return registry-friendly metadata without instantiating the class.
    """
    return {
        "agent_module": "Visual Agent",
        "file": "agents/visual_agent/form_reader.py",
        "class_name": "FormReader",
        "agent_type": FormReader.agent_type,
        "capability": FormReader.capability,
        "public_methods": list(FormReader.public_methods),
        "import_safe": True,
        "requires_user_workspace": True,
        "destructive_actions": False,
        "security_sensitive": True,
        "version": "1.0.0",
    }


__all__ = [
    "FormReader",
    "FormReaderConfig",
    "FormStructure",
    "FormField",
    "SubmitControl",
    "ValidationIssue",
    "Rect",
    "FormReadStatus",
    "FormFieldType",
    "FormControlType",
    "ValidationSeverity",
    "create_form_reader",
    "get_agent_metadata",
]


# ---------------------------------------------------------------------------
# Lightweight self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    reader = FormReader()
    context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
    }

    sample_text = """
    Contact Us

    Full Name *
    Email Address *
    Phone Number
    Project Message

    Email is invalid.
    Please fill out this field.

    Submit
    """

    result = reader.read_from_text(
        context,
        text=sample_text,
        source="self_test_ocr",
    )
    print(result)


"""
William / Jarvis All-File Prompt Bible - Digital Promotix
Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.

Agent/Module: Visual Agent
File Completed: form_reader.py
Completion: 66.7%
Completed Files: ['visual_agent.py', 'screenshot_reader.py', 'video_analyzer.py', 'ocr_engine.py', 'ui_mapper.py', 'image_analyzer.py', 'screen_context.py', 'element_detector.py', 'workflow_learner.py', 'visual_memory.py', 'error_screen_detector.py', 'form_reader.py']
Remaining Files: ['app_screen_mapper.py', 'video_frame_extractor.py', 'visual_validator.py', 'privacy_filter.py', 'annotation_tool.py', 'config.py']
Next Recommended File: agents/visual_agent/app_screen_mapper.py
FILE COMPLETE
"""