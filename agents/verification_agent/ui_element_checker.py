"""
William / Jarvis Multi-Agent AI SaaS System
Verification Agent - UI Element Checker

File:
    agents/verification_agent/ui_element_checker.py

Purpose:
    Confirms whether UI elements such as buttons, inputs, modals, forms, toasts,
    and progress bars are visible, enabled, present, and optionally match expected
    text/value/state rules.

Architecture Notes:
    - Designed for the Verification Agent module.
    - Safe to import even when the full William/Jarvis system is not available yet.
    - Compatible with SaaS user/workspace isolation.
    - Provides structured dict/JSON-style responses for API/dashboard integration.
    - Does not execute browser/system/destructive actions directly.
    - Can validate UI state from DOM-like snapshots, accessibility snapshots,
      screenshot-analysis outputs, browser-agent snapshots, or manually supplied
      UI element dictionaries.
    - Includes compatibility hooks expected by BaseAgent, Master Agent, Security
      Agent, Memory Agent, Agent Registry, Agent Router, Dashboard/API, and Audit logs.

Responsibilities:
    - Confirm buttons are visible/enabled/clickable.
    - Confirm inputs are visible/enabled/filled/empty/typed.
    - Confirm modals/dialogs are visible/open/closed.
    - Confirm forms are visible and contain expected fields/buttons.
    - Confirm toasts/alerts are visible and match expected messages.
    - Confirm progress bars/spinners/loaders are visible and optionally complete.
    - Return confidence, evidence, normalized element data, and verification payloads.

Public Class:
    UIElementChecker

Typical Usage:
    checker = UIElementChecker()
    result = checker.check_button_visible(
        user_id="user_123",
        workspace_id="workspace_abc",
        snapshot={
            "elements": [
                {"role": "button", "text": "Save", "visible": True, "enabled": True}
            ]
        },
        text="Save",
    )

Result Format:
    {
        "success": True,
        "message": "...",
        "data": {...},
        "error": None,
        "metadata": {...}
    }
"""

from __future__ import annotations

import copy
import datetime as _dt
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports / fallback stubs
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows this file to be imported before the full William/Jarvis
        framework exists. The real BaseAgent can override these behaviors.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


try:
    from agents.verification_agent.config import VERIFICATION_AGENT_CONFIG  # type: ignore
except Exception:  # pragma: no cover
    VERIFICATION_AGENT_CONFIG: Dict[str, Any] = {
        "ui_element_checker": {
            "default_confidence_threshold": 0.70,
            "strict_confidence_threshold": 0.90,
            "max_elements_to_scan": 5000,
            "audit_enabled": True,
            "memory_payload_enabled": True,
            "case_sensitive_default": False,
            "fuzzy_text_default": True,
        }
    }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants / Enums
# ---------------------------------------------------------------------------

class UIElementType(str, Enum):
    """Supported high-level UI element types."""

    ANY = "any"
    BUTTON = "button"
    INPUT = "input"
    MODAL = "modal"
    FORM = "form"
    TOAST = "toast"
    PROGRESS_BAR = "progress_bar"
    LINK = "link"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    DROPDOWN = "dropdown"
    TAB = "tab"
    MENU = "menu"
    ALERT = "alert"
    SPINNER = "spinner"


class UIVisibilityStatus(str, Enum):
    """Visibility status returned by checks."""

    VISIBLE = "visible"
    NOT_VISIBLE = "not_visible"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


class UIMatchStrength(str, Enum):
    """Match strength labels for evidence scoring."""

    EXACT = "exact"
    STRONG = "strong"
    PARTIAL = "partial"
    WEAK = "weak"
    NONE = "none"


DEFAULT_VISIBLE_KEYS = (
    "visible",
    "is_visible",
    "displayed",
    "is_displayed",
    "shown",
    "in_viewport",
    "viewport_visible",
    "rendered",
)

DEFAULT_ENABLED_KEYS = (
    "enabled",
    "is_enabled",
    "clickable",
    "editable",
    "interactable",
    "active",
)

DEFAULT_TEXT_KEYS = (
    "text",
    "label",
    "name",
    "title",
    "aria_label",
    "aria-label",
    "placeholder",
    "value",
    "inner_text",
    "innerText",
    "accessible_name",
    "content",
    "message",
)

DEFAULT_SELECTOR_KEYS = (
    "selector",
    "css",
    "css_selector",
    "xpath",
    "id",
    "data_testid",
    "data-testid",
    "test_id",
    "name",
)

ROLE_ALIASES: Dict[str, Tuple[str, ...]] = {
    UIElementType.BUTTON.value: ("button", "btn", "submit", "reset"),
    UIElementType.INPUT.value: (
        "input",
        "textbox",
        "text",
        "textarea",
        "searchbox",
        "combobox",
        "email",
        "password",
        "number",
        "tel",
        "url",
    ),
    UIElementType.MODAL.value: ("modal", "dialog", "popup", "overlay", "drawer"),
    UIElementType.FORM.value: ("form", "fieldset"),
    UIElementType.TOAST.value: ("toast", "snackbar", "notification", "flash", "message"),
    UIElementType.PROGRESS_BAR.value: ("progressbar", "progress", "meter"),
    UIElementType.LINK.value: ("link", "anchor", "a"),
    UIElementType.CHECKBOX.value: ("checkbox",),
    UIElementType.RADIO.value: ("radio", "radio button"),
    UIElementType.DROPDOWN.value: ("select", "dropdown", "combobox", "listbox"),
    UIElementType.TAB.value: ("tab",),
    UIElementType.MENU.value: ("menu", "menuitem", "navigation"),
    UIElementType.ALERT.value: ("alert", "error", "warning", "success", "info"),
    UIElementType.SPINNER.value: ("spinner", "loader", "loading", "busy"),
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class UIElementEvidence:
    """Evidence collected for one matched or candidate UI element."""

    element_id: Optional[str] = None
    element_type: str = UIElementType.ANY.value
    role: Optional[str] = None
    tag: Optional[str] = None
    text: Optional[str] = None
    selector: Optional[str] = None
    visible: Optional[bool] = None
    enabled: Optional[bool] = None
    matched_by: List[str] = field(default_factory=list)
    match_strength: str = UIMatchStrength.NONE.value
    confidence: float = 0.0
    bounds: Optional[Dict[str, Any]] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    raw_index: Optional[int] = None


@dataclass
class UIElementExpectation:
    """
    Defines what should be checked.

    This object can be built directly by public methods or from API payloads.
    """

    element_type: str = UIElementType.ANY.value
    selector: Optional[str] = None
    text: Optional[str] = None
    role: Optional[str] = None
    tag: Optional[str] = None
    name: Optional[str] = None
    placeholder: Optional[str] = None
    value: Optional[str] = None
    expected_visible: Optional[bool] = True
    expected_enabled: Optional[bool] = None
    expected_present: bool = True
    expected_text_contains: Optional[str] = None
    expected_value: Optional[str] = None
    expected_empty: Optional[bool] = None
    expected_checked: Optional[bool] = None
    expected_selected: Optional[bool] = None
    expected_progress_min: Optional[float] = None
    expected_progress_max: Optional[float] = None
    required_fields: List[str] = field(default_factory=list)
    required_buttons: List[str] = field(default_factory=list)
    timeout_ms: Optional[int] = None
    case_sensitive: Optional[bool] = None
    fuzzy_text: Optional[bool] = None
    strict: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UITaskContext:
    """SaaS task context required for isolation and auditability."""

    user_id: str
    workspace_id: str
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = "verification_agent"
    source_agent: Optional[str] = None
    session_id: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""

    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _coerce_bool(value: Any) -> Optional[bool]:
    """Safely coerce common truthy/falsy values to bool."""

    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1", "visible", "enabled", "open", "shown"}:
            return True
        if normalized in {"false", "no", "n", "0", "hidden", "disabled", "closed", "none"}:
            return False
    return None


def _normalize_space(value: Any) -> str:
    """Normalize whitespace for text matching."""

    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _normalize_key(value: Any) -> str:
    """Normalize strings for flexible comparisons."""

    return _normalize_space(value).lower()


def _safe_float(value: Any) -> Optional[float]:
    """Convert a value to float safely."""

    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    try:
        if isinstance(value, str):
            cleaned = value.strip().replace("%", "")
            if not cleaned:
                return None
            number = float(cleaned)
            if "%" in value:
                return number / 100.0 if number > 1 else number
            return number
        return float(value)
    except Exception:
        return None


def _compact_dict(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy without None values at top level."""

    return {key: value for key, value in data.items() if value is not None}


def _deep_get(mapping: Mapping[str, Any], keys: Sequence[str], default: Any = None) -> Any:
    """Return first available key from a mapping."""

    for key in keys:
        if key in mapping:
            return mapping.get(key)
    return default


def _listify(value: Any) -> List[Any]:
    """Normalize a value into a list."""

    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _safe_len(value: Any) -> int:
    """Return length safely."""

    try:
        return len(value)  # type: ignore[arg-type]
    except Exception:
        return 0


def _contains_text(
    haystack: str,
    needle: str,
    *,
    case_sensitive: bool = False,
    fuzzy: bool = True,
) -> bool:
    """Check whether text contains another text with optional loose matching."""

    haystack_norm = _normalize_space(haystack)
    needle_norm = _normalize_space(needle)

    if not case_sensitive:
        haystack_cmp = haystack_norm.lower()
        needle_cmp = needle_norm.lower()
    else:
        haystack_cmp = haystack_norm
        needle_cmp = needle_norm

    if not needle_cmp:
        return True

    if needle_cmp in haystack_cmp:
        return True

    if fuzzy:
        haystack_words = set(re.findall(r"[a-zA-Z0-9]+", haystack_cmp))
        needle_words = set(re.findall(r"[a-zA-Z0-9]+", needle_cmp))
        if needle_words and needle_words.issubset(haystack_words):
            return True

    return False


def _text_similarity_score(
    haystack: str,
    needle: str,
    *,
    case_sensitive: bool = False,
) -> float:
    """
    Lightweight similarity score without external dependencies.

    Returns:
        1.00 exact normalized match
        0.90 containment match
        0.60+ token-overlap match
        0.00 no match
    """

    haystack_norm = _normalize_space(haystack)
    needle_norm = _normalize_space(needle)

    if not needle_norm:
        return 0.0

    if not case_sensitive:
        haystack_cmp = haystack_norm.lower()
        needle_cmp = needle_norm.lower()
    else:
        haystack_cmp = haystack_norm
        needle_cmp = needle_norm

    if haystack_cmp == needle_cmp:
        return 1.0
    if needle_cmp in haystack_cmp:
        return 0.9

    haystack_tokens = set(re.findall(r"[a-zA-Z0-9]+", haystack_cmp))
    needle_tokens = set(re.findall(r"[a-zA-Z0-9]+", needle_cmp))

    if not haystack_tokens or not needle_tokens:
        return 0.0

    overlap = len(haystack_tokens.intersection(needle_tokens))
    coverage = overlap / max(len(needle_tokens), 1)
    precision = overlap / max(len(haystack_tokens), 1)

    if coverage >= 0.85:
        return 0.8
    if coverage >= 0.60:
        return 0.65
    if coverage >= 0.35 and precision >= 0.20:
        return 0.45

    return 0.0


def _bound_area(bounds: Optional[Mapping[str, Any]]) -> Optional[float]:
    """Estimate element area from bounds."""

    if not bounds:
        return None

    width = _safe_float(bounds.get("width"))
    height = _safe_float(bounds.get("height"))

    if width is None:
        left = _safe_float(bounds.get("left") or bounds.get("x"))
        right = _safe_float(bounds.get("right"))
        if left is not None and right is not None:
            width = max(0.0, right - left)

    if height is None:
        top = _safe_float(bounds.get("top") or bounds.get("y"))
        bottom = _safe_float(bounds.get("bottom"))
        if top is not None and bottom is not None:
            height = max(0.0, bottom - top)

    if width is None or height is None:
        return None

    return max(0.0, width) * max(0.0, height)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class UIElementChecker(BaseAgent):
    """
    Confirms whether expected UI elements are visible/present/enabled in a UI snapshot.

    Master Agent / Router:
        The Master Agent can route verification tasks here when the task intent is
        "confirm UI element", "check button visible", "verify modal", etc.

    Security Agent:
        This checker is read-only. It does not click, type, navigate, send messages,
        or perform destructive actions. Security hooks are still provided for
        consistency and future policy enforcement.

    Memory Agent:
        Successful verification summaries can be transformed into memory-compatible
        payloads through `_prepare_memory_payload`.

    Verification Agent:
        Returns verification payloads with status, confidence, evidence, and expected
        vs actual UI state.

    Dashboard/API:
        Public methods return consistent dict structures suitable for FastAPI or
        dashboard cards.

    Registry/Loader:
        Import-safe and exposes a stable class name: UIElementChecker.
    """

    agent_name = "ui_element_checker"
    agent_module = "verification_agent"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
    ) -> None:
        super().__init__()

        config_root = copy.deepcopy(VERIFICATION_AGENT_CONFIG or {})
        checker_config = config_root.get("ui_element_checker", {})
        if config:
            checker_config.update(dict(config))

        self.config: Dict[str, Any] = checker_config
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.security_client = security_client
        self.memory_client = memory_client

        self.default_confidence_threshold = float(
            self.config.get("default_confidence_threshold", 0.70)
        )
        self.strict_confidence_threshold = float(
            self.config.get("strict_confidence_threshold", 0.90)
        )
        self.max_elements_to_scan = int(self.config.get("max_elements_to_scan", 5000))
        self.audit_enabled = bool(self.config.get("audit_enabled", True))
        self.memory_payload_enabled = bool(self.config.get("memory_payload_enabled", True))
        self.case_sensitive_default = bool(self.config.get("case_sensitive_default", False))
        self.fuzzy_text_default = bool(self.config.get("fuzzy_text_default", True))

        self.logger = logging.getLogger(f"{self.agent_module}.{self.agent_name}")

    # ------------------------------------------------------------------
    # Public primary methods
    # ------------------------------------------------------------------

    def check_element(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        expectation: Union[UIElementExpectation, Mapping[str, Any]],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check one generic UI element expectation against a UI snapshot.

        Args:
            user_id: SaaS user id.
            workspace_id: SaaS workspace id.
            snapshot: UI snapshot containing elements, accessibility nodes,
                browser state, screenshot analyzer results, or DOM-like records.
            expectation: Expected UI element rules.
            task_id: Optional verification task id.
            request_id: Optional request correlation id.
            source_agent: Optional source agent name.
            session_id: Optional UI/browser/session id.
            permissions: Optional task permissions.
            metadata: Optional extra metadata.

        Returns:
            Structured verification result.
        """

        context = UITaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
            source_agent=source_agent,
            session_id=session_id,
            permissions=dict(permissions or {}),
            metadata=dict(metadata or {}),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        normalized_expectation = self._coerce_expectation(expectation)

        security_result = self._request_security_approval(
            context=context,
            action="ui_element_check",
            payload={"expectation": asdict(normalized_expectation)},
        )
        if not security_result["success"]:
            return security_result

        started_at = _utc_now_iso()

        try:
            elements = self._extract_elements(snapshot)
            candidates = self._rank_candidates(
                elements=elements,
                expectation=normalized_expectation,
            )

            best = candidates[0] if candidates else None
            status = self._evaluate_expectation(
                best=best,
                candidates=candidates,
                expectation=normalized_expectation,
            )

            verification_payload = self._prepare_verification_payload(
                context=context,
                expectation=normalized_expectation,
                status=status,
                evidence=candidates[:10],
                started_at=started_at,
            )

            memory_payload = self._prepare_memory_payload(
                context=context,
                verification_payload=verification_payload,
            )

            result = self._safe_result(
                success=status["passed"],
                message=status["message"],
                data={
                    "passed": status["passed"],
                    "status": status["status"],
                    "visibility_status": status["visibility_status"],
                    "confidence": status["confidence"],
                    "element_type": normalized_expectation.element_type,
                    "expected": asdict(normalized_expectation),
                    "best_match": asdict(best) if best else None,
                    "evidence": [asdict(item) for item in candidates[:10]],
                    "candidate_count": len(candidates),
                    "scanned_element_count": len(elements),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "version": self.version,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "started_at": started_at,
                    "completed_at": _utc_now_iso(),
                },
            )

            self._emit_agent_event(
                "verification.ui_element.checked",
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": context.task_id,
                    "passed": status["passed"],
                    "element_type": normalized_expectation.element_type,
                    "confidence": status["confidence"],
                },
            )

            self._log_audit_event(
                {
                    "event": "ui_element_check",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "passed": status["passed"],
                    "element_type": normalized_expectation.element_type,
                    "selector": normalized_expectation.selector,
                    "text": normalized_expectation.text,
                    "confidence": status["confidence"],
                    "timestamp": _utc_now_iso(),
                }
            )

            return result

        except Exception as exc:
            self.logger.exception("UI element check failed")
            return self._error_result(
                message="UI element check failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

    def check_many(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        expectations: Sequence[Union[UIElementExpectation, Mapping[str, Any]]],
        require_all: bool = True,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check multiple UI expectations against one snapshot.

        Args:
            require_all:
                True means all expectations must pass.
                False means at least one expectation must pass.

        Returns:
            Structured combined result.
        """

        if not expectations:
            return self._error_result(
                message="No UI expectations were provided.",
                error="empty_expectations",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        results: List[Dict[str, Any]] = []

        for index, item in enumerate(expectations):
            item_result = self.check_element(
                user_id=user_id,
                workspace_id=workspace_id,
                snapshot=snapshot,
                expectation=item,
                task_id=task_id,
                request_id=request_id,
                source_agent=source_agent,
                session_id=session_id,
                permissions=permissions,
                metadata={
                    **dict(metadata or {}),
                    "batch_index": index,
                    "batch_total": len(expectations),
                },
            )
            results.append(item_result)

        passed_count = sum(1 for result in results if bool(result.get("success")))
        failed_count = len(results) - passed_count

        if require_all:
            success = failed_count == 0
            message = (
                f"All {passed_count} UI element checks passed."
                if success
                else f"{failed_count} of {len(results)} UI element checks failed."
            )
        else:
            success = passed_count > 0
            message = (
                f"{passed_count} of {len(results)} UI element checks passed."
                if success
                else "No UI element checks passed."
            )

        return self._safe_result(
            success=success,
            message=message,
            data={
                "require_all": require_all,
                "total": len(results),
                "passed_count": passed_count,
                "failed_count": failed_count,
                "results": results,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "version": self.version,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "completed_at": _utc_now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Public specialized helpers
    # ------------------------------------------------------------------

    def check_button_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        text: Optional[str] = None,
        selector: Optional[str] = None,
        expected_enabled: Optional[bool] = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm a button is visible and optionally enabled."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.BUTTON.value,
                text=text,
                selector=selector,
                expected_visible=True,
                expected_enabled=expected_enabled,
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    def check_input_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        text: Optional[str] = None,
        selector: Optional[str] = None,
        placeholder: Optional[str] = None,
        expected_value: Optional[str] = None,
        expected_empty: Optional[bool] = None,
        expected_enabled: Optional[bool] = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm an input field is visible and optionally has expected value/empty state."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.INPUT.value,
                text=text,
                selector=selector,
                placeholder=placeholder,
                expected_visible=True,
                expected_enabled=expected_enabled,
                expected_value=expected_value,
                expected_empty=expected_empty,
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    def check_modal_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        text: Optional[str] = None,
        selector: Optional[str] = None,
        expected_visible: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm a modal/dialog/popup is visible or not visible."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.MODAL.value,
                text=text,
                selector=selector,
                expected_visible=expected_visible,
                expected_present=expected_visible,
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    def check_form_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        text: Optional[str] = None,
        selector: Optional[str] = None,
        required_fields: Optional[Sequence[str]] = None,
        required_buttons: Optional[Sequence[str]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm a form is visible and optionally contains required fields/buttons."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.FORM.value,
                text=text,
                selector=selector,
                expected_visible=True,
                required_fields=list(required_fields or []),
                required_buttons=list(required_buttons or []),
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    def check_toast_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        message: Optional[str] = None,
        selector: Optional[str] = None,
        expected_visible: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm a toast/snackbar/notification is visible and optionally matches text."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.TOAST.value,
                text=message,
                selector=selector,
                expected_text_contains=message,
                expected_visible=expected_visible,
                expected_present=expected_visible,
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    def check_progress_bar_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        selector: Optional[str] = None,
        expected_progress_min: Optional[float] = None,
        expected_progress_max: Optional[float] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm a progress bar is visible and optionally inside expected progress range."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.PROGRESS_BAR.value,
                selector=selector,
                expected_visible=True,
                expected_progress_min=expected_progress_min,
                expected_progress_max=expected_progress_max,
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    def check_spinner_visible(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        text: Optional[str] = None,
        selector: Optional[str] = None,
        expected_visible: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm a spinner/loader is visible or hidden."""

        return self.check_element(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            expectation=UIElementExpectation(
                element_type=UIElementType.SPINNER.value,
                text=text,
                selector=selector,
                expected_visible=expected_visible,
                expected_present=expected_visible,
                strict=bool(kwargs.pop("strict", False)),
                metadata=dict(kwargs.pop("expectation_metadata", {})),
            ),
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Snapshot normalization
    # ------------------------------------------------------------------

    def _extract_elements(self, snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract UI elements from flexible snapshot shapes.

        Supported snapshot shapes:
            {"elements": [...]}
            {"ui_elements": [...]}
            {"nodes": [...]}
            {"accessibility_tree": {"nodes": [...]}}
            {"dom": {"elements": [...]}}
            {"browser_state": {"elements": [...]}}
            {"screenshot_analysis": {"elements": [...]}}
            {"matches": [...]}

        Also recursively scans limited common nested children.
        """

        if not isinstance(snapshot, Mapping):
            return []

        raw_collections: List[Any] = []

        for key in (
            "elements",
            "ui_elements",
            "nodes",
            "matches",
            "detected_elements",
            "visible_elements",
            "components",
        ):
            if key in snapshot:
                raw_collections.extend(_listify(snapshot.get(key)))

        nested_keys = (
            "accessibility_tree",
            "dom",
            "browser_state",
            "screenshot_analysis",
            "page",
            "window",
            "screen",
            "result",
            "data",
        )

        for key in nested_keys:
            nested = snapshot.get(key)
            if isinstance(nested, Mapping):
                for child_key in (
                    "elements",
                    "ui_elements",
                    "nodes",
                    "matches",
                    "detected_elements",
                    "visible_elements",
                    "components",
                ):
                    if child_key in nested:
                        raw_collections.extend(_listify(nested.get(child_key)))

        normalized: List[Dict[str, Any]] = []
        seen_signatures: set = set()

        def walk(item: Any, depth: int = 0) -> None:
            if len(normalized) >= self.max_elements_to_scan:
                return
            if depth > 5:
                return

            if isinstance(item, Mapping):
                element = self._normalize_element(item, raw_index=len(normalized))
                signature = self._element_signature(element)
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    normalized.append(element)

                for child_key in ("children", "child_nodes", "nodes", "items", "options"):
                    children = item.get(child_key)
                    if isinstance(children, (list, tuple)):
                        for child in children:
                            walk(child, depth + 1)

            elif isinstance(item, (list, tuple)):
                for child in item:
                    walk(child, depth + 1)

        for collection_item in raw_collections:
            walk(collection_item)

        return normalized[: self.max_elements_to_scan]

    def _normalize_element(self, element: Mapping[str, Any], raw_index: int) -> Dict[str, Any]:
        """Normalize one element dictionary into consistent fields."""

        attrs = dict(element.get("attributes") or {})
        merged = {**attrs, **dict(element)}

        role = merged.get("role") or merged.get("aria_role") or merged.get("type")
        tag = merged.get("tag") or merged.get("tag_name") or merged.get("nodeName")
        text = self._extract_text(merged)
        selector = self._extract_selector(merged)
        bounds = self._extract_bounds(merged)
        visible = self._infer_visible(merged, bounds)
        enabled = self._infer_enabled(merged)

        element_id = (
            merged.get("element_id")
            or merged.get("id")
            or merged.get("uid")
            or merged.get("uuid")
            or merged.get("backend_node_id")
            or merged.get("node_id")
        )

        normalized = {
            "element_id": str(element_id) if element_id is not None else None,
            "role": str(role).lower() if role is not None else None,
            "tag": str(tag).lower() if tag is not None else None,
            "text": text,
            "selector": selector,
            "visible": visible,
            "enabled": enabled,
            "bounds": bounds,
            "attributes": attrs,
            "raw": dict(element),
            "raw_index": raw_index,
            "value": merged.get("value"),
            "checked": _coerce_bool(merged.get("checked") or merged.get("is_checked")),
            "selected": _coerce_bool(merged.get("selected") or merged.get("is_selected")),
            "progress": self._extract_progress(merged),
            "placeholder": merged.get("placeholder") or attrs.get("placeholder"),
            "name": merged.get("name") or attrs.get("name"),
            "class": merged.get("class") or merged.get("className") or attrs.get("class"),
        }

        return normalized

    def _extract_text(self, element: Mapping[str, Any]) -> str:
        """Extract best available visible/accessibility text."""

        parts: List[str] = []

        for key in DEFAULT_TEXT_KEYS:
            value = element.get(key)
            if value is not None and not isinstance(value, (dict, list, tuple)):
                text = _normalize_space(value)
                if text:
                    parts.append(text)

        attributes = element.get("attributes")
        if isinstance(attributes, Mapping):
            for key in DEFAULT_TEXT_KEYS:
                value = attributes.get(key)
                if value is not None and not isinstance(value, (dict, list, tuple)):
                    text = _normalize_space(value)
                    if text:
                        parts.append(text)

        unique_parts: List[str] = []
        seen: set = set()
        for part in parts:
            normalized = _normalize_key(part)
            if normalized not in seen:
                seen.add(normalized)
                unique_parts.append(part)

        return " | ".join(unique_parts)

    def _extract_selector(self, element: Mapping[str, Any]) -> Optional[str]:
        """Extract best available selector-like identifier."""

        for key in DEFAULT_SELECTOR_KEYS:
            value = element.get(key)
            if value:
                return str(value)

        attributes = element.get("attributes")
        if isinstance(attributes, Mapping):
            for key in DEFAULT_SELECTOR_KEYS:
                value = attributes.get(key)
                if value:
                    if key == "id" and not str(value).startswith("#"):
                        return f"#{value}"
                    return str(value)

        return None

    def _extract_bounds(self, element: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract bounds from common shapes."""

        for key in ("bounds", "bounding_box", "bbox", "rect", "location"):
            value = element.get(key)
            if isinstance(value, Mapping):
                return dict(value)

        keys = ("x", "y", "left", "top", "right", "bottom", "width", "height")
        if any(key in element for key in keys):
            return {key: element.get(key) for key in keys if key in element}

        return None

    def _infer_visible(
        self,
        element: Mapping[str, Any],
        bounds: Optional[Mapping[str, Any]],
    ) -> Optional[bool]:
        """Infer element visibility from boolean flags, style, aria, and size."""

        for key in DEFAULT_VISIBLE_KEYS:
            if key in element:
                value = _coerce_bool(element.get(key))
                if value is not None:
                    return value

        attributes = element.get("attributes")
        if isinstance(attributes, Mapping):
            aria_hidden = _coerce_bool(attributes.get("aria-hidden"))
            if aria_hidden is True:
                return False

            hidden = _coerce_bool(attributes.get("hidden"))
            if hidden is True:
                return False

            style = str(attributes.get("style") or "").lower()
            if "display: none" in style or "visibility: hidden" in style or "opacity: 0" in style:
                return False

        style = str(element.get("style") or "").lower()
        if "display: none" in style or "visibility: hidden" in style or "opacity: 0" in style:
            return False

        area = _bound_area(bounds)
        if area is not None:
            return area > 0

        return None

    def _infer_enabled(self, element: Mapping[str, Any]) -> Optional[bool]:
        """Infer enabled/clickable state."""

        if "disabled" in element:
            disabled = _coerce_bool(element.get("disabled"))
            if disabled is not None:
                return not disabled

        for key in DEFAULT_ENABLED_KEYS:
            if key in element:
                value = _coerce_bool(element.get(key))
                if value is not None:
                    return value

        attributes = element.get("attributes")
        if isinstance(attributes, Mapping):
            disabled = _coerce_bool(attributes.get("disabled") or attributes.get("aria-disabled"))
            if disabled is not None:
                return not disabled

        return None

    def _extract_progress(self, element: Mapping[str, Any]) -> Optional[float]:
        """Extract progress value as 0..1 when possible."""

        for key in ("progress", "percentage", "percent", "value", "aria-valuenow"):
            value = element.get(key)
            number = _safe_float(value)
            if number is not None:
                if number > 1.0:
                    return max(0.0, min(1.0, number / 100.0))
                return max(0.0, min(1.0, number))

        attributes = element.get("attributes")
        if isinstance(attributes, Mapping):
            now = _safe_float(attributes.get("aria-valuenow"))
            min_value = _safe_float(attributes.get("aria-valuemin"))
            max_value = _safe_float(attributes.get("aria-valuemax"))
            if now is not None:
                if min_value is not None and max_value is not None and max_value > min_value:
                    return max(0.0, min(1.0, (now - min_value) / (max_value - min_value)))
                if now > 1.0:
                    return max(0.0, min(1.0, now / 100.0))
                return max(0.0, min(1.0, now))

        return None

    def _element_signature(self, element: Mapping[str, Any]) -> Tuple[Any, ...]:
        """Build a dedupe signature for normalized elements."""

        return (
            element.get("element_id"),
            element.get("role"),
            element.get("tag"),
            _normalize_key(element.get("text")),
            element.get("selector"),
            str(element.get("bounds")),
        )

    # ------------------------------------------------------------------
    # Matching / scoring
    # ------------------------------------------------------------------

    def _rank_candidates(
        self,
        *,
        elements: Sequence[Mapping[str, Any]],
        expectation: UIElementExpectation,
    ) -> List[UIElementEvidence]:
        """Score and rank candidate elements."""

        evidence: List[UIElementEvidence] = []

        for element in elements:
            item = self._score_element(element, expectation)
            if item.confidence > 0:
                evidence.append(item)

        evidence.sort(key=lambda item: item.confidence, reverse=True)
        return evidence

    def _score_element(
        self,
        element: Mapping[str, Any],
        expectation: UIElementExpectation,
    ) -> UIElementEvidence:
        """Score a normalized element against an expectation."""

        case_sensitive = (
            expectation.case_sensitive
            if expectation.case_sensitive is not None
            else self.case_sensitive_default
        )
        fuzzy_text = (
            expectation.fuzzy_text
            if expectation.fuzzy_text is not None
            else self.fuzzy_text_default
        )

        matched_by: List[str] = []
        score = 0.0
        possible_score = 0.0

        element_role = _normalize_key(element.get("role"))
        element_tag = _normalize_key(element.get("tag"))
        element_text = _normalize_space(element.get("text"))
        element_selector = _normalize_space(element.get("selector"))
        element_name = _normalize_space(element.get("name"))
        element_placeholder = _normalize_space(element.get("placeholder"))

        # Type/role/tag score
        if expectation.element_type and expectation.element_type != UIElementType.ANY.value:
            possible_score += 0.28
            if self._matches_element_type(element, expectation.element_type):
                score += 0.28
                matched_by.append("element_type")

        # Explicit role score
        if expectation.role:
            possible_score += 0.18
            if _normalize_key(expectation.role) == element_role:
                score += 0.18
                matched_by.append("role_exact")

        # Explicit tag score
        if expectation.tag:
            possible_score += 0.14
            if _normalize_key(expectation.tag) == element_tag:
                score += 0.14
                matched_by.append("tag_exact")

        # Selector score
        if expectation.selector:
            possible_score += 0.30
            selector_score = self._selector_score(
                element_selector=element_selector,
                element=element,
                expected_selector=expectation.selector,
            )
            if selector_score > 0:
                score += 0.30 * selector_score
                matched_by.append("selector_exact" if selector_score >= 1.0 else "selector_partial")

        # Text score
        expected_texts = [
            expectation.text,
            expectation.expected_text_contains,
            expectation.name,
            expectation.placeholder,
        ]
        expected_texts = [text for text in expected_texts if text]

        if expected_texts:
            possible_score += 0.30
            best_text_score = 0.0
            for expected_text in expected_texts:
                target_blob = " | ".join(
                    part for part in (element_text, element_name, element_placeholder) if part
                )
                best_text_score = max(
                    best_text_score,
                    _text_similarity_score(
                        target_blob,
                        str(expected_text),
                        case_sensitive=case_sensitive,
                    ),
                )
            if best_text_score > 0:
                score += 0.30 * best_text_score
                if best_text_score >= 1.0:
                    matched_by.append("text_exact")
                elif best_text_score >= 0.80:
                    matched_by.append("text_strong")
                else:
                    matched_by.append("text_partial")

        # Visible state score
        if expectation.expected_visible is not None:
            possible_score += 0.16
            visible = element.get("visible")
            if visible is expectation.expected_visible:
                score += 0.16
                matched_by.append("visibility")
            elif visible is None:
                score += 0.05
                matched_by.append("visibility_unknown")

        # Enabled state score
        if expectation.expected_enabled is not None:
            possible_score += 0.10
            enabled = element.get("enabled")
            if enabled is expectation.expected_enabled:
                score += 0.10
                matched_by.append("enabled")
            elif enabled is None:
                score += 0.03
                matched_by.append("enabled_unknown")

        # Value score
        if expectation.expected_value is not None:
            possible_score += 0.14
            actual_value = _normalize_space(element.get("value"))
            if _contains_text(
                actual_value,
                expectation.expected_value,
                case_sensitive=case_sensitive,
                fuzzy=fuzzy_text,
            ):
                score += 0.14
                matched_by.append("value")

        # Empty score
        if expectation.expected_empty is not None:
            possible_score += 0.12
            actual_value = _normalize_space(element.get("value"))
            actual_empty = actual_value == ""
            if actual_empty is expectation.expected_empty:
                score += 0.12
                matched_by.append("empty_state")

        # Checked score
        if expectation.expected_checked is not None:
            possible_score += 0.12
            if element.get("checked") is expectation.expected_checked:
                score += 0.12
                matched_by.append("checked_state")

        # Selected score
        if expectation.expected_selected is not None:
            possible_score += 0.12
            if element.get("selected") is expectation.expected_selected:
                score += 0.12
                matched_by.append("selected_state")

        # Progress range score
        if expectation.expected_progress_min is not None or expectation.expected_progress_max is not None:
            possible_score += 0.14
            progress = element.get("progress")
            if progress is not None:
                min_ok = (
                    True
                    if expectation.expected_progress_min is None
                    else progress >= expectation.expected_progress_min
                )
                max_ok = (
                    True
                    if expectation.expected_progress_max is None
                    else progress <= expectation.expected_progress_max
                )
                if min_ok and max_ok:
                    score += 0.14
                    matched_by.append("progress_range")

        if possible_score <= 0:
            possible_score = 1.0

        confidence = max(0.0, min(1.0, score / possible_score))

        # Strong type-only matches should remain useful but not overconfident.
        if matched_by == ["element_type"]:
            confidence = min(confidence, 0.50)

        # Boost when selector and text both match.
        if any(item.startswith("selector") for item in matched_by) and any(
            item.startswith("text") for item in matched_by
        ):
            confidence = min(1.0, confidence + 0.08)

        # Penalize hidden elements when visible expected.
        if expectation.expected_visible is True and element.get("visible") is False:
            confidence = min(confidence, 0.45)

        # Penalize wrong type for type-specific checks.
        if (
            expectation.element_type
            and expectation.element_type != UIElementType.ANY.value
            and not self._matches_element_type(element, expectation.element_type)
        ):
            confidence = min(confidence, 0.55)

        match_strength = self._match_strength(confidence)

        return UIElementEvidence(
            element_id=element.get("element_id"),
            element_type=expectation.element_type,
            role=element.get("role"),
            tag=element.get("tag"),
            text=element.get("text"),
            selector=element.get("selector"),
            visible=element.get("visible"),
            enabled=element.get("enabled"),
            matched_by=matched_by,
            match_strength=match_strength,
            confidence=round(confidence, 4),
            bounds=dict(element.get("bounds")) if isinstance(element.get("bounds"), Mapping) else None,
            attributes={
                "value": element.get("value"),
                "checked": element.get("checked"),
                "selected": element.get("selected"),
                "progress": element.get("progress"),
                "placeholder": element.get("placeholder"),
                "name": element.get("name"),
                "class": element.get("class"),
            },
            raw_index=element.get("raw_index"),
        )

    def _selector_score(
        self,
        *,
        element_selector: str,
        element: Mapping[str, Any],
        expected_selector: str,
    ) -> float:
        """Score selector match."""

        expected = _normalize_space(expected_selector)
        actual = _normalize_space(element_selector)

        if not expected:
            return 0.0

        if actual == expected:
            return 1.0

        expected_norm = expected.lower()
        actual_norm = actual.lower()

        if actual_norm == expected_norm:
            return 0.95

        # Match CSS ID selector against raw id.
        raw = element.get("raw")
        attrs = element.get("attributes") or {}
        raw_id = None
        if isinstance(raw, Mapping):
            raw_id = raw.get("id")
        if not raw_id and isinstance(attrs, Mapping):
            raw_id = attrs.get("id")

        if expected.startswith("#") and raw_id and expected[1:].lower() == str(raw_id).lower():
            return 1.0

        # Match data-testid.
        for key in ("data-testid", "data_testid", "test_id"):
            raw_value = None
            if isinstance(raw, Mapping):
                raw_value = raw.get(key)
            if raw_value is None and isinstance(attrs, Mapping):
                raw_value = attrs.get(key)
            if raw_value and str(raw_value).lower() == expected_norm:
                return 0.95

        if expected_norm in actual_norm or actual_norm in expected_norm:
            return 0.75

        return 0.0

    def _matches_element_type(self, element: Mapping[str, Any], expected_type: str) -> bool:
        """Check role/tag/class/text hints against expected element type."""

        expected = _normalize_key(expected_type)
        if expected == UIElementType.ANY.value:
            return True

        aliases = ROLE_ALIASES.get(expected, (expected,))
        role = _normalize_key(element.get("role"))
        tag = _normalize_key(element.get("tag"))
        class_name = _normalize_key(element.get("class"))
        raw = element.get("raw") if isinstance(element.get("raw"), Mapping) else {}
        attrs = element.get("attributes") if isinstance(element.get("attributes"), Mapping) else {}

        type_hint = _normalize_key(
            raw.get("type")
            or attrs.get("type")
            or raw.get("aria_role")
            or attrs.get("role")
        )

        haystack = " ".join([role, tag, class_name, type_hint])

        if any(alias == role or alias == tag or alias == type_hint for alias in aliases):
            return True

        if any(alias in haystack for alias in aliases):
            return True

        # HTML-specific inference.
        if expected == UIElementType.BUTTON.value:
            return tag == "button" or type_hint in {"button", "submit", "reset"}

        if expected == UIElementType.INPUT.value:
            return tag in {"input", "textarea"} or role in {"textbox", "searchbox"}

        if expected == UIElementType.FORM.value:
            return tag == "form"

        if expected == UIElementType.LINK.value:
            return tag == "a" or role == "link"

        if expected == UIElementType.PROGRESS_BAR.value:
            return tag in {"progress", "meter"} or role == "progressbar"

        return False

    def _match_strength(self, confidence: float) -> str:
        """Convert confidence to match strength."""

        if confidence >= 0.95:
            return UIMatchStrength.EXACT.value
        if confidence >= 0.80:
            return UIMatchStrength.STRONG.value
        if confidence >= 0.60:
            return UIMatchStrength.PARTIAL.value
        if confidence > 0:
            return UIMatchStrength.WEAK.value
        return UIMatchStrength.NONE.value

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _evaluate_expectation(
        self,
        *,
        best: Optional[UIElementEvidence],
        candidates: Sequence[UIElementEvidence],
        expectation: UIElementExpectation,
    ) -> Dict[str, Any]:
        """Evaluate best candidate and expectation into pass/fail status."""

        threshold = (
            self.strict_confidence_threshold
            if expectation.strict
            else self.default_confidence_threshold
        )

        if not best:
            if expectation.expected_present is False:
                return {
                    "passed": True,
                    "status": "passed",
                    "visibility_status": UIVisibilityStatus.NOT_FOUND.value,
                    "confidence": 1.0,
                    "message": "Expected UI element was not present, and absence was expected.",
                }

            return {
                "passed": False,
                "status": "failed",
                "visibility_status": UIVisibilityStatus.NOT_FOUND.value,
                "confidence": 0.0,
                "message": "Expected UI element was not found in the supplied snapshot.",
            }

        confidence = float(best.confidence)

        if expectation.expected_present is False:
            passed = confidence < threshold
            return {
                "passed": passed,
                "status": "passed" if passed else "failed",
                "visibility_status": (
                    UIVisibilityStatus.NOT_FOUND.value
                    if passed
                    else self._visibility_status(best.visible)
                ),
                "confidence": round(1.0 - confidence if passed else confidence, 4),
                "message": (
                    "Expected UI element absence was confirmed."
                    if passed
                    else "UI element was found, but it was expected to be absent."
                ),
            }

        if confidence < threshold:
            return {
                "passed": False,
                "status": "failed",
                "visibility_status": self._visibility_status(best.visible),
                "confidence": round(confidence, 4),
                "message": (
                    f"Best UI element match confidence {confidence:.2f} is below "
                    f"required threshold {threshold:.2f}."
                ),
            }

        detailed_failure = self._validate_detailed_rules(best, expectation)
        if detailed_failure:
            return {
                "passed": False,
                "status": "failed",
                "visibility_status": self._visibility_status(best.visible),
                "confidence": round(confidence, 4),
                "message": detailed_failure,
            }

        return {
            "passed": True,
            "status": "passed",
            "visibility_status": self._visibility_status(best.visible),
            "confidence": round(confidence, 4),
            "message": "Expected UI element was confirmed.",
        }

    def _validate_detailed_rules(
        self,
        evidence: UIElementEvidence,
        expectation: UIElementExpectation,
    ) -> Optional[str]:
        """Validate final detailed rules against the best evidence."""

        if expectation.expected_visible is True and evidence.visible is False:
            return "UI element was found but is not visible."

        if expectation.expected_visible is False and evidence.visible is True:
            return "UI element is visible but was expected to be hidden."

        if expectation.expected_enabled is True and evidence.enabled is False:
            return "UI element is disabled but was expected to be enabled."

        if expectation.expected_enabled is False and evidence.enabled is True:
            return "UI element is enabled but was expected to be disabled."

        attrs = evidence.attributes or {}

        if expectation.expected_value is not None:
            actual_value = _normalize_space(attrs.get("value"))
            expected_value = _normalize_space(expectation.expected_value)
            if actual_value != expected_value and expected_value not in actual_value:
                return "UI element value does not match expected value."

        if expectation.expected_empty is not None:
            actual_empty = _normalize_space(attrs.get("value")) == ""
            if actual_empty is not expectation.expected_empty:
                return "UI input empty/non-empty state does not match expectation."

        if expectation.expected_checked is not None:
            if attrs.get("checked") is not expectation.expected_checked:
                return "UI checkbox/radio checked state does not match expectation."

        if expectation.expected_selected is not None:
            if attrs.get("selected") is not expectation.expected_selected:
                return "UI selected state does not match expectation."

        if (
            expectation.expected_progress_min is not None
            or expectation.expected_progress_max is not None
        ):
            progress = attrs.get("progress")
            if progress is None:
                return "UI progress value could not be determined."

            if expectation.expected_progress_min is not None and progress < expectation.expected_progress_min:
                return "UI progress value is below the expected minimum."

            if expectation.expected_progress_max is not None and progress > expectation.expected_progress_max:
                return "UI progress value is above the expected maximum."

        # Form-level rules are best-effort because snapshots vary. If child elements
        # were flattened, callers should use check_many for exact field/button checks.
        if expectation.element_type == UIElementType.FORM.value:
            form_text = evidence.text or ""
            missing_fields = [
                field_name
                for field_name in expectation.required_fields
                if not _contains_text(form_text, field_name, case_sensitive=False, fuzzy=True)
            ]
            missing_buttons = [
                button_name
                for button_name in expectation.required_buttons
                if not _contains_text(form_text, button_name, case_sensitive=False, fuzzy=True)
            ]

            if missing_fields:
                return f"Form is visible but missing expected field text: {', '.join(missing_fields)}."

            if missing_buttons:
                return f"Form is visible but missing expected button text: {', '.join(missing_buttons)}."

        return None

    def _visibility_status(self, value: Optional[bool]) -> str:
        """Return normalized visibility status."""

        if value is True:
            return UIVisibilityStatus.VISIBLE.value
        if value is False:
            return UIVisibilityStatus.NOT_VISIBLE.value
        return UIVisibilityStatus.UNKNOWN.value

    # ------------------------------------------------------------------
    # Context / security / memory / audit compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: UITaskContext) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Every user-specific execution must include both user_id and workspace_id.
        """

        if not context.user_id or not str(context.user_id).strip():
            return self._error_result(
                message="Missing required user_id for UI element verification.",
                error="missing_user_id",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

        if not context.workspace_id or not str(context.workspace_id).strip():
            return self._error_result(
                message="Missing required workspace_id for UI element verification.",
                error="missing_workspace_id",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": context.user_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

        return self._safe_result(
            success=True,
            message="Task context is valid.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "request_id": context.request_id,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
            },
        )

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Return whether action requires Security Agent approval.

        UI checks are read-only, but this hook exists for consistent policy routing.
        """

        _ = payload
        read_only_actions = {
            "ui_element_check",
            "ui_element_batch_check",
            "prepare_verification_payload",
        }
        return action not in read_only_actions

    def _request_security_approval(
        self,
        *,
        context: UITaskContext,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when needed.

        Because this file only reads supplied snapshots and does not execute actions,
        approval is normally not required. If a future policy marks the action as
        sensitive, this method can call an injected security client.
        """

        if not self._requires_security_check(action, payload):
            return self._safe_result(
                success=True,
                message="Security approval not required for read-only UI verification.",
                data={"approved": True, "action": action, "read_only": True},
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": context.task_id,
                },
            )

        if self.security_client and hasattr(self.security_client, "approve"):
            try:
                approval = self.security_client.approve(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    action=action,
                    payload=dict(payload or {}),
                )
                approved = bool(
                    approval.get("approved")
                    if isinstance(approval, Mapping)
                    else approval
                )
                if approved:
                    return self._safe_result(
                        success=True,
                        message="Security Agent approved UI verification action.",
                        data={"approved": True, "action": action},
                        metadata={
                            "agent": self.agent_name,
                            "module": self.agent_module,
                        },
                    )
            except Exception as exc:
                return self._error_result(
                    message="Security approval failed.",
                    error=exc,
                    metadata={
                        "agent": self.agent_name,
                        "module": self.agent_module,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "task_id": context.task_id,
                    },
                )

        return self._error_result(
            message="Security approval is required but was not granted.",
            error="security_approval_required",
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "action": action,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        context: UITaskContext,
        expectation: UIElementExpectation,
        status: Mapping[str, Any],
        evidence: Sequence[UIElementEvidence],
        started_at: str,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.

        This payload can be stored in task history, dashboard analytics, audit logs,
        or passed back to Master Agent as proof of UI state.
        """

        return {
            "verification_type": "ui_element",
            "agent": self.agent_name,
            "module": self.agent_module,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "source_agent": context.source_agent,
            "session_id": context.session_id,
            "started_at": started_at,
            "completed_at": _utc_now_iso(),
            "status": status.get("status"),
            "passed": bool(status.get("passed")),
            "message": status.get("message"),
            "confidence": status.get("confidence"),
            "visibility_status": status.get("visibility_status"),
            "expected": asdict(expectation),
            "actual": {
                "best_match": asdict(evidence[0]) if evidence else None,
                "evidence_count": len(evidence),
                "top_evidence": [asdict(item) for item in evidence[:5]],
            },
            "proof": {
                "method": "snapshot_element_matching",
                "read_only": True,
                "destructive_action_performed": False,
            },
            "metadata": {
                **context.metadata,
                "permissions": context.permissions,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: UITaskContext,
        verification_payload: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Prepare Memory Agent-compatible payload.

        The Memory Agent can choose to persist task summaries, verification proof,
        or recurring UI patterns per user/workspace. This method does not write to
        memory directly unless an injected memory client supports it.
        """

        if not self.memory_payload_enabled:
            return None

        payload = {
            "memory_type": "verification_summary",
            "scope": "workspace",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "source": self.agent_name,
            "content": {
                "verification_type": verification_payload.get("verification_type"),
                "passed": verification_payload.get("passed"),
                "message": verification_payload.get("message"),
                "confidence": verification_payload.get("confidence"),
                "expected": verification_payload.get("expected"),
                "actual": verification_payload.get("actual"),
            },
            "created_at": _utc_now_iso(),
        }

        if self.memory_client and hasattr(self.memory_client, "prepare_payload"):
            try:
                prepared = self.memory_client.prepare_payload(payload)
                if isinstance(prepared, Mapping):
                    return dict(prepared)
            except Exception:
                self.logger.debug("Memory payload preparation via client failed", exc_info=True)

        return payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit an agent event for Dashboard/API/analytics.

        Safe no-op if no event emitter is configured.
        """

        safe_payload = copy.deepcopy(payload)
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("module", self.agent_module)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return

            if hasattr(self, "emit_event"):
                try:
                    self.emit_event(event_name, safe_payload)  # type: ignore[attr-defined]
                    return
                except TypeError:
                    pass

            self.logger.debug("Agent event emitted: %s %s", event_name, safe_payload)
        except Exception:
            self.logger.debug("Agent event emission failed", exc_info=True)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """
        Log audit event.

        Audit logs should remain user/workspace scoped. This method avoids crashing
        if audit infrastructure is not installed yet.
        """

        if not self.audit_enabled:
            return

        safe_payload = copy.deepcopy(payload)
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("module", self.agent_module)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.audit_logger:
                self.audit_logger(safe_payload)
                return

            if hasattr(self, "log_audit"):
                try:
                    self.log_audit(safe_payload)  # type: ignore[attr-defined]
                    return
                except TypeError:
                    pass

            self.logger.info("Audit event: %s", safe_payload)
        except Exception:
            self.logger.debug("Audit logging failed", exc_info=True)

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured success/error result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": self._serialize_error(error) if error else None,
            "metadata": {
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured error result."""

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

    def _serialize_error(self, error: Any) -> Dict[str, Any]:
        """Serialize errors safely for JSON responses."""

        if isinstance(error, Mapping):
            return dict(error)

        if isinstance(error, str):
            return {
                "type": "Error",
                "message": error,
            }

        return {
            "type": error.__class__.__name__,
            "message": str(error),
        }

    # ------------------------------------------------------------------
    # Coercion helpers
    # ------------------------------------------------------------------

    def _coerce_expectation(
        self,
        expectation: Union[UIElementExpectation, Mapping[str, Any]],
    ) -> UIElementExpectation:
        """Coerce dict/API payload into UIElementExpectation."""

        if isinstance(expectation, UIElementExpectation):
            return expectation

        if not isinstance(expectation, Mapping):
            raise TypeError("expectation must be UIElementExpectation or mapping")

        allowed_fields = set(UIElementExpectation.__dataclass_fields__.keys())
        values = {key: value for key, value in expectation.items() if key in allowed_fields}

        aliases = {
            "type": "element_type",
            "ui_type": "element_type",
            "expected_text": "text",
            "message": "expected_text_contains",
            "visible": "expected_visible",
            "enabled": "expected_enabled",
            "present": "expected_present",
            "checked": "expected_checked",
            "selected": "expected_selected",
            "progress_min": "expected_progress_min",
            "progress_max": "expected_progress_max",
        }

        for source_key, target_key in aliases.items():
            if source_key in expectation and target_key not in values:
                values[target_key] = expectation[source_key]

        if "element_type" in values and isinstance(values["element_type"], UIElementType):
            values["element_type"] = values["element_type"].value

        if "required_fields" in values:
            values["required_fields"] = [str(item) for item in _listify(values["required_fields"])]

        if "required_buttons" in values:
            values["required_buttons"] = [str(item) for item in _listify(values["required_buttons"])]

        return UIElementExpectation(**values)

    # ------------------------------------------------------------------
    # Registry / health helpers
    # ------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return module capabilities for Agent Registry / Dashboard.

        This method is intentionally read-only and import-safe.
        """

        return {
            "agent": self.agent_name,
            "module": self.agent_module,
            "version": self.version,
            "class": self.__class__.__name__,
            "read_only": True,
            "supports": [
                "button_visibility",
                "input_visibility",
                "modal_visibility",
                "form_visibility",
                "toast_visibility",
                "progress_bar_visibility",
                "spinner_visibility",
                "batch_ui_checks",
                "snapshot_element_matching",
                "verification_payload",
                "memory_payload",
                "audit_event",
                "saas_user_workspace_isolation",
            ],
            "public_methods": [
                "check_element",
                "check_many",
                "check_button_visible",
                "check_input_visible",
                "check_modal_visible",
                "check_form_visible",
                "check_toast_visible",
                "check_progress_bar_visible",
                "check_spinner_visible",
                "get_capabilities",
                "health_check",
            ],
        }

    def health_check(self) -> Dict[str, Any]:
        """Return simple health result for FastAPI/dashboard checks."""

        return self._safe_result(
            success=True,
            message="UIElementChecker is healthy.",
            data={
                "agent": self.agent_name,
                "module": self.agent_module,
                "version": self.version,
                "max_elements_to_scan": self.max_elements_to_scan,
                "default_confidence_threshold": self.default_confidence_threshold,
                "strict_confidence_threshold": self.strict_confidence_threshold,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
            },
        )


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def create_ui_element_checker(
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> UIElementChecker:
    """
    Factory function for Agent Loader / Registry.

    Args:
        config: Optional checker configuration.
        **kwargs: Optional injected clients/callbacks.

    Returns:
        UIElementChecker instance.
    """

    return UIElementChecker(config=config, **kwargs)


__all__ = [
    "UIElementChecker",
    "UIElementExpectation",
    "UIElementEvidence",
    "UITaskContext",
    "UIElementType",
    "UIVisibilityStatus",
    "UIMatchStrength",
    "create_ui_element_checker",
]