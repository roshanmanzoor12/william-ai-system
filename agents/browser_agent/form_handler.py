"""
agents/browser_agent/form_handler.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detect, fill, validate forms with approval; never submit sensitive forms silently.

This module belongs to the Browser Agent and is designed to be:
    - Import-safe even if other William/Jarvis modules are not created yet
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing
    - SaaS-safe with user_id/workspace_id validation
    - Security-first for sensitive forms and form submission
    - Memory Agent compatible through structured memory payloads
    - Verification Agent compatible through structured verification payloads
    - Dashboard/API ready through structured JSON-style results

Security rule:
    This file must never silently submit sensitive forms.
    All form submission requires explicit approval through Security Agent hooks.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ======================================================================================
# Optional / Safe Imports
# ======================================================================================

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows this file to import safely before the real William/Jarvis BaseAgent
        exists. The real BaseAgent should replace this automatically when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger("William.BrowserAgent.FormHandler")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Constants
# ======================================================================================

DEFAULT_AGENT_NAME = "browser_form_handler"
DEFAULT_AGENT_MODULE = "Browser Agent"
DEFAULT_FILE_PATH = "agents/browser_agent/form_handler.py"

SENSITIVE_FIELD_KEYWORDS = {
    "password",
    "pass",
    "pwd",
    "pin",
    "otp",
    "2fa",
    "mfa",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "ssn",
    "social_security",
    "sin",
    "national_id",
    "passport",
    "driver_license",
    "license",
    "credit_card",
    "card_number",
    "card",
    "cvv",
    "cvc",
    "expiry",
    "expiration",
    "bank",
    "iban",
    "routing",
    "account_number",
    "tax",
    "ein",
    "payment",
    "billing",
    "medical",
    "health",
    "insurance",
}

SENSITIVE_FORM_KEYWORDS = {
    "login",
    "signin",
    "sign_in",
    "signup",
    "register",
    "checkout",
    "payment",
    "billing",
    "bank",
    "loan",
    "insurance",
    "medical",
    "health",
    "tax",
    "government",
    "passport",
    "identity",
    "verification",
    "password",
    "reset",
    "oauth",
    "authorization",
}

SUBMIT_BUTTON_KEYWORDS = {
    "submit",
    "send",
    "continue",
    "checkout",
    "pay",
    "purchase",
    "confirm",
    "register",
    "sign up",
    "login",
    "sign in",
    "save",
    "apply",
}

SAFE_INPUT_TYPES = {
    "text",
    "search",
    "email",
    "tel",
    "url",
    "number",
    "date",
    "datetime-local",
    "month",
    "week",
    "time",
    "color",
    "hidden",
}

FORM_FIELD_TYPES = {
    "input",
    "textarea",
    "select",
    "button",
}


# ======================================================================================
# Enums / Data Structures
# ======================================================================================

class FormSensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FormAction(str, Enum):
    DETECT = "detect"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    FILL = "fill"
    SUBMIT = "submit"
    PLAN = "plan"


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    APPROVED = "approved"
    DENIED = "denied"
    MISSING = "missing"


@dataclass
class FormField:
    """
    Normalized representation of a form field detected from HTML or a browser page.
    """

    field_id: str
    tag: str
    name: Optional[str] = None
    field_type: Optional[str] = None
    label: Optional[str] = None
    placeholder: Optional[str] = None
    value: Optional[str] = None
    required: bool = False
    disabled: bool = False
    readonly: bool = False
    selector: Optional[str] = None
    options: List[str] = field(default_factory=list)
    autocomplete: Optional[str] = None
    aria_label: Optional[str] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    is_sensitive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FormInfo:
    """
    Normalized representation of one detected form.
    """

    form_id: str
    index: int
    selector: Optional[str] = None
    action: Optional[str] = None
    method: Optional[str] = None
    title: Optional[str] = None
    fields: List[FormField] = field(default_factory=list)
    submit_buttons: List[FormField] = field(default_factory=list)
    sensitivity: FormSensitivity = FormSensitivity.LOW
    requires_approval: bool = False
    fingerprint: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationIssue:
    """
    Represents a validation issue found before filling/submitting a form.
    """

    field_id: Optional[str]
    field_name: Optional[str]
    severity: str
    message: str
    code: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FillPlan:
    """
    Safe dashboard/API-ready plan for filling a form.

    The plan can be shown to the user or Security Agent before real execution.
    """

    plan_id: str
    form_id: str
    action: FormAction
    safe_to_fill: bool
    safe_to_submit: bool
    approval_status: ApprovalStatus
    sensitivity: FormSensitivity
    fields_to_fill: List[Dict[str, Any]]
    blocked_fields: List[Dict[str, Any]]
    validation_issues: List[Dict[str, Any]]
    warnings: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


# ======================================================================================
# Helper Functions
# ======================================================================================

def _now_ts() -> float:
    return time.time()


def _clean_text(value: Any, max_length: int = 500) -> str:
    if value is None:
        return ""
    text = str(value)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _safe_lower(value: Any) -> str:
    return _clean_text(value).lower()


def _hash_payload(payload: Any) -> str:
    try:
        raw = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        raw = str(payload)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _contains_any_keyword(value: str, keywords: Iterable[str]) -> bool:
    value_lower = _safe_lower(value)
    return any(keyword in value_lower for keyword in keywords)


def _mask_sensitive_value(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * max(3, len(text) - 4)}{text[-2:]}"


def _is_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value.strip()))


def _is_url(value: str) -> bool:
    return bool(re.match(r"^https?://[^\s]+\.[^\s]+$", value.strip(), re.I))


def _is_phone_like(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 16


def _slugify(value: str) -> str:
    value = _safe_lower(value)
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "field"


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Awaitable[Any]:
    if asyncio.iscoroutine(value) or isinstance(value, Awaitable):
        return value  # type: ignore

    async def _wrapper() -> Any:
        return value

    return _wrapper()


# ======================================================================================
# Main Class
# ======================================================================================

class FormHandler(BaseAgent):
    """
    Browser Agent helper responsible for detecting, validating, filling and submitting forms.

    Master Agent connection:
        The Master Agent can route browser form tasks to this class using `run()`.

    Security Agent connection:
        Submission and sensitive form actions call approval hooks before execution.

    Memory Agent connection:
        Safe summaries can be prepared through `_prepare_memory_payload()`.

    Verification Agent connection:
        Every meaningful action can prepare a verification payload through
        `_prepare_verification_payload()`.

    Dashboard/API connection:
        All public methods return structured dict responses with:
        success, message, data, error, metadata.
    """

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        allow_sensitive_fill_without_submit: bool = True,
        default_timeout_ms: int = 10_000,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.agent_name = DEFAULT_AGENT_NAME
        self.agent_module = DEFAULT_AGENT_MODULE
        self.file_path = DEFAULT_FILE_PATH

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.allow_sensitive_fill_without_submit = allow_sensitive_fill_without_submit
        self.default_timeout_ms = default_timeout_ms
        self.logger = logging.getLogger("William.BrowserAgent.FormHandler")

    # ==================================================================================
    # Public Router Entry
    # ==================================================================================

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic BaseAgent-compatible task runner.

        Expected task shape:
            {
                "action": "detect" | "analyze" | "validate" | "plan" | "fill" | "submit",
                "user_id": "...",
                "workspace_id": "...",
                "html": "...",
                "page": optional browser page object,
                "form_id": optional,
                "values": {...},
                "approval_token": optional,
                "metadata": {...}
            }
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        action = _safe_lower(task.get("action", "detect"))

        try:
            if action in {"detect", "analyze"}:
                return await self.detect_forms(
                    html_content=task.get("html") or task.get("html_content"),
                    page=task.get("page"),
                    user_id=task.get("user_id"),
                    workspace_id=task.get("workspace_id"),
                    metadata=task.get("metadata"),
                )

            if action == "validate":
                return await self.validate_form_values(
                    form=task.get("form"),
                    values=task.get("values") or {},
                    html_content=task.get("html") or task.get("html_content"),
                    page=task.get("page"),
                    form_id=task.get("form_id"),
                    user_id=task.get("user_id"),
                    workspace_id=task.get("workspace_id"),
                    metadata=task.get("metadata"),
                )

            if action == "plan":
                return await self.prepare_fill_plan(
                    values=task.get("values") or {},
                    html_content=task.get("html") or task.get("html_content"),
                    page=task.get("page"),
                    form_id=task.get("form_id"),
                    user_id=task.get("user_id"),
                    workspace_id=task.get("workspace_id"),
                    submit_after_fill=bool(task.get("submit_after_fill", False)),
                    approval_token=task.get("approval_token"),
                    metadata=task.get("metadata"),
                )

            if action == "fill":
                return await self.fill_form(
                    values=task.get("values") or {},
                    html_content=task.get("html") or task.get("html_content"),
                    page=task.get("page"),
                    form_id=task.get("form_id"),
                    user_id=task.get("user_id"),
                    workspace_id=task.get("workspace_id"),
                    submit_after_fill=bool(task.get("submit_after_fill", False)),
                    approval_token=task.get("approval_token"),
                    metadata=task.get("metadata"),
                )

            if action == "submit":
                return await self.submit_form(
                    html_content=task.get("html") or task.get("html_content"),
                    page=task.get("page"),
                    form_id=task.get("form_id"),
                    user_id=task.get("user_id"),
                    workspace_id=task.get("workspace_id"),
                    approval_token=task.get("approval_token"),
                    metadata=task.get("metadata"),
                )

            return self._error_result(
                message=f"Unsupported form handler action: {action}",
                code="unsupported_action",
                metadata={"supported_actions": [item.value for item in FormAction]},
            )

        except Exception as exc:
            self.logger.exception("FormHandler.run failed")
            return self._error_result(
                message="Form handler task failed.",
                code="form_handler_exception",
                error=str(exc),
                metadata={"action": action},
            )

    # ==================================================================================
    # Detection
    # ==================================================================================

    async def detect_forms(
        self,
        html_content: Optional[str] = None,
        page: Optional[Any] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect forms from raw HTML or a Playwright/Selenium-like page object.

        This method does not submit anything and is safe for analysis.
        """
        task_context = {
            "action": FormAction.DETECT.value,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": metadata or {},
        }
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        forms: List[FormInfo] = []

        if html_content:
            forms = self._detect_forms_from_html(html_content)
        elif page is not None:
            forms = await self._detect_forms_from_page(page)
        else:
            return self._error_result(
                message="No HTML content or browser page was provided for form detection.",
                code="missing_form_source",
                metadata=task_context,
            )

        payload = {
            "forms": [self._form_to_dict(form) for form in forms],
            "form_count": len(forms),
            "sensitive_form_count": sum(1 for form in forms if form.requires_approval),
        }

        await self._emit_agent_event(
            event_type="browser.form.detected",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "form_count": payload["form_count"],
                "sensitive_form_count": payload["sensitive_form_count"],
            },
        )

        await self._log_audit_event(
            action="detect_forms",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success",
            metadata={
                "form_count": payload["form_count"],
                "source": "html" if html_content else "page",
            },
        )

        return self._safe_result(
            message=f"Detected {len(forms)} form(s).",
            data=payload,
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "verification": self._prepare_verification_payload(
                    action="detect_forms",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data=payload,
                ),
                "memory": self._prepare_memory_payload(
                    action="detect_forms",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data=payload,
                ),
            },
        )

    def _detect_forms_from_html(self, html_content: str) -> List[FormInfo]:
        if BeautifulSoup is None:
            return self._detect_forms_from_html_regex(html_content)

        soup = BeautifulSoup(html_content, "html.parser")
        form_tags = soup.find_all("form")

        forms: List[FormInfo] = []

        if form_tags:
            for index, form_tag in enumerate(form_tags):
                form_info = self._parse_bs4_form(form_tag, index=index, soup=soup)
                forms.append(form_info)
        else:
            # Some modern sites use form-like containers without <form>.
            pseudo_forms = self._detect_pseudo_forms_bs4(soup)
            forms.extend(pseudo_forms)

        return forms

    def _detect_forms_from_html_regex(self, html_content: str) -> List[FormInfo]:
        """
        Lightweight fallback detector if BeautifulSoup is unavailable.

        This is intentionally conservative and import-safe.
        """
        forms: List[FormInfo] = []
        form_matches = list(re.finditer(r"<form\b[^>]*>(.*?)</form>", html_content, re.I | re.S))

        for index, match in enumerate(form_matches):
            form_html = match.group(0)
            attrs = self._parse_html_attrs(match.group(0))
            fields = self._parse_fields_from_html_regex(form_html, form_index=index)
            form = FormInfo(
                form_id=attrs.get("id") or attrs.get("name") or f"form_{index}",
                index=index,
                selector=self._build_form_selector(attrs, index),
                action=attrs.get("action"),
                method=(attrs.get("method") or "GET").upper(),
                title=attrs.get("aria-label") or attrs.get("name") or attrs.get("id"),
                fields=[field for field in fields if field.tag != "button"],
                submit_buttons=[field for field in fields if field.tag == "button"],
            )
            self._finalize_form_info(form)
            forms.append(form)

        return forms

    async def _detect_forms_from_page(self, page: Any) -> List[FormInfo]:
        """
        Detect forms from browser page object.

        Supports Playwright-style page objects first. Falls back to page.content().
        """
        try:
            if hasattr(page, "content"):
                content_result = page.content()
                html_content = await _maybe_await(content_result)
                if html_content:
                    return self._detect_forms_from_html(str(html_content))
        except Exception as exc:
            self.logger.warning("Could not read page.content(): %s", exc)

        # Minimal fallback through JS evaluation.
        try:
            if hasattr(page, "evaluate"):
                script = """
                () => Array.from(document.forms).map((form, index) => ({
                    index,
                    id: form.id || null,
                    name: form.getAttribute('name'),
                    action: form.getAttribute('action'),
                    method: form.getAttribute('method') || 'GET',
                    html: form.outerHTML
                }))
                """
                result = page.evaluate(script)
                page_forms = await _maybe_await(result)
                forms: List[FormInfo] = []
                for item in page_forms or []:
                    single_forms = self._detect_forms_from_html(item.get("html", ""))
                    if single_forms:
                        form = single_forms[0]
                        form.index = int(item.get("index", len(forms)))
                        form.form_id = item.get("id") or item.get("name") or form.form_id
                        form.action = item.get("action") or form.action
                        form.method = str(item.get("method") or form.method or "GET").upper()
                        forms.append(form)
                return forms
        except Exception as exc:
            self.logger.warning("Could not detect forms through page.evaluate(): %s", exc)

        return []

    def _parse_bs4_form(self, form_tag: Any, index: int, soup: Any) -> FormInfo:
        attrs = dict(form_tag.attrs or {})
        form_id = attrs.get("id") or attrs.get("name") or f"form_{index}"

        form = FormInfo(
            form_id=str(form_id),
            index=index,
            selector=self._build_form_selector(attrs, index),
            action=attrs.get("action"),
            method=str(attrs.get("method") or "GET").upper(),
            title=self._extract_form_title(form_tag),
            fields=[],
            submit_buttons=[],
            metadata={
                "raw_attributes": self._safe_attrs(attrs),
            },
        )

        field_tags = form_tag.find_all(["input", "textarea", "select", "button"])
        for field_index, field_tag in enumerate(field_tags):
            parsed_field = self._parse_bs4_field(
                field_tag=field_tag,
                field_index=field_index,
                form_index=index,
                soup=soup,
            )

            if parsed_field.tag == "button" or parsed_field.field_type in {"submit", "button"}:
                form.submit_buttons.append(parsed_field)
            else:
                form.fields.append(parsed_field)

        self._finalize_form_info(form)
        return form

    def _detect_pseudo_forms_bs4(self, soup: Any) -> List[FormInfo]:
        """
        Detect form-like groups when no <form> tag exists.

        Many SPAs use div containers with inputs and buttons. This safely creates
        pseudo-form objects for planning/validation.
        """
        input_tags = soup.find_all(["input", "textarea", "select"])
        if not input_tags:
            return []

        groups: Dict[str, List[Any]] = {}

        for tag in input_tags:
            parent = tag.find_parent(["section", "main", "div", "article"]) or soup
            key = parent.get("id") or parent.get("class") or str(id(parent))
            if isinstance(key, list):
                key = " ".join(key)
            groups.setdefault(str(key), []).append(tag)

        forms: List[FormInfo] = []
        for index, (_, tags) in enumerate(groups.items()):
            if len(tags) < 1:
                continue

            first_parent = tags[0].find_parent(["section", "main", "div", "article"]) or soup
            buttons = first_parent.find_all(["button", "input"])
            submit_buttons = []
            fields = []

            for field_index, tag in enumerate(tags):
                fields.append(
                    self._parse_bs4_field(
                        field_tag=tag,
                        field_index=field_index,
                        form_index=index,
                        soup=soup,
                    )
                )

            for button_index, button in enumerate(buttons):
                parsed_button = self._parse_bs4_field(
                    field_tag=button,
                    field_index=button_index + len(fields),
                    form_index=index,
                    soup=soup,
                )
                if parsed_button.tag == "button" or parsed_button.field_type in {"submit", "button"}:
                    text_hint = " ".join(
                        [
                            parsed_button.name or "",
                            parsed_button.label or "",
                            parsed_button.value or "",
                            parsed_button.aria_label or "",
                        ]
                    )
                    if _contains_any_keyword(text_hint, SUBMIT_BUTTON_KEYWORDS):
                        submit_buttons.append(parsed_button)

            form = FormInfo(
                form_id=f"pseudo_form_{index}",
                index=index,
                selector=None,
                action=None,
                method=None,
                title=self._extract_form_title(first_parent),
                fields=fields,
                submit_buttons=submit_buttons,
                metadata={"pseudo_form": True},
            )
            self._finalize_form_info(form)
            forms.append(form)

        return forms

    def _parse_bs4_field(
        self,
        field_tag: Any,
        field_index: int,
        form_index: int,
        soup: Any,
    ) -> FormField:
        attrs = dict(field_tag.attrs or {})
        tag_name = str(field_tag.name or "").lower()
        field_type = str(attrs.get("type") or tag_name).lower()

        field_name = attrs.get("name")
        field_id_attr = attrs.get("id")
        field_id = str(field_id_attr or field_name or f"form_{form_index}_field_{field_index}")

        label = self._find_label_for_field(field_tag, soup)
        placeholder = attrs.get("placeholder")
        aria_label = attrs.get("aria-label")
        autocomplete = attrs.get("autocomplete")

        options: List[str] = []
        if tag_name == "select":
            for option in field_tag.find_all("option"):
                option_value = option.get("value")
                option_text = _clean_text(option.get_text(" ", strip=True))
                options.append(str(option_value or option_text))

        value = attrs.get("value")
        if tag_name == "textarea":
            value = _clean_text(field_tag.get_text(" ", strip=True))

        selector = self._build_field_selector(attrs, tag_name, form_index, field_index)

        field_info = FormField(
            field_id=field_id,
            tag=tag_name,
            name=str(field_name) if field_name else None,
            field_type=field_type,
            label=label,
            placeholder=str(placeholder) if placeholder else None,
            value=str(value) if value is not None else None,
            required=self._attr_bool(attrs, "required"),
            disabled=self._attr_bool(attrs, "disabled"),
            readonly=self._attr_bool(attrs, "readonly"),
            selector=selector,
            options=options,
            autocomplete=str(autocomplete) if autocomplete else None,
            aria_label=str(aria_label) if aria_label else None,
            max_length=self._safe_int(attrs.get("maxlength")),
            pattern=str(attrs.get("pattern")) if attrs.get("pattern") else None,
            metadata={
                "raw_attributes": self._safe_attrs(attrs),
                "form_index": form_index,
                "field_index": field_index,
            },
        )
        field_info.is_sensitive = self._is_sensitive_field(field_info)
        return field_info

    def _parse_fields_from_html_regex(self, form_html: str, form_index: int) -> List[FormField]:
        field_pattern = r"<(input|textarea|select|button)\b([^>]*)>(.*?)</\1>|<(input)\b([^>]*)/?>"
        fields: List[FormField] = []

        for field_index, match in enumerate(re.finditer(field_pattern, form_html, re.I | re.S)):
            tag = match.group(1) or match.group(4) or "input"
            attrs_raw = match.group(2) or match.group(5) or ""
            attrs = self._parse_html_attrs(attrs_raw)
            body = match.group(3) or ""

            field_type = str(attrs.get("type") or tag).lower()
            field_name = attrs.get("name")
            field_id_attr = attrs.get("id")
            field_id = str(field_id_attr or field_name or f"form_{form_index}_field_{field_index}")

            options: List[str] = []
            if tag.lower() == "select":
                for option_match in re.finditer(r"<option\b([^>]*)>(.*?)</option>", body, re.I | re.S):
                    option_attrs = self._parse_html_attrs(option_match.group(1))
                    option_text = _clean_text(option_match.group(2))
                    options.append(option_attrs.get("value") or option_text)

            field_info = FormField(
                field_id=field_id,
                tag=tag.lower(),
                name=field_name,
                field_type=field_type,
                label=None,
                placeholder=attrs.get("placeholder"),
                value=attrs.get("value") or (_clean_text(body) if tag.lower() == "textarea" else None),
                required="required" in attrs,
                disabled="disabled" in attrs,
                readonly="readonly" in attrs,
                selector=self._build_field_selector(attrs, tag.lower(), form_index, field_index),
                options=options,
                autocomplete=attrs.get("autocomplete"),
                aria_label=attrs.get("aria-label"),
                max_length=self._safe_int(attrs.get("maxlength")),
                pattern=attrs.get("pattern"),
                metadata={
                    "raw_attributes": self._safe_attrs(attrs),
                    "form_index": form_index,
                    "field_index": field_index,
                },
            )
            field_info.is_sensitive = self._is_sensitive_field(field_info)
            fields.append(field_info)

        return fields

    # ==================================================================================
    # Validation / Planning
    # ==================================================================================

    async def validate_form_values(
        self,
        values: Dict[str, Any],
        form: Optional[Union[FormInfo, Dict[str, Any]]] = None,
        html_content: Optional[str] = None,
        page: Optional[Any] = None,
        form_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate values against detected or provided form.
        """
        task_context = {
            "action": FormAction.VALIDATE.value,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": metadata or {},
        }
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        resolved_form = await self._resolve_form(
            form=form,
            html_content=html_content,
            page=page,
            form_id=form_id,
        )

        if resolved_form is None:
            return self._error_result(
                message="Could not resolve target form for validation.",
                code="form_not_found",
                metadata={"form_id": form_id},
            )

        issues = self._validate_values_against_form(resolved_form, values)
        warnings = self._build_form_warnings(resolved_form, submit_after_fill=False)

        data = {
            "valid": not any(issue.severity == "error" for issue in issues),
            "issues": [asdict(issue) for issue in issues],
            "warnings": warnings,
            "form": self._form_to_dict(resolved_form),
            "sensitivity": resolved_form.sensitivity.value,
            "requires_approval": resolved_form.requires_approval,
        }

        await self._log_audit_event(
            action="validate_form_values",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success",
            metadata={
                "form_id": resolved_form.form_id,
                "issue_count": len(issues),
                "requires_approval": resolved_form.requires_approval,
            },
        )

        return self._safe_result(
            message="Form values validated.",
            data=data,
            metadata={
                "verification": self._prepare_verification_payload(
                    action="validate_form_values",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data=data,
                )
            },
        )

    async def prepare_fill_plan(
        self,
        values: Dict[str, Any],
        html_content: Optional[str] = None,
        page: Optional[Any] = None,
        form_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        submit_after_fill: bool = False,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a safe fill plan without modifying the browser page.

        This is recommended before execution so dashboard/API can show exactly what
        will happen.
        """
        task_context = {
            "action": FormAction.PLAN.value,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": metadata or {},
        }
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        resolved_form = await self._resolve_form(
            html_content=html_content,
            page=page,
            form_id=form_id,
        )

        if resolved_form is None:
            return self._error_result(
                message="Could not resolve target form for fill plan.",
                code="form_not_found",
                metadata={"form_id": form_id},
            )

        plan = await self._build_fill_plan(
            form=resolved_form,
            values=values,
            submit_after_fill=submit_after_fill,
            approval_token=approval_token,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata or {},
        )

        await self._emit_agent_event(
            event_type="browser.form.fill_plan_prepared",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "form_id": resolved_form.form_id,
                "plan_id": plan.plan_id,
                "safe_to_fill": plan.safe_to_fill,
                "safe_to_submit": plan.safe_to_submit,
            },
        )

        await self._log_audit_event(
            action="prepare_fill_plan",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success",
            metadata={
                "form_id": resolved_form.form_id,
                "plan_id": plan.plan_id,
                "submit_after_fill": submit_after_fill,
            },
        )

        return self._safe_result(
            message="Form fill plan prepared.",
            data={
                "plan": asdict(plan),
                "form": self._form_to_dict(resolved_form),
            },
            metadata={
                "verification": self._prepare_verification_payload(
                    action="prepare_fill_plan",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data=asdict(plan),
                ),
                "memory": self._prepare_memory_payload(
                    action="prepare_fill_plan",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data={
                        "form_id": resolved_form.form_id,
                        "sensitivity": resolved_form.sensitivity.value,
                        "submit_after_fill": submit_after_fill,
                    },
                ),
            },
        )

    async def _build_fill_plan(
        self,
        form: FormInfo,
        values: Dict[str, Any],
        submit_after_fill: bool,
        approval_token: Optional[str],
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        metadata: Dict[str, Any],
    ) -> FillPlan:
        issues = self._validate_values_against_form(form, values)
        warnings = self._build_form_warnings(form, submit_after_fill=submit_after_fill)

        fields_to_fill: List[Dict[str, Any]] = []
        blocked_fields: List[Dict[str, Any]] = []

        for field_item in form.fields:
            key = self._find_value_key_for_field(field_item, values)
            if key is None:
                continue

            raw_value = values.get(key)
            field_payload = {
                "field_id": field_item.field_id,
                "name": field_item.name,
                "label": field_item.label,
                "selector": field_item.selector,
                "field_type": field_item.field_type,
                "is_sensitive": field_item.is_sensitive,
                "value_preview": _mask_sensitive_value(raw_value) if field_item.is_sensitive else _clean_text(raw_value),
            }

            if field_item.disabled or field_item.readonly:
                blocked_fields.append(
                    {
                        **field_payload,
                        "reason": "Field is disabled or readonly.",
                    }
                )
            elif field_item.is_sensitive and not self.allow_sensitive_fill_without_submit:
                blocked_fields.append(
                    {
                        **field_payload,
                        "reason": "Sensitive field filling is disabled by configuration.",
                    }
                )
            else:
                fields_to_fill.append(field_payload)

        approval_required = self._requires_security_check(
            action=FormAction.SUBMIT.value if submit_after_fill else FormAction.FILL.value,
            form=form,
            values=values,
            metadata=metadata,
        )

        approval_status = ApprovalStatus.NOT_REQUIRED
        safe_to_submit = False

        if approval_required:
            approval_result = await self._request_security_approval(
                action=FormAction.SUBMIT.value if submit_after_fill else FormAction.FILL.value,
                user_id=user_id,
                workspace_id=workspace_id,
                form=form,
                values=values,
                approval_token=approval_token,
                metadata=metadata,
            )
            approval_status = approval_result
            safe_to_submit = approval_result == ApprovalStatus.APPROVED
        else:
            safe_to_submit = True

        has_errors = any(issue.severity == "error" for issue in issues)
        safe_to_fill = not has_errors and len(blocked_fields) == 0

        if submit_after_fill:
            safe_to_submit = safe_to_submit and safe_to_fill
        else:
            safe_to_submit = False

        return FillPlan(
            plan_id=str(uuid.uuid4()),
            form_id=form.form_id,
            action=FormAction.SUBMIT if submit_after_fill else FormAction.FILL,
            safe_to_fill=safe_to_fill,
            safe_to_submit=safe_to_submit,
            approval_status=approval_status,
            sensitivity=form.sensitivity,
            fields_to_fill=fields_to_fill,
            blocked_fields=blocked_fields,
            validation_issues=[asdict(issue) for issue in issues],
            warnings=warnings,
            metadata={
                "submit_after_fill": submit_after_fill,
                "field_count": len(form.fields),
                "fields_to_fill_count": len(fields_to_fill),
                "blocked_fields_count": len(blocked_fields),
                "requires_approval": approval_required,
            },
        )

    # ==================================================================================
    # Fill / Submit
    # ==================================================================================

    async def fill_form(
        self,
        values: Dict[str, Any],
        html_content: Optional[str] = None,
        page: Optional[Any] = None,
        form_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        submit_after_fill: bool = False,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fill a detected form.

        Requires a browser `page` object for actual UI filling.
        If only HTML is provided, this returns a plan and does not modify anything.

        If submit_after_fill=True, submission is blocked unless approval passes.
        """
        task_context = {
            "action": FormAction.FILL.value,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": metadata or {},
        }
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        resolved_form = await self._resolve_form(
            html_content=html_content,
            page=page,
            form_id=form_id,
        )

        if resolved_form is None:
            return self._error_result(
                message="Could not resolve target form for filling.",
                code="form_not_found",
                metadata={"form_id": form_id},
            )

        plan = await self._build_fill_plan(
            form=resolved_form,
            values=values,
            submit_after_fill=submit_after_fill,
            approval_token=approval_token,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata or {},
        )

        if not plan.safe_to_fill:
            await self._log_audit_event(
                action="fill_form_blocked",
                user_id=user_id,
                workspace_id=workspace_id,
                status="blocked",
                metadata={
                    "form_id": resolved_form.form_id,
                    "reason": "Fill plan was not safe.",
                    "plan": asdict(plan),
                },
            )
            return self._error_result(
                message="Form fill blocked because validation or safety checks failed.",
                code="form_fill_blocked",
                data={
                    "plan": asdict(plan),
                    "form": self._form_to_dict(resolved_form),
                },
            )

        if page is None:
            return self._safe_result(
                message="No browser page was provided. Returning safe fill plan only.",
                data={
                    "executed": False,
                    "plan": asdict(plan),
                    "form": self._form_to_dict(resolved_form),
                },
                metadata={"mode": "plan_only"},
            )

        filled_fields: List[Dict[str, Any]] = []
        failed_fields: List[Dict[str, Any]] = []

        for field_item in resolved_form.fields:
            key = self._find_value_key_for_field(field_item, values)
            if key is None:
                continue

            value = values.get(key)
            try:
                did_fill = await self._fill_field_on_page(page, field_item, value)
                if did_fill:
                    filled_fields.append(
                        {
                            "field_id": field_item.field_id,
                            "name": field_item.name,
                            "selector": field_item.selector,
                            "is_sensitive": field_item.is_sensitive,
                            "value_preview": _mask_sensitive_value(value)
                            if field_item.is_sensitive
                            else _clean_text(value),
                        }
                    )
                else:
                    failed_fields.append(
                        {
                            "field_id": field_item.field_id,
                            "name": field_item.name,
                            "selector": field_item.selector,
                            "reason": "No compatible fill method or selector failed.",
                        }
                    )
            except Exception as exc:
                failed_fields.append(
                    {
                        "field_id": field_item.field_id,
                        "name": field_item.name,
                        "selector": field_item.selector,
                        "reason": str(exc),
                    }
                )

        submit_result: Optional[Dict[str, Any]] = None
        if submit_after_fill:
            if not plan.safe_to_submit:
                submit_result = self._error_result(
                    message="Form submit blocked because approval is missing or denied.",
                    code="form_submit_approval_required",
                    data={"approval_status": plan.approval_status.value},
                )
            else:
                submit_result = await self._submit_form_on_page(page, resolved_form)

        data = {
            "executed": True,
            "filled_fields": filled_fields,
            "failed_fields": failed_fields,
            "submit_result": submit_result,
            "plan": asdict(plan),
            "form": self._form_to_dict(resolved_form),
        }

        await self._emit_agent_event(
            event_type="browser.form.filled",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "form_id": resolved_form.form_id,
                "filled_count": len(filled_fields),
                "failed_count": len(failed_fields),
                "submitted": bool(submit_result and submit_result.get("success")),
            },
        )

        await self._log_audit_event(
            action="fill_form",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success" if not failed_fields else "partial",
            metadata={
                "form_id": resolved_form.form_id,
                "filled_count": len(filled_fields),
                "failed_count": len(failed_fields),
                "submit_after_fill": submit_after_fill,
            },
        )

        return self._safe_result(
            message="Form fill completed." if not failed_fields else "Form fill completed with some field failures.",
            data=data,
            metadata={
                "verification": self._prepare_verification_payload(
                    action="fill_form",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data={
                        "form_id": resolved_form.form_id,
                        "filled_count": len(filled_fields),
                        "failed_count": len(failed_fields),
                    },
                ),
                "memory": self._prepare_memory_payload(
                    action="fill_form",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data={
                        "form_id": resolved_form.form_id,
                        "filled_count": len(filled_fields),
                        "sensitivity": resolved_form.sensitivity.value,
                    },
                ),
            },
        )

    async def submit_form(
        self,
        html_content: Optional[str] = None,
        page: Optional[Any] = None,
        form_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Submit a form only after Security Agent approval.

        This method never submits silently.
        """
        task_context = {
            "action": FormAction.SUBMIT.value,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": metadata or {},
        }
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        if page is None:
            return self._error_result(
                message="A browser page object is required for form submission.",
                code="missing_browser_page",
            )

        resolved_form = await self._resolve_form(
            html_content=html_content,
            page=page,
            form_id=form_id,
        )

        if resolved_form is None:
            return self._error_result(
                message="Could not resolve target form for submission.",
                code="form_not_found",
                metadata={"form_id": form_id},
            )

        approval_required = self._requires_security_check(
            action=FormAction.SUBMIT.value,
            form=resolved_form,
            values={},
            metadata=metadata or {},
        )

        if approval_required:
            approval_status = await self._request_security_approval(
                action=FormAction.SUBMIT.value,
                user_id=user_id,
                workspace_id=workspace_id,
                form=resolved_form,
                values={},
                approval_token=approval_token,
                metadata=metadata or {},
            )

            if approval_status != ApprovalStatus.APPROVED:
                await self._log_audit_event(
                    action="submit_form_blocked",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    status="blocked",
                    metadata={
                        "form_id": resolved_form.form_id,
                        "approval_status": approval_status.value,
                    },
                )
                return self._error_result(
                    message="Form submission blocked. Security approval is required.",
                    code="form_submit_approval_required",
                    data={
                        "approval_status": approval_status.value,
                        "form": self._form_to_dict(resolved_form),
                    },
                )

        submit_result = await self._submit_form_on_page(page, resolved_form)

        await self._emit_agent_event(
            event_type="browser.form.submitted",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "form_id": resolved_form.form_id,
                "submit_success": submit_result.get("success"),
            },
        )

        await self._log_audit_event(
            action="submit_form",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success" if submit_result.get("success") else "failed",
            metadata={
                "form_id": resolved_form.form_id,
                "approval_required": approval_required,
            },
        )

        if not submit_result.get("success"):
            return submit_result

        return self._safe_result(
            message="Form submitted after approval.",
            data={
                "submitted": True,
                "form": self._form_to_dict(resolved_form),
                "submit_result": submit_result,
            },
            metadata={
                "verification": self._prepare_verification_payload(
                    action="submit_form",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data={"form_id": resolved_form.form_id, "submitted": True},
                )
            },
        )

    # ==================================================================================
    # Browser Page Execution Helpers
    # ==================================================================================

    async def _fill_field_on_page(self, page: Any, field_item: FormField, value: Any) -> bool:
        if not field_item.selector:
            return False

        selector = field_item.selector
        tag = field_item.tag
        field_type = _safe_lower(field_item.field_type)

        if field_item.disabled or field_item.readonly:
            return False

        # Playwright-style API.
        if hasattr(page, "locator"):
            locator = page.locator(selector)
            if field_type in {"checkbox", "radio"}:
                checked = bool(value)
                if hasattr(locator, "set_checked"):
                    await _maybe_await(locator.set_checked(checked, timeout=self.default_timeout_ms))
                    return True

            if tag == "select" and hasattr(locator, "select_option"):
                await _maybe_await(locator.select_option(str(value), timeout=self.default_timeout_ms))
                return True

            if hasattr(locator, "fill"):
                await _maybe_await(locator.fill(str(value), timeout=self.default_timeout_ms))
                return True

        # Selenium-style API.
        if hasattr(page, "find_element"):
            element = page.find_element("css selector", selector)
            if field_type in {"checkbox", "radio"}:
                current_selected = bool(element.is_selected()) if hasattr(element, "is_selected") else False
                target_selected = bool(value)
                if current_selected != target_selected and hasattr(element, "click"):
                    element.click()
                return True

            if hasattr(element, "clear"):
                element.clear()
            if hasattr(element, "send_keys"):
                element.send_keys(str(value))
                return True

        # Generic evaluate fallback.
        if hasattr(page, "evaluate"):
            script = """
            ({ selector, value }) => {
                const el = document.querySelector(selector);
                if (!el) return false;
                if (el.disabled || el.readOnly) return false;
                const tag = (el.tagName || '').toLowerCase();
                const type = (el.getAttribute('type') || '').toLowerCase();

                if (type === 'checkbox' || type === 'radio') {
                    el.checked = Boolean(value);
                } else {
                    el.value = value == null ? '' : String(value);
                }

                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                return true;
            }
            """
            result = page.evaluate(script, {"selector": selector, "value": value})
            return bool(await _maybe_await(result))

        return False

    async def _submit_form_on_page(self, page: Any, form: FormInfo) -> Dict[str, Any]:
        """
        Submit a form using safe browser interactions.

        Assumes approval was already checked.
        """
        try:
            # Prefer clicking an explicit submit button.
            for button in form.submit_buttons:
                if button.selector:
                    clicked = await self._click_selector(page, button.selector)
                    if clicked:
                        return self._safe_result(
                            message="Clicked form submit button.",
                            data={
                                "submitted": True,
                                "method": "submit_button_click",
                                "selector": button.selector,
                            },
                        )

            # Fallback to form.submit through DOM.
            if form.selector and hasattr(page, "evaluate"):
                script = """
                ({ selector }) => {
                    const form = document.querySelector(selector);
                    if (!form) return false;
                    if (typeof form.requestSubmit === 'function') {
                        form.requestSubmit();
                    } else {
                        form.submit();
                    }
                    return true;
                }
                """
                result = page.evaluate(script, {"selector": form.selector})
                ok = bool(await _maybe_await(result))
                if ok:
                    return self._safe_result(
                        message="Submitted form through DOM requestSubmit.",
                        data={
                            "submitted": True,
                            "method": "request_submit",
                            "selector": form.selector,
                        },
                    )

            return self._error_result(
                message="Could not submit form because no submit method was available.",
                code="submit_method_unavailable",
                data={"form_id": form.form_id},
            )

        except Exception as exc:
            self.logger.exception("Form submission failed")
            return self._error_result(
                message="Form submission failed.",
                code="form_submission_exception",
                error=str(exc),
                data={"form_id": form.form_id},
            )

    async def _click_selector(self, page: Any, selector: str) -> bool:
        if hasattr(page, "locator"):
            locator = page.locator(selector)
            if hasattr(locator, "click"):
                await _maybe_await(locator.click(timeout=self.default_timeout_ms))
                return True

        if hasattr(page, "click"):
            await _maybe_await(page.click(selector, timeout=self.default_timeout_ms))
            return True

        if hasattr(page, "find_element"):
            element = page.find_element("css selector", selector)
            if hasattr(element, "click"):
                element.click()
                return True

        if hasattr(page, "evaluate"):
            script = """
            ({ selector }) => {
                const el = document.querySelector(selector);
                if (!el) return false;
                el.click();
                return true;
            }
            """
            result = page.evaluate(script, {"selector": selector})
            return bool(await _maybe_await(result))

        return False

    # ==================================================================================
    # Form Resolution
    # ==================================================================================

    async def _resolve_form(
        self,
        form: Optional[Union[FormInfo, Dict[str, Any]]] = None,
        html_content: Optional[str] = None,
        page: Optional[Any] = None,
        form_id: Optional[str] = None,
    ) -> Optional[FormInfo]:
        if isinstance(form, FormInfo):
            return form

        if isinstance(form, dict):
            return self._dict_to_form(form)

        forms: List[FormInfo] = []

        if html_content:
            forms = self._detect_forms_from_html(html_content)
        elif page is not None:
            forms = await self._detect_forms_from_page(page)

        if not forms:
            return None

        if form_id:
            for item in forms:
                if item.form_id == form_id or item.fingerprint == form_id:
                    return item

            # Also allow index as string.
            if str(form_id).isdigit():
                index = int(str(form_id))
                if 0 <= index < len(forms):
                    return forms[index]

            return None

        return forms[0]

    def _dict_to_form(self, data: Dict[str, Any]) -> FormInfo:
        fields = [
            field_item if isinstance(field_item, FormField) else FormField(**field_item)
            for field_item in data.get("fields", [])
        ]
        submit_buttons = [
            field_item if isinstance(field_item, FormField) else FormField(**field_item)
            for field_item in data.get("submit_buttons", [])
        ]

        sensitivity_value = data.get("sensitivity", FormSensitivity.LOW.value)
        try:
            sensitivity = FormSensitivity(sensitivity_value)
        except Exception:
            sensitivity = FormSensitivity.LOW

        return FormInfo(
            form_id=str(data.get("form_id") or data.get("id") or "form_0"),
            index=int(data.get("index", 0)),
            selector=data.get("selector"),
            action=data.get("action"),
            method=data.get("method"),
            title=data.get("title"),
            fields=fields,
            submit_buttons=submit_buttons,
            sensitivity=sensitivity,
            requires_approval=bool(data.get("requires_approval", False)),
            fingerprint=data.get("fingerprint"),
            metadata=data.get("metadata") or {},
        )

    # ==================================================================================
    # Field / Form Analysis
    # ==================================================================================

    def _finalize_form_info(self, form: FormInfo) -> None:
        sensitive_fields = [field_item for field_item in form.fields if field_item.is_sensitive]

        text_blob_parts = [
            form.form_id,
            form.title or "",
            form.action or "",
            form.method or "",
        ]

        for field_item in form.fields + form.submit_buttons:
            text_blob_parts.extend(
                [
                    field_item.field_id,
                    field_item.name or "",
                    field_item.label or "",
                    field_item.placeholder or "",
                    field_item.field_type or "",
                    field_item.autocomplete or "",
                    field_item.aria_label or "",
                ]
            )

        text_blob = " ".join(text_blob_parts)

        sensitivity_score = 0

        if sensitive_fields:
            sensitivity_score += 2

        if _contains_any_keyword(text_blob, SENSITIVE_FORM_KEYWORDS):
            sensitivity_score += 2

        if any((field.field_type or "").lower() == "password" for field in form.fields):
            sensitivity_score += 3

        if _contains_any_keyword(text_blob, {"payment", "credit", "card", "cvv", "bank"}):
            sensitivity_score += 3

        if _contains_any_keyword(text_blob, {"ssn", "social", "passport", "national_id", "medical"}):
            sensitivity_score += 4

        if sensitivity_score >= 6:
            form.sensitivity = FormSensitivity.CRITICAL
        elif sensitivity_score >= 4:
            form.sensitivity = FormSensitivity.HIGH
        elif sensitivity_score >= 2:
            form.sensitivity = FormSensitivity.MEDIUM
        else:
            form.sensitivity = FormSensitivity.LOW

        form.requires_approval = form.sensitivity in {
            FormSensitivity.MEDIUM,
            FormSensitivity.HIGH,
            FormSensitivity.CRITICAL,
        }

        fingerprint_payload = {
            "form_id": form.form_id,
            "action": form.action,
            "method": form.method,
            "fields": [
                {
                    "name": field_item.name,
                    "type": field_item.field_type,
                    "label": field_item.label,
                    "placeholder": field_item.placeholder,
                }
                for field_item in form.fields
            ],
        }
        form.fingerprint = _hash_payload(fingerprint_payload)

    def _is_sensitive_field(self, field_item: FormField) -> bool:
        text_blob = " ".join(
            [
                field_item.field_id or "",
                field_item.name or "",
                field_item.field_type or "",
                field_item.label or "",
                field_item.placeholder or "",
                field_item.autocomplete or "",
                field_item.aria_label or "",
            ]
        )

        if (field_item.field_type or "").lower() == "password":
            return True

        return _contains_any_keyword(text_blob, SENSITIVE_FIELD_KEYWORDS)

    def _validate_values_against_form(self, form: FormInfo, values: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        for field_item in form.fields:
            if field_item.disabled or field_item.readonly:
                continue

            key = self._find_value_key_for_field(field_item, values)
            value_exists = key is not None
            value = values.get(key) if key is not None else None

            if field_item.required and not value_exists:
                issues.append(
                    ValidationIssue(
                        field_id=field_item.field_id,
                        field_name=field_item.name,
                        severity="error",
                        message="Required field is missing.",
                        code="required_field_missing",
                    )
                )
                continue

            if value is None or value == "":
                continue

            text_value = str(value)

            if field_item.max_length and len(text_value) > field_item.max_length:
                issues.append(
                    ValidationIssue(
                        field_id=field_item.field_id,
                        field_name=field_item.name,
                        severity="error",
                        message=f"Value exceeds max length of {field_item.max_length}.",
                        code="max_length_exceeded",
                        metadata={"max_length": field_item.max_length},
                    )
                )

            field_type = _safe_lower(field_item.field_type)
            if field_type == "email" and not _is_email(text_value):
                issues.append(
                    ValidationIssue(
                        field_id=field_item.field_id,
                        field_name=field_item.name,
                        severity="error",
                        message="Value is not a valid email address.",
                        code="invalid_email",
                    )
                )

            if field_type == "url" and not _is_url(text_value):
                issues.append(
                    ValidationIssue(
                        field_id=field_item.field_id,
                        field_name=field_item.name,
                        severity="error",
                        message="Value is not a valid URL.",
                        code="invalid_url",
                    )
                )

            if field_type == "tel" and not _is_phone_like(text_value):
                issues.append(
                    ValidationIssue(
                        field_id=field_item.field_id,
                        field_name=field_item.name,
                        severity="warning",
                        message="Phone number does not look valid.",
                        code="invalid_phone_like",
                    )
                )

            if field_item.pattern:
                try:
                    if not re.match(field_item.pattern, text_value):
                        issues.append(
                            ValidationIssue(
                                field_id=field_item.field_id,
                                field_name=field_item.name,
                                severity="warning",
                                message="Value does not match field pattern.",
                                code="pattern_mismatch",
                                metadata={"pattern": field_item.pattern},
                            )
                        )
                except re.error:
                    issues.append(
                        ValidationIssue(
                            field_id=field_item.field_id,
                            field_name=field_item.name,
                            severity="warning",
                            message="Field pattern is invalid and could not be checked.",
                            code="invalid_field_pattern",
                        )
                    )

            if field_item.options and field_item.tag == "select":
                option_values = {str(option) for option in field_item.options}
                if str(value) not in option_values:
                    issues.append(
                        ValidationIssue(
                            field_id=field_item.field_id,
                            field_name=field_item.name,
                            severity="warning",
                            message="Value is not one of the detected select options.",
                            code="select_option_not_detected",
                            metadata={"available_options": field_item.options[:25]},
                        )
                    )

        unknown_keys = []
        known_keys = set()
        for field_item in form.fields:
            for candidate in self._field_key_candidates(field_item):
                known_keys.add(candidate)

        for key in values.keys():
            if key not in known_keys:
                unknown_keys.append(key)

        if unknown_keys:
            issues.append(
                ValidationIssue(
                    field_id=None,
                    field_name=None,
                    severity="info",
                    message="Some provided values did not match detected form fields.",
                    code="unknown_value_keys",
                    metadata={"unknown_keys": unknown_keys},
                )
            )

        return issues

    def _build_form_warnings(self, form: FormInfo, submit_after_fill: bool) -> List[str]:
        warnings: List[str] = []

        if form.requires_approval:
            warnings.append(
                f"This form is classified as {form.sensitivity.value} sensitivity and requires approval for sensitive actions."
            )

        if submit_after_fill:
            warnings.append("Form submission requested. Submission will be blocked unless Security Agent approval is provided.")

        if any(field_item.is_sensitive for field_item in form.fields):
            warnings.append("Sensitive fields were detected. Values should be masked in logs and dashboard output.")

        if not form.submit_buttons:
            warnings.append("No explicit submit button was detected.")

        if not form.selector:
            warnings.append("No stable form selector was detected. Browser execution may require field-level selectors only.")

        return warnings

    def _find_value_key_for_field(self, field_item: FormField, values: Dict[str, Any]) -> Optional[str]:
        for candidate in self._field_key_candidates(field_item):
            if candidate in values:
                return candidate
        return None

    def _field_key_candidates(self, field_item: FormField) -> List[str]:
        raw_candidates = [
            field_item.name,
            field_item.field_id,
            field_item.label,
            field_item.placeholder,
            field_item.aria_label,
            _slugify(field_item.label or "") if field_item.label else None,
            _slugify(field_item.placeholder or "") if field_item.placeholder else None,
        ]

        candidates: List[str] = []
        for item in raw_candidates:
            if not item:
                continue
            item_str = str(item)
            candidates.append(item_str)
            candidates.append(_slugify(item_str))

        # Deduplicate while preserving order.
        seen = set()
        output = []
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                output.append(candidate)
        return output

    # ==================================================================================
    # HTML Parsing Utilities
    # ==================================================================================

    def _find_label_for_field(self, field_tag: Any, soup: Any) -> Optional[str]:
        field_id = field_tag.get("id")
        if field_id:
            label = soup.find("label", attrs={"for": field_id})
            if label:
                text = _clean_text(label.get_text(" ", strip=True))
                if text:
                    return text

        parent_label = field_tag.find_parent("label")
        if parent_label:
            text = _clean_text(parent_label.get_text(" ", strip=True))
            if text:
                return text

        aria_labelledby = field_tag.get("aria-labelledby")
        if aria_labelledby:
            label_node = soup.find(id=aria_labelledby)
            if label_node:
                text = _clean_text(label_node.get_text(" ", strip=True))
                if text:
                    return text

        # Nearby text fallback.
        previous = field_tag.find_previous(["label", "span", "p", "div"])
        if previous:
            text = _clean_text(previous.get_text(" ", strip=True), max_length=120)
            if text and len(text.split()) <= 12:
                return text

        return None

    def _extract_form_title(self, form_tag: Any) -> Optional[str]:
        attrs = dict(getattr(form_tag, "attrs", {}) or {})
        for key in ("aria-label", "name", "id", "title"):
            if attrs.get(key):
                return _clean_text(attrs.get(key), max_length=120)

        heading = None
        try:
            heading = form_tag.find(["h1", "h2", "h3", "legend"])
        except Exception:
            heading = None

        if heading:
            title = _clean_text(heading.get_text(" ", strip=True), max_length=120)
            if title:
                return title

        return None

    def _parse_html_attrs(self, raw: str) -> Dict[str, str]:
        attrs: Dict[str, str] = {}

        attr_pattern = r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))'
        for match in re.finditer(attr_pattern, raw or ""):
            key = match.group(1).lower()
            value = match.group(3) or match.group(4) or match.group(5) or ""
            attrs[key] = html.unescape(value)

        bool_pattern = r"\s(required|disabled|readonly|checked|selected)\b"
        for match in re.finditer(bool_pattern, raw or "", re.I):
            attrs[match.group(1).lower()] = match.group(1).lower()

        return attrs

    def _build_form_selector(self, attrs: Dict[str, Any], index: int) -> str:
        if attrs.get("id"):
            return f"form#{self._css_escape(str(attrs['id']))}"
        if attrs.get("name"):
            return f"form[name='{self._css_attr_escape(str(attrs['name']))}']"
        return f"form:nth-of-type({index + 1})"

    def _build_field_selector(
        self,
        attrs: Dict[str, Any],
        tag_name: str,
        form_index: int,
        field_index: int,
    ) -> str:
        if attrs.get("id"):
            return f"#{self._css_escape(str(attrs['id']))}"

        if attrs.get("name"):
            return f"{tag_name}[name='{self._css_attr_escape(str(attrs['name']))}']"

        placeholder = attrs.get("placeholder")
        if placeholder:
            return f"{tag_name}[placeholder='{self._css_attr_escape(str(placeholder))}']"

        return f"form:nth-of-type({form_index + 1}) {tag_name}:nth-of-type({field_index + 1})"

    def _css_escape(self, value: str) -> str:
        return re.sub(r"([^a-zA-Z0-9_-])", r"\\\1", value)

    def _css_attr_escape(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _attr_bool(self, attrs: Dict[str, Any], key: str) -> bool:
        return key in attrs and attrs.get(key) not in {False, None, "false", "False", "0"}

    def _safe_int(self, value: Any) -> Optional[int]:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except Exception:
            return None

    def _safe_attrs(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        safe: Dict[str, Any] = {}
        for key, value in attrs.items():
            key_lower = _safe_lower(key)
            if _contains_any_keyword(key_lower, SENSITIVE_FIELD_KEYWORDS):
                safe[key] = "***"
            else:
                safe[key] = _clean_text(value, max_length=200)
        return safe

    # ==================================================================================
    # Required Compatibility Hooks
    # ==================================================================================

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Every user-specific execution must include user_id and workspace_id.
        """
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        if user_id in {None, ""}:
            return self._error_result(
                message="Missing required user_id for SaaS-isolated form task.",
                code="missing_user_id",
                metadata={"required": ["user_id", "workspace_id"]},
            )

        if workspace_id in {None, ""}:
            return self._error_result(
                message="Missing required workspace_id for SaaS-isolated form task.",
                code="missing_workspace_id",
                metadata={"required": ["user_id", "workspace_id"]},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        action: str,
        form: Optional[FormInfo] = None,
        values: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.
        """
        action_lower = _safe_lower(action)
        metadata = metadata or {}
        values = values or {}

        if action_lower == FormAction.SUBMIT.value:
            return True

        if metadata.get("force_security_check") is True:
            return True

        if form and form.requires_approval:
            return True

        if form and any(field_item.is_sensitive for field_item in form.fields):
            return True

        for key, value in values.items():
            blob = f"{key} {value}"
            if _contains_any_keyword(blob, SENSITIVE_FIELD_KEYWORDS):
                return True

        return False

    async def _request_security_approval(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        form: FormInfo,
        values: Dict[str, Any],
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalStatus:
        """
        Request approval from Security Agent if available.

        Safe fallback:
            If no Security Agent exists, submission/sensitive action is blocked unless
            an explicit approval_token is provided and metadata allows token fallback.
        """
        metadata = metadata or {}

        approval_payload = {
            "request_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "form": {
                "form_id": form.form_id,
                "title": form.title,
                "action": form.action,
                "method": form.method,
                "sensitivity": form.sensitivity.value,
                "requires_approval": form.requires_approval,
                "fingerprint": form.fingerprint,
            },
            "values_preview": self._safe_values_preview(form, values),
            "risk": {
                "reason": "Sensitive form action or form submission requires explicit approval.",
                "submit_blocked_without_approval": True,
            },
            "metadata": metadata,
            "approval_token": approval_token,
        }

        if self.security_agent is not None:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    result = self.security_agent.approve_action(approval_payload)
                    result = await _maybe_await(result)
                    return self._parse_approval_result(result)

                if hasattr(self.security_agent, "request_approval"):
                    result = self.security_agent.request_approval(approval_payload)
                    result = await _maybe_await(result)
                    return self._parse_approval_result(result)

                if hasattr(self.security_agent, "run"):
                    result = self.security_agent.run(
                        {
                            "action": "approve_browser_form_action",
                            **approval_payload,
                        }
                    )
                    result = await _maybe_await(result)
                    return self._parse_approval_result(result)
            except Exception as exc:
                self.logger.warning("Security approval request failed: %s", exc)
                return ApprovalStatus.DENIED

        # Safe fallback mode:
        # For development/testing, dashboard may provide approval_token and explicitly enable fallback.
        if approval_token and metadata.get("allow_approval_token_fallback") is True:
            expected_hash = metadata.get("approval_token_hash")
            if expected_hash:
                if _hash_payload(approval_token) == expected_hash:
                    return ApprovalStatus.APPROVED
                return ApprovalStatus.DENIED

            # If no expected hash is configured, treat token presence as manual approval
            # only in explicit fallback mode.
            return ApprovalStatus.APPROVED

        return ApprovalStatus.MISSING

    def _parse_approval_result(self, result: Any) -> ApprovalStatus:
        if isinstance(result, ApprovalStatus):
            return result

        if isinstance(result, bool):
            return ApprovalStatus.APPROVED if result else ApprovalStatus.DENIED

        if isinstance(result, dict):
            if result.get("approved") is True:
                return ApprovalStatus.APPROVED
            if result.get("success") is True and result.get("data", {}).get("approved") is True:
                return ApprovalStatus.APPROVED

            status = _safe_lower(result.get("status") or result.get("approval_status"))
            if status in {"approved", "allow", "allowed"}:
                return ApprovalStatus.APPROVED
            if status in {"denied", "deny", "blocked", "rejected"}:
                return ApprovalStatus.DENIED

        return ApprovalStatus.DENIED

    def _prepare_verification_payload(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This does not call Verification Agent directly; it creates a compatible
        structured payload for Master Agent or dashboard pipelines.
        """
        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "timestamp": _now_ts(),
            "data_hash": _hash_payload(data or {}),
            "data_summary": self._summarize_for_verification(data or {}),
        }

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Sensitive values are never included.
        """
        return {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "timestamp": _now_ts(),
            "safe_summary": self._summarize_for_memory(data or {}),
            "sensitive_values_excluded": True,
        }

    async def _emit_agent_event(
        self,
        event_type: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "module": self.agent_module,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "timestamp": _now_ts(),
            "data": data or {},
        }

        if self.event_emitter:
            try:
                result = self.event_emitter(event)
                await _maybe_await(result)
            except Exception as exc:
                self.logger.warning("Event emitter failed: %s", exc)
        else:
            self.logger.debug("Agent event: %s", event)

    async def _log_audit_event(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "status": status,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "timestamp": _now_ts(),
            "metadata": metadata or {},
        }

        if self.audit_logger:
            try:
                result = self.audit_logger(event)
                await _maybe_await(result)
            except Exception as exc:
                self.logger.warning("Audit logger failed: %s", exc)
        else:
            self.logger.debug("Audit event: %s", event)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        code: str = "error",
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": code,
                "details": error or message,
            },
            "metadata": metadata or {},
        }

    # ==================================================================================
    # Safe Serialization / Summaries
    # ==================================================================================

    def _form_to_dict(self, form: FormInfo) -> Dict[str, Any]:
        data = asdict(form)

        # Ensure enum serializes cleanly.
        data["sensitivity"] = form.sensitivity.value

        # Mask existing sensitive field values.
        for field_item in data.get("fields", []):
            if field_item.get("is_sensitive") and field_item.get("value"):
                field_item["value"] = _mask_sensitive_value(field_item["value"])

        return data

    def _safe_values_preview(self, form: FormInfo, values: Dict[str, Any]) -> Dict[str, Any]:
        preview: Dict[str, Any] = {}

        for key, value in values.items():
            matched_field = None
            for field_item in form.fields:
                if key in self._field_key_candidates(field_item):
                    matched_field = field_item
                    break

            if matched_field and matched_field.is_sensitive:
                preview[key] = _mask_sensitive_value(value)
            elif _contains_any_keyword(str(key), SENSITIVE_FIELD_KEYWORDS):
                preview[key] = _mask_sensitive_value(value)
            else:
                preview[key] = _clean_text(value, max_length=120)

        return preview

    def _summarize_for_verification(self, data: Dict[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}

        if "form_count" in data:
            summary["form_count"] = data.get("form_count")

        if "sensitive_form_count" in data:
            summary["sensitive_form_count"] = data.get("sensitive_form_count")

        if "form_id" in data:
            summary["form_id"] = data.get("form_id")

        if "filled_count" in data:
            summary["filled_count"] = data.get("filled_count")

        if "failed_count" in data:
            summary["failed_count"] = data.get("failed_count")

        if "submitted" in data:
            summary["submitted"] = data.get("submitted")

        if "sensitivity" in data:
            summary["sensitivity"] = data.get("sensitivity")

        return summary or {"summary": "verification payload prepared"}

    def _summarize_for_memory(self, data: Dict[str, Any]) -> Dict[str, Any]:
        summary = self._summarize_for_verification(data)
        summary["note"] = "Browser form interaction summary. Sensitive values excluded."
        return summary


# ======================================================================================
# Module Metadata
# ======================================================================================

FORM_HANDLER_MODULE_INFO = {
    "agent_module": DEFAULT_AGENT_MODULE,
    "file": "form_handler.py",
    "path": DEFAULT_FILE_PATH,
    "class": "FormHandler",
    "purpose": "Detect, fill, validate forms with approval; never submit sensitive forms silently.",
    "safety": {
        "silent_sensitive_submission_allowed": False,
        "submission_requires_security_approval": True,
        "sensitive_values_masked_in_logs": True,
    },
    "compatibility_hooks": [
        "_validate_task_context",
        "_requires_security_check",
        "_request_security_approval",
        "_prepare_verification_payload",
        "_prepare_memory_payload",
        "_emit_agent_event",
        "_log_audit_event",
        "_safe_result",
        "_error_result",
    ],
    "completion": {
        "agent_module": "Browser Agent",
        "file_completed": "form_handler.py",
        "completion_percent": 73.7,
        "remaining_files": [
            "download_manager.py",
            "screenshot_tool.py",
            "browser_memory.py",
            "permissions.py",
            "config.py",
        ],
        "next_recommended_file": "agents/browser_agent/download_manager.py",
    },
}


__all__ = [
    "FormHandler",
    "FormField",
    "FormInfo",
    "ValidationIssue",
    "FillPlan",
    "FormSensitivity",
    "FormAction",
    "ApprovalStatus",
    "FORM_HANDLER_MODULE_INFO",
]


"""
Agent/Module: Browser Agent
File Completed: form_handler.py
Completion: 73.7%
Completed Files: ['browser_agent.py', 'search_engine.py', 'scraper.py', 'page_analyzer.py', 'multi_tab_planner.py', 'automation.py', 'browser_session.py', 'tab_manager.py', 'content_extractor.py', 'seo_analyzer.py', 'competitor_analyzer.py', 'price_monitor.py', 'workflow_learner.py', 'form_handler.py']
Remaining Files: ['download_manager.py', 'screenshot_tool.py', 'browser_memory.py', 'permissions.py', 'config.py']
Next Recommended File: agents/browser_agent/download_manager.py
FILE COMPLETE
"""