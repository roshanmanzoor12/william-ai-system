"""
William / Jarvis Multi-Agent AI SaaS System
Browser Agent - Browser Automation Helper

File: agents/browser_agent/automation.py
Class: BrowserAutomation

Purpose:
    Provides safe, SaaS-aware browser automation actions for:
    - Opening URLs
    - Clicking elements
    - Scrolling pages
    - Filling forms with approval protection
    - Capturing screenshots

Architecture Compatibility:
    - Master Agent routing compatible
    - BaseAgent compatible through optional inheritance/fallback behavior
    - Security Agent approval hooks for sensitive browser actions
    - Verification Agent payload preparation after actions
    - Memory Agent payload preparation for useful context
    - Dashboard/API structured results
    - Audit/event logging hooks
    - User/workspace isolation enforcement

Safety:
    This file does not perform destructive browser actions without security approval.
    Form submission, clicking sensitive selectors, login/payment/account actions, and
    screenshot capture can be gated through the Security Agent.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Optional William / Jarvis imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe when the wider William/Jarvis system
        has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from core.context import TaskContext  # type: ignore
except Exception:
    TaskContext = Dict[str, Any]  # type: ignore


try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    async_playwright = None  # type: ignore
    Browser = Any  # type: ignore
    BrowserContext = Any  # type: ignore
    Page = Any  # type: ignore
    PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and Data Structures
# ---------------------------------------------------------------------------

class BrowserAction(str, Enum):
    """Supported browser automation action names."""

    OPEN_URL = "open_url"
    CLICK = "click"
    SCROLL = "scroll"
    FILL_FORM = "fill_form"
    SCREENSHOT = "screenshot"
    GET_PAGE_INFO = "get_page_info"
    CLOSE = "close"


class BrowserRiskLevel(str, Enum):
    """Risk level used for Security Agent routing and audit logs."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BrowserExecutionMode(str, Enum):
    """Browser execution behavior."""

    SAFE = "safe"
    APPROVAL_REQUIRED = "approval_required"
    DRY_RUN = "dry_run"


@dataclass
class BrowserAutomationConfig:
    """
    Runtime configuration for BrowserAutomation.

    All defaults are safe for SaaS/API use.
    """

    headless: bool = True
    browser_type: str = "chromium"
    timeout_ms: int = 30_000
    navigation_timeout_ms: int = 45_000
    viewport_width: int = 1366
    viewport_height: int = 768
    user_agent: Optional[str] = None

    allow_external_urls: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)

    screenshot_dir: str = "storage/browser_screenshots"
    screenshot_format: str = "png"
    save_screenshots: bool = True

    require_approval_for_clicks: bool = True
    require_approval_for_forms: bool = True
    require_approval_for_screenshots: bool = False

    block_sensitive_form_submit: bool = True
    dry_run: bool = False

    max_scroll_steps: int = 20
    default_scroll_pixels: int = 700
    slow_mo_ms: int = 0

    audit_enabled: bool = True
    event_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True


@dataclass
class BrowserActionRequest:
    """
    Normalized browser action request.

    This can be created by Master Agent, Browser Agent, API route, dashboard,
    workflow runner, or future plugin-style agents.
    """

    action: BrowserAction
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    url: Optional[str] = None
    selector: Optional[str] = None
    text: Optional[str] = None
    form_data: Optional[Dict[str, Any]] = None
    options: Dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    session_id: Optional[str] = None
    approval_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserActionRecord:
    """Internal action history record."""

    action_id: str
    action: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    task_id: Optional[str]
    session_id: Optional[str]
    success: bool
    message: str
    created_at: str
    risk_level: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# BrowserAutomation
# ---------------------------------------------------------------------------

class BrowserAutomation(BaseAgent):
    """
    Production-level browser automation helper for William/Jarvis Browser Agent.

    This class is intentionally designed as a helper/service class rather than
    a raw uncontrolled automation runner. Every public method:
        1. validates SaaS context
        2. evaluates risk
        3. optionally requests security approval
        4. executes browser-safe behavior
        5. prepares verification and memory payloads
        6. emits audit/event records
        7. returns structured JSON-style dicts

    Integration points:
        - Master Agent can call `run_action()`
        - Browser Agent can call specific methods
        - Security Agent can be injected through `security_approval_callback`
        - Verification Agent can consume `_prepare_verification_payload()`
        - Memory Agent can consume `_prepare_memory_payload()`
        - Dashboard/API can consume structured results
    """

    SENSITIVE_SELECTOR_PATTERNS: Tuple[str, ...] = (
        "password",
        "passwd",
        "passcode",
        "token",
        "secret",
        "api_key",
        "apikey",
        "credit",
        "card",
        "cvv",
        "cvc",
        "ssn",
        "bank",
        "wallet",
        "payment",
        "billing",
        "transfer",
        "delete",
        "remove",
        "logout",
        "submit",
        "confirm",
        "purchase",
        "checkout",
    )

    SENSITIVE_URL_PATTERNS: Tuple[str, ...] = (
        "/login",
        "/signin",
        "/signup",
        "/register",
        "/checkout",
        "/payment",
        "/billing",
        "/account",
        "/settings",
        "/admin",
        "/delete",
        "/remove",
        "/transfer",
        "/bank",
        "/wallet",
    )

    BLOCKED_SCHEMES: Tuple[str, ...] = (
        "file",
        "javascript",
        "data",
        "ftp",
    )

    def __init__(
        self,
        config: Optional[BrowserAutomationConfig] = None,
        security_approval_callback: Optional[
            Callable[[Dict[str, Any]], Union[bool, Dict[str, Any], Awaitable[Union[bool, Dict[str, Any]]]]]
        ] = None,
        audit_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        event_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        memory_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        verification_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="BrowserAutomation", agent_id="browser_automation", **kwargs)

        self.config = config or BrowserAutomationConfig()
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self._playwright: Any = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

        self._action_history: List[BrowserActionRecord] = []
        self._active_user_id: Optional[Union[str, int]] = None
        self._active_workspace_id: Optional[Union[str, int]] = None
        self._active_session_id: Optional[str] = None

        self._ensure_storage_dirs()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def run_action(self, request: Union[BrowserActionRequest, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main router-compatible entry point.

        Master Agent, Agent Router, API routes, dashboard actions, or Browser
        Agent can pass a BrowserActionRequest or dict.

        Args:
            request: BrowserActionRequest or compatible dict.

        Returns:
            Structured result dict.
        """

        normalized = self._normalize_request(request)
        validation = self._validate_task_context(normalized)
        if not validation["success"]:
            return validation

        if normalized.action == BrowserAction.OPEN_URL:
            return await self.open_url(
                url=normalized.url or "",
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                options=normalized.options,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == BrowserAction.CLICK:
            return await self.click(
                selector=normalized.selector or "",
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                options=normalized.options,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == BrowserAction.SCROLL:
            return await self.scroll(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                options=normalized.options,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == BrowserAction.FILL_FORM:
            return await self.fill_form(
                form_data=normalized.form_data or {},
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                options=normalized.options,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == BrowserAction.SCREENSHOT:
            return await self.screenshot(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                options=normalized.options,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == BrowserAction.GET_PAGE_INFO:
            return await self.get_page_info(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                metadata=normalized.metadata,
            )

        if normalized.action == BrowserAction.CLOSE:
            return await self.close(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                task_id=normalized.task_id,
                session_id=normalized.session_id,
                metadata=normalized.metadata,
            )

        return self._error_result(
            message=f"Unsupported browser action: {normalized.action}",
            error_code="UNSUPPORTED_BROWSER_ACTION",
            metadata={"action": str(normalized.action)},
        )

    async def open_url(
        self,
        url: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Open a URL in the controlled browser context.

        Security:
            - Validates URL scheme
            - Enforces allowed/blocked domains
            - Risk-checks sensitive URLs
            - Does not bypass site security
        """

        options = options or {}
        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.OPEN_URL,
            user_id=user_id,
            workspace_id=workspace_id,
            url=url,
            task_id=task_id,
            session_id=session_id,
            options=options,
            approval_token=approval_token,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        url_validation = self._validate_url(url)
        if not url_validation["success"]:
            await self._record_failed_action(action_id, request, url_validation["message"], BrowserRiskLevel.MEDIUM)
            return url_validation

        risk_level = self._assess_risk(request)
        security = await self._maybe_request_security_approval(request, risk_level)
        if not security["success"]:
            await self._record_failed_action(action_id, request, security["message"], risk_level)
            return security

        if self.config.dry_run or options.get("dry_run"):
            result = self._safe_result(
                message="Dry-run: URL open action validated but not executed.",
                data={
                    "action_id": action_id,
                    "url": url,
                    "dry_run": True,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        browser_ready = await self._ensure_browser(user_id=user_id, workspace_id=workspace_id, session_id=session_id)
        if not browser_ready["success"]:
            return browser_ready

        try:
            assert self._page is not None
            response = await self._page.goto(
                url,
                wait_until=options.get("wait_until", "domcontentloaded"),
                timeout=int(options.get("timeout_ms", self.config.navigation_timeout_ms)),
            )

            title = await self._safe_page_title()
            current_url = self._page.url
            status_code = response.status if response is not None else None

            result = self._safe_result(
                message="URL opened successfully.",
                data={
                    "action_id": action_id,
                    "url": current_url,
                    "requested_url": url,
                    "title": title,
                    "status_code": status_code,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to open URL.",
                error=str(exc),
                error_code="OPEN_URL_FAILED",
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    async def click(
        self,
        selector: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Click a page element by selector.

        Security:
            - Sensitive selectors require approval by default
            - This method does not automate harmful, fraudulent, or deceptive clicks
            - Caller should provide explicit selector and task context
        """

        options = options or {}
        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.CLICK,
            user_id=user_id,
            workspace_id=workspace_id,
            selector=selector,
            task_id=task_id,
            session_id=session_id,
            options=options,
            approval_token=approval_token,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        if not selector or not isinstance(selector, str):
            return self._error_result(
                message="A valid selector is required for click action.",
                error_code="INVALID_SELECTOR",
                metadata=self._base_metadata(request, started, BrowserRiskLevel.MEDIUM),
            )

        risk_level = self._assess_risk(request)
        security = await self._maybe_request_security_approval(request, risk_level)
        if not security["success"]:
            await self._record_failed_action(action_id, request, security["message"], risk_level)
            return security

        if self.config.dry_run or options.get("dry_run"):
            result = self._safe_result(
                message="Dry-run: click action validated but not executed.",
                data={
                    "action_id": action_id,
                    "selector": selector,
                    "dry_run": True,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        browser_ready = await self._ensure_browser(user_id=user_id, workspace_id=workspace_id, session_id=session_id)
        if not browser_ready["success"]:
            return browser_ready

        try:
            assert self._page is not None

            locator = self._page.locator(selector)
            count = await locator.count()

            if count <= 0:
                result = self._error_result(
                    message="No element found for selector.",
                    error_code="ELEMENT_NOT_FOUND",
                    metadata={
                        **self._base_metadata(request, started, risk_level),
                        "selector": selector,
                    },
                )
                await self._after_action(request, result, risk_level, action_id)
                return result

            element_index = int(options.get("index", 0))
            if element_index < 0:
                element_index = 0
            if element_index >= count:
                element_index = count - 1

            target = locator.nth(element_index)

            if bool(options.get("scroll_into_view", True)):
                await target.scroll_into_view_if_needed(timeout=self.config.timeout_ms)

            click_options: Dict[str, Any] = {
                "timeout": int(options.get("timeout_ms", self.config.timeout_ms)),
            }

            if "button" in options:
                click_options["button"] = options["button"]

            if "click_count" in options:
                click_options["click_count"] = int(options["click_count"])

            if "delay" in options:
                click_options["delay"] = int(options["delay"])

            await target.click(**click_options)

            current_url = await self._safe_current_url()
            title = await self._safe_page_title()

            result = self._safe_result(
                message="Element clicked successfully.",
                data={
                    "action_id": action_id,
                    "selector": selector,
                    "element_index": element_index,
                    "matched_elements": count,
                    "url": current_url,
                    "title": title,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to click element.",
                error=str(exc),
                error_code="CLICK_FAILED",
                metadata={
                    **self._base_metadata(request, started, risk_level),
                    "selector": selector,
                },
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    async def scroll(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Scroll the current page.

        Supported options:
            direction: "down" | "up" | "top" | "bottom"
            pixels: int
            steps: int
            delay_ms: int
        """

        options = options or {}
        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.SCROLL,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            session_id=session_id,
            options=options,
            approval_token=approval_token,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        risk_level = self._assess_risk(request)

        if self.config.dry_run or options.get("dry_run"):
            result = self._safe_result(
                message="Dry-run: scroll action validated but not executed.",
                data={
                    "action_id": action_id,
                    "dry_run": True,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        browser_ready = await self._ensure_browser(user_id=user_id, workspace_id=workspace_id, session_id=session_id)
        if not browser_ready["success"]:
            return browser_ready

        try:
            assert self._page is not None

            direction = str(options.get("direction", "down")).lower().strip()
            pixels = int(options.get("pixels", self.config.default_scroll_pixels))
            steps = int(options.get("steps", 1))
            delay_ms = int(options.get("delay_ms", 150))

            steps = max(1, min(steps, self.config.max_scroll_steps))
            pixels = max(1, min(abs(pixels), 10_000))

            if direction == "up":
                pixels = -pixels

            if direction == "top":
                await self._page.evaluate("window.scrollTo({ top: 0, behavior: 'instant' });")
            elif direction == "bottom":
                await self._page.evaluate("window.scrollTo({ top: document.body.scrollHeight, behavior: 'instant' });")
            else:
                for _ in range(steps):
                    await self._page.mouse.wheel(0, pixels)
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)

            scroll_position = await self._page.evaluate(
                """
                () => ({
                    x: window.scrollX || 0,
                    y: window.scrollY || 0,
                    height: document.body ? document.body.scrollHeight : 0,
                    viewportHeight: window.innerHeight || 0
                })
                """
            )

            result = self._safe_result(
                message="Page scrolled successfully.",
                data={
                    "action_id": action_id,
                    "direction": direction,
                    "pixels": pixels,
                    "steps": steps,
                    "scroll_position": scroll_position,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to scroll page.",
                error=str(exc),
                error_code="SCROLL_FAILED",
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    async def fill_form(
        self,
        form_data: Dict[str, Any],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fill form fields using selector -> value mapping.

        Example:
            form_data = {
                "input[name='email']": "client@example.com",
                "textarea[name='message']": "Hello"
            }

        Supported options:
            submit_selector: optional selector to click after filling
            submit: bool, default False
            clear_existing: bool, default True

        Security:
            Form filling requires approval by default.
            Submitting forms requires approval and is treated as high risk.
        """

        options = options or {}
        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.FILL_FORM,
            user_id=user_id,
            workspace_id=workspace_id,
            form_data=form_data,
            task_id=task_id,
            session_id=session_id,
            options=options,
            approval_token=approval_token,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        if not isinstance(form_data, dict) or not form_data:
            return self._error_result(
                message="form_data must be a non-empty selector-to-value dictionary.",
                error_code="INVALID_FORM_DATA",
                metadata=self._base_metadata(request, started, BrowserRiskLevel.HIGH),
            )

        risk_level = self._assess_risk(request)
        security = await self._maybe_request_security_approval(request, risk_level)
        if not security["success"]:
            await self._record_failed_action(action_id, request, security["message"], risk_level)
            return security

        if self.config.dry_run or options.get("dry_run"):
            result = self._safe_result(
                message="Dry-run: form fill action validated but not executed.",
                data={
                    "action_id": action_id,
                    "field_count": len(form_data),
                    "submit_requested": bool(options.get("submit", False)),
                    "dry_run": True,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        browser_ready = await self._ensure_browser(user_id=user_id, workspace_id=workspace_id, session_id=session_id)
        if not browser_ready["success"]:
            return browser_ready

        try:
            assert self._page is not None

            clear_existing = bool(options.get("clear_existing", True))
            filled_fields: List[Dict[str, Any]] = []
            failed_fields: List[Dict[str, Any]] = []

            for selector, value in form_data.items():
                selector_str = str(selector)
                value_str = "" if value is None else str(value)

                try:
                    locator = self._page.locator(selector_str)
                    count = await locator.count()

                    if count <= 0:
                        failed_fields.append({
                            "selector": selector_str,
                            "reason": "element_not_found",
                        })
                        continue

                    target = locator.first
                    await target.scroll_into_view_if_needed(timeout=self.config.timeout_ms)

                    if clear_existing:
                        await target.fill(value_str, timeout=self.config.timeout_ms)
                    else:
                        await target.type(value_str, timeout=self.config.timeout_ms)

                    filled_fields.append({
                        "selector": selector_str,
                        "success": True,
                        "value_preview": self._safe_value_preview(value_str),
                    })

                except Exception as field_exc:
                    failed_fields.append({
                        "selector": selector_str,
                        "reason": str(field_exc),
                    })

            submit_requested = bool(options.get("submit", False))
            submit_result: Optional[Dict[str, Any]] = None

            if submit_requested:
                submit_selector = options.get("submit_selector")
                if not submit_selector:
                    submit_result = {
                        "success": False,
                        "message": "submit=True requires submit_selector.",
                    }
                elif self.config.block_sensitive_form_submit and not approval_token:
                    submit_result = {
                        "success": False,
                        "message": "Form submit blocked because approval_token is missing.",
                    }
                else:
                    try:
                        submit_locator = self._page.locator(str(submit_selector))
                        if await submit_locator.count() <= 0:
                            submit_result = {
                                "success": False,
                                "message": "Submit selector not found.",
                                "selector": submit_selector,
                            }
                        else:
                            await submit_locator.first.click(timeout=self.config.timeout_ms)
                            submit_result = {
                                "success": True,
                                "message": "Form submitted successfully.",
                                "selector": submit_selector,
                            }
                    except Exception as submit_exc:
                        submit_result = {
                            "success": False,
                            "message": "Form submit failed.",
                            "error": str(submit_exc),
                            "selector": submit_selector,
                        }

            success = len(filled_fields) > 0 and len(failed_fields) == 0
            message = "Form filled successfully." if success else "Form fill completed with issues."

            result = self._safe_result(
                success=success,
                message=message,
                data={
                    "action_id": action_id,
                    "filled_fields": filled_fields,
                    "failed_fields": failed_fields,
                    "submit_requested": submit_requested,
                    "submit_result": submit_result,
                    "risk_level": risk_level.value,
                    "url": await self._safe_current_url(),
                    "title": await self._safe_page_title(),
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to fill form.",
                error=str(exc),
                error_code="FILL_FORM_FAILED",
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    async def screenshot(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Capture a screenshot of the current page.

        Supported options:
            full_page: bool
            selector: optional selector screenshot
            return_base64: bool
            file_name: optional custom filename
        """

        options = options or {}
        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.SCREENSHOT,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            session_id=session_id,
            options=options,
            approval_token=approval_token,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        risk_level = self._assess_risk(request)
        security = await self._maybe_request_security_approval(request, risk_level)
        if not security["success"]:
            await self._record_failed_action(action_id, request, security["message"], risk_level)
            return security

        if self.config.dry_run or options.get("dry_run"):
            result = self._safe_result(
                message="Dry-run: screenshot action validated but not executed.",
                data={
                    "action_id": action_id,
                    "dry_run": True,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        browser_ready = await self._ensure_browser(user_id=user_id, workspace_id=workspace_id, session_id=session_id)
        if not browser_ready["success"]:
            return browser_ready

        try:
            assert self._page is not None

            screenshot_bytes: bytes
            selector = options.get("selector")
            full_page = bool(options.get("full_page", True))
            return_base64 = bool(options.get("return_base64", False))

            screenshot_options: Dict[str, Any] = {
                "type": self.config.screenshot_format,
                "timeout": int(options.get("timeout_ms", self.config.timeout_ms)),
            }

            if selector:
                locator = self._page.locator(str(selector))
                if await locator.count() <= 0:
                    result = self._error_result(
                        message="Screenshot selector not found.",
                        error_code="SCREENSHOT_SELECTOR_NOT_FOUND",
                        metadata={
                            **self._base_metadata(request, started, risk_level),
                            "selector": selector,
                        },
                    )
                    await self._after_action(request, result, risk_level, action_id)
                    return result

                screenshot_bytes = await locator.first.screenshot(**screenshot_options)
            else:
                screenshot_options["full_page"] = full_page
                screenshot_bytes = await self._page.screenshot(**screenshot_options)

            file_path: Optional[str] = None

            if self.config.save_screenshots and not options.get("disable_save", False):
                file_path = self._build_screenshot_path(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    action_id=action_id,
                    file_name=options.get("file_name"),
                )
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, "wb") as file:
                    file.write(screenshot_bytes)

            b64_value: Optional[str] = None
            if return_base64:
                b64_value = base64.b64encode(screenshot_bytes).decode("utf-8")

            result = self._safe_result(
                message="Screenshot captured successfully.",
                data={
                    "action_id": action_id,
                    "file_path": file_path,
                    "bytes": len(screenshot_bytes),
                    "base64": b64_value,
                    "format": self.config.screenshot_format,
                    "selector": selector,
                    "full_page": full_page,
                    "risk_level": risk_level.value,
                    "url": await self._safe_current_url(),
                    "title": await self._safe_page_title(),
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to capture screenshot.",
                error=str(exc),
                error_code="SCREENSHOT_FAILED",
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    async def get_page_info(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return safe page information for dashboard, verification, and agent routing.
        """

        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.GET_PAGE_INFO,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        browser_ready = await self._ensure_browser(user_id=user_id, workspace_id=workspace_id, session_id=session_id)
        if not browser_ready["success"]:
            return browser_ready

        risk_level = BrowserRiskLevel.LOW

        try:
            assert self._page is not None

            page_info = await self._page.evaluate(
                """
                () => {
                    const meta = {};
                    document.querySelectorAll('meta').forEach((m) => {
                        const name = m.getAttribute('name') || m.getAttribute('property');
                        const content = m.getAttribute('content');
                        if (name && content) meta[name] = content;
                    });

                    return {
                        title: document.title || '',
                        url: window.location.href,
                        origin: window.location.origin,
                        readyState: document.readyState,
                        textLength: document.body ? document.body.innerText.length : 0,
                        linkCount: document.links ? document.links.length : 0,
                        formCount: document.forms ? document.forms.length : 0,
                        imageCount: document.images ? document.images.length : 0,
                        meta,
                        scroll: {
                            x: window.scrollX || 0,
                            y: window.scrollY || 0,
                            height: document.body ? document.body.scrollHeight : 0,
                            viewportHeight: window.innerHeight || 0
                        }
                    };
                }
                """
            )

            result = self._safe_result(
                message="Page info collected successfully.",
                data={
                    "action_id": action_id,
                    "page": page_info,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to collect page info.",
                error=str(exc),
                error_code="PAGE_INFO_FAILED",
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    async def close(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Close browser resources safely.
        """

        metadata = metadata or {}
        action_id = self._new_action_id()
        started = self._utc_now()

        request = BrowserActionRequest(
            action=BrowserAction.CLOSE,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        risk_level = BrowserRiskLevel.LOW

        try:
            if self._context is not None:
                await self._context.close()
            if self._browser is not None:
                await self._browser.close()
            if self._playwright is not None:
                await self._playwright.stop()

            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None
            self._active_user_id = None
            self._active_workspace_id = None
            self._active_session_id = None

            result = self._safe_result(
                message="Browser automation resources closed successfully.",
                data={
                    "action_id": action_id,
                    "closed": True,
                    "risk_level": risk_level.value,
                },
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to close browser resources.",
                error=str(exc),
                error_code="BROWSER_CLOSE_FAILED",
                metadata=self._base_metadata(request, started, risk_level),
            )
            await self._after_action(request, result, risk_level, action_id)
            return result

    def get_action_history(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Return in-memory action history.

        This is dashboard-friendly and SaaS-safe: when user_id/workspace_id are
        provided, history is filtered by both.
        """

        limit = max(1, min(int(limit), 500))

        records = self._action_history

        if user_id is not None:
            records = [record for record in records if str(record.user_id) == str(user_id)]

        if workspace_id is not None:
            records = [record for record in records if str(record.workspace_id) == str(workspace_id)]

        sliced = records[-limit:]

        return self._safe_result(
            message="Browser automation action history fetched successfully.",
            data={
                "count": len(sliced),
                "records": [asdict(record) for record in sliced],
            },
            metadata={
                "filtered_user_id": str(user_id) if user_id is not None else None,
                "filtered_workspace_id": str(workspace_id) if workspace_id is not None else None,
                "limit": limit,
            },
        )

    # -----------------------------------------------------------------------
    # Compatibility Hooks Required by Prompt
    # -----------------------------------------------------------------------

    def _validate_task_context(self, request: BrowserActionRequest) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required by William/Jarvis compatibility.

        Every user-specific browser action must include user_id and workspace_id.
        This prevents mixing browser state, files, screenshots, logs, memory,
        analytics, and audit data between users/workspaces.
        """

        if request is None:
            return self._error_result(
                message="Task context is missing.",
                error_code="MISSING_TASK_CONTEXT",
            )

        if request.user_id is None or str(request.user_id).strip() == "":
            return self._error_result(
                message="user_id is required for browser automation.",
                error_code="MISSING_USER_ID",
            )

        if request.workspace_id is None or str(request.workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for browser automation.",
                error_code="MISSING_WORKSPACE_ID",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(request.user_id),
                "workspace_id": str(request.workspace_id),
                "task_id": request.task_id,
                "session_id": request.session_id,
            },
        )

    def _requires_security_check(
        self,
        request: BrowserActionRequest,
        risk_level: Optional[BrowserRiskLevel] = None,
    ) -> bool:
        """
        Decide whether the Security Agent must approve the action.

        Required by William/Jarvis compatibility.
        """

        risk = risk_level or self._assess_risk(request)

        if self.config.dry_run or request.options.get("dry_run"):
            return False

        if risk in {BrowserRiskLevel.HIGH, BrowserRiskLevel.CRITICAL}:
            return True

        if request.action == BrowserAction.CLICK and self.config.require_approval_for_clicks:
            return True

        if request.action == BrowserAction.FILL_FORM and self.config.require_approval_for_forms:
            return True

        if request.action == BrowserAction.SCREENSHOT and self.config.require_approval_for_screenshots:
            return True

        return False

    async def _request_security_approval(
        self,
        request: BrowserActionRequest,
        risk_level: BrowserRiskLevel,
    ) -> Dict[str, Any]:
        """
        Request approval from the Security Agent.

        Required by William/Jarvis compatibility.

        If a security callback is injected, it is used.
        If no callback exists, low/medium risk can proceed unless config forces
        approval. High/critical risk is blocked without explicit approval token.
        """

        approval_payload = {
            "request_id": self._new_action_id(),
            "agent": "BrowserAutomation",
            "action": request.action.value,
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "session_id": request.session_id,
            "url": request.url,
            "selector": request.selector,
            "metadata": {
                **request.metadata,
                "safe_value_preview_only": True,
                "timestamp": self._utc_now(),
            },
        }

        if request.approval_token:
            return self._safe_result(
                message="Security approval token provided.",
                data={
                    "approved": True,
                    "approval_token_present": True,
                    "risk_level": risk_level.value,
                },
            )

        if self.security_approval_callback is not None:
            try:
                callback_result = self.security_approval_callback(approval_payload)
                if asyncio.iscoroutine(callback_result):
                    callback_result = await callback_result

                if isinstance(callback_result, bool):
                    if callback_result:
                        return self._safe_result(
                            message="Security Agent approved browser action.",
                            data={"approved": True, "risk_level": risk_level.value},
                        )

                    return self._error_result(
                        message="Security Agent denied browser action.",
                        error_code="SECURITY_DENIED",
                        metadata={"risk_level": risk_level.value},
                    )

                if isinstance(callback_result, dict):
                    approved = bool(callback_result.get("approved") or callback_result.get("success"))
                    if approved:
                        return self._safe_result(
                            message=callback_result.get("message", "Security Agent approved browser action."),
                            data={
                                "approved": True,
                                "risk_level": risk_level.value,
                                "security_response": callback_result,
                            },
                        )

                    return self._error_result(
                        message=callback_result.get("message", "Security Agent denied browser action."),
                        error_code=callback_result.get("error_code", "SECURITY_DENIED"),
                        metadata={
                            "risk_level": risk_level.value,
                            "security_response": callback_result,
                        },
                    )

            except Exception as exc:
                return self._error_result(
                    message="Security approval callback failed.",
                    error=str(exc),
                    error_code="SECURITY_CALLBACK_FAILED",
                    metadata={"risk_level": risk_level.value},
                )

        if risk_level in {BrowserRiskLevel.HIGH, BrowserRiskLevel.CRITICAL}:
            return self._error_result(
                message="Browser action requires Security Agent approval or approval_token.",
                error_code="SECURITY_APPROVAL_REQUIRED",
                metadata={
                    "risk_level": risk_level.value,
                    "action": request.action.value,
                },
            )

        return self._safe_result(
            message="Security approval not required for this risk level.",
            data={
                "approved": True,
                "risk_level": risk_level.value,
                "approval_callback_configured": False,
            },
        )

    def _prepare_verification_payload(
        self,
        request: BrowserActionRequest,
        result: Dict[str, Any],
        risk_level: BrowserRiskLevel,
        action_id: str,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by William/Jarvis compatibility.
        """

        return {
            "type": "browser_action_verification",
            "agent": "BrowserAutomation",
            "action_id": action_id,
            "action": request.action.value,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "session_id": request.session_id,
            "url": self._extract_result_url(result) or request.url,
            "selector": request.selector,
            "timestamp": self._utc_now(),
            "evidence": {
                "result_data_keys": list((result.get("data") or {}).keys()),
                "metadata": result.get("metadata", {}),
            },
        }

    def _prepare_memory_payload(
        self,
        request: BrowserActionRequest,
        result: Dict[str, Any],
        risk_level: BrowserRiskLevel,
        action_id: str,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Required by William/Jarvis compatibility.

        This payload intentionally avoids storing secrets or raw form values.
        """

        result_url = self._extract_result_url(result) or request.url

        return {
            "type": "browser_action_memory",
            "agent": "BrowserAutomation",
            "action_id": action_id,
            "action": request.action.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "session_id": request.session_id,
            "url": result_url,
            "title": self._extract_result_title(result),
            "success": bool(result.get("success")),
            "risk_level": risk_level.value,
            "summary": result.get("message"),
            "timestamp": self._utc_now(),
            "safe_context": {
                "selector": request.selector,
                "field_count": len(request.form_data or {}) if request.form_data else 0,
                "options_keys": list((request.options or {}).keys()),
            },
        }

    async def _emit_agent_event(self, event: Dict[str, Any]) -> None:
        """
        Emit Browser Agent event for dashboard, task history, and analytics.

        Required by William/Jarvis compatibility.
        """

        if not self.config.event_enabled:
            return

        try:
            if self.event_callback is not None:
                response = self.event_callback(event)
                if asyncio.iscoroutine(response):
                    await response

            logger.info("BrowserAutomation event: %s", event)

        except Exception as exc:
            logger.warning("Failed to emit browser automation event: %s", exc)

    async def _log_audit_event(self, event: Dict[str, Any]) -> None:
        """
        Log audit event.

        Required by William/Jarvis compatibility.

        Audit events should later be persisted to SaaS audit logs by user/workspace.
        """

        if not self.config.audit_enabled:
            return

        try:
            if self.audit_callback is not None:
                response = self.audit_callback(event)
                if asyncio.iscoroutine(response):
                    await response

            logger.info("BrowserAutomation audit: %s", event)

        except Exception as exc:
            logger.warning("Failed to log browser automation audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return standard success dict.

        Required by William/Jarvis compatibility.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[str] = None,
        error_code: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error dict.

        Required by William/Jarvis compatibility.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error or message,
            "metadata": {
                **(metadata or {}),
                "error_code": error_code,
            },
        }

    # -----------------------------------------------------------------------
    # Browser Runtime Helpers
    # -----------------------------------------------------------------------

    async def _ensure_browser(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Start or reuse a browser context.

        If a different user/workspace attempts to reuse the same instance, the
        current browser context is closed first to prevent data/session leakage.
        """

        if not PLAYWRIGHT_AVAILABLE:
            return self._error_result(
                message="Playwright is not installed. Install it before using BrowserAutomation.",
                error_code="PLAYWRIGHT_NOT_AVAILABLE",
                metadata={
                    "install": "pip install playwright && playwright install chromium",
                },
            )

        user_changed = (
            self._active_user_id is not None
            and str(self._active_user_id) != str(user_id)
        )
        workspace_changed = (
            self._active_workspace_id is not None
            and str(self._active_workspace_id) != str(workspace_id)
        )

        if user_changed or workspace_changed:
            await self._hard_reset_browser()

        try:
            if self._playwright is None:
                self._playwright = await async_playwright().start()

            if self._browser is None:
                browser_launcher = getattr(self._playwright, self.config.browser_type, None)
                if browser_launcher is None:
                    return self._error_result(
                        message=f"Unsupported browser_type: {self.config.browser_type}",
                        error_code="UNSUPPORTED_BROWSER_TYPE",
                    )

                self._browser = await browser_launcher.launch(
                    headless=self.config.headless,
                    slow_mo=self.config.slow_mo_ms,
                )

            if self._context is None:
                context_options: Dict[str, Any] = {
                    "viewport": {
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height,
                    }
                }

                if self.config.user_agent:
                    context_options["user_agent"] = self.config.user_agent

                self._context = await self._browser.new_context(**context_options)
                self._context.set_default_timeout(self.config.timeout_ms)
                self._context.set_default_navigation_timeout(self.config.navigation_timeout_ms)

            if self._page is None:
                self._page = await self._context.new_page()

            self._active_user_id = user_id
            self._active_workspace_id = workspace_id
            self._active_session_id = session_id or self._active_session_id or str(uuid.uuid4())

            return self._safe_result(
                message="Browser runtime is ready.",
                data={
                    "ready": True,
                    "user_id": str(user_id),
                    "workspace_id": str(workspace_id),
                    "session_id": self._active_session_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to initialize browser runtime.",
                error=str(exc),
                error_code="BROWSER_INIT_FAILED",
            )

    async def _hard_reset_browser(self) -> None:
        """Close current browser resources without producing public output."""

        try:
            if self._context is not None:
                await self._context.close()
        except Exception:
            pass

        try:
            if self._browser is not None:
                await self._browser.close()
        except Exception:
            pass

        try:
            if self._playwright is not None:
                await self._playwright.stop()
        except Exception:
            pass

        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
        self._active_user_id = None
        self._active_workspace_id = None
        self._active_session_id = None

    # -----------------------------------------------------------------------
    # Risk, Security, Validation
    # -----------------------------------------------------------------------

    async def _maybe_request_security_approval(
        self,
        request: BrowserActionRequest,
        risk_level: BrowserRiskLevel,
    ) -> Dict[str, Any]:
        """Run Security Agent approval only when required."""

        if self._requires_security_check(request, risk_level):
            return await self._request_security_approval(request, risk_level)

        return self._safe_result(
            message="Security check not required.",
            data={
                "approved": True,
                "risk_level": risk_level.value,
            },
        )

    def _assess_risk(self, request: BrowserActionRequest) -> BrowserRiskLevel:
        """
        Assess browser action risk for Security Agent and audit logging.
        """

        if request.action == BrowserAction.FILL_FORM:
            if request.options.get("submit"):
                return BrowserRiskLevel.CRITICAL
            if self._contains_sensitive_form_data(request.form_data or {}):
                return BrowserRiskLevel.HIGH
            return BrowserRiskLevel.HIGH if self.config.require_approval_for_forms else BrowserRiskLevel.MEDIUM

        if request.action == BrowserAction.CLICK:
            selector = request.selector or ""
            if self._is_sensitive_text(selector):
                return BrowserRiskLevel.HIGH
            if self.config.require_approval_for_clicks:
                return BrowserRiskLevel.MEDIUM
            return BrowserRiskLevel.LOW

        if request.action == BrowserAction.OPEN_URL:
            url = request.url or ""
            if self._url_looks_sensitive(url):
                return BrowserRiskLevel.MEDIUM
            return BrowserRiskLevel.LOW

        if request.action == BrowserAction.SCREENSHOT:
            if self.config.require_approval_for_screenshots:
                return BrowserRiskLevel.MEDIUM
            return BrowserRiskLevel.LOW

        if request.action in {BrowserAction.SCROLL, BrowserAction.GET_PAGE_INFO, BrowserAction.CLOSE}:
            return BrowserRiskLevel.LOW

        return BrowserRiskLevel.MEDIUM

    def _validate_url(self, url: str) -> Dict[str, Any]:
        """Validate URL safety and domain policy."""

        if not url or not isinstance(url, str):
            return self._error_result(
                message="A valid URL is required.",
                error_code="INVALID_URL",
            )

        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return self._error_result(
                message="URL must include scheme and hostname.",
                error_code="INVALID_URL_FORMAT",
                metadata={"url": url},
            )

        if parsed.scheme.lower() in self.BLOCKED_SCHEMES:
            return self._error_result(
                message=f"Blocked URL scheme: {parsed.scheme}",
                error_code="BLOCKED_URL_SCHEME",
                metadata={"scheme": parsed.scheme},
            )

        if parsed.scheme.lower() not in {"http", "https"}:
            return self._error_result(
                message="Only http and https URLs are allowed.",
                error_code="UNSUPPORTED_URL_SCHEME",
                metadata={"scheme": parsed.scheme},
            )

        domain = parsed.netloc.lower()

        for blocked in self.config.blocked_domains:
            if blocked and blocked.lower() in domain:
                return self._error_result(
                    message="URL domain is blocked by BrowserAutomation config.",
                    error_code="BLOCKED_DOMAIN",
                    metadata={"domain": domain},
                )

        if self.config.allowed_domains:
            allowed = any(allowed_domain.lower() in domain for allowed_domain in self.config.allowed_domains)
            if not allowed:
                return self._error_result(
                    message="URL domain is not in allowed_domains.",
                    error_code="DOMAIN_NOT_ALLOWED",
                    metadata={
                        "domain": domain,
                        "allowed_domains": self.config.allowed_domains,
                    },
                )

        if not self.config.allow_external_urls and not self.config.allowed_domains:
            return self._error_result(
                message="External URLs are disabled and no allowed_domains are configured.",
                error_code="EXTERNAL_URLS_DISABLED",
            )

        return self._safe_result(
            message="URL validated.",
            data={
                "url": url,
                "domain": domain,
                "scheme": parsed.scheme,
            },
        )

    def _url_looks_sensitive(self, url: str) -> bool:
        """Check if URL path suggests sensitive action/page."""

        lower_url = url.lower()
        return any(pattern in lower_url for pattern in self.SENSITIVE_URL_PATTERNS)

    def _contains_sensitive_form_data(self, form_data: Dict[str, Any]) -> bool:
        """Detect sensitive form selectors/keys."""

        for selector, value in form_data.items():
            if self._is_sensitive_text(str(selector)):
                return True
            if self._is_sensitive_text(str(value)) and len(str(value)) < 120:
                return True
        return False

    def _is_sensitive_text(self, text: str) -> bool:
        """Detect sensitive words in selectors, labels, URLs, or values."""

        safe_text = text.lower()
        return any(pattern in safe_text for pattern in self.SENSITIVE_SELECTOR_PATTERNS)

    # -----------------------------------------------------------------------
    # Request Normalization
    # -----------------------------------------------------------------------

    def _normalize_request(self, request: Union[BrowserActionRequest, Dict[str, Any]]) -> BrowserActionRequest:
        """Normalize incoming dict/request for router compatibility."""

        if isinstance(request, BrowserActionRequest):
            return request

        if not isinstance(request, dict):
            raise TypeError("request must be BrowserActionRequest or dict")

        raw_action = request.get("action")
        if isinstance(raw_action, BrowserAction):
            action = raw_action
        else:
            action = BrowserAction(str(raw_action))

        return BrowserActionRequest(
            action=action,
            user_id=request.get("user_id"),
            workspace_id=request.get("workspace_id"),
            url=request.get("url"),
            selector=request.get("selector"),
            text=request.get("text"),
            form_data=request.get("form_data"),
            options=request.get("options") or {},
            task_id=request.get("task_id"),
            session_id=request.get("session_id"),
            approval_token=request.get("approval_token"),
            metadata=request.get("metadata") or {},
        )

    # -----------------------------------------------------------------------
    # After Action Processing
    # -----------------------------------------------------------------------

    async def _after_action(
        self,
        request: BrowserActionRequest,
        result: Dict[str, Any],
        risk_level: BrowserRiskLevel,
        action_id: str,
    ) -> None:
        """
        Post-action compatibility processing.

        Handles:
            - local history record
            - audit log
            - dashboard/event stream
            - memory payload
            - verification payload
        """

        record = BrowserActionRecord(
            action_id=action_id,
            action=request.action.value,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            task_id=request.task_id,
            session_id=request.session_id,
            success=bool(result.get("success")),
            message=str(result.get("message", "")),
            created_at=self._utc_now(),
            risk_level=risk_level.value,
            metadata={
                "url": self._extract_result_url(result) or request.url,
                "selector": request.selector,
                "error_code": (result.get("metadata") or {}).get("error_code"),
            },
        )
        self._action_history.append(record)

        if len(self._action_history) > 1000:
            self._action_history = self._action_history[-1000:]

        audit_event = {
            "type": "browser_automation_audit",
            "action_id": action_id,
            "agent": "BrowserAutomation",
            "action": request.action.value,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "session_id": request.session_id,
            "timestamp": self._utc_now(),
            "metadata": {
                "url": self._extract_result_url(result) or request.url,
                "selector": request.selector,
                "error_code": (result.get("metadata") or {}).get("error_code"),
            },
        }

        await self._log_audit_event(audit_event)
        await self._emit_agent_event(audit_event)

        if self.config.memory_enabled and self.memory_callback is not None:
            try:
                memory_payload = self._prepare_memory_payload(request, result, risk_level, action_id)
                response = self.memory_callback(memory_payload)
                if asyncio.iscoroutine(response):
                    await response
            except Exception as exc:
                logger.warning("Failed to send browser memory payload: %s", exc)

        if self.config.verification_enabled and self.verification_callback is not None:
            try:
                verification_payload = self._prepare_verification_payload(request, result, risk_level, action_id)
                response = self.verification_callback(verification_payload)
                if asyncio.iscoroutine(response):
                    await response
            except Exception as exc:
                logger.warning("Failed to send browser verification payload: %s", exc)

    async def _record_failed_action(
        self,
        action_id: str,
        request: BrowserActionRequest,
        message: str,
        risk_level: BrowserRiskLevel,
    ) -> None:
        """Record pre-execution failed action for audit visibility."""

        result = self._error_result(
            message=message,
            error_code="PRE_EXECUTION_BLOCKED",
            metadata={
                "action_id": action_id,
                "risk_level": risk_level.value,
            },
        )
        await self._after_action(request, result, risk_level, action_id)

    # -----------------------------------------------------------------------
    # Utility Helpers
    # -----------------------------------------------------------------------

    def _base_metadata(
        self,
        request: BrowserActionRequest,
        started_at: str,
        risk_level: BrowserRiskLevel,
    ) -> Dict[str, Any]:
        """Common metadata returned with public results."""

        ended_at = self._utc_now()
        duration_ms = self._duration_ms(started_at, ended_at)

        return {
            "agent": "BrowserAutomation",
            "action": request.action.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "session_id": request.session_id,
            "risk_level": risk_level.value,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": duration_ms,
        }

    def _ensure_storage_dirs(self) -> None:
        """Create screenshot storage directory if configured."""

        try:
            Path(self.config.screenshot_dir).mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Could not create screenshot directory: %s", exc)

    def _build_screenshot_path(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        task_id: Optional[str],
        action_id: str,
        file_name: Optional[str] = None,
    ) -> str:
        """
        Build SaaS-isolated screenshot path:
            screenshot_dir/user_{id}/workspace_{id}/...
        """

        safe_user = self._safe_path_part(str(user_id))
        safe_workspace = self._safe_path_part(str(workspace_id))
        safe_task = self._safe_path_part(str(task_id or "manual"))

        if file_name:
            clean_file_name = self._safe_path_part(str(file_name))
            if not clean_file_name.endswith(f".{self.config.screenshot_format}"):
                clean_file_name = f"{clean_file_name}.{self.config.screenshot_format}"
        else:
            clean_file_name = f"{int(time.time())}_{action_id}.{self.config.screenshot_format}"

        return str(
            Path(self.config.screenshot_dir)
            / f"user_{safe_user}"
            / f"workspace_{safe_workspace}"
            / safe_task
            / clean_file_name
        )

    def _safe_path_part(self, value: str) -> str:
        """Sanitize path component."""

        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value.strip())
        return safe[:120] or "unknown"

    def _safe_value_preview(self, value: str) -> str:
        """
        Return a safe preview of a form value without leaking secrets.

        Sensitive-looking values are redacted.
        """

        if self._is_sensitive_text(value):
            return "[REDACTED]"

        if len(value) <= 3:
            return "***"

        return f"{value[:2]}***{value[-2:]}" if len(value) > 8 else f"{value[:1]}***"

    async def _safe_page_title(self) -> Optional[str]:
        """Safely fetch current page title."""

        try:
            if self._page is None:
                return None
            return await self._page.title()
        except Exception:
            return None

    async def _safe_current_url(self) -> Optional[str]:
        """Safely fetch current page URL."""

        try:
            if self._page is None:
                return None
            return self._page.url
        except Exception:
            return None

    def _extract_result_url(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract URL from result dict if present."""

        data = result.get("data") or {}
        if isinstance(data, dict):
            if data.get("url"):
                return str(data["url"])
            page = data.get("page")
            if isinstance(page, dict) and page.get("url"):
                return str(page["url"])
        return None

    def _extract_result_title(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract page title from result dict if present."""

        data = result.get("data") or {}
        if isinstance(data, dict):
            if data.get("title"):
                return str(data["title"])
            page = data.get("page")
            if isinstance(page, dict) and page.get("title"):
                return str(page["title"])
        return None

    def _new_action_id(self) -> str:
        """Create a unique browser action id."""

        return f"browser_action_{uuid.uuid4().hex}"

    def _utc_now(self) -> str:
        """Return UTC ISO timestamp."""

        return datetime.now(timezone.utc).isoformat()

    def _duration_ms(self, started_at: str, ended_at: str) -> Optional[int]:
        """Calculate duration in milliseconds from ISO timestamps."""

        try:
            start_dt = datetime.fromisoformat(started_at)
            end_dt = datetime.fromisoformat(ended_at)
            return int((end_dt - start_dt).total_seconds() * 1000)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Sync wrappers for non-async dashboard/API compatibility
    # -----------------------------------------------------------------------

    def run_action_sync(self, request: Union[BrowserActionRequest, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Synchronous wrapper for run_action().

        Useful for scripts, tests, or simple API handlers that are not async.
        """

        return self._run_async_safely(self.run_action(request))

    def open_url_sync(
        self,
        url: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for open_url()."""

        return self._run_async_safely(
            self.open_url(url=url, user_id=user_id, workspace_id=workspace_id, **kwargs)
        )

    def close_sync(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for close()."""

        return self._run_async_safely(
            self.close(user_id=user_id, workspace_id=workspace_id, **kwargs)
        )

    def _run_async_safely(self, coro: Awaitable[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run async coroutine from sync context.

        If called inside an existing event loop, returns a clear error instead
        of causing RuntimeError.
        """

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                return self._error_result(
                    message="Cannot use sync wrapper inside a running event loop. Use async method instead.",
                    error_code="EVENT_LOOP_ALREADY_RUNNING",
                )
        except RuntimeError:
            pass

        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Module Exports
# ---------------------------------------------------------------------------

__all__ = [
    "BrowserAutomation",
    "BrowserAutomationConfig",
    "BrowserActionRequest",
    "BrowserActionRecord",
    "BrowserAction",
    "BrowserRiskLevel",
    "BrowserExecutionMode",
]


# ---------------------------------------------------------------------------
# Minimal Self-Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    async def _demo() -> None:
        automation = BrowserAutomation(
            config=BrowserAutomationConfig(
                headless=True,
                dry_run=True,
                require_approval_for_clicks=True,
                require_approval_for_forms=True,
            )
        )

        result = await automation.run_action({
            "action": "open_url",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "url": "https://example.com",
            "options": {"dry_run": True},
            "metadata": {"source": "__main__ demo"},
        })

        print(result)

    asyncio.run(_demo())