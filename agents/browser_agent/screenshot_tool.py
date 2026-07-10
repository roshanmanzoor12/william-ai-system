"""
agents/browser_agent/screenshot_tool.py

BrowserScreenshotTool for the William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Capture page, viewport, and section screenshots for audits, proofs,
    reports, dashboard evidence, SEO checks, competitor audits, form testing,
    workflow verification, and browser automation proof records.

Architecture Compatibility:
    - Master Agent routing compatible
    - BaseAgent compatible
    - Agent Registry / Agent Loader safe
    - SaaS user_id / workspace_id isolation
    - Security Agent approval hooks
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard/API structured output compatible
    - Audit/event logging compatible
    - Import-safe even when future William modules are missing

Safety:
    This file does not perform destructive browser actions.
    It can capture screenshots only when permissions/context allow.
    It avoids hardcoded secrets and keeps outputs isolated per user/workspace.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import logging
import mimetypes
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This keeps the file import-safe before the real William BaseAgent exists.
        The real BaseAgent can replace this automatically when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "browser")
            self.logger = logging.getLogger(self.agent_name)


try:
    from core.config import settings  # type: ignore
except Exception:
    class _FallbackSettings:
        SCREENSHOT_STORAGE_DIR = "storage/screenshots"
        SCREENSHOT_DEFAULT_TIMEOUT_MS = 30000
        SCREENSHOT_MAX_WIDTH = 3840
        SCREENSHOT_MAX_HEIGHT = 2160
        SCREENSHOT_ALLOW_FILE_URLS = False
        SCREENSHOT_ALLOW_LOCALHOST = True
        SCREENSHOT_IMAGE_FORMAT = "png"

    settings = _FallbackSettings()  # type: ignore


try:
    from core.security import SecurityDecision  # type: ignore
except Exception:
    @dataclass
    class SecurityDecision:  # type: ignore
        approved: bool = True
        reason: str = "fallback-approved"
        metadata: Dict[str, Any] = field(default_factory=dict)


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

logger = logging.getLogger("BrowserScreenshotTool")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ScreenshotTarget:
    """
    Represents a screenshot target.

    url:
        Web page URL to open and capture.

    selector:
        Optional CSS selector for section/element screenshots.

    html:
        Optional raw HTML content. Useful for dashboard previews, reports,
        local rendering, and test captures without hitting external websites.

    name:
        Human-readable label used in metadata and generated filenames.
    """

    url: Optional[str] = None
    selector: Optional[str] = None
    html: Optional[str] = None
    name: Optional[str] = None
    wait_for_selector: Optional[str] = None
    wait_until: str = "networkidle"


@dataclass
class ScreenshotOptions:
    """
    Screenshot behavior options.
    """

    full_page: bool = True
    viewport_width: int = 1440
    viewport_height: int = 1200
    device_scale_factor: float = 1.0
    timeout_ms: int = int(getattr(settings, "SCREENSHOT_DEFAULT_TIMEOUT_MS", 30000))
    image_format: str = str(getattr(settings, "SCREENSHOT_IMAGE_FORMAT", "png")).lower()
    quality: Optional[int] = None
    omit_background: bool = False
    animations_disabled: bool = True
    hide_cookie_banners: bool = True
    hide_fixed_overlays: bool = False
    wait_after_load_ms: int = 500
    return_base64: bool = False
    save_file: bool = True
    safe_filename_prefix: str = "screenshot"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScreenshotContext:
    """
    SaaS execution context.

    user_id and workspace_id are required for user-specific execution.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    agent_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    subscription_plan: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScreenshotArtifact:
    """
    Screenshot output artifact.

    This object is converted to dict/JSON result for dashboard/API usage.
    """

    artifact_id: str
    file_path: Optional[str]
    file_name: Optional[str]
    mime_type: str
    image_format: str
    sha256: Optional[str]
    size_bytes: Optional[int]
    base64_data: Optional[str]
    width: Optional[int]
    height: Optional[int]
    target: Dict[str, Any]
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slugify(value: str, max_length: int = 80) -> str:
    value = value.strip().lower()
    value = re.sub(r"https?://", "", value)
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value[:max_length] or "capture"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_awaitable(value: Any) -> bool:
    return inspect.isawaitable(value) or isinstance(value, Awaitable)


async def _maybe_await(value: Any) -> Any:
    if _is_awaitable(value):
        return await value
    return value


def _safe_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
        return max(minimum, min(maximum, number))
    except Exception:
        return default


def _safe_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
        return max(minimum, min(maximum, number))
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class BrowserScreenshotTool(BaseAgent):
    """
    Production-level screenshot capture helper for the Browser Agent.

    Main responsibilities:
        - Capture full-page screenshots
        - Capture viewport screenshots
        - Capture CSS selector / section screenshots
        - Save artifacts under isolated user/workspace folders
        - Return structured dict results
        - Prepare verification and memory payloads
        - Emit audit/event payloads for dashboard visibility

    Security model:
        Screenshot capture can reveal sensitive user or third-party content.
        Therefore, sensitive targets and user/workspace execution should pass
        through `_request_security_approval()` before capture.

    Browser engine:
        Uses Playwright when installed.
        If Playwright is unavailable, the class remains import-safe and returns
        a structured dependency error instead of crashing.
    """

    AGENT_NAME = "browser_screenshot_tool"
    AGENT_TYPE = "browser"
    REQUIRED_PERMISSION = "browser.screenshot.capture"

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        headless: bool = True,
        browser_channel: Optional[str] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            agent_type=self.AGENT_TYPE,
            **kwargs,
        )

        self.logger = logger_instance or logging.getLogger(self.AGENT_NAME)
        self.storage_dir = Path(
            storage_dir or getattr(settings, "SCREENSHOT_STORAGE_DIR", "storage/screenshots")
        )

        self.security_callback = security_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self.headless = bool(headless)
        self.browser_channel = browser_channel

        self.max_width = int(getattr(settings, "SCREENSHOT_MAX_WIDTH", 3840))
        self.max_height = int(getattr(settings, "SCREENSHOT_MAX_HEIGHT", 2160))
        self.allow_file_urls = bool(getattr(settings, "SCREENSHOT_ALLOW_FILE_URLS", False))
        self.allow_localhost = bool(getattr(settings, "SCREENSHOT_ALLOW_LOCALHOST", True))

    # -----------------------------------------------------------------------
    # Public sync wrappers
    # -----------------------------------------------------------------------

    def capture_page_screenshot(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        target: Union[ScreenshotTarget, Dict[str, Any], str],
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper for full page screenshot capture.
        """

        return self._run_async_safely(
            self.capture_page_screenshot_async(context=context, target=target, options=options)
        )

    def capture_viewport_screenshot(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        target: Union[ScreenshotTarget, Dict[str, Any], str],
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper for viewport screenshot capture.
        """

        normalized_options = self._normalize_options(options)
        normalized_options.full_page = False

        return self._run_async_safely(
            self.capture_page_screenshot_async(
                context=context,
                target=target,
                options=normalized_options,
            )
        )

    def capture_section_screenshot(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        target: Union[ScreenshotTarget, Dict[str, Any], str],
        selector: Optional[str] = None,
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper for CSS selector / section screenshot capture.
        """

        normalized_target = self._normalize_target(target)
        if selector:
            normalized_target.selector = selector

        return self._run_async_safely(
            self.capture_section_screenshot_async(
                context=context,
                target=normalized_target,
                options=options,
            )
        )

    # -----------------------------------------------------------------------
    # Public async methods
    # -----------------------------------------------------------------------

    async def capture_page_screenshot_async(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        target: Union[ScreenshotTarget, Dict[str, Any], str],
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Capture a full-page or viewport screenshot.

        This method is designed for Master Agent / Browser Agent routing.
        It returns a structured result with success, message, data, error,
        and metadata.
        """

        started_at = time.time()
        normalized_context = self._normalize_context(context)
        normalized_target = self._normalize_target(target)
        normalized_options = self._normalize_options(options)

        task_payload = {
            "operation": "capture_page_screenshot",
            "context": asdict(normalized_context),
            "target": self._target_to_safe_dict(normalized_target),
            "options": self._options_to_safe_dict(normalized_options),
        }

        validation = self._validate_task_context(normalized_context, normalized_target)
        if not validation["success"]:
            return validation

        permission_result = await self._request_security_approval(task_payload)
        if not permission_result.get("success", False):
            return permission_result

        if not PLAYWRIGHT_AVAILABLE:
            return self._error_result(
                message="Playwright is not installed. Screenshot capture requires the 'playwright' package.",
                error_code="PLAYWRIGHT_NOT_AVAILABLE",
                context=normalized_context,
                metadata={
                    "install": "pip install playwright && playwright install chromium",
                    "operation": "capture_page_screenshot",
                },
            )

        await self._emit_agent_event(
            "browser_screenshot.started",
            normalized_context,
            {
                "operation": "capture_page_screenshot",
                "target": self._target_to_safe_dict(normalized_target),
            },
        )

        try:
            screenshot_bytes, page_info = await self._capture_with_playwright(
                context=normalized_context,
                target=normalized_target,
                options=normalized_options,
                mode="page",
            )

            artifact = self._build_artifact(
                context=normalized_context,
                target=normalized_target,
                options=normalized_options,
                screenshot_bytes=screenshot_bytes,
                page_info=page_info,
            )

            data = {
                "artifact": asdict(artifact),
                "verification_payload": self._prepare_verification_payload(
                    context=normalized_context,
                    target=normalized_target,
                    artifact=artifact,
                    operation="capture_page_screenshot",
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=normalized_context,
                    target=normalized_target,
                    artifact=artifact,
                    operation="capture_page_screenshot",
                ),
            }

            await self._dispatch_post_capture_payloads(data)

            duration_ms = int((time.time() - started_at) * 1000)

            result = self._safe_result(
                message="Page screenshot captured successfully.",
                data=data,
                context=normalized_context,
                metadata={
                    "operation": "capture_page_screenshot",
                    "duration_ms": duration_ms,
                    "playwright_available": PLAYWRIGHT_AVAILABLE,
                },
            )

            await self._log_audit_event(
                normalized_context,
                "browser_screenshot.completed",
                {
                    "artifact_id": artifact.artifact_id,
                    "file_path": artifact.file_path,
                    "target": self._target_to_safe_dict(normalized_target),
                    "duration_ms": duration_ms,
                },
            )

            await self._emit_agent_event(
                "browser_screenshot.completed",
                normalized_context,
                {
                    "artifact_id": artifact.artifact_id,
                    "file_path": artifact.file_path,
                    "duration_ms": duration_ms,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Page screenshot capture failed")

            await self._emit_agent_event(
                "browser_screenshot.failed",
                normalized_context,
                {
                    "operation": "capture_page_screenshot",
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="Page screenshot capture failed.",
                error_code="SCREENSHOT_CAPTURE_FAILED",
                context=normalized_context,
                exception=exc,
                metadata={
                    "operation": "capture_page_screenshot",
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

    async def capture_section_screenshot_async(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        target: Union[ScreenshotTarget, Dict[str, Any], str],
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Capture a screenshot of a specific page section using CSS selector.
        """

        started_at = time.time()
        normalized_context = self._normalize_context(context)
        normalized_target = self._normalize_target(target)
        normalized_options = self._normalize_options(options)

        if not normalized_target.selector:
            return self._error_result(
                message="Section screenshot requires a CSS selector.",
                error_code="MISSING_SELECTOR",
                context=normalized_context,
                metadata={"operation": "capture_section_screenshot"},
            )

        task_payload = {
            "operation": "capture_section_screenshot",
            "context": asdict(normalized_context),
            "target": self._target_to_safe_dict(normalized_target),
            "options": self._options_to_safe_dict(normalized_options),
        }

        validation = self._validate_task_context(normalized_context, normalized_target)
        if not validation["success"]:
            return validation

        permission_result = await self._request_security_approval(task_payload)
        if not permission_result.get("success", False):
            return permission_result

        if not PLAYWRIGHT_AVAILABLE:
            return self._error_result(
                message="Playwright is not installed. Section screenshot capture requires the 'playwright' package.",
                error_code="PLAYWRIGHT_NOT_AVAILABLE",
                context=normalized_context,
                metadata={
                    "install": "pip install playwright && playwright install chromium",
                    "operation": "capture_section_screenshot",
                },
            )

        await self._emit_agent_event(
            "browser_section_screenshot.started",
            normalized_context,
            {
                "operation": "capture_section_screenshot",
                "target": self._target_to_safe_dict(normalized_target),
            },
        )

        try:
            screenshot_bytes, page_info = await self._capture_with_playwright(
                context=normalized_context,
                target=normalized_target,
                options=normalized_options,
                mode="section",
            )

            artifact = self._build_artifact(
                context=normalized_context,
                target=normalized_target,
                options=normalized_options,
                screenshot_bytes=screenshot_bytes,
                page_info=page_info,
            )

            data = {
                "artifact": asdict(artifact),
                "verification_payload": self._prepare_verification_payload(
                    context=normalized_context,
                    target=normalized_target,
                    artifact=artifact,
                    operation="capture_section_screenshot",
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=normalized_context,
                    target=normalized_target,
                    artifact=artifact,
                    operation="capture_section_screenshot",
                ),
            }

            await self._dispatch_post_capture_payloads(data)

            duration_ms = int((time.time() - started_at) * 1000)

            result = self._safe_result(
                message="Section screenshot captured successfully.",
                data=data,
                context=normalized_context,
                metadata={
                    "operation": "capture_section_screenshot",
                    "duration_ms": duration_ms,
                    "selector": normalized_target.selector,
                    "playwright_available": PLAYWRIGHT_AVAILABLE,
                },
            )

            await self._log_audit_event(
                normalized_context,
                "browser_section_screenshot.completed",
                {
                    "artifact_id": artifact.artifact_id,
                    "file_path": artifact.file_path,
                    "selector": normalized_target.selector,
                    "target": self._target_to_safe_dict(normalized_target),
                    "duration_ms": duration_ms,
                },
            )

            await self._emit_agent_event(
                "browser_section_screenshot.completed",
                normalized_context,
                {
                    "artifact_id": artifact.artifact_id,
                    "file_path": artifact.file_path,
                    "selector": normalized_target.selector,
                    "duration_ms": duration_ms,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Section screenshot capture failed")

            await self._emit_agent_event(
                "browser_section_screenshot.failed",
                normalized_context,
                {
                    "operation": "capture_section_screenshot",
                    "selector": normalized_target.selector,
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="Section screenshot capture failed.",
                error_code="SECTION_SCREENSHOT_CAPTURE_FAILED",
                context=normalized_context,
                exception=exc,
                metadata={
                    "operation": "capture_section_screenshot",
                    "selector": normalized_target.selector,
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

    async def capture_from_existing_page_async(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        page: Any,
        target: Optional[Union[ScreenshotTarget, Dict[str, Any]]] = None,
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Capture screenshot from an already-open Playwright page.

        This is useful when BrowserAgent, Automation, TabManager, or
        WorkflowLearner already controls a page/session.
        """

        started_at = time.time()
        normalized_context = self._normalize_context(context)
        normalized_target = self._normalize_target(target or ScreenshotTarget(name="existing-page"))
        normalized_options = self._normalize_options(options)

        validation = self._validate_task_context(normalized_context, normalized_target)
        if not validation["success"]:
            return validation

        if page is None:
            return self._error_result(
                message="A valid browser page instance is required.",
                error_code="MISSING_PAGE_INSTANCE",
                context=normalized_context,
                metadata={"operation": "capture_from_existing_page"},
            )

        try:
            await self._prepare_page_for_screenshot(page, normalized_options)

            if normalized_target.selector:
                element = await page.query_selector(normalized_target.selector)
                if element is None:
                    return self._error_result(
                        message=f"Selector not found: {normalized_target.selector}",
                        error_code="SELECTOR_NOT_FOUND",
                        context=normalized_context,
                        metadata={
                            "operation": "capture_from_existing_page",
                            "selector": normalized_target.selector,
                        },
                    )
                screenshot_bytes = await element.screenshot(
                    type=normalized_options.image_format,
                    omit_background=normalized_options.omit_background,
                    quality=normalized_options.quality if normalized_options.image_format == "jpeg" else None,
                    timeout=normalized_options.timeout_ms,
                )
            else:
                screenshot_bytes = await page.screenshot(
                    full_page=normalized_options.full_page,
                    type=normalized_options.image_format,
                    omit_background=normalized_options.omit_background,
                    quality=normalized_options.quality if normalized_options.image_format == "jpeg" else None,
                    timeout=normalized_options.timeout_ms,
                )

            page_info = await self._extract_page_info(page)

            artifact = self._build_artifact(
                context=normalized_context,
                target=normalized_target,
                options=normalized_options,
                screenshot_bytes=screenshot_bytes,
                page_info=page_info,
            )

            data = {
                "artifact": asdict(artifact),
                "verification_payload": self._prepare_verification_payload(
                    context=normalized_context,
                    target=normalized_target,
                    artifact=artifact,
                    operation="capture_from_existing_page",
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=normalized_context,
                    target=normalized_target,
                    artifact=artifact,
                    operation="capture_from_existing_page",
                ),
            }

            await self._dispatch_post_capture_payloads(data)

            return self._safe_result(
                message="Screenshot captured from existing page successfully.",
                data=data,
                context=normalized_context,
                metadata={
                    "operation": "capture_from_existing_page",
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

        except Exception as exc:
            self.logger.exception("Existing page screenshot capture failed")
            return self._error_result(
                message="Existing page screenshot capture failed.",
                error_code="EXISTING_PAGE_SCREENSHOT_FAILED",
                context=normalized_context,
                exception=exc,
                metadata={
                    "operation": "capture_from_existing_page",
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

    # -----------------------------------------------------------------------
    # Playwright capture internals
    # -----------------------------------------------------------------------

    async def _capture_with_playwright(
        self,
        context: ScreenshotContext,
        target: ScreenshotTarget,
        options: ScreenshotOptions,
        mode: str,
    ) -> Tuple[bytes, Dict[str, Any]]:
        if async_playwright is None:
            raise RuntimeError("Playwright async API is unavailable.")

        async with async_playwright() as p:
            launch_kwargs: Dict[str, Any] = {
                "headless": self.headless,
            }

            if self.browser_channel:
                launch_kwargs["channel"] = self.browser_channel

            browser = await p.chromium.launch(**launch_kwargs)

            try:
                browser_context = await browser.new_context(
                    viewport={
                        "width": options.viewport_width,
                        "height": options.viewport_height,
                    },
                    device_scale_factor=options.device_scale_factor,
                    user_agent=context.user_agent,
                    ignore_https_errors=True,
                )

                page = await browser_context.new_page()
                page.set_default_timeout(options.timeout_ms)

                await self._load_target(page, target, options)
                await self._prepare_page_for_screenshot(page, options)

                if mode == "section":
                    if not target.selector:
                        raise ValueError("Section mode requires selector.")

                    element = await page.query_selector(target.selector)
                    if element is None:
                        raise ValueError(f"Selector not found: {target.selector}")

                    screenshot_bytes = await element.screenshot(
                        type=options.image_format,
                        omit_background=options.omit_background,
                        quality=options.quality if options.image_format == "jpeg" else None,
                        timeout=options.timeout_ms,
                    )
                else:
                    screenshot_bytes = await page.screenshot(
                        full_page=options.full_page,
                        type=options.image_format,
                        omit_background=options.omit_background,
                        quality=options.quality if options.image_format == "jpeg" else None,
                        timeout=options.timeout_ms,
                    )

                page_info = await self._extract_page_info(page)
                return screenshot_bytes, page_info

            finally:
                await browser.close()

    async def _load_target(
        self,
        page: Any,
        target: ScreenshotTarget,
        options: ScreenshotOptions,
    ) -> None:
        if target.html:
            await page.set_content(target.html, wait_until="domcontentloaded", timeout=options.timeout_ms)
        elif target.url:
            await page.goto(target.url, wait_until=target.wait_until, timeout=options.timeout_ms)
        else:
            raise ValueError("Screenshot target requires either url or html.")

        if target.wait_for_selector:
            await page.wait_for_selector(target.wait_for_selector, timeout=options.timeout_ms)

        if options.wait_after_load_ms > 0:
            await page.wait_for_timeout(options.wait_after_load_ms)

    async def _prepare_page_for_screenshot(self, page: Any, options: ScreenshotOptions) -> None:
        if options.animations_disabled:
            await page.add_style_tag(
                content="""
                *,
                *::before,
                *::after {
                    transition-duration: 0s !important;
                    animation-duration: 0s !important;
                    animation-delay: 0s !important;
                    scroll-behavior: auto !important;
                }
                """
            )

        if options.hide_cookie_banners:
            await page.add_style_tag(
                content="""
                #cookie-banner,
                .cookie-banner,
                .cookie-consent,
                .cookie-notice,
                .cookies,
                .cc-window,
                .osano-cm-window,
                [aria-label*="cookie" i],
                [id*="cookie" i],
                [class*="cookie" i],
                [id*="consent" i],
                [class*="consent" i] {
                    display: none !important;
                    visibility: hidden !important;
                    opacity: 0 !important;
                    pointer-events: none !important;
                }
                """
            )

        if options.hide_fixed_overlays:
            await page.add_style_tag(
                content="""
                [style*="position: fixed"],
                [style*="position:fixed"],
                .modal,
                .popup,
                .overlay,
                .newsletter-popup,
                .chat-widget,
                .intercom-lightweight-app,
                iframe[src*="chat"],
                iframe[src*="intercom"],
                iframe[src*="drift"] {
                    display: none !important;
                    visibility: hidden !important;
                    opacity: 0 !important;
                    pointer-events: none !important;
                }
                """
            )

    async def _extract_page_info(self, page: Any) -> Dict[str, Any]:
        info: Dict[str, Any] = {}

        try:
            info["url"] = page.url
        except Exception:
            info["url"] = None

        try:
            info["title"] = await page.title()
        except Exception:
            info["title"] = None

        try:
            viewport = page.viewport_size
            info["viewport"] = viewport
        except Exception:
            info["viewport"] = None

        try:
            dimensions = await page.evaluate(
                """
                () => ({
                    width: Math.max(
                        document.body.scrollWidth,
                        document.documentElement.scrollWidth,
                        document.body.offsetWidth,
                        document.documentElement.offsetWidth,
                        document.documentElement.clientWidth
                    ),
                    height: Math.max(
                        document.body.scrollHeight,
                        document.documentElement.scrollHeight,
                        document.body.offsetHeight,
                        document.documentElement.offsetHeight,
                        document.documentElement.clientHeight
                    )
                })
                """
            )
            info["document_dimensions"] = dimensions
        except Exception:
            info["document_dimensions"] = None

        return info

    # -----------------------------------------------------------------------
    # Normalization / validation
    # -----------------------------------------------------------------------

    def _normalize_context(self, context: Union[ScreenshotContext, Dict[str, Any]]) -> ScreenshotContext:
        if isinstance(context, ScreenshotContext):
            return context

        if not isinstance(context, dict):
            raise TypeError("context must be ScreenshotContext or dict.")

        return ScreenshotContext(
            user_id=context.get("user_id"),
            workspace_id=context.get("workspace_id"),
            request_id=str(context.get("request_id") or uuid.uuid4()),
            task_id=context.get("task_id"),
            agent_id=context.get("agent_id"),
            role=context.get("role"),
            permissions=list(context.get("permissions") or []),
            subscription_plan=context.get("subscription_plan"),
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent"),
            metadata=dict(context.get("metadata") or {}),
        )

    def _normalize_target(
        self,
        target: Union[ScreenshotTarget, Dict[str, Any], str],
    ) -> ScreenshotTarget:
        if isinstance(target, ScreenshotTarget):
            return target

        if isinstance(target, str):
            if target.strip().lower().startswith("<!doctype") or target.strip().lower().startswith("<html"):
                return ScreenshotTarget(html=target, name="html-target")
            return ScreenshotTarget(url=target, name=target)

        if isinstance(target, dict):
            return ScreenshotTarget(
                url=target.get("url"),
                selector=target.get("selector"),
                html=target.get("html"),
                name=target.get("name"),
                wait_for_selector=target.get("wait_for_selector"),
                wait_until=target.get("wait_until", "networkidle"),
            )

        raise TypeError("target must be ScreenshotTarget, dict, or URL/HTML string.")

    def _normalize_options(
        self,
        options: Optional[Union[ScreenshotOptions, Dict[str, Any]]],
    ) -> ScreenshotOptions:
        if isinstance(options, ScreenshotOptions):
            normalized = options
        elif isinstance(options, dict):
            normalized = ScreenshotOptions(
                full_page=bool(options.get("full_page", True)),
                viewport_width=_safe_int(
                    options.get("viewport_width", 1440),
                    1440,
                    320,
                    self.max_width,
                ),
                viewport_height=_safe_int(
                    options.get("viewport_height", 1200),
                    1200,
                    320,
                    self.max_height,
                ),
                device_scale_factor=_safe_float(
                    options.get("device_scale_factor", 1.0),
                    1.0,
                    0.5,
                    3.0,
                ),
                timeout_ms=_safe_int(
                    options.get("timeout_ms", getattr(settings, "SCREENSHOT_DEFAULT_TIMEOUT_MS", 30000)),
                    int(getattr(settings, "SCREENSHOT_DEFAULT_TIMEOUT_MS", 30000)),
                    1000,
                    120000,
                ),
                image_format=str(options.get("image_format", "png")).lower(),
                quality=options.get("quality"),
                omit_background=bool(options.get("omit_background", False)),
                animations_disabled=bool(options.get("animations_disabled", True)),
                hide_cookie_banners=bool(options.get("hide_cookie_banners", True)),
                hide_fixed_overlays=bool(options.get("hide_fixed_overlays", False)),
                wait_after_load_ms=_safe_int(
                    options.get("wait_after_load_ms", 500),
                    500,
                    0,
                    30000,
                ),
                return_base64=bool(options.get("return_base64", False)),
                save_file=bool(options.get("save_file", True)),
                safe_filename_prefix=str(options.get("safe_filename_prefix", "screenshot")),
                metadata=dict(options.get("metadata") or {}),
            )
        else:
            normalized = ScreenshotOptions()

        if normalized.image_format not in {"png", "jpeg"}:
            normalized.image_format = "png"

        if normalized.image_format == "png":
            normalized.quality = None
        elif normalized.quality is not None:
            normalized.quality = _safe_int(normalized.quality, 85, 1, 100)

        normalized.viewport_width = _safe_int(
            normalized.viewport_width,
            1440,
            320,
            self.max_width,
        )
        normalized.viewport_height = _safe_int(
            normalized.viewport_height,
            1200,
            320,
            self.max_height,
        )

        return normalized

    def _validate_task_context(
        self,
        context: ScreenshotContext,
        target: Optional[ScreenshotTarget] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Validates SaaS isolation requirements and target safety.
        """

        if context.user_id is None or str(context.user_id).strip() == "":
            return self._error_result(
                message="user_id is required for screenshot capture.",
                error_code="MISSING_USER_ID",
                context=context,
            )

        if context.workspace_id is None or str(context.workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for screenshot capture.",
                error_code="MISSING_WORKSPACE_ID",
                context=context,
            )

        if self.REQUIRED_PERMISSION not in context.permissions and "admin" not in context.permissions:
            return self._error_result(
                message=f"Missing required permission: {self.REQUIRED_PERMISSION}",
                error_code="MISSING_PERMISSION",
                context=context,
                metadata={"required_permission": self.REQUIRED_PERMISSION},
            )

        if target:
            if not target.url and not target.html:
                return self._error_result(
                    message="Screenshot target must include either url or html.",
                    error_code="INVALID_TARGET",
                    context=context,
                )

            if target.url:
                url_validation = self._validate_url(target.url)
                if not url_validation["success"]:
                    return self._error_result(
                        message=url_validation["message"],
                        error_code=url_validation["error_code"],
                        context=context,
                        metadata={"url": self._redact_url(target.url)},
                    )

        return self._safe_result(
            message="Task context validated.",
            data={"valid": True},
            context=context,
            metadata={"operation": "validate_task_context"},
        )

    def _validate_url(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https", "file"}:
            return {
                "success": False,
                "message": "Only http, https, and approved file URLs are supported.",
                "error_code": "UNSUPPORTED_URL_SCHEME",
            }

        if parsed.scheme == "file" and not self.allow_file_urls:
            return {
                "success": False,
                "message": "File URLs are disabled for screenshot capture.",
                "error_code": "FILE_URL_DISABLED",
            }

        hostname = (parsed.hostname or "").lower()

        localhost_names = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if hostname in localhost_names and not self.allow_localhost:
            return {
                "success": False,
                "message": "Localhost URLs are disabled for screenshot capture.",
                "error_code": "LOCALHOST_DISABLED",
            }

        return {"success": True, "message": "URL validated.", "error_code": None}

    def _requires_security_check(
        self,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Required compatibility hook.

        Screenshot capture should be treated as security-sensitive because
        it can capture private dashboard pages, customer portals, reports,
        financial dashboards, or authenticated SaaS sessions.
        """

        return True

    async def _request_security_approval(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Required compatibility hook.

        If Security Agent callback exists, use it.
        Otherwise approve safe validated operations by default.
        """

        if not self._requires_security_check(payload):
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True},
                metadata={"security": "not_required"},
            )

        if self.security_callback:
            try:
                decision = await _maybe_await(self.security_callback(payload))

                if isinstance(decision, SecurityDecision):
                    approved = bool(decision.approved)
                    reason = decision.reason
                    metadata = decision.metadata
                elif isinstance(decision, dict):
                    approved = bool(decision.get("approved", decision.get("success", False)))
                    reason = str(decision.get("reason") or decision.get("message") or "")
                    metadata = dict(decision.get("metadata") or {})
                else:
                    approved = bool(decision)
                    reason = "security callback returned boolean approval"
                    metadata = {}

                if not approved:
                    return self._error_result(
                        message=reason or "Security Agent rejected screenshot capture.",
                        error_code="SECURITY_REJECTED",
                        metadata=metadata,
                    )

                return self._safe_result(
                    message="Security Agent approved screenshot capture.",
                    data={"approved": True, "reason": reason},
                    metadata=metadata,
                )

            except Exception as exc:
                return self._error_result(
                    message="Security approval callback failed.",
                    error_code="SECURITY_CALLBACK_FAILED",
                    exception=exc,
                    metadata={"operation": "request_security_approval"},
                )

        return self._safe_result(
            message="Security approval passed by safe default policy.",
            data={"approved": True},
            metadata={
                "security": "fallback_default_policy",
                "note": "Connect Security Agent callback in production for strict approvals.",
            },
        )

    # -----------------------------------------------------------------------
    # Artifact handling
    # -----------------------------------------------------------------------

    def _build_artifact(
        self,
        context: ScreenshotContext,
        target: ScreenshotTarget,
        options: ScreenshotOptions,
        screenshot_bytes: bytes,
        page_info: Dict[str, Any],
    ) -> ScreenshotArtifact:
        artifact_id = str(uuid.uuid4())
        created_at = _utc_now_iso()
        image_format = options.image_format
        mime_type = mimetypes.types_map.get(f".{image_format}", f"image/{image_format}")

        sha256 = _sha256_bytes(screenshot_bytes)
        size_bytes = len(screenshot_bytes)

        file_path: Optional[str] = None
        file_name: Optional[str] = None

        if options.save_file:
            isolated_dir = self._get_isolated_storage_dir(context)
            isolated_dir.mkdir(parents=True, exist_ok=True)

            target_name = target.name or target.url or target.selector or "html"
            safe_target_name = _slugify(str(target_name))
            prefix = _slugify(options.safe_filename_prefix or "screenshot")
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

            file_name = f"{prefix}-{safe_target_name}-{timestamp}-{artifact_id[:8]}.{image_format}"
            destination = isolated_dir / file_name
            destination.write_bytes(screenshot_bytes)
            file_path = str(destination)

        base64_data: Optional[str] = None
        if options.return_base64:
            base64_data = base64.b64encode(screenshot_bytes).decode("utf-8")

        document_dimensions = page_info.get("document_dimensions") or {}
        width = document_dimensions.get("width")
        height = document_dimensions.get("height")

        return ScreenshotArtifact(
            artifact_id=artifact_id,
            file_path=file_path,
            file_name=file_name,
            mime_type=mime_type,
            image_format=image_format,
            sha256=sha256,
            size_bytes=size_bytes,
            base64_data=base64_data,
            width=width,
            height=height,
            target=self._target_to_safe_dict(target),
            created_at=created_at,
            metadata={
                "page_info": page_info,
                "options": self._options_to_safe_dict(options),
                "user_id": str(context.user_id),
                "workspace_id": str(context.workspace_id),
                "request_id": context.request_id,
                "task_id": context.task_id,
            },
        )

    def _get_isolated_storage_dir(self, context: ScreenshotContext) -> Path:
        safe_user = _slugify(str(context.user_id))
        safe_workspace = _slugify(str(context.workspace_id))
        return self.storage_dir / f"user_{safe_user}" / f"workspace_{safe_workspace}"

    # -----------------------------------------------------------------------
    # Verification / memory hooks
    # -----------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        context: ScreenshotContext,
        target: ScreenshotTarget,
        artifact: ScreenshotArtifact,
        operation: str,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Payload for Verification Agent to confirm screenshot artifact exists,
        belongs to the right user/workspace, and matches expected metadata.
        """

        return {
            "type": "browser_screenshot_verification",
            "operation": operation,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "artifact_id": artifact.artifact_id,
            "file_path": artifact.file_path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "target": self._target_to_safe_dict(target),
            "checks": {
                "file_saved": bool(artifact.file_path),
                "hash_available": bool(artifact.sha256),
                "workspace_isolated": True,
                "non_empty_image": bool(artifact.size_bytes and artifact.size_bytes > 0),
            },
            "created_at": artifact.created_at,
        }

    def _prepare_memory_payload(
        self,
        context: ScreenshotContext,
        target: ScreenshotTarget,
        artifact: ScreenshotArtifact,
        operation: str,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Memory Agent can store useful non-sensitive summary metadata.
        It should not store raw screenshot base64 by default.
        """

        return {
            "type": "browser_screenshot_memory",
            "operation": operation,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "summary": "Browser screenshot artifact captured for audit/proof.",
            "target": self._target_to_safe_dict(target),
            "artifact": {
                "artifact_id": artifact.artifact_id,
                "file_name": artifact.file_name,
                "file_path": artifact.file_path,
                "mime_type": artifact.mime_type,
                "image_format": artifact.image_format,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "created_at": artifact.created_at,
            },
            "safe_to_embed_in_task_history": True,
        }

    async def _dispatch_post_capture_payloads(self, data: Dict[str, Any]) -> None:
        verification_payload = data.get("verification_payload")
        memory_payload = data.get("memory_payload")

        if self.verification_callback and verification_payload:
            try:
                await _maybe_await(self.verification_callback(verification_payload))
            except Exception:
                self.logger.exception("Verification callback failed")

        if self.memory_callback and memory_payload:
            try:
                await _maybe_await(self.memory_callback(memory_payload))
            except Exception:
                self.logger.exception("Memory callback failed")

    # -----------------------------------------------------------------------
    # Events / audit
    # -----------------------------------------------------------------------

    async def _emit_agent_event(
        self,
        event_name: str,
        context: ScreenshotContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Required compatibility hook.

        Used by dashboard analytics, task history, live agent status,
        and future event streaming.
        """

        event = {
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        if self.event_callback:
            try:
                await _maybe_await(self.event_callback(event))
            except Exception:
                self.logger.exception("Agent event callback failed")

        self.logger.info("Agent event: %s", json.dumps(event, default=str))

    async def _log_audit_event(
        self,
        context: ScreenshotContext,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Required compatibility hook.

        Audit logs should remain user/workspace isolated and searchable
        from SaaS dashboard later.
        """

        audit_event = {
            "action": action,
            "agent": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "role": context.role,
            "ip_address": context.ip_address,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        if self.audit_callback:
            try:
                await _maybe_await(self.audit_callback(audit_event))
            except Exception:
                self.logger.exception("Audit callback failed")

        self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))

    # -----------------------------------------------------------------------
    # Result helpers
    # -----------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[ScreenshotContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Standard William/Jarvis success result.
        """

        result_metadata = metadata or {}

        if context:
            result_metadata.update(
                {
                    "user_id": str(context.user_id),
                    "workspace_id": str(context.workspace_id),
                    "request_id": context.request_id,
                    "task_id": context.task_id,
                }
            )

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": result_metadata,
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "ERROR",
        context: Optional[ScreenshotContext] = None,
        exception: Optional[Exception] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Standard William/Jarvis error result.
        """

        result_metadata = metadata or {}

        if context:
            result_metadata.update(
                {
                    "user_id": str(context.user_id),
                    "workspace_id": str(context.workspace_id),
                    "request_id": context.request_id,
                    "task_id": context.task_id,
                }
            )

        error_payload = {
            "code": error_code,
            "message": message,
        }

        if exception:
            error_payload["exception_type"] = exception.__class__.__name__
            error_payload["exception"] = str(exception)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_payload,
            "metadata": result_metadata,
        }

    # -----------------------------------------------------------------------
    # Safe serialization helpers
    # -----------------------------------------------------------------------

    def _target_to_safe_dict(self, target: ScreenshotTarget) -> Dict[str, Any]:
        return {
            "url": self._redact_url(target.url) if target.url else None,
            "selector": target.selector,
            "has_html": bool(target.html),
            "html_sha256": _sha256_bytes(target.html.encode("utf-8")) if target.html else None,
            "name": target.name,
            "wait_for_selector": target.wait_for_selector,
            "wait_until": target.wait_until,
        }

    def _options_to_safe_dict(self, options: ScreenshotOptions) -> Dict[str, Any]:
        return {
            "full_page": options.full_page,
            "viewport_width": options.viewport_width,
            "viewport_height": options.viewport_height,
            "device_scale_factor": options.device_scale_factor,
            "timeout_ms": options.timeout_ms,
            "image_format": options.image_format,
            "quality": options.quality,
            "omit_background": options.omit_background,
            "animations_disabled": options.animations_disabled,
            "hide_cookie_banners": options.hide_cookie_banners,
            "hide_fixed_overlays": options.hide_fixed_overlays,
            "wait_after_load_ms": options.wait_after_load_ms,
            "return_base64": options.return_base64,
            "save_file": options.save_file,
            "safe_filename_prefix": options.safe_filename_prefix,
            "metadata": options.metadata,
        }

    def _redact_url(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return None

        parsed = urlparse(url)

        if not parsed.query and not parsed.fragment:
            return url

        clean = parsed._replace(query="[redacted]", fragment="[redacted]")
        return clean.geturl()

    # -----------------------------------------------------------------------
    # Runtime helpers
    # -----------------------------------------------------------------------

    def _run_async_safely(self, coroutine: Awaitable[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Safely execute async capture from sync code.

        If called inside an already-running event loop, users should prefer
        the async methods directly. This method still gives a clear error
        instead of crashing with confusing loop messages.
        """

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                return self._error_result(
                    message=(
                        "An event loop is already running. Use the async method "
                        "capture_page_screenshot_async() or capture_section_screenshot_async()."
                    ),
                    error_code="EVENT_LOOP_ALREADY_RUNNING",
                    metadata={"operation": "run_async_safely"},
                )
        except RuntimeError:
            pass

        return asyncio.run(coroutine)

    # -----------------------------------------------------------------------
    # Dashboard/API helper methods
    # -----------------------------------------------------------------------

    def list_user_workspace_artifacts(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        List screenshot files for the given isolated user/workspace folder.

        This is dashboard/API friendly and does not expose other users' files.
        """

        normalized_context = self._normalize_context(context)
        validation = self._validate_task_context(normalized_context)
        if not validation["success"]:
            return validation

        isolated_dir = self._get_isolated_storage_dir(normalized_context)
        if not isolated_dir.exists():
            return self._safe_result(
                message="No screenshot artifacts found.",
                data={"artifacts": []},
                context=normalized_context,
                metadata={"operation": "list_user_workspace_artifacts"},
            )

        files = sorted(
            [
                path
                for path in isolated_dir.iterdir()
                if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg"}
            ],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        safe_limit = _safe_int(limit, 50, 1, 500)
        artifacts = []

        for path in files[:safe_limit]:
            stat = path.stat()
            artifacts.append(
                {
                    "file_name": path.name,
                    "file_path": str(path),
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "mime_type": mimetypes.guess_type(str(path))[0],
                }
            )

        return self._safe_result(
            message="Screenshot artifacts listed successfully.",
            data={"artifacts": artifacts},
            context=normalized_context,
            metadata={
                "operation": "list_user_workspace_artifacts",
                "count": len(artifacts),
            },
        )

    def delete_user_workspace_artifact(
        self,
        context: Union[ScreenshotContext, Dict[str, Any]],
        file_name: str,
    ) -> Dict[str, Any]:
        """
        Delete a screenshot artifact inside the isolated user/workspace folder.

        This is intentionally limited to the user/workspace storage folder.
        """

        normalized_context = self._normalize_context(context)
        validation = self._validate_task_context(normalized_context)
        if not validation["success"]:
            return validation

        safe_name = Path(file_name).name
        isolated_dir = self._get_isolated_storage_dir(normalized_context)
        target_path = isolated_dir / safe_name

        if not target_path.exists() or not target_path.is_file():
            return self._error_result(
                message="Screenshot artifact not found.",
                error_code="ARTIFACT_NOT_FOUND",
                context=normalized_context,
                metadata={
                    "operation": "delete_user_workspace_artifact",
                    "file_name": safe_name,
                },
            )

        if target_path.parent.resolve() != isolated_dir.resolve():
            return self._error_result(
                message="Invalid artifact path.",
                error_code="INVALID_ARTIFACT_PATH",
                context=normalized_context,
                metadata={"operation": "delete_user_workspace_artifact"},
            )

        target_path.unlink()

        return self._safe_result(
            message="Screenshot artifact deleted successfully.",
            data={"file_name": safe_name},
            context=normalized_context,
            metadata={"operation": "delete_user_workspace_artifact"},
        )


# ---------------------------------------------------------------------------
# Simple module-level factory
# ---------------------------------------------------------------------------

def create_browser_screenshot_tool(**kwargs: Any) -> BrowserScreenshotTool:
    """
    Factory for Agent Loader / Registry integration.
    """

    return BrowserScreenshotTool(**kwargs)


# ---------------------------------------------------------------------------
# Manual smoke test helper
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tool = BrowserScreenshotTool()

    test_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "permissions": ["browser.screenshot.capture"],
        "task_id": "manual-smoke-test",
    }

    test_target = {
        "html": """
        <!doctype html>
        <html>
            <head>
                <title>William Screenshot Smoke Test</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        padding: 40px;
                        background: #f6f7fb;
                    }
                    .card {
                        background: white;
                        border-radius: 16px;
                        padding: 24px;
                        box-shadow: 0 8px 24px rgba(0,0,0,0.08);
                    }
                </style>
            </head>
            <body>
                <div class="card" id="proof-card">
                    <h1>William / Jarvis Screenshot Tool</h1>
                    <p>Smoke test capture for BrowserScreenshotTool.</p>
                </div>
            </body>
        </html>
        """,
        "name": "smoke-test",
        "selector": "#proof-card",
    }

    test_options = {
        "full_page": True,
        "viewport_width": 1200,
        "viewport_height": 800,
        "return_base64": False,
        "save_file": True,
    }

    print(json.dumps(
        tool.capture_section_screenshot(
            context=test_context,
            target=test_target,
            options=test_options,
        ),
        indent=2,
        default=str,
    ))