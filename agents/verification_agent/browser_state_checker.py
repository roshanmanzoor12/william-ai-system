"""
agents/verification_agent/browser_state_checker.py

BrowserStateChecker for William / Jarvis Verification Agent.

Purpose:
    Confirms browser opened, tab exists, URL/page title/content loaded, and no visible
    browser/page errors are present.

Architecture Fit:
    - Designed for the William / Jarvis multi-agent SaaS system.
    - Import-safe even if BaseAgent, Security Agent, Registry, Router, or other future
      modules are not created yet.
    - Supports user_id and workspace_id isolation for every verification task.
    - Produces structured dict/JSON-style results:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[dict],
            "metadata": dict
        }
    - Provides compatibility hooks required by the broader system:
        _validate_task_context()
        _requires_security_check()
        _request_security_approval()
        _prepare_verification_payload()
        _prepare_memory_payload()
        _emit_agent_event()
        _log_audit_event()
        _safe_result()
        _error_result()

Notes:
    This checker does not launch or control a real browser by itself. It safely inspects
    browser/page state objects supplied by Browser Agent, Visual Agent, test runners,
    dashboard/API calls, Playwright, Selenium, or a simple tab snapshot list.

    Optional supported inputs:
        - Selenium WebDriver-like object
        - Playwright Page-like object
        - Playwright Browser/Context-like object where pages can be discovered
        - Plain tab dictionaries/lists from Browser Agent or dashboard telemetry
        - Optional HTTP probe for URL availability/content if explicitly enabled in config

Security:
    - Browser inspection is read-only.
    - Network probing is disabled by default and goes through the security hook.
    - Sensitive context is sanitized before audit/memory payload preparation.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import json
import logging
import re
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse


# ======================================================================================
# Optional BaseAgent import with fallback
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project bootstrap
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent used only when the real William/Jarvis BaseAgent
        has not been created yet.

        The real system can replace this transparently because BrowserStateChecker
        only relies on simple optional hooks.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit_event: %s %s", event_name, payload)


# ======================================================================================
# Constants
# ======================================================================================

DEFAULT_ERROR_PATTERNS: Tuple[str, ...] = (
    r"\b404\b",
    r"\b403\b",
    r"\b401\b",
    r"\b500\b",
    r"\b502\b",
    r"\b503\b",
    r"\b504\b",
    r"page not found",
    r"not found",
    r"access denied",
    r"forbidden",
    r"unauthorized",
    r"internal server error",
    r"bad gateway",
    r"service unavailable",
    r"gateway timeout",
    r"this site can.?t be reached",
    r"connection timed out",
    r"connection refused",
    r"dns_probe",
    r"err_name_not_resolved",
    r"err_connection",
    r"privacy error",
    r"certificate error",
    r"ssl error",
    r"too many redirects",
    r"aw,\s*snap",
    r"chrome error",
    r"browser crashed",
)

DEFAULT_BROWSER_NAMES: Tuple[str, ...] = (
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "safari",
    "brave",
    "opera",
    "browser",
)

SENSITIVE_KEYS: Tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "cookies",
    "session",
    "credential",
    "private_key",
)


# ======================================================================================
# Data Structures
# ======================================================================================

@dataclass(frozen=True)
class BrowserStateCheckerConfig:
    """
    Configuration for BrowserStateChecker.

    allow_http_probe:
        Disabled by default. When enabled and no browser/page object is supplied,
        the checker may perform a safe HTTP GET request to inspect URL availability
        and content. This is useful for API/dashboard checks but should normally be
        guarded by Security Agent policy.

    http_timeout_seconds:
        Timeout for optional HTTP probe.

    max_content_chars:
        Maximum page body/content characters to collect in snapshots.

    strict_workspace_isolation:
        Requires user_id and workspace_id in task context.

    include_content_excerpt:
        Whether result data may include short content excerpts. Sensitive values are
        still redacted.

    default_url_match_mode:
        Supported: "exact", "contains", "regex", "normalized_exact".

    default_text_match_mode:
        Supported: "exact", "contains", "regex", "case_insensitive_contains".

    detect_error_patterns:
        Regex strings used to detect visible browser/page errors.

    allowed_schemes:
        URL schemes accepted by validator/probe.

    audit_enabled:
        Enables local audit hook calls.

    event_enabled:
        Enables local event hook calls.
    """

    allow_http_probe: bool = False
    http_timeout_seconds: float = 8.0
    max_content_chars: int = 12000
    strict_workspace_isolation: bool = True
    include_content_excerpt: bool = True
    default_url_match_mode: str = "normalized_exact"
    default_text_match_mode: str = "case_insensitive_contains"
    detect_error_patterns: Tuple[str, ...] = DEFAULT_ERROR_PATTERNS
    allowed_schemes: Tuple[str, ...] = ("http", "https", "file", "about", "chrome", "edge")
    audit_enabled: bool = True
    event_enabled: bool = True


@dataclass
class BrowserCheckCriteria:
    """
    User/task requested browser state expectations.
    """

    expected_url: Optional[str] = None
    expected_url_contains: Optional[str] = None
    expected_url_regex: Optional[str] = None
    expected_title: Optional[str] = None
    expected_title_contains: Optional[str] = None
    expected_title_regex: Optional[str] = None
    expected_content_contains: Optional[Union[str, Sequence[str]]] = None
    expected_content_regex: Optional[str] = None
    expected_browser_open: bool = True
    expected_tab_exists: bool = True
    expected_no_errors: bool = True
    tab_index: Optional[int] = None
    require_active_tab: bool = False
    min_content_length: Optional[int] = None
    url_match_mode: Optional[str] = None
    title_match_mode: Optional[str] = None
    content_match_mode: Optional[str] = None


@dataclass
class BrowserTabSnapshot:
    """
    Normalized tab/page state used internally by BrowserStateChecker.
    """

    url: Optional[str] = None
    title: Optional[str] = None
    content: Optional[str] = None
    is_active: Optional[bool] = None
    index: Optional[int] = None
    browser_name: Optional[str] = None
    status_code: Optional[int] = None
    loaded: Optional[bool] = None
    error_text: Optional[str] = None
    source: str = "unknown"
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_safe_dict(self, *, max_content_chars: int = 1000, include_content: bool = True) -> Dict[str, Any]:
        content_excerpt: Optional[str] = None
        content_length = len(self.content or "")

        if include_content and self.content:
            content_excerpt = self.content[:max_content_chars]

        return {
            "url": self.url,
            "title": self.title,
            "content_excerpt": content_excerpt,
            "content_length": content_length,
            "is_active": self.is_active,
            "index": self.index,
            "browser_name": self.browser_name,
            "status_code": self.status_code,
            "loaded": self.loaded,
            "error_text": self.error_text,
            "source": self.source,
            "raw_metadata": self.raw_metadata,
        }


@dataclass
class BrowserCheckFinding:
    """
    A single verification finding.
    """

    name: str
    passed: bool
    message: str
    expected: Any = None
    actual: Any = None
    confidence: float = 1.0
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ======================================================================================
# BrowserStateChecker
# ======================================================================================

class BrowserStateChecker(BaseAgent):
    """
    Confirms browser/page state for Verification Agent.

    Main usage:
        checker = BrowserStateChecker()
        result = checker.check_browser_state(
            task_context={"user_id": "...", "workspace_id": "..."},
            criteria={"expected_url_contains": "example.com"},
            selenium_driver=driver
        )

    This file intentionally avoids launching browsers. Browser Agent or test runners
    should supply a driver/page/snapshot. That keeps Verification Agent read-only and
    safe by default.
    """

    public_methods: Tuple[str, ...] = (
        "check_browser_state",
        "check_from_selenium",
        "check_from_playwright_page",
        "check_from_tabs",
        "check_url_loaded",
        "check_title_loaded",
        "check_content_loaded",
        "detect_browser_errors",
        "build_tab_snapshot",
    )

    def __init__(
        self,
        config: Optional[BrowserStateCheckerConfig] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="BrowserStateChecker", **kwargs)
        self.config = config or BrowserStateCheckerConfig()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback
        self.logger = logger or logging.getLogger("william.verification.browser_state_checker")

    # ----------------------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------------------

    def check_browser_state(
        self,
        task_context: Mapping[str, Any],
        criteria: Optional[Union[BrowserCheckCriteria, Mapping[str, Any]]] = None,
        *,
        selenium_driver: Any = None,
        playwright_page: Any = None,
        playwright_browser: Any = None,
        playwright_context: Any = None,
        tabs: Optional[Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]]] = None,
        browser_name: Optional[str] = None,
        allow_http_probe: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Verify browser opened, tab exists, URL/title/content loaded, and no errors.

        Args:
            task_context:
                Must contain user_id and workspace_id for SaaS isolation.

            criteria:
                BrowserCheckCriteria or dict with expected URL/title/content checks.

            selenium_driver:
                Optional Selenium WebDriver-like object.

            playwright_page:
                Optional Playwright Page-like object.

            playwright_browser:
                Optional Playwright Browser-like object.

            playwright_context:
                Optional Playwright BrowserContext-like object.

            tabs:
                Optional plain tab snapshots from Browser Agent/dashboard.

            browser_name:
                Optional browser name hint.

            allow_http_probe:
                Per-call override for optional HTTP probe.

        Returns:
            Structured JSON-style result dict.
        """
        started_at = self._utc_now()
        criteria_obj = self._coerce_criteria(criteria)

        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        operation = "browser_state_check"
        security_payload = {
            "operation": operation,
            "read_only": True,
            "network_probe_requested": bool(
                allow_http_probe if allow_http_probe is not None else self.config.allow_http_probe
            ),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "expected_url": criteria_obj.expected_url,
            "expected_url_contains": criteria_obj.expected_url_contains,
        }

        if self._requires_security_check(security_payload):
            approved = self._request_security_approval(security_payload)
            if not approved:
                return self._error_result(
                    message="Browser state check blocked by security policy.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    details={"operation": operation},
                    metadata=self._base_metadata(task_context, started_at),
                )

        self._emit_agent_event(
            "verification.browser_state_check.started",
            {
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "criteria": self._safe_serialize(criteria_obj),
            },
        )

        try:
            snapshots = self._collect_snapshots(
                selenium_driver=selenium_driver,
                playwright_page=playwright_page,
                playwright_browser=playwright_browser,
                playwright_context=playwright_context,
                tabs=tabs,
                browser_name=browser_name,
                criteria=criteria_obj,
                allow_http_probe=allow_http_probe,
            )

            findings = self._evaluate_snapshots(snapshots, criteria_obj)

            success = all(f.passed for f in findings if f.severity in {"info", "warning", "error", "critical"})
            confidence = self._calculate_confidence(findings, snapshots)

            selected_snapshot = self._select_best_snapshot(snapshots, criteria_obj)
            data = {
                "browser_open": len(snapshots) > 0,
                "tab_exists": selected_snapshot is not None,
                "selected_tab": (
                    selected_snapshot.to_safe_dict(
                        max_content_chars=1000,
                        include_content=self.config.include_content_excerpt,
                    )
                    if selected_snapshot
                    else None
                ),
                "tab_count": len(snapshots),
                "tabs": [
                    snapshot.to_safe_dict(
                        max_content_chars=500,
                        include_content=self.config.include_content_excerpt,
                    )
                    for snapshot in snapshots
                ],
                "findings": [finding.to_dict() for finding in findings],
                "confidence": confidence,
                "criteria": self._safe_serialize(criteria_obj),
            }

            message = (
                "Browser state verified successfully."
                if success
                else "Browser state verification completed with failed checks."
            )

            result = self._safe_result(
                success=success,
                message=message,
                data=data,
                metadata=self._base_metadata(task_context, started_at),
            )

            verification_payload = self._prepare_verification_payload(
                task_context=task_context,
                result=result,
                checker_name="browser_state_checker",
            )
            memory_payload = self._prepare_memory_payload(
                task_context=task_context,
                result=result,
                checker_name="browser_state_checker",
            )

            self._dispatch_optional_payloads(verification_payload, memory_payload)
            self._log_audit_event(
                "verification.browser_state_check.completed",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "success": success,
                    "confidence": confidence,
                    "tab_count": len(snapshots),
                },
            )
            self._emit_agent_event(
                "verification.browser_state_check.completed",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "success": success,
                    "confidence": confidence,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Browser state check failed unexpectedly.")
            result = self._error_result(
                message="Browser state check failed due to an unexpected error.",
                error_code="BROWSER_STATE_CHECK_FAILED",
                details={
                    "exception_type": exc.__class__.__name__,
                    "exception": str(exc),
                },
                metadata=self._base_metadata(task_context, started_at),
            )
            self._log_audit_event(
                "verification.browser_state_check.failed",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "error": str(exc),
                },
            )
            return result

    def check_from_selenium(
        self,
        task_context: Mapping[str, Any],
        selenium_driver: Any,
        criteria: Optional[Union[BrowserCheckCriteria, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for Selenium WebDriver objects.
        """
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            selenium_driver=selenium_driver,
        )

    def check_from_playwright_page(
        self,
        task_context: Mapping[str, Any],
        playwright_page: Any,
        criteria: Optional[Union[BrowserCheckCriteria, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for Playwright Page objects.
        """
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            playwright_page=playwright_page,
        )

    def check_from_tabs(
        self,
        task_context: Mapping[str, Any],
        tabs: Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]],
        criteria: Optional[Union[BrowserCheckCriteria, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for Browser Agent/dashboard tab snapshots.
        """
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            tabs=tabs,
        )

    def check_url_loaded(
        self,
        task_context: Mapping[str, Any],
        expected_url: Optional[str] = None,
        *,
        expected_url_contains: Optional[str] = None,
        expected_url_regex: Optional[str] = None,
        selenium_driver: Any = None,
        playwright_page: Any = None,
        tabs: Optional[Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        Verify URL loaded in at least one selected tab.
        """
        criteria = BrowserCheckCriteria(
            expected_url=expected_url,
            expected_url_contains=expected_url_contains,
            expected_url_regex=expected_url_regex,
            expected_browser_open=True,
            expected_tab_exists=True,
            expected_no_errors=False,
        )
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            selenium_driver=selenium_driver,
            playwright_page=playwright_page,
            tabs=tabs,
        )

    def check_title_loaded(
        self,
        task_context: Mapping[str, Any],
        expected_title: Optional[str] = None,
        *,
        expected_title_contains: Optional[str] = None,
        expected_title_regex: Optional[str] = None,
        selenium_driver: Any = None,
        playwright_page: Any = None,
        tabs: Optional[Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        Verify page title loaded in at least one selected tab.
        """
        criteria = BrowserCheckCriteria(
            expected_title=expected_title,
            expected_title_contains=expected_title_contains,
            expected_title_regex=expected_title_regex,
            expected_browser_open=True,
            expected_tab_exists=True,
            expected_no_errors=False,
        )
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            selenium_driver=selenium_driver,
            playwright_page=playwright_page,
            tabs=tabs,
        )

    def check_content_loaded(
        self,
        task_context: Mapping[str, Any],
        expected_content_contains: Optional[Union[str, Sequence[str]]] = None,
        *,
        expected_content_regex: Optional[str] = None,
        min_content_length: Optional[int] = None,
        selenium_driver: Any = None,
        playwright_page: Any = None,
        tabs: Optional[Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        Verify page content/body text loaded.
        """
        criteria = BrowserCheckCriteria(
            expected_content_contains=expected_content_contains,
            expected_content_regex=expected_content_regex,
            min_content_length=min_content_length,
            expected_browser_open=True,
            expected_tab_exists=True,
            expected_no_errors=False,
        )
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            selenium_driver=selenium_driver,
            playwright_page=playwright_page,
            tabs=tabs,
        )

    def detect_browser_errors(
        self,
        task_context: Mapping[str, Any],
        *,
        selenium_driver: Any = None,
        playwright_page: Any = None,
        tabs: Optional[Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        Detect visible browser/page errors such as 404, 500, DNS, SSL, crash,
        connection timeout, and browser error pages.
        """
        criteria = BrowserCheckCriteria(
            expected_browser_open=True,
            expected_tab_exists=True,
            expected_no_errors=True,
        )
        return self.check_browser_state(
            task_context=task_context,
            criteria=criteria,
            selenium_driver=selenium_driver,
            playwright_page=playwright_page,
            tabs=tabs,
        )

    def build_tab_snapshot(
        self,
        *,
        url: Optional[str] = None,
        title: Optional[str] = None,
        content: Optional[str] = None,
        is_active: Optional[bool] = None,
        index: Optional[int] = None,
        browser_name: Optional[str] = None,
        status_code: Optional[int] = None,
        loaded: Optional[bool] = None,
        error_text: Optional[str] = None,
        source: str = "manual",
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> BrowserTabSnapshot:
        """
        Public helper for Browser Agent/dashboard integrations to build normalized
        tab snapshots.
        """
        return BrowserTabSnapshot(
            url=url,
            title=title,
            content=self._trim_content(content),
            is_active=is_active,
            index=index,
            browser_name=browser_name,
            status_code=status_code,
            loaded=loaded,
            error_text=error_text,
            source=source,
            raw_metadata=raw_metadata or {},
        )

    # ----------------------------------------------------------------------------------
    # Snapshot Collection
    # ----------------------------------------------------------------------------------

    def _collect_snapshots(
        self,
        *,
        selenium_driver: Any = None,
        playwright_page: Any = None,
        playwright_browser: Any = None,
        playwright_context: Any = None,
        tabs: Optional[Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]]] = None,
        browser_name: Optional[str] = None,
        criteria: BrowserCheckCriteria,
        allow_http_probe: Optional[bool] = None,
    ) -> List[BrowserTabSnapshot]:
        snapshots: List[BrowserTabSnapshot] = []

        if tabs is not None:
            snapshots.extend(self._snapshots_from_tabs(tabs, browser_name=browser_name))

        if selenium_driver is not None:
            snapshots.extend(self._snapshots_from_selenium(selenium_driver, browser_name=browser_name))

        if playwright_page is not None:
            snapshots.append(self._snapshot_from_playwright_page(playwright_page, index=0, browser_name=browser_name))

        if playwright_context is not None:
            snapshots.extend(self._snapshots_from_playwright_context(playwright_context, browser_name=browser_name))

        if playwright_browser is not None:
            snapshots.extend(self._snapshots_from_playwright_browser(playwright_browser, browser_name=browser_name))

        should_probe = self.config.allow_http_probe if allow_http_probe is None else allow_http_probe
        probe_url = criteria.expected_url or criteria.expected_url_contains

        if not snapshots and should_probe and probe_url and self._looks_like_probeable_url(probe_url):
            snapshots.append(self._snapshot_from_http_probe(probe_url, browser_name=browser_name))

        return self._deduplicate_snapshots(snapshots)

    def _snapshots_from_tabs(
        self,
        tabs: Sequence[Union[BrowserTabSnapshot, Mapping[str, Any]]],
        *,
        browser_name: Optional[str] = None,
    ) -> List[BrowserTabSnapshot]:
        snapshots: List[BrowserTabSnapshot] = []

        for idx, tab in enumerate(tabs):
            if isinstance(tab, BrowserTabSnapshot):
                snapshot = tab
                if snapshot.index is None:
                    snapshot.index = idx
                if browser_name and not snapshot.browser_name:
                    snapshot.browser_name = browser_name
                snapshots.append(snapshot)
                continue

            if isinstance(tab, Mapping):
                snapshots.append(
                    BrowserTabSnapshot(
                        url=self._none_if_empty(tab.get("url") or tab.get("current_url")),
                        title=self._none_if_empty(tab.get("title") or tab.get("page_title")),
                        content=self._trim_content(
                            self._none_if_empty(
                                tab.get("content")
                                or tab.get("body")
                                or tab.get("text")
                                or tab.get("page_content")
                                or tab.get("html")
                            )
                        ),
                        is_active=self._to_optional_bool(tab.get("is_active", tab.get("active"))),
                        index=self._to_optional_int(tab.get("index", idx)),
                        browser_name=self._none_if_empty(tab.get("browser_name") or browser_name),
                        status_code=self._to_optional_int(tab.get("status_code") or tab.get("http_status")),
                        loaded=self._to_optional_bool(tab.get("loaded") or tab.get("is_loaded")),
                        error_text=self._none_if_empty(tab.get("error_text") or tab.get("error")),
                        source=str(tab.get("source") or "tab_snapshot"),
                        raw_metadata=self._safe_mapping(
                            tab.get("metadata") if isinstance(tab.get("metadata"), Mapping) else {}
                        ),
                    )
                )

        return snapshots

    def _snapshots_from_selenium(self, driver: Any, *, browser_name: Optional[str] = None) -> List[BrowserTabSnapshot]:
        """
        Collect snapshots from a Selenium WebDriver-like object.

        This method is read-only. It switches between existing windows if possible,
        then restores the original handle.
        """
        snapshots: List[BrowserTabSnapshot] = []

        handles = self._safe_getattr(driver, "window_handles")
        current_handle = self._safe_getattr(driver, "current_window_handle")

        if not handles:
            snapshots.append(self._snapshot_from_selenium_current(driver, index=0, browser_name=browser_name))
            return snapshots

        for idx, handle in enumerate(handles):
            with contextlib.suppress(Exception):
                switch_to = self._safe_getattr(driver, "switch_to")
                if switch_to is not None and hasattr(switch_to, "window"):
                    switch_to.window(handle)

            snapshots.append(self._snapshot_from_selenium_current(driver, index=idx, browser_name=browser_name))

        if current_handle:
            with contextlib.suppress(Exception):
                switch_to = self._safe_getattr(driver, "switch_to")
                if switch_to is not None and hasattr(switch_to, "window"):
                    switch_to.window(current_handle)

        return snapshots

    def _snapshot_from_selenium_current(
        self,
        driver: Any,
        *,
        index: Optional[int],
        browser_name: Optional[str] = None,
    ) -> BrowserTabSnapshot:
        url = self._safe_getattr(driver, "current_url")
        title = self._safe_getattr(driver, "title")
        page_source = self._safe_getattr(driver, "page_source")

        body_text = None
        with contextlib.suppress(Exception):
            body = driver.find_element("tag name", "body")
            body_text = getattr(body, "text", None)

        browser_name_final = browser_name or self._infer_browser_name(driver)
        content = body_text or self._html_to_text(page_source)

        return BrowserTabSnapshot(
            url=self._none_if_empty(url),
            title=self._none_if_empty(title),
            content=self._trim_content(content),
            is_active=None,
            index=index,
            browser_name=browser_name_final,
            status_code=None,
            loaded=self._infer_loaded(url=url, title=title, content=content),
            error_text=None,
            source="selenium",
            raw_metadata={
                "driver_class": driver.__class__.__name__,
                "has_page_source": bool(page_source),
            },
        )

    def _snapshot_from_playwright_page(
        self,
        page: Any,
        *,
        index: Optional[int],
        browser_name: Optional[str] = None,
    ) -> BrowserTabSnapshot:
        url = self._call_or_attr(page, "url")
        title = self._safe_call(page, "title")

        content = None
        with contextlib.suppress(Exception):
            locator = page.locator("body")
            content = locator.inner_text(timeout=1000)

        if not content:
            with contextlib.suppress(Exception):
                content = self._html_to_text(page.content())

        loaded = self._infer_loaded(url=url, title=title, content=content)
        browser_name_final = browser_name or self._infer_playwright_browser_name(page)

        return BrowserTabSnapshot(
            url=self._none_if_empty(url),
            title=self._none_if_empty(title),
            content=self._trim_content(content),
            is_active=None,
            index=index,
            browser_name=browser_name_final,
            status_code=None,
            loaded=loaded,
            error_text=None,
            source="playwright_page",
            raw_metadata={
                "page_class": page.__class__.__name__,
            },
        )

    def _snapshots_from_playwright_context(
        self,
        context: Any,
        *,
        browser_name: Optional[str] = None,
    ) -> List[BrowserTabSnapshot]:
        pages = self._call_or_attr(context, "pages")
        snapshots: List[BrowserTabSnapshot] = []

        if isinstance(pages, Iterable):
            for idx, page in enumerate(list(pages)):
                snapshots.append(
                    self._snapshot_from_playwright_page(page, index=idx, browser_name=browser_name)
                )

        return snapshots

    def _snapshots_from_playwright_browser(
        self,
        browser: Any,
        *,
        browser_name: Optional[str] = None,
    ) -> List[BrowserTabSnapshot]:
        snapshots: List[BrowserTabSnapshot] = []
        contexts = self._call_or_attr(browser, "contexts")

        if isinstance(contexts, Iterable):
            for context in list(contexts):
                snapshots.extend(self._snapshots_from_playwright_context(context, browser_name=browser_name))

        return snapshots

    def _snapshot_from_http_probe(self, url: str, *, browser_name: Optional[str] = None) -> BrowserTabSnapshot:
        """
        Optional URL content probe. Disabled by default.

        This is useful for dashboard/API verification when a browser object is not
        available. It does not replace actual browser state verification.
        """
        normalized_url = self._ensure_http_url(url)
        request = urllib.request.Request(
            normalized_url,
            headers={
                "User-Agent": "WilliamVerificationAgent/1.0 (+browser-state-checker)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
            },
            method="GET",
        )

        started = time.time()
        try:
            with urllib.request.urlopen(request, timeout=self.config.http_timeout_seconds) as response:
                raw = response.read(self.config.max_content_chars)
                charset = response.headers.get_content_charset() or "utf-8"
                text = raw.decode(charset, errors="replace")
                title = self._extract_title_from_html(text)
                content = self._html_to_text(text)
                status_code = int(getattr(response, "status", 0) or response.getcode() or 0)

                return BrowserTabSnapshot(
                    url=normalized_url,
                    title=title,
                    content=self._trim_content(content),
                    is_active=None,
                    index=0,
                    browser_name=browser_name or "http_probe",
                    status_code=status_code,
                    loaded=200 <= status_code < 400 and bool(content or title),
                    error_text=None,
                    source="http_probe",
                    raw_metadata={
                        "elapsed_ms": round((time.time() - started) * 1000, 2),
                        "final_url": response.geturl(),
                        "content_type": response.headers.get("Content-Type"),
                    },
                )

        except urllib.error.HTTPError as exc:
            body = ""
            with contextlib.suppress(Exception):
                body = exc.read(self.config.max_content_chars).decode("utf-8", errors="replace")

            return BrowserTabSnapshot(
                url=normalized_url,
                title=self._extract_title_from_html(body),
                content=self._trim_content(self._html_to_text(body)),
                is_active=None,
                index=0,
                browser_name=browser_name or "http_probe",
                status_code=int(exc.code),
                loaded=False,
                error_text=f"HTTP error {exc.code}: {exc.reason}",
                source="http_probe",
                raw_metadata={
                    "elapsed_ms": round((time.time() - started) * 1000, 2),
                    "reason": str(exc.reason),
                },
            )

        except Exception as exc:
            return BrowserTabSnapshot(
                url=normalized_url,
                title=None,
                content=None,
                is_active=None,
                index=0,
                browser_name=browser_name or "http_probe",
                status_code=None,
                loaded=False,
                error_text=f"{exc.__class__.__name__}: {exc}",
                source="http_probe",
                raw_metadata={
                    "elapsed_ms": round((time.time() - started) * 1000, 2),
                },
            )

    # ----------------------------------------------------------------------------------
    # Evaluation
    # ----------------------------------------------------------------------------------

    def _evaluate_snapshots(
        self,
        snapshots: Sequence[BrowserTabSnapshot],
        criteria: BrowserCheckCriteria,
    ) -> List[BrowserCheckFinding]:
        findings: List[BrowserCheckFinding] = []

        browser_open = len(snapshots) > 0
        if criteria.expected_browser_open:
            findings.append(
                BrowserCheckFinding(
                    name="browser_open",
                    passed=browser_open,
                    message="Browser/tab snapshot is available." if browser_open else "No browser/tab snapshot is available.",
                    expected=True,
                    actual=browser_open,
                    confidence=1.0 if browser_open else 0.0,
                    severity="error" if not browser_open else "info",
                )
            )

        selected_snapshot = self._select_best_snapshot(snapshots, criteria)
        tab_exists = selected_snapshot is not None

        if criteria.expected_tab_exists:
            findings.append(
                BrowserCheckFinding(
                    name="tab_exists",
                    passed=tab_exists,
                    message="A matching or selectable tab exists." if tab_exists else "No matching or selectable tab exists.",
                    expected=True,
                    actual=tab_exists,
                    confidence=1.0 if tab_exists else 0.0,
                    severity="error" if not tab_exists else "info",
                )
            )

        if not selected_snapshot:
            return findings

        findings.extend(self._evaluate_url(selected_snapshot, criteria))
        findings.extend(self._evaluate_title(selected_snapshot, criteria))
        findings.extend(self._evaluate_content(selected_snapshot, criteria))
        findings.extend(self._evaluate_loaded(selected_snapshot, criteria))
        findings.extend(self._evaluate_errors(selected_snapshot, criteria))

        return findings

    def _evaluate_url(
        self,
        snapshot: BrowserTabSnapshot,
        criteria: BrowserCheckCriteria,
    ) -> List[BrowserCheckFinding]:
        findings: List[BrowserCheckFinding] = []
        actual = snapshot.url or ""

        if criteria.expected_url:
            mode = criteria.url_match_mode or self.config.default_url_match_mode
            passed = self._match_text(actual, criteria.expected_url, mode=mode, normalize_url=True)
            findings.append(
                BrowserCheckFinding(
                    name="url_match",
                    passed=passed,
                    message="URL matched expected URL." if passed else "URL did not match expected URL.",
                    expected=criteria.expected_url,
                    actual=snapshot.url,
                    confidence=1.0 if passed else 0.25,
                    severity="error" if not passed else "info",
                )
            )

        if criteria.expected_url_contains:
            passed = criteria.expected_url_contains.lower() in actual.lower()
            findings.append(
                BrowserCheckFinding(
                    name="url_contains",
                    passed=passed,
                    message="URL contains expected text." if passed else "URL does not contain expected text.",
                    expected=criteria.expected_url_contains,
                    actual=snapshot.url,
                    confidence=1.0 if passed else 0.25,
                    severity="error" if not passed else "info",
                )
            )

        if criteria.expected_url_regex:
            passed = self._regex_search(criteria.expected_url_regex, actual)
            findings.append(
                BrowserCheckFinding(
                    name="url_regex",
                    passed=passed,
                    message="URL matched expected regex." if passed else "URL did not match expected regex.",
                    expected=criteria.expected_url_regex,
                    actual=snapshot.url,
                    confidence=1.0 if passed else 0.25,
                    severity="error" if not passed else "info",
                )
            )

        return findings

    def _evaluate_title(
        self,
        snapshot: BrowserTabSnapshot,
        criteria: BrowserCheckCriteria,
    ) -> List[BrowserCheckFinding]:
        findings: List[BrowserCheckFinding] = []
        actual = snapshot.title or ""

        if criteria.expected_title:
            mode = criteria.title_match_mode or self.config.default_text_match_mode
            passed = self._match_text(actual, criteria.expected_title, mode=mode)
            findings.append(
                BrowserCheckFinding(
                    name="title_match",
                    passed=passed,
                    message="Page title matched expected title." if passed else "Page title did not match expected title.",
                    expected=criteria.expected_title,
                    actual=snapshot.title,
                    confidence=1.0 if passed else 0.3,
                    severity="error" if not passed else "info",
                )
            )

        if criteria.expected_title_contains:
            passed = criteria.expected_title_contains.lower() in actual.lower()
            findings.append(
                BrowserCheckFinding(
                    name="title_contains",
                    passed=passed,
                    message="Page title contains expected text." if passed else "Page title does not contain expected text.",
                    expected=criteria.expected_title_contains,
                    actual=snapshot.title,
                    confidence=1.0 if passed else 0.3,
                    severity="error" if not passed else "info",
                )
            )

        if criteria.expected_title_regex:
            passed = self._regex_search(criteria.expected_title_regex, actual)
            findings.append(
                BrowserCheckFinding(
                    name="title_regex",
                    passed=passed,
                    message="Page title matched expected regex." if passed else "Page title did not match expected regex.",
                    expected=criteria.expected_title_regex,
                    actual=snapshot.title,
                    confidence=1.0 if passed else 0.3,
                    severity="error" if not passed else "info",
                )
            )

        if any([criteria.expected_title, criteria.expected_title_contains, criteria.expected_title_regex]):
            title_loaded = bool(actual.strip())
            findings.append(
                BrowserCheckFinding(
                    name="title_loaded",
                    passed=title_loaded,
                    message="Page title is loaded." if title_loaded else "Page title is empty or unavailable.",
                    expected=True,
                    actual=title_loaded,
                    confidence=0.9 if title_loaded else 0.2,
                    severity="warning" if not title_loaded else "info",
                )
            )

        return findings

    def _evaluate_content(
        self,
        snapshot: BrowserTabSnapshot,
        criteria: BrowserCheckCriteria,
    ) -> List[BrowserCheckFinding]:
        findings: List[BrowserCheckFinding] = []
        actual = snapshot.content or ""

        if criteria.min_content_length is not None:
            content_length = len(actual)
            passed = content_length >= criteria.min_content_length
            findings.append(
                BrowserCheckFinding(
                    name="content_min_length",
                    passed=passed,
                    message=(
                        "Page content length meets minimum requirement."
                        if passed
                        else "Page content is shorter than expected."
                    ),
                    expected=criteria.min_content_length,
                    actual=content_length,
                    confidence=1.0 if passed else 0.35,
                    severity="error" if not passed else "info",
                )
            )

        if criteria.expected_content_contains:
            expected_items = (
                [criteria.expected_content_contains]
                if isinstance(criteria.expected_content_contains, str)
                else list(criteria.expected_content_contains)
            )
            missing_items: List[str] = []
            for item in expected_items:
                mode = criteria.content_match_mode or self.config.default_text_match_mode
                if not self._match_text(actual, item, mode=mode):
                    missing_items.append(item)

            passed = not missing_items
            findings.append(
                BrowserCheckFinding(
                    name="content_contains",
                    passed=passed,
                    message=(
                        "Page content contains all expected text."
                        if passed
                        else "Page content is missing expected text."
                    ),
                    expected=expected_items,
                    actual={
                        "missing": missing_items,
                        "content_length": len(actual),
                    },
                    confidence=1.0 if passed else 0.35,
                    severity="error" if not passed else "info",
                )
            )

        if criteria.expected_content_regex:
            passed = self._regex_search(criteria.expected_content_regex, actual)
            findings.append(
                BrowserCheckFinding(
                    name="content_regex",
                    passed=passed,
                    message="Page content matched expected regex." if passed else "Page content did not match expected regex.",
                    expected=criteria.expected_content_regex,
                    actual={"content_length": len(actual)},
                    confidence=1.0 if passed else 0.35,
                    severity="error" if not passed else "info",
                )
            )

        if any([
            criteria.expected_content_contains,
            criteria.expected_content_regex,
            criteria.min_content_length is not None,
        ]):
            content_loaded = bool(actual.strip())
            findings.append(
                BrowserCheckFinding(
                    name="content_loaded",
                    passed=content_loaded,
                    message="Page content/body text is loaded." if content_loaded else "Page content/body text is empty.",
                    expected=True,
                    actual=content_loaded,
                    confidence=0.9 if content_loaded else 0.2,
                    severity="warning" if not content_loaded else "info",
                )
            )

        return findings

    def _evaluate_loaded(
        self,
        snapshot: BrowserTabSnapshot,
        criteria: BrowserCheckCriteria,
    ) -> List[BrowserCheckFinding]:
        loaded = snapshot.loaded
        if loaded is None:
            loaded = self._infer_loaded(url=snapshot.url, title=snapshot.title, content=snapshot.content)

        return [
            BrowserCheckFinding(
                name="page_loaded",
                passed=bool(loaded),
                message="Page appears loaded." if loaded else "Page does not appear fully loaded.",
                expected=True,
                actual=bool(loaded),
                confidence=0.85 if loaded else 0.35,
                severity="warning" if not loaded else "info",
            )
        ]

    def _evaluate_errors(
        self,
        snapshot: BrowserTabSnapshot,
        criteria: BrowserCheckCriteria,
    ) -> List[BrowserCheckFinding]:
        if not criteria.expected_no_errors:
            return []

        detected_errors = self._detect_errors_in_snapshot(snapshot)
        status_code_error = snapshot.status_code is not None and snapshot.status_code >= 400

        passed = not detected_errors and not status_code_error and not snapshot.error_text
        actual = {
            "detected_errors": detected_errors,
            "status_code": snapshot.status_code,
            "error_text": snapshot.error_text,
        }

        return [
            BrowserCheckFinding(
                name="no_browser_errors",
                passed=passed,
                message="No browser/page error detected." if passed else "Browser/page error detected.",
                expected=True,
                actual=actual,
                confidence=0.95 if passed else 0.2,
                severity="critical" if not passed else "info",
            )
        ]

    def _detect_errors_in_snapshot(self, snapshot: BrowserTabSnapshot) -> List[str]:
        haystack = "\n".join(
            value for value in [
                snapshot.url or "",
                snapshot.title or "",
                snapshot.content or "",
                snapshot.error_text or "",
            ]
            if value
        ).lower()

        matched: List[str] = []
        for pattern in self.config.detect_error_patterns:
            if self._regex_search(pattern, haystack, flags=re.IGNORECASE):
                matched.append(pattern)

        if snapshot.status_code is not None and snapshot.status_code >= 400:
            matched.append(f"http_status_{snapshot.status_code}")

        return sorted(set(matched))

    def _select_best_snapshot(
        self,
        snapshots: Sequence[BrowserTabSnapshot],
        criteria: BrowserCheckCriteria,
    ) -> Optional[BrowserTabSnapshot]:
        if not snapshots:
            return None

        if criteria.tab_index is not None:
            for snapshot in snapshots:
                if snapshot.index == criteria.tab_index:
                    return snapshot
            if 0 <= criteria.tab_index < len(snapshots):
                return snapshots[criteria.tab_index]
            return None

        if criteria.require_active_tab:
            active_tabs = [snapshot for snapshot in snapshots if snapshot.is_active is True]
            if active_tabs:
                snapshots = active_tabs
            else:
                return None

        scored: List[Tuple[int, BrowserTabSnapshot]] = []
        for snapshot in snapshots:
            score = 0
            url = snapshot.url or ""
            title = snapshot.title or ""
            content = snapshot.content or ""

            if criteria.expected_url and self._match_text(
                url,
                criteria.expected_url,
                mode=criteria.url_match_mode or self.config.default_url_match_mode,
                normalize_url=True,
            ):
                score += 50
            if criteria.expected_url_contains and criteria.expected_url_contains.lower() in url.lower():
                score += 40
            if criteria.expected_url_regex and self._regex_search(criteria.expected_url_regex, url):
                score += 40

            if criteria.expected_title and self._match_text(
                title,
                criteria.expected_title,
                mode=criteria.title_match_mode or self.config.default_text_match_mode,
            ):
                score += 25
            if criteria.expected_title_contains and criteria.expected_title_contains.lower() in title.lower():
                score += 20
            if criteria.expected_title_regex and self._regex_search(criteria.expected_title_regex, title):
                score += 20

            if criteria.expected_content_contains:
                expected_items = (
                    [criteria.expected_content_contains]
                    if isinstance(criteria.expected_content_contains, str)
                    else list(criteria.expected_content_contains)
                )
                for item in expected_items:
                    if self._match_text(
                        content,
                        item,
                        mode=criteria.content_match_mode or self.config.default_text_match_mode,
                    ):
                        score += 10

            if criteria.expected_content_regex and self._regex_search(criteria.expected_content_regex, content):
                score += 10

            if snapshot.loaded:
                score += 5
            if snapshot.is_active:
                score += 3

            scored.append((score, snapshot))

        scored.sort(key=lambda item: item[0], reverse=True)

        if not any([
            criteria.expected_url,
            criteria.expected_url_contains,
            criteria.expected_url_regex,
            criteria.expected_title,
            criteria.expected_title_contains,
            criteria.expected_title_regex,
            criteria.expected_content_contains,
            criteria.expected_content_regex,
        ]):
            active = [snapshot for snapshot in snapshots if snapshot.is_active is True]
            return active[0] if active else snapshots[0]

        best_score, best_snapshot = scored[0]
        if best_score <= 0:
            return snapshots[0]

        return best_snapshot

    def _calculate_confidence(
        self,
        findings: Sequence[BrowserCheckFinding],
        snapshots: Sequence[BrowserTabSnapshot],
    ) -> float:
        if not findings:
            return 0.0

        weighted_total = 0.0
        weight_sum = 0.0

        severity_weight = {
            "info": 1.0,
            "warning": 1.5,
            "error": 2.0,
            "critical": 3.0,
        }

        for finding in findings:
            weight = severity_weight.get(finding.severity, 1.0)
            weighted_total += (finding.confidence if finding.passed else (1.0 - finding.confidence)) * weight
            weight_sum += weight

        base = weighted_total / weight_sum if weight_sum else 0.0

        if snapshots:
            base = max(base, 0.15)

        return round(max(0.0, min(1.0, base)), 4)

    # ----------------------------------------------------------------------------------
    # Required Compatibility Hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific execution must carry user_id and workspace_id to prevent
        cross-user data mixing.
        """
        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context. Expected mapping/dict.",
                error_code="INVALID_TASK_CONTEXT",
                details={"received_type": type(task_context).__name__},
            )

        user_id = task_context.get("user_id")
        workspace_id = task_context.get("workspace_id")

        if self.config.strict_workspace_isolation:
            missing = []
            if not user_id:
                missing.append("user_id")
            if not workspace_id:
                missing.append("workspace_id")

            if missing:
                return self._error_result(
                    message="Task context missing required SaaS isolation fields.",
                    error_code="MISSING_CONTEXT_FIELDS",
                    details={"missing": missing},
                )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(self, payload: Mapping[str, Any]) -> bool:
        """
        Decide whether Security Agent approval is required.

        Read-only browser inspection does not require approval. Optional HTTP/network
        probing does require approval because it touches external resources.
        """
        if payload.get("network_probe_requested"):
            return True
        if payload.get("operation") in {"browser_write", "browser_control", "browser_launch"}:
            return True
        return False

    def _request_security_approval(self, payload: Mapping[str, Any]) -> bool:
        """
        Request approval from Security Agent or callback.

        Fallback behavior:
            - Read-only operations are allowed.
            - Network probe is denied unless config.allow_http_probe is true and callback
              is absent. If callback exists, callback decides.
        """
        safe_payload = self._sanitize_for_output(dict(payload))

        if self.security_approval_callback:
            try:
                return bool(self.security_approval_callback(safe_payload))
            except Exception as exc:
                self.logger.warning("Security approval callback failed: %s", exc)
                return False

        if safe_payload.get("network_probe_requested"):
            return bool(self.config.allow_http_probe)

        return True

    def _prepare_verification_payload(
        self,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        checker_name: str,
    ) -> Dict[str, Any]:
        """
        Payload prepared for Verification Agent aggregation/proof reports.
        """
        return self._sanitize_for_output(
            {
                "type": "verification_payload",
                "checker": checker_name,
                "agent_module": "verification_agent",
                "file": "browser_state_checker.py",
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "success": result.get("success"),
                "message": result.get("message"),
                "data": result.get("data"),
                "metadata": result.get("metadata"),
                "created_at": self._utc_now_iso(),
            }
        )

    def _prepare_memory_payload(
        self,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        checker_name: str,
    ) -> Dict[str, Any]:
        """
        Payload prepared for Memory Agent.

        Stores useful context only, not secrets or full browser content.
        """
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
        selected_tab = data.get("selected_tab") if isinstance(data, Mapping) else {}

        return self._sanitize_for_output(
            {
                "type": "verification_memory",
                "checker": checker_name,
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "success": result.get("success"),
                "summary": result.get("message"),
                "browser_open": data.get("browser_open") if isinstance(data, Mapping) else None,
                "tab_exists": data.get("tab_exists") if isinstance(data, Mapping) else None,
                "selected_url": selected_tab.get("url") if isinstance(selected_tab, Mapping) else None,
                "selected_title": selected_tab.get("title") if isinstance(selected_tab, Mapping) else None,
                "confidence": data.get("confidence") if isinstance(data, Mapping) else None,
                "created_at": self._utc_now_iso(),
            }
        )

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit event for Master Agent, Registry, Router, or Dashboard listeners.
        """
        if not self.config.event_enabled:
            return

        safe_payload = self._sanitize_for_output(dict(payload))

        if self.event_callback:
            with contextlib.suppress(Exception):
                self.event_callback(event_name, safe_payload)
                return

        if hasattr(super(), "emit_event"):
            with contextlib.suppress(Exception):
                super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                return

        self.logger.debug("Agent event: %s %s", event_name, safe_payload)

    def _log_audit_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Write audit event for SaaS dashboard/audit logs.
        """
        if not self.config.audit_enabled:
            return

        safe_payload = self._sanitize_for_output(dict(payload))

        if self.audit_callback:
            with contextlib.suppress(Exception):
                self.audit_callback(event_name, safe_payload)
                return

        if hasattr(super(), "log_audit_event"):
            with contextlib.suppress(Exception):
                super().log_audit_event(event_name, safe_payload)  # type: ignore[misc]
                return

        self.logger.info("Audit event: %s %s", event_name, safe_payload)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard successful/neutral result envelope.
        """
        return {
            "success": bool(success),
            "message": str(message),
            "data": self._sanitize_for_output(data or {}),
            "error": self._sanitize_for_output(error) if error else None,
            "metadata": self._sanitize_for_output(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error_code: str,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result envelope.
        """
        return {
            "success": False,
            "message": str(message),
            "data": {},
            "error": {
                "code": str(error_code),
                "details": self._sanitize_for_output(details or {}),
            },
            "metadata": self._sanitize_for_output(metadata or {}),
        }

    # ----------------------------------------------------------------------------------
    # Internal Helpers
    # ----------------------------------------------------------------------------------

    def _dispatch_optional_payloads(
        self,
        verification_payload: Dict[str, Any],
        memory_payload: Dict[str, Any],
    ) -> None:
        if self.verification_callback:
            with contextlib.suppress(Exception):
                self.verification_callback(verification_payload)

        if self.memory_callback:
            with contextlib.suppress(Exception):
                self.memory_callback(memory_payload)

    def _coerce_criteria(
        self,
        criteria: Optional[Union[BrowserCheckCriteria, Mapping[str, Any]]],
    ) -> BrowserCheckCriteria:
        if criteria is None:
            return BrowserCheckCriteria()

        if isinstance(criteria, BrowserCheckCriteria):
            return criteria

        if isinstance(criteria, Mapping):
            allowed = {field.name for field in dataclasses.fields(BrowserCheckCriteria)}
            clean = {key: value for key, value in criteria.items() if key in allowed}
            return BrowserCheckCriteria(**clean)

        raise TypeError(f"Unsupported criteria type: {type(criteria).__name__}")

    def _match_text(
        self,
        actual: str,
        expected: str,
        *,
        mode: str,
        normalize_url: bool = False,
    ) -> bool:
        if actual is None or expected is None:
            return False

        actual_text = str(actual)
        expected_text = str(expected)

        if normalize_url:
            actual_text = self._normalize_url(actual_text)
            expected_text = self._normalize_url(expected_text)

        if mode == "exact":
            return actual_text == expected_text

        if mode == "normalized_exact":
            return actual_text.strip().rstrip("/") == expected_text.strip().rstrip("/")

        if mode == "contains":
            return expected_text in actual_text

        if mode == "case_insensitive_contains":
            return expected_text.lower() in actual_text.lower()

        if mode == "regex":
            return self._regex_search(expected_text, actual_text)

        return expected_text.lower() in actual_text.lower()

    def _regex_search(self, pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> bool:
        if not pattern or text is None:
            return False
        try:
            return re.search(pattern, text, flags=flags) is not None
        except re.error:
            self.logger.warning("Invalid regex pattern: %s", pattern)
            return False

    def _normalize_url(self, url: str) -> str:
        if not url:
            return ""

        url = url.strip()
        parsed = urlparse(url if "://" in url else f"https://{url}")

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or ""

        if path != "/":
            path = path.rstrip("/")

        query = parsed.query
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized = f"{normalized}?{query}"

        return normalized

    def _ensure_http_url(self, url: str) -> str:
        if "://" not in url:
            return f"https://{url}"
        return url

    def _looks_like_probeable_url(self, url: str) -> bool:
        candidate = self._ensure_http_url(url)
        parsed = urlparse(candidate)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _infer_loaded(self, *, url: Any, title: Any, content: Any) -> bool:
        url_text = str(url or "").strip().lower()
        title_text = str(title or "").strip()
        content_text = str(content or "").strip()

        if not url_text and not title_text and not content_text:
            return False

        if url_text.startswith(("about:blank", "chrome://newtab", "edge://newtab")):
            return False

        if content_text or title_text:
            return True

        return bool(url_text)

    def _deduplicate_snapshots(self, snapshots: Sequence[BrowserTabSnapshot]) -> List[BrowserTabSnapshot]:
        seen: set = set()
        deduped: List[BrowserTabSnapshot] = []

        for snapshot in snapshots:
            key = (
                snapshot.source,
                snapshot.index,
                snapshot.url,
                snapshot.title,
                snapshot.is_active,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(snapshot)

        return deduped

    def _infer_browser_name(self, driver: Any) -> Optional[str]:
        capabilities = self._safe_getattr(driver, "capabilities")
        if isinstance(capabilities, Mapping):
            for key in ("browserName", "browser_name", "browser"):
                value = capabilities.get(key)
                if value:
                    return str(value)

        name = driver.__class__.__name__.lower()
        for browser in DEFAULT_BROWSER_NAMES:
            if browser in name:
                return browser

        return None

    def _infer_playwright_browser_name(self, page: Any) -> Optional[str]:
        with contextlib.suppress(Exception):
            context = page.context
            browser = context.browser
            browser_type = browser.browser_type
            name = browser_type.name
            if name:
                return str(name)

        return None

    def _safe_getattr(self, obj: Any, attr: str, default: Any = None) -> Any:
        try:
            return getattr(obj, attr, default)
        except Exception:
            return default

    def _safe_call(self, obj: Any, method_name: str, *args: Any, **kwargs: Any) -> Any:
        try:
            method = getattr(obj, method_name)
            if callable(method):
                return method(*args, **kwargs)
            return method
        except Exception:
            return None

    def _call_or_attr(self, obj: Any, name: str) -> Any:
        value = self._safe_getattr(obj, name)
        if callable(value):
            with contextlib.suppress(Exception):
                return value()
        return value

    def _html_to_text(self, html: Optional[str]) -> Optional[str]:
        if not html:
            return None

        text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
        text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
        text = re.sub(r"(?is)<noscript.*?>.*?</noscript>", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = re.sub(r"&nbsp;", " ", text, flags=re.IGNORECASE)
        text = re.sub(r"&amp;", "&", text, flags=re.IGNORECASE)
        text = re.sub(r"&lt;", "<", text, flags=re.IGNORECASE)
        text = re.sub(r"&gt;", ">", text, flags=re.IGNORECASE)
        text = re.sub(r"&quot;", '"', text, flags=re.IGNORECASE)
        text = re.sub(r"&#39;", "'", text, flags=re.IGNORECASE)
        text = re.sub(r"\s+", " ", text).strip()

        return text or None

    def _extract_title_from_html(self, html: Optional[str]) -> Optional[str]:
        if not html:
            return None

        match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
        if not match:
            return None

        title = self._html_to_text(match.group(1))
        return title.strip() if title else None

    def _trim_content(self, content: Optional[Any]) -> Optional[str]:
        if content is None:
            return None

        text = str(content)
        if len(text) > self.config.max_content_chars:
            return text[: self.config.max_content_chars]

        return text

    def _none_if_empty(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    def _to_optional_bool(self, value: Any) -> Optional[bool]:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "yes", "1", "active", "loaded"}:
                return True
            if lowered in {"false", "no", "0", "inactive", "unloaded"}:
                return False
        return bool(value)

    def _to_optional_int(self, value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except Exception:
            return None

    def _safe_mapping(self, value: Mapping[str, Any]) -> Dict[str, Any]:
        return self._sanitize_for_output(dict(value))

    def _sanitize_for_output(self, value: Any) -> Any:
        """
        Redact secrets and convert objects into JSON-safe values.
        """
        if isinstance(value, Mapping):
            clean: Dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if any(secret_key in key_text.lower() for secret_key in SENSITIVE_KEYS):
                    clean[key_text] = "[REDACTED]"
                else:
                    clean[key_text] = self._sanitize_for_output(item)
            return clean

        if isinstance(value, (list, tuple, set)):
            return [self._sanitize_for_output(item) for item in value]

        if dataclasses.is_dataclass(value):
            return self._sanitize_for_output(dataclasses.asdict(value))

        if isinstance(value, (_dt.datetime, _dt.date)):
            return value.isoformat()

        if isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, str):
                return self._redact_sensitive_inline(value)
            return value

        try:
            json.dumps(value)
            return value
        except Exception:
            return repr(value)

    def _redact_sensitive_inline(self, text: str) -> str:
        redacted = text

        redaction_patterns = (
            r"(?i)(api[_-]?key\s*[:=]\s*)([^\s&]+)",
            r"(?i)(token\s*[:=]\s*)([^\s&]+)",
            r"(?i)(password\s*[:=]\s*)([^\s&]+)",
            r"(?i)(authorization\s*[:=]\s*)([^\s&]+)",
            r"(?i)(secret\s*[:=]\s*)([^\s&]+)",
        )

        for pattern in redaction_patterns:
            redacted = re.sub(pattern, r"\1[REDACTED]", redacted)

        return redacted

    def _safe_serialize(self, value: Any) -> Dict[str, Any]:
        sanitized = self._sanitize_for_output(value)
        if isinstance(sanitized, dict):
            return sanitized
        return {"value": sanitized}

    def _base_metadata(
        self,
        task_context: Mapping[str, Any],
        started_at: Optional[_dt.datetime] = None,
    ) -> Dict[str, Any]:
        now = self._utc_now()
        metadata = {
            "agent": "BrowserStateChecker",
            "module": "verification_agent",
            "file": "browser_state_checker.py",
            "user_id": task_context.get("user_id") if isinstance(task_context, Mapping) else None,
            "workspace_id": task_context.get("workspace_id") if isinstance(task_context, Mapping) else None,
            "timestamp": now.isoformat(),
        }

        if started_at:
            metadata["started_at"] = started_at.isoformat()
            metadata["duration_ms"] = round((now - started_at).total_seconds() * 1000, 2)

        return metadata

    def _utc_now(self) -> _dt.datetime:
        return _dt.datetime.now(tz=_dt.timezone.utc)

    def _utc_now_iso(self) -> str:
        return self._utc_now().isoformat()


# ======================================================================================
# Module-level helpers for Registry/Loader compatibility
# ======================================================================================

def get_agent_class() -> type:
    """
    Registry/Agent Loader compatibility helper.
    """
    return BrowserStateChecker


def create_agent(**kwargs: Any) -> BrowserStateChecker:
    """
    Factory helper for dynamic loaders.
    """
    return BrowserStateChecker(**kwargs)


def health_check() -> Dict[str, Any]:
    """
    Lightweight import/health check for dashboard/API.
    """
    checker = BrowserStateChecker()
    return checker._safe_result(
        success=True,
        message="BrowserStateChecker is importable and ready.",
        data={
            "agent": "BrowserStateChecker",
            "public_methods": list(BrowserStateChecker.public_methods),
            "http_probe_default": checker.config.allow_http_probe,
        },
        metadata={
            "module": "verification_agent",
            "file": "browser_state_checker.py",
            "timestamp": checker._utc_now_iso(),
        },
    )


__all__ = [
    "BrowserStateChecker",
    "BrowserStateCheckerConfig",
    "BrowserCheckCriteria",
    "BrowserTabSnapshot",
    "BrowserCheckFinding",
    "get_agent_class",
    "create_agent",
    "health_check",
]