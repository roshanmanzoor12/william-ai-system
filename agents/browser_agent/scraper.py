"""
William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File: agents/browser_agent/scraper.py
Agent/Module: Browser Agent
Purpose: Fetches public pages and extracts visible data safely.

This file is designed to be:
- Import-safe even if the rest of the William/Jarvis system is not created yet.
- Compatible with BaseAgent, Agent Registry, Agent Loader, Router, and Master Agent routing.
- SaaS-ready with strict user_id and workspace_id context validation.
- Security-aware for any network/browser-related action.
- Verification-ready for completed task payloads.
- Memory-compatible for safe contextual summaries.
- Dashboard/API-ready with structured dict/JSON-style results.

Public Class:
- Scraper

Main Public Methods:
- fetch_page()
- extract_visible_data()
- scrape()
- scrape_many()
- health_check()
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import logging
import re
import socket
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    from bs4 import BeautifulSoup, Comment
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore
    Comment = None  # type: ignore


# ---------------------------------------------------------------------------
# Optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    try:
        from agents.base_agent.base_agent import BaseAgent  # type: ignore
    except Exception:  # pragma: no cover

        class BaseAgent:  # type: ignore
            """
            Fallback BaseAgent stub.

            This keeps scraper.py safe to import before the complete William/Jarvis
            project structure exists.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.agent_type = kwargs.get("agent_type", "browser_agent")
                self.logger = logging.getLogger(self.agent_name)

            def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
                return {
                    "success": False,
                    "message": "Fallback BaseAgent run() is not implemented.",
                    "data": {},
                    "error": "BASE_AGENT_NOT_AVAILABLE",
                    "metadata": {},
                }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.BrowserAgent.Scraper")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_USER_AGENT = (
    "WilliamJarvisBrowserAgent/1.0 "
    "(Safe public page scraper; +https://digitalpromotix.dev)"
)

BLOCKED_SCHEMES = {
    "file",
    "ftp",
    "ftps",
    "gopher",
    "mailto",
    "tel",
    "javascript",
    "data",
    "blob",
    "chrome",
    "chrome-extension",
    "about",
}

DEFAULT_ALLOWED_SCHEMES = {"http", "https"}

PRIVATE_HOST_KEYWORDS = {
    "localhost",
    "metadata.google.internal",
}

DEFAULT_TIMEOUT_SECONDS = 12
DEFAULT_MAX_BYTES = 2_000_000
DEFAULT_MAX_TEXT_CHARS = 100_000
DEFAULT_MAX_LINKS = 250
DEFAULT_MAX_IMAGES = 150
DEFAULT_MAX_HEADINGS = 150
DEFAULT_MAX_PARAGRAPHS = 300

VISIBLE_TEXT_SEPARATOR = "\n"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ScraperConfig:
    """
    Runtime configuration for safe public web scraping.

    The defaults are intentionally conservative for SaaS production usage.
    """

    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_BYTES
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
    max_links: int = DEFAULT_MAX_LINKS
    max_images: int = DEFAULT_MAX_IMAGES
    max_headings: int = DEFAULT_MAX_HEADINGS
    max_paragraphs: int = DEFAULT_MAX_PARAGRAPHS
    user_agent: str = DEFAULT_USER_AGENT
    allow_private_networks: bool = False
    allow_redirects: bool = True
    verify_ssl: bool = True
    allowed_schemes: set = field(default_factory=lambda: set(DEFAULT_ALLOWED_SCHEMES))
    blocked_schemes: set = field(default_factory=lambda: set(BLOCKED_SCHEMES))
    allowed_content_types: Tuple[str, ...] = (
        "text/html",
        "application/xhtml+xml",
        "text/plain",
    )
    strip_scripts: bool = True
    strip_styles: bool = True
    normalize_whitespace: bool = True
    collect_links: bool = True
    collect_images: bool = True
    collect_meta: bool = True
    collect_headings: bool = True
    collect_paragraphs: bool = True
    include_raw_html: bool = False


@dataclass
class FetchResponse:
    """
    Internal normalized fetch response.
    """

    url: str
    final_url: str
    status_code: int
    content_type: str
    encoding: Optional[str]
    elapsed_ms: int
    headers: Dict[str, str]
    text: str
    size_bytes: int


@dataclass
class ScrapeContext:
    """
    SaaS execution context.

    Every user-specific task must include user_id and workspace_id to prevent
    accidental cross-user data mixing.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    task_id: Optional[str] = None
    agent_run_id: Optional[str] = None
    request_id: Optional[str] = None
    source: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scraper
# ---------------------------------------------------------------------------

class Scraper(BaseAgent):
    """
    Browser Agent helper responsible for safely fetching public pages and
    extracting visible data.

    This class is intentionally not a full browser automation engine.
    It does not click, login, submit forms, bypass protections, scrape private
    systems, evade anti-bot controls, or perform destructive actions.

    It is safe to route through:
    - Master Agent
    - Browser Agent
    - Agent Registry
    - Agent Loader
    - Agent Router
    - Future FastAPI endpoints
    """

    public_methods = [
        "fetch_page",
        "extract_visible_data",
        "scrape",
        "scrape_many",
        "health_check",
    ]

    def __init__(
        self,
        config: Optional[ScraperConfig] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", "BrowserScraper"),
            agent_type=kwargs.pop("agent_type", "browser_agent"),
            *args,
            **kwargs,
        )

        self.config = config or ScraperConfig()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.logger = logging.getLogger("William.BrowserAgent.Scraper")

    # -----------------------------------------------------------------------
    # BaseAgent / Router compatible entry point
    # -----------------------------------------------------------------------

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Generic router-compatible entry point.

        Expected task example:
        {
            "action": "scrape",
            "url": "https://example.com",
            "user_id": "1",
            "workspace_id": "default"
        }
        """

        task = task or {}
        merged = {**task, **kwargs}
        action = str(merged.get("action", "scrape")).strip().lower()

        context = {
            "user_id": merged.get("user_id"),
            "workspace_id": merged.get("workspace_id"),
            "role": merged.get("role"),
            "task_id": merged.get("task_id"),
            "agent_run_id": merged.get("agent_run_id"),
            "request_id": merged.get("request_id"),
            "source": merged.get("source", "router"),
            "permissions": merged.get("permissions", {}),
        }

        if action in {"scrape", "scrape_page"}:
            return self.scrape(
                url=str(merged.get("url", "")),
                context=context,
                options=merged.get("options") or {},
            )

        if action in {"fetch", "fetch_page"}:
            return self.fetch_page(
                url=str(merged.get("url", "")),
                context=context,
                options=merged.get("options") or {},
            )

        if action in {"scrape_many", "bulk_scrape"}:
            urls = merged.get("urls") or []
            return self.scrape_many(
                urls=urls,
                context=context,
                options=merged.get("options") or {},
            )

        if action in {"health", "health_check"}:
            return self.health_check(context=context)

        return self._error_result(
            message=f"Unsupported Scraper action: {action}",
            error="UNSUPPORTED_ACTION",
            metadata={"action": action},
        )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def fetch_page(
        self,
        url: str,
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch a public page safely and return normalized response data.

        This method does not parse or extract structured content beyond
        network-level fetch details.
        """

        started = time.time()
        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        safe_url_result = self._validate_public_url(url)
        if not safe_url_result["success"]:
            return safe_url_result

        normalized_url = safe_url_result["data"]["url"]

        security_result = self._request_security_approval(
            action="browser.fetch_page",
            url=normalized_url,
            context=ctx_result["data"]["context"],
            options=options,
        )
        if not security_result["success"]:
            return security_result

        self._emit_agent_event(
            event_name="scraper.fetch.started",
            context=ctx_result["data"]["context"],
            payload={"url": normalized_url},
        )

        self._log_audit_event(
            action="browser.fetch_page.started",
            context=ctx_result["data"]["context"],
            payload={"url": normalized_url},
        )

        try:
            fetch_response = self._perform_http_fetch(normalized_url, options=options)
            payload = asdict(fetch_response)

            result = self._safe_result(
                message="Page fetched successfully.",
                data=payload,
                metadata={
                    "agent": "Scraper",
                    "elapsed_ms": self._elapsed_ms(started),
                    "verification": self._prepare_verification_payload(
                        action="browser.fetch_page",
                        context=ctx_result["data"]["context"],
                        data=payload,
                    ),
                    "memory": self._prepare_memory_payload(
                        action="browser.fetch_page",
                        context=ctx_result["data"]["context"],
                        data=payload,
                    ),
                },
            )

            self._emit_agent_event(
                event_name="scraper.fetch.completed",
                context=ctx_result["data"]["context"],
                payload={
                    "url": normalized_url,
                    "final_url": fetch_response.final_url,
                    "status_code": fetch_response.status_code,
                },
            )

            self._log_audit_event(
                action="browser.fetch_page.completed",
                context=ctx_result["data"]["context"],
                payload={
                    "url": normalized_url,
                    "final_url": fetch_response.final_url,
                    "status_code": fetch_response.status_code,
                    "elapsed_ms": self._elapsed_ms(started),
                },
            )

            return result

        except Exception as exc:
            self.logger.warning("Fetch failed for %s: %s", normalized_url, exc)
            self._log_audit_event(
                action="browser.fetch_page.failed",
                context=ctx_result["data"]["context"],
                payload={
                    "url": normalized_url,
                    "error": str(exc),
                    "elapsed_ms": self._elapsed_ms(started),
                },
            )
            return self._error_result(
                message="Page fetch failed.",
                error=str(exc),
                metadata={
                    "url": normalized_url,
                    "elapsed_ms": self._elapsed_ms(started),
                    "trace": traceback.format_exc(limit=3),
                },
            )

    def extract_visible_data(
        self,
        html_text: str,
        base_url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract visible text and safe public page data from HTML.

        Extracted fields:
        - title
        - meta description
        - canonical URL
        - headings
        - paragraphs
        - visible text
        - links
        - images
        - text hash
        """

        started = time.time()
        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        if not isinstance(html_text, str) or not html_text.strip():
            return self._error_result(
                message="HTML text is empty or invalid.",
                error="INVALID_HTML_TEXT",
                metadata={"base_url": base_url},
            )

        if base_url:
            safe_url_result = self._validate_public_url(base_url)
            if not safe_url_result["success"]:
                return safe_url_result
            base_url = safe_url_result["data"]["url"]

        security_result = self._request_security_approval(
            action="browser.extract_visible_data",
            url=base_url,
            context=ctx_result["data"]["context"],
            options=options,
        )
        if not security_result["success"]:
            return security_result

        try:
            extracted = self._extract_from_html(
                html_text=html_text,
                base_url=base_url,
                options=options,
            )

            result = self._safe_result(
                message="Visible data extracted successfully.",
                data=extracted,
                metadata={
                    "agent": "Scraper",
                    "elapsed_ms": self._elapsed_ms(started),
                    "verification": self._prepare_verification_payload(
                        action="browser.extract_visible_data",
                        context=ctx_result["data"]["context"],
                        data=extracted,
                    ),
                    "memory": self._prepare_memory_payload(
                        action="browser.extract_visible_data",
                        context=ctx_result["data"]["context"],
                        data=extracted,
                    ),
                },
            )

            self._emit_agent_event(
                event_name="scraper.extract.completed",
                context=ctx_result["data"]["context"],
                payload={
                    "base_url": base_url,
                    "text_chars": len(extracted.get("visible_text", "")),
                    "links_count": len(extracted.get("links", [])),
                },
            )

            self._log_audit_event(
                action="browser.extract_visible_data.completed",
                context=ctx_result["data"]["context"],
                payload={
                    "base_url": base_url,
                    "text_chars": len(extracted.get("visible_text", "")),
                    "links_count": len(extracted.get("links", [])),
                    "elapsed_ms": self._elapsed_ms(started),
                },
            )

            return result

        except Exception as exc:
            self.logger.warning("Extraction failed for %s: %s", base_url, exc)
            return self._error_result(
                message="Visible data extraction failed.",
                error=str(exc),
                metadata={
                    "base_url": base_url,
                    "elapsed_ms": self._elapsed_ms(started),
                    "trace": traceback.format_exc(limit=3),
                },
            )

    def scrape(
        self,
        url: str,
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch a public page and extract visible data in one safe workflow.
        """

        started = time.time()
        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        safe_url_result = self._validate_public_url(url)
        if not safe_url_result["success"]:
            return safe_url_result

        normalized_url = safe_url_result["data"]["url"]

        security_result = self._request_security_approval(
            action="browser.scrape",
            url=normalized_url,
            context=ctx_result["data"]["context"],
            options=options,
        )
        if not security_result["success"]:
            return security_result

        self._emit_agent_event(
            event_name="scraper.scrape.started",
            context=ctx_result["data"]["context"],
            payload={"url": normalized_url},
        )

        self._log_audit_event(
            action="browser.scrape.started",
            context=ctx_result["data"]["context"],
            payload={"url": normalized_url},
        )

        fetch_result = self.fetch_page(
            url=normalized_url,
            context=ctx_result["data"]["context"],
            options=options,
        )

        if not fetch_result.get("success"):
            return fetch_result

        fetch_data = fetch_result.get("data", {})
        html_text = fetch_data.get("text", "")
        final_url = fetch_data.get("final_url") or normalized_url

        extract_result = self.extract_visible_data(
            html_text=html_text,
            base_url=final_url,
            context=ctx_result["data"]["context"],
            options=options,
        )

        if not extract_result.get("success"):
            return extract_result

        scrape_data = {
            "url": normalized_url,
            "final_url": final_url,
            "status_code": fetch_data.get("status_code"),
            "content_type": fetch_data.get("content_type"),
            "encoding": fetch_data.get("encoding"),
            "size_bytes": fetch_data.get("size_bytes"),
            "fetch_elapsed_ms": fetch_data.get("elapsed_ms"),
            "extracted": extract_result.get("data", {}),
        }

        result = self._safe_result(
            message="Page scraped successfully.",
            data=scrape_data,
            metadata={
                "agent": "Scraper",
                "elapsed_ms": self._elapsed_ms(started),
                "verification": self._prepare_verification_payload(
                    action="browser.scrape",
                    context=ctx_result["data"]["context"],
                    data=scrape_data,
                ),
                "memory": self._prepare_memory_payload(
                    action="browser.scrape",
                    context=ctx_result["data"]["context"],
                    data=scrape_data,
                ),
            },
        )

        self._emit_agent_event(
            event_name="scraper.scrape.completed",
            context=ctx_result["data"]["context"],
            payload={
                "url": normalized_url,
                "final_url": final_url,
                "status_code": fetch_data.get("status_code"),
                "visible_text_chars": len(
                    scrape_data.get("extracted", {}).get("visible_text", "")
                ),
            },
        )

        self._log_audit_event(
            action="browser.scrape.completed",
            context=ctx_result["data"]["context"],
            payload={
                "url": normalized_url,
                "final_url": final_url,
                "status_code": fetch_data.get("status_code"),
                "elapsed_ms": self._elapsed_ms(started),
            },
        )

        return result

    def scrape_many(
        self,
        urls: Iterable[str],
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Safely scrape multiple public URLs.

        This method processes URLs sequentially by default to keep behavior
        predictable and safer for SaaS usage.
        """

        started = time.time()
        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        if not urls:
            return self._error_result(
                message="No URLs provided.",
                error="NO_URLS_PROVIDED",
                metadata={},
            )

        url_list = [str(u).strip() for u in urls if str(u).strip()]
        max_urls = int(options.get("max_urls", 10))

        if len(url_list) > max_urls:
            url_list = url_list[:max_urls]

        security_result = self._request_security_approval(
            action="browser.scrape_many",
            url=None,
            context=ctx_result["data"]["context"],
            options={**options, "url_count": len(url_list)},
        )
        if not security_result["success"]:
            return security_result

        results: List[Dict[str, Any]] = []
        success_count = 0
        failure_count = 0

        for target_url in url_list:
            item_result = self.scrape(
                url=target_url,
                context=ctx_result["data"]["context"],
                options=options,
            )
            results.append(item_result)
            if item_result.get("success"):
                success_count += 1
            else:
                failure_count += 1

        data = {
            "total": len(url_list),
            "success_count": success_count,
            "failure_count": failure_count,
            "results": results,
        }

        return self._safe_result(
            message="Bulk scrape completed.",
            data=data,
            metadata={
                "agent": "Scraper",
                "elapsed_ms": self._elapsed_ms(started),
                "verification": self._prepare_verification_payload(
                    action="browser.scrape_many",
                    context=ctx_result["data"]["context"],
                    data=data,
                ),
                "memory": self._prepare_memory_payload(
                    action="browser.scrape_many",
                    context=ctx_result["data"]["context"],
                    data=data,
                ),
            },
        )

    def health_check(
        self,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Lightweight health check for Dashboard/API integration.
        """

        ctx_result = self._validate_task_context(context, allow_system=True)
        if not ctx_result["success"]:
            return ctx_result

        data = {
            "agent": "Scraper",
            "status": "healthy",
            "requests_available": requests is not None,
            "beautifulsoup_available": BeautifulSoup is not None,
            "config": {
                "timeout_seconds": self.config.timeout_seconds,
                "max_response_bytes": self.config.max_response_bytes,
                "allow_private_networks": self.config.allow_private_networks,
                "allowed_schemes": sorted(list(self.config.allowed_schemes)),
            },
            "public_methods": self.public_methods,
            "timestamp": self._utc_now(),
        }

        return self._safe_result(
            message="Scraper health check completed.",
            data=data,
            metadata={"agent": "Scraper"},
        )

    # -----------------------------------------------------------------------
    # Required Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Dict[str, Any]],
        allow_system: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Every user-specific Browser Agent action must include user_id and
        workspace_id. This prevents mixing tasks, memory, files, logs, or
        analytics between SaaS accounts.
        """

        context = context or {}

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if allow_system and not user_id and not workspace_id:
            user_id = "system"
            workspace_id = "system"

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing required user_id for SaaS isolation.",
                error="MISSING_USER_ID",
                metadata={"required": ["user_id", "workspace_id"]},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing required workspace_id for SaaS isolation.",
                error="MISSING_WORKSPACE_ID",
                metadata={"required": ["user_id", "workspace_id"]},
            )

        safe_context = ScrapeContext(
            user_id=str(user_id).strip(),
            workspace_id=str(workspace_id).strip(),
            role=self._optional_str(context.get("role")),
            task_id=self._optional_str(context.get("task_id")),
            agent_run_id=self._optional_str(context.get("agent_run_id")),
            request_id=self._optional_str(context.get("request_id")),
            source=self._optional_str(context.get("source")),
            permissions=context.get("permissions") or {},
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": asdict(safe_context)},
            metadata={"isolation": "user_workspace_scoped"},
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Browser/network actions require security approval.
        """

        protected_actions = {
            "browser.fetch_page",
            "browser.extract_visible_data",
            "browser.scrape",
            "browser.scrape_many",
        }
        return action in protected_actions

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        url: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when available.

        If Security Agent is not wired yet, this method applies local safe
        default checks and returns approval only for public, non-destructive
        scraping actions.
        """

        options = options or {}

        if not self._requires_security_check(action):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "mode": "not_required"},
                metadata={"action": action},
            )

        if url:
            url_result = self._validate_public_url(url)
            if not url_result["success"]:
                return url_result

        local_policy = self._local_security_policy(action=action, url=url, options=options)
        if not local_policy["success"]:
            return local_policy

        if self.security_agent is not None:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    approval = self.security_agent.approve_action(
                        action=action,
                        context=context,
                        target=url,
                        metadata=options,
                    )
                elif hasattr(self.security_agent, "run"):
                    approval = self.security_agent.run(
                        {
                            "action": "approve_action",
                            "requested_action": action,
                            "target": url,
                            "context": context,
                            "metadata": options,
                        }
                    )
                else:
                    approval = None

                if isinstance(approval, dict):
                    if approval.get("success") is False or approval.get("approved") is False:
                        return self._error_result(
                            message="Security Agent rejected this browser action.",
                            error="SECURITY_AGENT_REJECTED",
                            metadata={
                                "action": action,
                                "url": url,
                                "security_response": approval,
                            },
                        )

                    return self._safe_result(
                        message="Security Agent approved browser action.",
                        data={"approved": True, "mode": "security_agent"},
                        metadata={
                            "action": action,
                            "url": url,
                            "security_response": approval,
                        },
                    )

            except Exception as exc:
                return self._error_result(
                    message="Security Agent approval failed.",
                    error=str(exc),
                    metadata={
                        "action": action,
                        "url": url,
                        "trace": traceback.format_exc(limit=3),
                    },
                )

        return self._safe_result(
            message="Local security policy approved browser action.",
            data={"approved": True, "mode": "local_policy"},
            metadata={"action": action, "url": url},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This does not call the Verification Agent directly by default; it
        creates a clean payload that Master Agent or Router can forward.
        """

        payload = {
            "verification_type": "browser_scrape_result",
            "agent": "Scraper",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "timestamp": self._utc_now(),
            "checks": {
                "has_success_flag": True,
                "has_structured_data": isinstance(data, dict),
                "contains_user_scope": bool(context.get("user_id"))
                and bool(context.get("workspace_id")),
                "non_destructive": True,
            },
            "summary": self._verification_summary(data),
        }

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        The payload intentionally avoids storing full raw HTML. It stores safe
        summaries and page metadata only.
        """

        extracted = data.get("extracted", data)
        title = extracted.get("title") if isinstance(extracted, dict) else None
        description = extracted.get("description") if isinstance(extracted, dict) else None
        visible_text = extracted.get("visible_text", "") if isinstance(extracted, dict) else ""

        summary_text = self._truncate_text(
            self._normalize_space(f"{title or ''} {description or ''} {visible_text or ''}"),
            1000,
        )

        return {
            "memory_type": "browser_page_context",
            "agent": "Scraper",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "timestamp": self._utc_now(),
            "safe_to_store": True,
            "data": {
                "url": data.get("url") or data.get("final_url") or extracted.get("url"),
                "final_url": data.get("final_url") or extracted.get("final_url"),
                "title": title,
                "description": description,
                "summary": summary_text,
                "text_hash": extracted.get("text_hash") if isinstance(extracted, dict) else None,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit Browser Agent event for future dashboard/event bus integration.
        """

        event = {
            "event": event_name,
            "agent": "Scraper",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "timestamp": self._utc_now(),
            "payload": payload or {},
        }

        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit"):
                    self.event_bus.emit(event_name, event)
                elif hasattr(self.event_bus, "publish"):
                    self.event_bus.publish(event_name, event)
                return

            self.logger.debug("Agent event: %s", event)

        except Exception as exc:
            self.logger.warning("Failed to emit agent event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event scoped to user_id and workspace_id.

        This prevents sensitive Browser Agent actions from becoming invisible
        in a SaaS dashboard.
        """

        audit_payload = {
            "action": action,
            "agent": "Scraper",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "timestamp": self._utc_now(),
            "payload": payload or {},
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit_payload)
                elif hasattr(self.audit_logger, "write"):
                    self.audit_logger.write(audit_payload)
                return

            self.logger.info("Audit event: %s", audit_payload)

        except Exception as exc:
            self.logger.warning("Failed to log audit event %s: %s", action, exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success response.
        """

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
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error),
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Fetching
    # -----------------------------------------------------------------------

    def _perform_http_fetch(
        self,
        url: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> FetchResponse:
        """
        Perform safe HTTP GET fetch with response size limits.
        """

        options = options or {}

        if requests is None:
            raise RuntimeError(
                "The 'requests' package is required for HTTP fetching. "
                "Install it with: pip install requests"
            )

        timeout_seconds = int(options.get("timeout_seconds", self.config.timeout_seconds))
        max_response_bytes = int(
            options.get("max_response_bytes", self.config.max_response_bytes)
        )

        headers = {
            "User-Agent": str(options.get("user_agent", self.config.user_agent)),
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }

        started = time.time()

        response = requests.get(
            url,
            headers=headers,
            timeout=timeout_seconds,
            allow_redirects=bool(options.get("allow_redirects", self.config.allow_redirects)),
            verify=bool(options.get("verify_ssl", self.config.verify_ssl)),
            stream=True,
        )

        content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type and not self._is_allowed_content_type(content_type):
            response.close()
            raise ValueError(f"Unsupported content type: {content_type}")

        content_chunks: List[bytes] = []
        total = 0

        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue

            total += len(chunk)

            if total > max_response_bytes:
                response.close()
                raise ValueError(
                    f"Response exceeds max_response_bytes limit: {max_response_bytes}"
                )

            content_chunks.append(chunk)

        raw = b"".join(content_chunks)
        encoding = response.encoding or response.apparent_encoding or "utf-8"

        try:
            text = raw.decode(encoding, errors="replace")
        except Exception:
            text = raw.decode("utf-8", errors="replace")

        return FetchResponse(
            url=url,
            final_url=str(response.url),
            status_code=int(response.status_code),
            content_type=content_type or "unknown",
            encoding=encoding,
            elapsed_ms=self._elapsed_ms(started),
            headers=self._safe_headers(dict(response.headers)),
            text=text,
            size_bytes=len(raw),
        )

    def _is_allowed_content_type(self, content_type: str) -> bool:
        """
        Check content type against allow list.
        """

        if not content_type:
            return True

        normalized = content_type.lower().strip()
        return any(normalized.startswith(allowed) for allowed in self.config.allowed_content_types)

    def _safe_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        """
        Return safe response headers without cookies or sensitive data.
        """

        blocked = {
            "set-cookie",
            "cookie",
            "authorization",
            "proxy-authorization",
            "x-api-key",
        }

        safe: Dict[str, str] = {}
        for key, value in headers.items():
            normalized_key = str(key).lower().strip()
            if normalized_key in blocked:
                continue
            safe[str(key)] = self._truncate_text(str(value), 500)

        return safe

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def _extract_from_html(
        self,
        html_text: str,
        base_url: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract visible data from HTML using BeautifulSoup when available,
        otherwise fallback to a minimal regex-based extraction.
        """

        options = options or {}

        if BeautifulSoup is None:
            return self._extract_with_regex_fallback(html_text, base_url, options)

        soup = BeautifulSoup(html_text, "html.parser")

        if self.config.strip_scripts:
            for tag in soup(["script", "noscript"]):
                tag.decompose()

        if self.config.strip_styles:
            for tag in soup(["style"]):
                tag.decompose()

        for tag in soup(["template", "svg", "canvas"]):
            tag.decompose()

        if Comment is not None:
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                comment.extract()

        title = self._extract_title(soup)
        description = self._extract_meta_description(soup)
        canonical_url = self._extract_canonical_url(soup, base_url)
        language = self._extract_language(soup)

        headings = []
        if self.config.collect_headings and options.get("collect_headings", True):
            headings = self._extract_headings(soup)

        paragraphs = []
        if self.config.collect_paragraphs and options.get("collect_paragraphs", True):
            paragraphs = self._extract_paragraphs(soup)

        links = []
        if self.config.collect_links and options.get("collect_links", True):
            links = self._extract_links(soup, base_url)

        images = []
        if self.config.collect_images and options.get("collect_images", True):
            images = self._extract_images(soup, base_url)

        visible_text = self._extract_visible_text(soup)
        visible_text = self._truncate_text(
            visible_text,
            int(options.get("max_text_chars", self.config.max_text_chars)),
        )

        data: Dict[str, Any] = {
            "url": base_url,
            "final_url": base_url,
            "title": title,
            "description": description,
            "canonical_url": canonical_url,
            "language": language,
            "headings": headings,
            "paragraphs": paragraphs,
            "links": links,
            "images": images,
            "visible_text": visible_text,
            "visible_text_length": len(visible_text),
            "text_hash": self._hash_text(visible_text),
            "extracted_at": self._utc_now(),
            "extractor": "beautifulsoup" if BeautifulSoup is not None else "regex_fallback",
        }

        if bool(options.get("include_raw_html", self.config.include_raw_html)):
            data["raw_html"] = self._truncate_text(
                html_text,
                int(options.get("max_raw_html_chars", 250_000)),
            )

        return data

    def _extract_with_regex_fallback(
        self,
        html_text: str,
        base_url: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Minimal extraction fallback if BeautifulSoup is unavailable.
        """

        options = options or {}

        title_match = re.search(
            r"<title[^>]*>(.*?)</title>",
            html_text,
            flags=re.IGNORECASE | re.DOTALL,
        )

        title = self._clean_text(title_match.group(1)) if title_match else None

        no_script = re.sub(
            r"<(script|style|noscript)[^>]*>.*?</\1>",
            " ",
            html_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        no_tags = re.sub(r"<[^>]+>", " ", no_script)
        visible_text = self._clean_text(html.unescape(no_tags))
        visible_text = self._truncate_text(
            visible_text,
            int(options.get("max_text_chars", self.config.max_text_chars)),
        )

        return {
            "url": base_url,
            "final_url": base_url,
            "title": title,
            "description": None,
            "canonical_url": None,
            "language": None,
            "headings": [],
            "paragraphs": [],
            "links": [],
            "images": [],
            "visible_text": visible_text,
            "visible_text_length": len(visible_text),
            "text_hash": self._hash_text(visible_text),
            "extracted_at": self._utc_now(),
            "extractor": "regex_fallback",
        }

    def _extract_title(self, soup: Any) -> Optional[str]:
        title_tag = soup.find("title")
        if not title_tag:
            og_title = soup.find("meta", attrs={"property": "og:title"})
            if og_title and og_title.get("content"):
                return self._clean_text(str(og_title.get("content")))
            return None

        return self._clean_text(title_tag.get_text(" ", strip=True))

    def _extract_meta_description(self, soup: Any) -> Optional[str]:
        selectors = [
            {"name": "description"},
            {"property": "og:description"},
            {"name": "twitter:description"},
        ]

        for selector in selectors:
            tag = soup.find("meta", attrs=selector)
            if tag and tag.get("content"):
                return self._clean_text(str(tag.get("content")))

        return None

    def _extract_canonical_url(self, soup: Any, base_url: str) -> Optional[str]:
        canonical = soup.find("link", attrs={"rel": lambda value: value and "canonical" in value})
        if canonical and canonical.get("href"):
            return self._safe_join_url(base_url, str(canonical.get("href")))
        return None

    def _extract_language(self, soup: Any) -> Optional[str]:
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            return self._clean_text(str(html_tag.get("lang")))
        return None

    def _extract_headings(self, soup: Any) -> List[Dict[str, Any]]:
        headings: List[Dict[str, Any]] = []

        for tag in soup.find_all(re.compile("^h[1-6]$")):
            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text:
                continue

            headings.append(
                {
                    "level": str(tag.name).lower(),
                    "text": self._truncate_text(text, 500),
                }
            )

            if len(headings) >= self.config.max_headings:
                break

        return headings

    def _extract_paragraphs(self, soup: Any) -> List[str]:
        paragraphs: List[str] = []

        for tag in soup.find_all(["p", "li"]):
            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text or len(text) < 2:
                continue

            paragraphs.append(self._truncate_text(text, 1000))

            if len(paragraphs) >= self.config.max_paragraphs:
                break

        return paragraphs

    def _extract_links(self, soup: Any, base_url: str) -> List[Dict[str, Any]]:
        links: List[Dict[str, Any]] = []
        seen = set()

        for tag in soup.find_all("a", href=True):
            href = str(tag.get("href", "")).strip()
            if not href:
                continue

            full_url = self._safe_join_url(base_url, href)
            if not full_url:
                continue

            parsed = urlparse(full_url)
            if parsed.scheme.lower() in self.config.blocked_schemes:
                continue

            text = self._clean_text(tag.get_text(" ", strip=True))
            key = (full_url, text)

            if key in seen:
                continue
            seen.add(key)

            links.append(
                {
                    "url": full_url,
                    "text": self._truncate_text(text, 300),
                    "rel": self._safe_attr_list(tag.get("rel")),
                    "target": self._optional_str(tag.get("target")),
                }
            )

            if len(links) >= self.config.max_links:
                break

        return links

    def _extract_images(self, soup: Any, base_url: str) -> List[Dict[str, Any]]:
        images: List[Dict[str, Any]] = []
        seen = set()

        for tag in soup.find_all("img"):
            src = str(tag.get("src", "")).strip()
            if not src:
                continue

            full_url = self._safe_join_url(base_url, src)
            if not full_url:
                continue

            if full_url in seen:
                continue
            seen.add(full_url)

            images.append(
                {
                    "url": full_url,
                    "alt": self._truncate_text(
                        self._clean_text(str(tag.get("alt", ""))),
                        300,
                    ),
                    "title": self._truncate_text(
                        self._clean_text(str(tag.get("title", ""))),
                        300,
                    ),
                    "width": self._optional_str(tag.get("width")),
                    "height": self._optional_str(tag.get("height")),
                }
            )

            if len(images) >= self.config.max_images:
                break

        return images

    def _extract_visible_text(self, soup: Any) -> str:
        """
        Extract readable visible text.
        """

        body = soup.find("body") or soup
        text = body.get_text(VISIBLE_TEXT_SEPARATOR, strip=True)
        return self._clean_text(text, multiline=True)

    # -----------------------------------------------------------------------
    # URL Safety
    # -----------------------------------------------------------------------

    def _validate_public_url(self, url: str) -> Dict[str, Any]:
        """
        Validate that the target URL is public and safe to fetch.

        Blocks:
        - unsupported schemes
        - localhost/private IPs by default
        - internal hostnames
        - malformed URLs
        """

        if not isinstance(url, str) or not url.strip():
            return self._error_result(
                message="URL is required.",
                error="INVALID_URL",
                metadata={},
            )

        normalized_url = self._normalize_url(url)
        parsed = urlparse(normalized_url)

        if not parsed.scheme:
            return self._error_result(
                message="URL must include http or https scheme.",
                error="URL_SCHEME_REQUIRED",
                metadata={"url": url},
            )

        scheme = parsed.scheme.lower().strip()

        if scheme in self.config.blocked_schemes:
            return self._error_result(
                message=f"Blocked URL scheme: {scheme}",
                error="BLOCKED_URL_SCHEME",
                metadata={"url": url, "scheme": scheme},
            )

        if scheme not in self.config.allowed_schemes:
            return self._error_result(
                message=f"Unsupported URL scheme: {scheme}",
                error="UNSUPPORTED_URL_SCHEME",
                metadata={"url": url, "scheme": scheme},
            )

        hostname = parsed.hostname
        if not hostname:
            return self._error_result(
                message="URL hostname is missing.",
                error="MISSING_HOSTNAME",
                metadata={"url": url},
            )

        host_lower = hostname.lower().strip(".")

        if host_lower in PRIVATE_HOST_KEYWORDS:
            return self._error_result(
                message="Private/local hostnames are blocked.",
                error="PRIVATE_HOST_BLOCKED",
                metadata={"url": url, "hostname": host_lower},
            )

        if not self.config.allow_private_networks:
            private_check = self._is_private_or_local_hostname(host_lower)
            if private_check:
                return self._error_result(
                    message="Private/local network targets are blocked.",
                    error="PRIVATE_NETWORK_BLOCKED",
                    metadata={"url": url, "hostname": host_lower},
                )

        return self._safe_result(
            message="URL validated.",
            data={"url": normalized_url, "hostname": host_lower, "scheme": scheme},
            metadata={"public_url": True},
        )

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL while preserving path/query.
        """

        raw = url.strip()

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = "https://" + raw

        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.strip()
        path = parsed.path or "/"

        normalized = urlunparse(
            (
                scheme,
                netloc,
                path,
                "",
                parsed.query,
                "",
            )
        )

        return normalized

    def _safe_join_url(self, base_url: str, href: str) -> Optional[str]:
        """
        Safely convert relative URL to absolute URL.
        """

        if not href:
            return None

        href = href.strip()

        if href.startswith("#"):
            return None

        parsed = urlparse(href)
        if parsed.scheme and parsed.scheme.lower() in self.config.blocked_schemes:
            return None

        try:
            joined = urljoin(base_url or "", href)
            parsed_joined = urlparse(joined)

            if parsed_joined.scheme.lower() in self.config.blocked_schemes:
                return None

            if parsed_joined.scheme.lower() not in self.config.allowed_schemes:
                return None

            return joined

        except Exception:
            return None

    def _is_private_or_local_hostname(self, hostname: str) -> bool:
        """
        Check whether hostname resolves to private/local IP.
        """

        host = hostname.strip().lower()

        if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
            return True

        try:
            ip_obj = ipaddress.ip_address(host)
            return self._is_private_ip(ip_obj)
        except ValueError:
            pass

        try:
            resolved_items = socket.getaddrinfo(host, None)
        except Exception:
            # If DNS cannot resolve, do not assume private.
            return False

        for item in resolved_items:
            try:
                resolved_ip = item[4][0]
                ip_obj = ipaddress.ip_address(resolved_ip)
                if self._is_private_ip(ip_obj):
                    return True
            except Exception:
                continue

        return False

    def _is_private_ip(self, ip_obj: Any) -> bool:
        """
        Determine if an IP address is private, loopback, link-local, multicast,
        reserved, or otherwise unsafe for public scraping.
        """

        return bool(
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )

    # -----------------------------------------------------------------------
    # Local Security Policy
    # -----------------------------------------------------------------------

    def _local_security_policy(
        self,
        action: str,
        url: Optional[str],
        options: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Conservative local security approval.

        This method approves only safe public read-only operations.
        """

        if action not in {
            "browser.fetch_page",
            "browser.extract_visible_data",
            "browser.scrape",
            "browser.scrape_many",
        }:
            return self._error_result(
                message="Local security policy rejected unknown action.",
                error="ACTION_NOT_ALLOWED",
                metadata={"action": action},
            )

        if options.get("submit_forms") is True:
            return self._error_result(
                message="Form submission is not allowed by Scraper.",
                error="FORM_SUBMISSION_BLOCKED",
                metadata={"action": action},
            )

        if options.get("click") is True or options.get("automate_browser") is True:
            return self._error_result(
                message="Browser automation/clicking is not allowed by Scraper.",
                error="BROWSER_AUTOMATION_BLOCKED",
                metadata={"action": action},
            )

        if options.get("login") is True or options.get("authenticated") is True:
            return self._error_result(
                message="Authenticated/private scraping is not allowed by Scraper.",
                error="AUTHENTICATED_SCRAPING_BLOCKED",
                metadata={"action": action},
            )

        if url:
            url_check = self._validate_public_url(url)
            if not url_check["success"]:
                return url_check

        return self._safe_result(
            message="Local security policy approved.",
            data={"approved": True},
            metadata={"action": action, "mode": "read_only_public_fetch"},
        )

    # -----------------------------------------------------------------------
    # Text / Utility
    # -----------------------------------------------------------------------

    def _clean_text(self, value: Any, multiline: bool = False) -> str:
        """
        Decode HTML entities and normalize whitespace.
        """

        if value is None:
            return ""

        text = html.unescape(str(value))
        text = text.replace("\x00", " ")

        if multiline:
            lines = [self._normalize_space(line) for line in text.splitlines()]
            lines = [line for line in lines if line]
            return "\n".join(lines)

        return self._normalize_space(text)

    def _normalize_space(self, text: str) -> str:
        """
        Normalize repeated spaces/tabs/newlines.
        """

        if not isinstance(text, str):
            text = str(text)

        if self.config.normalize_whitespace:
            text = re.sub(r"[ \t\r\f\v]+", " ", text)
            text = re.sub(r"\n{3,}", "\n\n", text)

        return text.strip()

    def _truncate_text(self, text: Any, max_chars: int) -> str:
        """
        Safely truncate text fields.
        """

        if text is None:
            return ""

        value = str(text)

        if len(value) <= max_chars:
            return value

        return value[: max_chars - 3] + "..."

    def _hash_text(self, text: str) -> str:
        """
        Stable SHA-256 text hash for deduplication and verification.
        """

        normalized = self._normalize_space(text or "")
        return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()

    def _safe_attr_list(self, value: Any) -> List[str]:
        """
        Normalize HTML attribute list values.
        """

        if value is None:
            return []

        if isinstance(value, list):
            return [self._clean_text(v) for v in value if self._clean_text(v)]

        return [self._clean_text(value)] if self._clean_text(value) else []

    def _optional_str(self, value: Any) -> Optional[str]:
        """
        Convert optional value to clean string.
        """

        if value is None:
            return None

        cleaned = self._clean_text(value)
        return cleaned or None

    def _elapsed_ms(self, started: float) -> int:
        """
        Milliseconds since started.
        """

        return int((time.time() - started) * 1000)

    def _utc_now(self) -> str:
        """
        Current UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()

    def _verification_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compact summary for Verification Agent.
        """

        extracted = data.get("extracted", data)

        if not isinstance(extracted, dict):
            extracted = {}

        return {
            "url": data.get("url") or extracted.get("url"),
            "final_url": data.get("final_url") or extracted.get("final_url"),
            "status_code": data.get("status_code"),
            "title": extracted.get("title"),
            "description_present": bool(extracted.get("description")),
            "visible_text_length": extracted.get("visible_text_length"),
            "links_count": len(extracted.get("links", []) or []),
            "images_count": len(extracted.get("images", []) or []),
            "text_hash": extracted.get("text_hash"),
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_scraper(
    config: Optional[ScraperConfig] = None,
    **kwargs: Any,
) -> Scraper:
    """
    Factory helper for Agent Loader / Registry integration.
    """

    return Scraper(config=config, **kwargs)


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    scraper = Scraper()
    result = scraper.health_check(
        context={
            "user_id": "local_test_user",
            "workspace_id": "local_test_workspace",
            "source": "manual_smoke_test",
        }
    )
    print(result)