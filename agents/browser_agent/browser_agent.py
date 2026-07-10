"""
agents/browser_agent/browser_agent.py

Browser Agent for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Internet brain for search, website opening, scraping, page analysis,
    SEO and competitor research.

This file is designed to be:
    - Production-level
    - Import-safe
    - SaaS-aware with user_id and workspace_id isolation
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future browser submodules.

Important:
    This file does NOT hardcode secrets.
    This file does NOT perform destructive actions.
    Every external browser/network action can be routed through security checks.
    Every result returns structured dict/JSON style responses.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import html
import json
import logging
import re
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ======================================================================================
# Optional imports
# ======================================================================================

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore


# ======================================================================================
# Optional William/Jarvis internal imports with safe fallbacks
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:
        """
        Safe fallback BaseAgent.

        This keeps BrowserAgent import-safe when the full William/Jarvis project
        is not generated yet.
        """

        agent_name: str = "base_agent"
        agent_type: str = "base"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": None,
                "metadata": {},
            }

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            logging.getLogger(self.__class__.__name__).debug(
                "Fallback emit_event: %s | %s",
                event_name,
                payload,
            )


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover

    @dataclass
    class AgentContext:
        """
        Safe fallback AgentContext.

        The real system can replace this with core.context.AgentContext later.
        """

        user_id: Optional[Union[str, int]] = None
        workspace_id: Optional[Union[str, int]] = None
        role: Optional[str] = None
        permissions: List[str] = field(default_factory=list)
        metadata: Dict[str, Any] = field(default_factory=dict)


# ======================================================================================
# Logging
# ======================================================================================

LOGGER = logging.getLogger("william.browser_agent")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ======================================================================================
# Enums and data structures
# ======================================================================================

class BrowserAction(str, Enum):
    """
    Supported BrowserAgent actions.

    MasterAgent / Router can use these action names to route tasks.
    """

    HEALTH_CHECK = "health_check"
    SEARCH = "search"
    OPEN_WEBSITE = "open_website"
    SCRAPE_PAGE = "scrape_page"
    ANALYZE_PAGE = "analyze_page"
    EXTRACT_TEXT = "extract_text"
    EXTRACT_LINKS = "extract_links"
    SEO_ANALYZE = "seo_analyze"
    SEO_RESEARCH = "seo_research"
    COMPETITOR_RESEARCH = "competitor_research"
    PRICE_MONITOR = "price_monitor"
    SUMMARIZE_PAGE = "summarize_page"


class BrowserRiskLevel(str, Enum):
    """
    Risk levels used before performing browser/network actions.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BrowserAgentConfig:
    """
    Runtime configuration for BrowserAgent.

    The config is intentionally safe by default.
    """

    agent_name: str = "browser_agent"
    agent_display_name: str = "Browser Agent"
    version: str = "1.0.0"

    default_timeout_seconds: int = 20
    max_response_bytes: int = 3_000_000
    max_links: int = 100
    max_search_results: int = 10
    max_page_text_chars: int = 80_000
    max_summary_chars: int = 2_500

    user_agent: str = (
        "WilliamJarvisBrowserAgent/1.0 "
        "(Research Assistant; SaaS Workspace Safe; Digital Promotix)"
    )

    allow_http: bool = True
    allow_https: bool = True
    allow_localhost: bool = False
    allow_private_ips: bool = False
    follow_redirects: bool = True

    enable_network: bool = True
    require_security_for_network: bool = True
    require_security_for_scrape: bool = True
    require_security_for_competitor_research: bool = True

    search_provider: str = "duckduckgo_html"
    blocked_domains: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)

    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserTaskContext:
    """
    SaaS execution context for user/workspace isolation.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    task_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    request_id: Optional[str] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "role": self.role,
            "request_id": self.request_id,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class PageFetchResult:
    """
    Internal structured result for fetched pages.
    """

    url: str
    final_url: str
    status_code: Optional[int]
    content_type: Optional[str]
    text: str
    raw_html: str
    headers: Dict[str, Any]
    elapsed_ms: int
    error: Optional[str] = None


@dataclass
class PageAnalysis:
    """
    Structured page analysis payload.
    """

    url: str
    title: str
    meta_description: str
    h1: List[str]
    h2: List[str]
    h3: List[str]
    canonical: Optional[str]
    word_count: int
    links_internal_count: int
    links_external_count: int
    images_count: int
    images_missing_alt_count: int
    schema_types: List[str]
    emails: List[str]
    phones: List[str]
    social_links: List[str]
    page_summary: str
    seo_score: int
    seo_issues: List[str]
    seo_recommendations: List[str]


# ======================================================================================
# Helper functions
# ======================================================================================

def utc_now_iso() -> str:
    """Return current UTC datetime in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: str) -> str:
    """Return a stable SHA256 hash for safe IDs/cache keys."""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def compact_whitespace(value: str) -> str:
    """Normalize whitespace while preserving readable text."""
    return re.sub(r"\s+", " ", value or "").strip()


def truncate_text(value: str, max_chars: int) -> str:
    """Safely truncate text without crashing on None."""
    value = value or ""
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 20].rstrip() + " ...[truncated]"


def is_valid_url(value: str) -> bool:
    """Check whether a value is a valid HTTP/HTTPS URL."""
    if not value or not isinstance(value, str):
        return False
    parsed = urllib.parse.urlparse(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def normalize_url(url: str) -> str:
    """
    Normalize URL.

    Adds https:// if scheme is missing.
    """
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def domain_from_url(url: str) -> str:
    """Extract lowercase domain from URL."""
    try:
        parsed = urllib.parse.urlparse(normalize_url(url))
        return parsed.netloc.lower().replace("www.", "")
    except Exception:
        return ""


def make_absolute_url(base_url: str, link: str) -> str:
    """Convert relative URL into absolute URL."""
    try:
        return urllib.parse.urljoin(base_url, link)
    except Exception:
        return link


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text."""
    if not text:
        return []
    matches = re.findall(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        text,
    )
    return sorted(set(matches))


def extract_phone_numbers(text: str) -> List[str]:
    """Extract common phone number patterns from text."""
    if not text:
        return []

    phone_regex = re.compile(
        r"""
        (?:
            (?:\+?\d{1,3}[\s.\-()]*)?
            (?:\(?\d{2,4}\)?[\s.\-()]*)?
            \d{3,4}[\s.\-()]*\d{3,4}
        )
        """,
        re.VERBOSE,
    )

    raw = phone_regex.findall(text)
    cleaned: List[str] = []

    for item in raw:
        phone = compact_whitespace(item)
        digits = re.sub(r"\D", "", phone)
        if 7 <= len(digits) <= 15:
            cleaned.append(phone)

    return sorted(set(cleaned))


def safe_json_loads(value: str, default: Any = None) -> Any:
    """Safely parse JSON string."""
    try:
        return json.loads(value)
    except Exception:
        return default


# ======================================================================================
# BrowserAgent
# ======================================================================================

class BrowserAgent(BaseAgent):
    """
    BrowserAgent is the internet/research brain of William/Jarvis.

    Responsibilities:
        - Search web
        - Open websites
        - Scrape pages
        - Analyze pages
        - Extract content and links
        - SEO analysis
        - Competitor research
        - Price monitoring
        - Prepare memory payloads
        - Prepare verification payloads
        - Emit agent events
        - Log audit events

    Connections:
        - MasterAgent:
            Routes browser tasks here through execute()/run().
        - SecurityAgent:
            Network/browser actions can call _request_security_approval().
        - MemoryAgent:
            Useful search/page context is returned through _prepare_memory_payload().
        - VerificationAgent:
            Completed actions include _prepare_verification_payload().
        - Dashboard/API:
            Structured dict outputs are ready for FastAPI/dashboard display.
        - Registry/Loader/Router:
            Class name BrowserAgent and public action methods stay stable.
    """

    agent_name = "browser_agent"
    agent_type = "browser"
    public_name = "Browser Agent"

    def __init__(
        self,
        config: Optional[BrowserAgentConfig] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.config = config or BrowserAgentConfig()
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.logger = logging.getLogger("william.browser_agent.BrowserAgent")

        self._action_map: Dict[str, Callable[..., Any]] = {
            BrowserAction.HEALTH_CHECK.value: self.health_check,
            BrowserAction.SEARCH.value: self.search,
            BrowserAction.OPEN_WEBSITE.value: self.open_website,
            BrowserAction.SCRAPE_PAGE.value: self.scrape_page,
            BrowserAction.ANALYZE_PAGE.value: self.analyze_page,
            BrowserAction.EXTRACT_TEXT.value: self.extract_text,
            BrowserAction.EXTRACT_LINKS.value: self.extract_links,
            BrowserAction.SEO_ANALYZE.value: self.seo_analyze,
            BrowserAction.SEO_RESEARCH.value: self.seo_research,
            BrowserAction.COMPETITOR_RESEARCH.value: self.competitor_research,
            BrowserAction.PRICE_MONITOR.value: self.price_monitor,
            BrowserAction.SUMMARIZE_PAGE.value: self.summarize_page,
        }

    # ==================================================================================
    # BaseAgent / Router entrypoints
    # ==================================================================================

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entrypoint.

        MasterAgent, AgentRouter, or WorkflowAgent may call this method.
        """
        return await self.execute(task)

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a browser task.

        Expected task shape:
            {
                "action": "search",
                "user_id": "1",
                "workspace_id": "default",
                "payload": {
                    "query": "example",
                    "limit": 10
                },
                "task_id": "optional",
                "request_id": "optional"
            }
        """
        started_at = time.time()

        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error="INVALID_TASK_TYPE",
                metadata={"received_type": type(task).__name__},
            )

        action = str(task.get("action") or "").strip()
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(
                message="Task payload must be a dictionary.",
                error="INVALID_PAYLOAD_TYPE",
                metadata={"action": action},
            )

        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        context: BrowserTaskContext = context_result["data"]["context"]

        if not action:
            return self._error_result(
                message="Missing browser action.",
                error="MISSING_ACTION",
                metadata=context.to_metadata(),
            )

        handler = self._action_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported browser action: {action}",
                error="UNSUPPORTED_ACTION",
                data={"supported_actions": sorted(self._action_map.keys())},
                metadata=context.to_metadata(),
            )

        try:
            self._emit_agent_event(
                "browser_task_started",
                {
                    "action": action,
                    "context": context.to_metadata(),
                    "payload_keys": sorted(payload.keys()),
                },
            )

            result = handler(context=context, **payload)

            if asyncio.iscoroutine(result):
                result = await result

            elapsed_ms = int((time.time() - started_at) * 1000)

            if isinstance(result, dict):
                result.setdefault("metadata", {})
                result["metadata"].update(
                    {
                        "action": action,
                        "elapsed_ms": elapsed_ms,
                        "agent": self.agent_name,
                        "agent_version": self.config.version,
                        "context": context.to_metadata(),
                    }
                )

                if self.config.verification_enabled and result.get("success"):
                    result["verification_payload"] = self._prepare_verification_payload(
                        action=action,
                        context=context,
                        result=result,
                    )

                if self.config.memory_enabled and result.get("success"):
                    result["memory_payload"] = self._prepare_memory_payload(
                        action=action,
                        context=context,
                        result=result,
                    )

                self._log_audit_event(
                    context=context,
                    action=action,
                    status="success" if result.get("success") else "failed",
                    details={
                        "message": result.get("message"),
                        "error": result.get("error"),
                        "elapsed_ms": elapsed_ms,
                    },
                )

                self._emit_agent_event(
                    "browser_task_completed",
                    {
                        "action": action,
                        "success": result.get("success"),
                        "elapsed_ms": elapsed_ms,
                        "context": context.to_metadata(),
                    },
                )

                return result

            return self._safe_result(
                message="Browser action completed.",
                data={"result": result},
                metadata={
                    "action": action,
                    "elapsed_ms": elapsed_ms,
                    "context": context.to_metadata(),
                },
            )

        except Exception as exc:
            elapsed_ms = int((time.time() - started_at) * 1000)
            self.logger.exception("BrowserAgent execution failed.")

            self._log_audit_event(
                context=context,
                action=action,
                status="error",
                details={
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                    "elapsed_ms": elapsed_ms,
                },
            )

            return self._error_result(
                message="Browser action failed.",
                error=str(exc),
                metadata={
                    "action": action,
                    "elapsed_ms": elapsed_ms,
                    "context": context.to_metadata(),
                    "traceback": traceback.format_exc(),
                },
            )

    # ==================================================================================
    # Public methods
    # ==================================================================================

    def health_check(self, context: BrowserTaskContext, **kwargs: Any) -> Dict[str, Any]:
        """Return BrowserAgent health/status information."""
        return self._safe_result(
            message="BrowserAgent is healthy.",
            data={
                "agent": self.agent_name,
                "type": self.agent_type,
                "version": self.config.version,
                "network_enabled": self.config.enable_network,
                "requests_available": requests is not None,
                "beautifulsoup_available": BeautifulSoup is not None,
                "supported_actions": sorted(self._action_map.keys()),
            },
            metadata=context.to_metadata(),
        )

    def search(
        self,
        context: BrowserTaskContext,
        query: str,
        limit: Optional[int] = None,
        provider: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Search the web.

        Default provider:
            DuckDuckGo HTML endpoint.

        This method returns structured search results.
        """
        query = compact_whitespace(query)
        if not query:
            return self._error_result(
                message="Search query is required.",
                error="MISSING_QUERY",
                metadata=context.to_metadata(),
            )

        limit = int(limit or self.config.max_search_results)
        limit = max(1, min(limit, self.config.max_search_results))
        provider = provider or self.config.search_provider

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.SEARCH.value,
            risk_level=BrowserRiskLevel.MEDIUM,
            target=query,
            details={"provider": provider, "limit": limit},
        )
        if not approval["success"]:
            return approval

        if not self.config.enable_network:
            return self._error_result(
                message="Network access is disabled for BrowserAgent.",
                error="NETWORK_DISABLED",
                metadata=context.to_metadata(),
            )

        try:
            if provider == "duckduckgo_html":
                results = self._search_duckduckgo_html(query=query, limit=limit)
            else:
                return self._error_result(
                    message=f"Unsupported search provider: {provider}",
                    error="UNSUPPORTED_SEARCH_PROVIDER",
                    data={"supported_providers": ["duckduckgo_html"]},
                    metadata=context.to_metadata(),
                )

            return self._safe_result(
                message=f"Search completed for: {query}",
                data={
                    "query": query,
                    "provider": provider,
                    "count": len(results),
                    "results": results,
                },
                metadata=context.to_metadata(),
            )

        except Exception as exc:
            return self._error_result(
                message="Search failed.",
                error=str(exc),
                metadata={
                    **context.to_metadata(),
                    "query": query,
                    "provider": provider,
                    "traceback": traceback.format_exc(),
                },
            )

    def open_website(
        self,
        context: BrowserTaskContext,
        url: str,
        extract: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Open/fetch a website and return basic page data.

        This does not launch a real browser UI. It safely fetches the URL content.
        Future browser_session.py can replace this with Playwright/Selenium sessions.
        """
        normalized = normalize_url(url)
        if not self._is_url_allowed(normalized):
            return self._error_result(
                message="URL is not allowed by BrowserAgent policy.",
                error="URL_NOT_ALLOWED",
                data={"url": normalized},
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.OPEN_WEBSITE.value,
            risk_level=BrowserRiskLevel.MEDIUM,
            target=normalized,
            details={"extract": extract},
        )
        if not approval["success"]:
            return approval

        fetch = self._fetch_url(normalized)
        if fetch.error:
            return self._error_result(
                message="Website could not be opened.",
                error=fetch.error,
                data=dataclasses.asdict(fetch),
                metadata=context.to_metadata(),
            )

        page_data = {
            "url": fetch.url,
            "final_url": fetch.final_url,
            "status_code": fetch.status_code,
            "content_type": fetch.content_type,
            "headers": fetch.headers,
            "elapsed_ms": fetch.elapsed_ms,
        }

        if extract:
            page_data["title"] = self._extract_title(fetch.raw_html)
            page_data["text"] = truncate_text(
                self._html_to_text(fetch.raw_html),
                self.config.max_page_text_chars,
            )

        return self._safe_result(
            message="Website opened successfully.",
            data=page_data,
            metadata=context.to_metadata(),
        )

    def scrape_page(
        self,
        context: BrowserTaskContext,
        url: str,
        include_html: bool = False,
        include_links: bool = True,
        include_images: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Scrape a page and return structured content.

        This is designed for page understanding, SEO, and competitor analysis.
        """
        normalized = normalize_url(url)
        if not self._is_url_allowed(normalized):
            return self._error_result(
                message="URL is not allowed by BrowserAgent policy.",
                error="URL_NOT_ALLOWED",
                data={"url": normalized},
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.SCRAPE_PAGE.value,
            risk_level=BrowserRiskLevel.MEDIUM,
            target=normalized,
            details={
                "include_html": include_html,
                "include_links": include_links,
                "include_images": include_images,
            },
        )
        if not approval["success"]:
            return approval

        fetch = self._fetch_url(normalized)
        if fetch.error:
            return self._error_result(
                message="Page scrape failed.",
                error=fetch.error,
                data=dataclasses.asdict(fetch),
                metadata=context.to_metadata(),
            )

        text = self._html_to_text(fetch.raw_html)
        title = self._extract_title(fetch.raw_html)
        meta = self._extract_meta(fetch.raw_html)

        data: Dict[str, Any] = {
            "url": fetch.url,
            "final_url": fetch.final_url,
            "status_code": fetch.status_code,
            "content_type": fetch.content_type,
            "title": title,
            "meta": meta,
            "text": truncate_text(text, self.config.max_page_text_chars),
            "word_count": len(text.split()),
            "emails": extract_emails(text),
            "phones": extract_phone_numbers(text),
            "elapsed_ms": fetch.elapsed_ms,
        }

        if include_links:
            data["links"] = self._extract_links_from_html(fetch.final_url, fetch.raw_html)

        if include_images:
            data["images"] = self._extract_images_from_html(fetch.final_url, fetch.raw_html)

        if include_html:
            data["html"] = truncate_text(fetch.raw_html, self.config.max_response_bytes)

        return self._safe_result(
            message="Page scraped successfully.",
            data=data,
            metadata=context.to_metadata(),
        )

    def analyze_page(
        self,
        context: BrowserTaskContext,
        url: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Analyze a page for content, technical SEO signals, links, schema, and contact data.
        """
        normalized = normalize_url(url)
        if not self._is_url_allowed(normalized):
            return self._error_result(
                message="URL is not allowed by BrowserAgent policy.",
                error="URL_NOT_ALLOWED",
                data={"url": normalized},
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.ANALYZE_PAGE.value,
            risk_level=BrowserRiskLevel.MEDIUM,
            target=normalized,
            details={},
        )
        if not approval["success"]:
            return approval

        fetch = self._fetch_url(normalized)
        if fetch.error:
            return self._error_result(
                message="Page analysis failed.",
                error=fetch.error,
                data=dataclasses.asdict(fetch),
                metadata=context.to_metadata(),
            )

        analysis = self._build_page_analysis(fetch.final_url, fetch.raw_html)

        return self._safe_result(
            message="Page analysis completed.",
            data=dataclasses.asdict(analysis),
            metadata=context.to_metadata(),
        )

    def extract_text(
        self,
        context: BrowserTaskContext,
        url: str,
        max_chars: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Fetch URL and extract readable text."""
        scrape = self.scrape_page(
            context=context,
            url=url,
            include_html=False,
            include_links=False,
            include_images=False,
        )

        if not scrape.get("success"):
            return scrape

        text = scrape.get("data", {}).get("text", "")
        max_chars = int(max_chars or self.config.max_page_text_chars)

        return self._safe_result(
            message="Text extracted successfully.",
            data={
                "url": normalize_url(url),
                "text": truncate_text(text, max_chars),
                "chars": min(len(text), max_chars),
            },
            metadata=context.to_metadata(),
        )

    def extract_links(
        self,
        context: BrowserTaskContext,
        url: str,
        internal_only: bool = False,
        external_only: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Fetch URL and extract links."""
        scrape = self.scrape_page(
            context=context,
            url=url,
            include_html=False,
            include_links=True,
            include_images=False,
        )

        if not scrape.get("success"):
            return scrape

        links = scrape.get("data", {}).get("links", [])
        if internal_only:
            links = [link for link in links if link.get("type") == "internal"]
        if external_only:
            links = [link for link in links if link.get("type") == "external"]

        return self._safe_result(
            message="Links extracted successfully.",
            data={
                "url": normalize_url(url),
                "count": len(links),
                "links": links[: self.config.max_links],
            },
            metadata=context.to_metadata(),
        )

    def seo_analyze(
        self,
        context: BrowserTaskContext,
        url: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Perform SEO analysis for one page.
        """
        result = self.analyze_page(context=context, url=url)
        if not result.get("success"):
            return result

        data = result.get("data", {})
        seo_data = {
            "url": data.get("url"),
            "title": data.get("title"),
            "meta_description": data.get("meta_description"),
            "canonical": data.get("canonical"),
            "h1": data.get("h1"),
            "h2": data.get("h2"),
            "word_count": data.get("word_count"),
            "seo_score": data.get("seo_score"),
            "seo_issues": data.get("seo_issues"),
            "seo_recommendations": data.get("seo_recommendations"),
            "images_count": data.get("images_count"),
            "images_missing_alt_count": data.get("images_missing_alt_count"),
            "schema_types": data.get("schema_types"),
        }

        return self._safe_result(
            message="SEO analysis completed.",
            data=seo_data,
            metadata=context.to_metadata(),
        )

    def seo_research(
        self,
        context: BrowserTaskContext,
        keyword: str,
        target_url: Optional[str] = None,
        country: Optional[str] = None,
        limit: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        SEO research for a keyword.

        Includes SERP-style search results and optional target page analysis.
        """
        keyword = compact_whitespace(keyword)
        if not keyword:
            return self._error_result(
                message="Keyword is required for SEO research.",
                error="MISSING_KEYWORD",
                metadata=context.to_metadata(),
            )

        query = keyword if not country else f"{keyword} {country}"
        limit = int(limit or min(5, self.config.max_search_results))

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.SEO_RESEARCH.value,
            risk_level=BrowserRiskLevel.MEDIUM,
            target=query,
            details={"target_url": target_url, "country": country, "limit": limit},
        )
        if not approval["success"]:
            return approval

        search_result = self.search(context=context, query=query, limit=limit)
        if not search_result.get("success"):
            return search_result

        serp_results = search_result.get("data", {}).get("results", [])

        target_analysis: Optional[Dict[str, Any]] = None
        if target_url:
            target_result = self.seo_analyze(context=context, url=target_url)
            target_analysis = target_result.get("data") if target_result.get("success") else {
                "error": target_result.get("error"),
                "message": target_result.get("message"),
            }

        research = {
            "keyword": keyword,
            "country": country,
            "query": query,
            "serp_count": len(serp_results),
            "serp_results": serp_results,
            "target_url": target_url,
            "target_analysis": target_analysis,
            "opportunities": self._build_seo_opportunities(keyword, serp_results, target_analysis),
        }

        return self._safe_result(
            message="SEO research completed.",
            data=research,
            metadata=context.to_metadata(),
        )

    def competitor_research(
        self,
        context: BrowserTaskContext,
        competitors: List[str],
        keyword: Optional[str] = None,
        include_page_analysis: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Research competitor websites.

        For each competitor URL:
            - Opens/analyzes page
            - Extracts title, meta, headings, links, contact data
            - Produces simple SEO comparison signals
        """
        if not isinstance(competitors, list) or not competitors:
            return self._error_result(
                message="Competitors list is required.",
                error="MISSING_COMPETITORS",
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.COMPETITOR_RESEARCH.value,
            risk_level=BrowserRiskLevel.HIGH,
            target=", ".join(competitors[:10]),
            details={
                "keyword": keyword,
                "include_page_analysis": include_page_analysis,
                "competitor_count": len(competitors),
            },
        )
        if not approval["success"]:
            return approval

        competitor_reports: List[Dict[str, Any]] = []

        for competitor in competitors:
            url = normalize_url(str(competitor))
            if not self._is_url_allowed(url):
                competitor_reports.append(
                    {
                        "url": url,
                        "success": False,
                        "error": "URL_NOT_ALLOWED",
                        "message": "Competitor URL is not allowed by policy.",
                    }
                )
                continue

            if include_page_analysis:
                analysis = self.analyze_page(context=context, url=url)
                competitor_reports.append(
                    {
                        "url": url,
                        "success": bool(analysis.get("success")),
                        "message": analysis.get("message"),
                        "error": analysis.get("error"),
                        "analysis": analysis.get("data"),
                    }
                )
            else:
                opened = self.open_website(context=context, url=url, extract=True)
                competitor_reports.append(
                    {
                        "url": url,
                        "success": bool(opened.get("success")),
                        "message": opened.get("message"),
                        "error": opened.get("error"),
                        "data": opened.get("data"),
                    }
                )

        comparison = self._compare_competitors(keyword=keyword, reports=competitor_reports)

        return self._safe_result(
            message="Competitor research completed.",
            data={
                "keyword": keyword,
                "competitor_count": len(competitors),
                "reports": competitor_reports,
                "comparison": comparison,
            },
            metadata=context.to_metadata(),
        )

    def price_monitor(
        self,
        context: BrowserTaskContext,
        url: str,
        product_name: Optional[str] = None,
        currency_symbols: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Extract possible prices from a webpage.

        Note:
            This is a safe page-reading helper. Scheduled monitoring can be handled later
            by WorkflowAgent or automation.py.
        """
        normalized = normalize_url(url)
        if not self._is_url_allowed(normalized):
            return self._error_result(
                message="URL is not allowed by BrowserAgent policy.",
                error="URL_NOT_ALLOWED",
                data={"url": normalized},
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=BrowserAction.PRICE_MONITOR.value,
            risk_level=BrowserRiskLevel.MEDIUM,
            target=normalized,
            details={"product_name": product_name},
        )
        if not approval["success"]:
            return approval

        scrape = self.scrape_page(
            context=context,
            url=normalized,
            include_html=False,
            include_links=False,
            include_images=False,
        )

        if not scrape.get("success"):
            return scrape

        text = scrape.get("data", {}).get("text", "")
        prices = self._extract_prices(text, currency_symbols=currency_symbols)

        return self._safe_result(
            message="Price extraction completed.",
            data={
                "url": normalized,
                "product_name": product_name,
                "prices_found": prices,
                "count": len(prices),
                "best_guess": prices[0] if prices else None,
            },
            metadata=context.to_metadata(),
        )

    def summarize_page(
        self,
        context: BrowserTaskContext,
        url: str,
        max_chars: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Create a simple extractive page summary.

        This does not call external LLM APIs. MasterAgent can pass this output
        to CreatorAgent or another model layer for deeper summarization.
        """
        scrape = self.scrape_page(
            context=context,
            url=url,
            include_html=False,
            include_links=False,
            include_images=False,
        )

        if not scrape.get("success"):
            return scrape

        data = scrape.get("data", {})
        text = data.get("text", "")
        max_chars = int(max_chars or self.config.max_summary_chars)
        summary = self._simple_summary(text, max_chars=max_chars)

        return self._safe_result(
            message="Page summary generated.",
            data={
                "url": normalize_url(url),
                "title": data.get("title"),
                "summary": summary,
                "summary_chars": len(summary),
                "word_count": data.get("word_count"),
            },
            metadata=context.to_metadata(),
        )

    # ==================================================================================
    # Context, security, verification, memory, audit, result hooks
    # ==================================================================================

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Required:
            - user_id
            - workspace_id

        This prevents memory/files/logs/tasks from mixing between users/workspaces.
        """
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        payload = task.get("payload") or {}
        if isinstance(payload, dict):
            user_id = user_id or payload.get("user_id")
            workspace_id = workspace_id or payload.get("workspace_id")

        if user_id in (None, ""):
            return self._error_result(
                message="user_id is required for BrowserAgent tasks.",
                error="MISSING_USER_ID",
                metadata={"task_keys": sorted(task.keys())},
            )

        if workspace_id in (None, ""):
            return self._error_result(
                message="workspace_id is required for BrowserAgent tasks.",
                error="MISSING_WORKSPACE_ID",
                metadata={"task_keys": sorted(task.keys())},
            )

        permissions = task.get("permissions") or []
        if not isinstance(permissions, list):
            permissions = []

        context = BrowserTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task.get("task_id"),
            role=task.get("role"),
            permissions=permissions,
            request_id=task.get("request_id"),
            source=task.get("source"),
            metadata=task.get("metadata") or {},
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
            metadata=context.to_metadata(),
        )

    def _requires_security_check(
        self,
        action: str,
        risk_level: Union[str, BrowserRiskLevel] = BrowserRiskLevel.MEDIUM,
    ) -> bool:
        """
        Decide if an action requires SecurityAgent approval.
        """
        risk = BrowserRiskLevel(str(risk_level))

        if action in {
            BrowserAction.OPEN_WEBSITE.value,
            BrowserAction.SEARCH.value,
        }:
            return bool(self.config.require_security_for_network)

        if action in {
            BrowserAction.SCRAPE_PAGE.value,
            BrowserAction.ANALYZE_PAGE.value,
            BrowserAction.EXTRACT_TEXT.value,
            BrowserAction.EXTRACT_LINKS.value,
            BrowserAction.SEO_ANALYZE.value,
            BrowserAction.SEO_RESEARCH.value,
            BrowserAction.PRICE_MONITOR.value,
        }:
            return bool(self.config.require_security_for_scrape)

        if action == BrowserAction.COMPETITOR_RESEARCH.value:
            return bool(self.config.require_security_for_competitor_research)

        return risk in {BrowserRiskLevel.MEDIUM, BrowserRiskLevel.HIGH}

    def _request_security_approval(
        self,
        context: BrowserTaskContext,
        action: str,
        risk_level: Union[str, BrowserRiskLevel],
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from SecurityAgent if available.

        Fallback behavior:
            If no security_client is attached, allow safe read-only browser actions
            but return approval metadata. This keeps the file import-safe and usable
            before the full Security Agent exists.
        """
        payload = {
            "agent": self.agent_name,
            "action": action,
            "risk_level": str(risk_level),
            "target": target,
            "details": details or {},
            "context": context.to_metadata(),
            "timestamp": utc_now_iso(),
        }

        if self.security_client is None:
            return self._safe_result(
                message="Security approval fallback granted for read-only browser action.",
                data={
                    "approved": True,
                    "approval_source": "fallback",
                    "payload": payload,
                },
                metadata=context.to_metadata(),
            )

        try:
            if hasattr(self.security_client, "approve_action"):
                approval = self.security_client.approve_action(payload)
            elif hasattr(self.security_client, "request_approval"):
                approval = self.security_client.request_approval(payload)
            else:
                approval = {
                    "success": False,
                    "approved": False,
                    "error": "SECURITY_CLIENT_MISSING_APPROVAL_METHOD",
                }

            if asyncio.iscoroutine(approval):
                raise RuntimeError(
                    "Async security client approval must be awaited by caller integration."
                )

            approved = bool(
                approval.get("approved")
                if isinstance(approval, dict)
                else False
            )

            if not approved:
                return self._error_result(
                    message="Security Agent denied this browser action.",
                    error="SECURITY_APPROVAL_DENIED",
                    data={"approval": approval, "payload": payload},
                    metadata=context.to_metadata(),
                )

            return self._safe_result(
                message="Security Agent approved browser action.",
                data={"approved": True, "approval": approval, "payload": payload},
                metadata=context.to_metadata(),
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval failed.",
                error=str(exc),
                data={"payload": payload},
                metadata=context.to_metadata(),
            )

    def _maybe_request_security(
        self,
        context: BrowserTaskContext,
        action: str,
        risk_level: BrowserRiskLevel,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run security approval only when required.
        """
        if not self._requires_security_check(action=action, risk_level=risk_level):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "approval_source": "not_required"},
                metadata=context.to_metadata(),
            )

        return self._request_security_approval(
            context=context,
            action=action,
            risk_level=risk_level,
            target=target,
            details=details,
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: BrowserTaskContext,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for VerificationAgent.

        VerificationAgent can use this to confirm that the browser task result is
        complete, source-aware, and safe to show.
        """
        data = result.get("data", {})
        return {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "success": result.get("success"),
            "message": result.get("message"),
            "data_fingerprint": stable_hash(
                json.dumps(data, default=str, sort_keys=True)[:50_000]
            ),
            "checks": {
                "has_structured_result": isinstance(result, dict),
                "has_context": bool(context.user_id and context.workspace_id),
                "has_message": bool(result.get("message")),
                "has_error_field": "error" in result,
            },
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: BrowserTaskContext,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for MemoryAgent.

        This does not write memory directly unless memory_client integration is attached.
        It returns a safe structured payload that MemoryAgent can store per user/workspace.
        """
        data = result.get("data", {})
        memory_items: List[Dict[str, Any]] = []

        if action == BrowserAction.SEARCH.value:
            memory_items.append(
                {
                    "type": "browser_search",
                    "query": data.get("query"),
                    "provider": data.get("provider"),
                    "count": data.get("count"),
                }
            )

        if action in {
            BrowserAction.OPEN_WEBSITE.value,
            BrowserAction.SCRAPE_PAGE.value,
            BrowserAction.ANALYZE_PAGE.value,
            BrowserAction.SEO_ANALYZE.value,
            BrowserAction.SUMMARIZE_PAGE.value,
        }:
            memory_items.append(
                {
                    "type": "browser_page_context",
                    "url": data.get("url") or data.get("final_url"),
                    "title": data.get("title"),
                    "summary": data.get("page_summary") or data.get("summary"),
                    "seo_score": data.get("seo_score"),
                }
            )

        if action in {
            BrowserAction.SEO_RESEARCH.value,
            BrowserAction.COMPETITOR_RESEARCH.value,
        }:
            memory_items.append(
                {
                    "type": "browser_research",
                    "keyword": data.get("keyword"),
                    "target_url": data.get("target_url"),
                    "competitor_count": data.get("competitor_count"),
                }
            )

        payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "items": memory_items,
            "created_at": utc_now_iso(),
        }

        if self.memory_client is not None:
            try:
                if hasattr(self.memory_client, "prepare"):
                    self.memory_client.prepare(payload)
                elif hasattr(self.memory_client, "store"):
                    self.memory_client.store(payload)
            except Exception as exc:
                self.logger.warning("Memory client write failed: %s", exc)

        return payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit agent event for Dashboard/API/Workflow logs.

        This intentionally does not crash the main task.
        """
        event_payload = {
            "event": event_name,
            "agent": self.agent_name,
            "timestamp": utc_now_iso(),
            "payload": payload,
        }

        try:
            if self.event_callback:
                self.event_callback(event_name, event_payload)
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, event_payload)  # type: ignore
                except Exception:
                    pass

            self.logger.debug("Agent event emitted: %s", event_payload)

        except Exception as exc:
            self.logger.warning("Failed to emit agent event: %s", exc)

    def _log_audit_event(
        self,
        context: BrowserTaskContext,
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        All audit payloads include user_id/workspace_id for SaaS isolation.
        """
        if not self.config.audit_enabled:
            return

        event = {
            "agent": self.agent_name,
            "action": action,
            "status": status,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "details": details or {},
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(event)
            else:
                self.logger.info("AUDIT | %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # ==================================================================================
    # URL/network helpers
    # ==================================================================================

    def _is_url_allowed(self, url: str) -> bool:
        """
        Check URL against BrowserAgent safety policy.
        """
        if not is_valid_url(url):
            return False

        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()

        if scheme == "http" and not self.config.allow_http:
            return False

        if scheme == "https" and not self.config.allow_https:
            return False

        if not self.config.allow_localhost:
            if domain.startswith("localhost") or domain.startswith("127."):
                return False

        if not self.config.allow_private_ips:
            private_patterns = (
                "10.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "192.168.",
            )
            if any(domain.startswith(pattern) for pattern in private_patterns):
                return False

        clean_domain = domain.replace("www.", "")

        if self.config.blocked_domains:
            for blocked in self.config.blocked_domains:
                blocked = blocked.lower().replace("www.", "")
                if clean_domain == blocked or clean_domain.endswith("." + blocked):
                    return False

        if self.config.allowed_domains:
            allowed_match = False
            for allowed in self.config.allowed_domains:
                allowed = allowed.lower().replace("www.", "")
                if clean_domain == allowed or clean_domain.endswith("." + allowed):
                    allowed_match = True
                    break
            if not allowed_match:
                return False

        return True

    def _fetch_url(self, url: str) -> PageFetchResult:
        """
        Fetch URL using requests if available, otherwise urllib.

        This method is read-only.
        """
        started_at = time.time()
        url = normalize_url(url)

        if not self.config.enable_network:
            return PageFetchResult(
                url=url,
                final_url=url,
                status_code=None,
                content_type=None,
                text="",
                raw_html="",
                headers={},
                elapsed_ms=0,
                error="NETWORK_DISABLED",
            )

        if not self._is_url_allowed(url):
            return PageFetchResult(
                url=url,
                final_url=url,
                status_code=None,
                content_type=None,
                text="",
                raw_html="",
                headers={},
                elapsed_ms=0,
                error="URL_NOT_ALLOWED",
            )

        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            if requests is not None:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.config.default_timeout_seconds,
                    allow_redirects=self.config.follow_redirects,
                )

                content = response.content[: self.config.max_response_bytes]
                encoding = response.encoding or "utf-8"
                raw_html = content.decode(encoding, errors="replace")

                return PageFetchResult(
                    url=url,
                    final_url=str(response.url),
                    status_code=int(response.status_code),
                    content_type=response.headers.get("content-type"),
                    text=response.text[: self.config.max_response_bytes],
                    raw_html=raw_html,
                    headers=dict(response.headers),
                    elapsed_ms=int((time.time() - started_at) * 1000),
                    error=None if response.ok else f"HTTP_{response.status_code}",
                )

            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(
                request,
                timeout=self.config.default_timeout_seconds,
            ) as response:
                content = response.read(self.config.max_response_bytes)
                raw_html = content.decode("utf-8", errors="replace")
                final_url = response.geturl()
                response_headers = dict(response.headers.items())
                status_code = getattr(response, "status", None)

                return PageFetchResult(
                    url=url,
                    final_url=final_url,
                    status_code=status_code,
                    content_type=response_headers.get("Content-Type"),
                    text=raw_html,
                    raw_html=raw_html,
                    headers=response_headers,
                    elapsed_ms=int((time.time() - started_at) * 1000),
                    error=None,
                )

        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read(self.config.max_response_bytes).decode(
                    "utf-8",
                    errors="replace",
                )
            except Exception:
                body = ""

            return PageFetchResult(
                url=url,
                final_url=url,
                status_code=exc.code,
                content_type=None,
                text=body,
                raw_html=body,
                headers={},
                elapsed_ms=int((time.time() - started_at) * 1000),
                error=f"HTTP_{exc.code}",
            )

        except Exception as exc:
            return PageFetchResult(
                url=url,
                final_url=url,
                status_code=None,
                content_type=None,
                text="",
                raw_html="",
                headers={},
                elapsed_ms=int((time.time() - started_at) * 1000),
                error=str(exc),
            )

    # ==================================================================================
    # Search helpers
    # ==================================================================================

    def _search_duckduckgo_html(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """
        Search using DuckDuckGo HTML endpoint.

        This avoids API secrets and keeps the search provider simple.
        """
        encoded = urllib.parse.urlencode({"q": query})
        url = f"https://duckduckgo.com/html/?{encoded}"

        fetch = self._fetch_url(url)
        if fetch.error:
            raise RuntimeError(fetch.error)

        results = self._parse_duckduckgo_results(fetch.raw_html)
        return results[:limit]

    def _parse_duckduckgo_results(self, raw_html: str) -> List[Dict[str, Any]]:
        """
        Parse DuckDuckGo HTML search results.
        """
        results: List[Dict[str, Any]] = []

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            result_nodes = soup.select(".result")

            for index, node in enumerate(result_nodes, start=1):
                title_node = node.select_one(".result__title a") or node.select_one("a.result__a")
                snippet_node = node.select_one(".result__snippet")
                url_node = title_node

                title = compact_whitespace(title_node.get_text(" ")) if title_node else ""
                href = url_node.get("href") if url_node else ""
                snippet = compact_whitespace(snippet_node.get_text(" ")) if snippet_node else ""

                clean_url = self._clean_duckduckgo_redirect(href)

                if title and clean_url:
                    results.append(
                        {
                            "rank": index,
                            "title": title,
                            "url": clean_url,
                            "domain": domain_from_url(clean_url),
                            "snippet": snippet,
                        }
                    )

            if results:
                return results

        pattern = re.compile(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )

        for index, match in enumerate(pattern.findall(raw_html), start=1):
            href, title_html = match
            title = compact_whitespace(re.sub(r"<.*?>", "", html.unescape(title_html)))
            clean_url = self._clean_duckduckgo_redirect(html.unescape(href))

            if title and clean_url:
                results.append(
                    {
                        "rank": index,
                        "title": title,
                        "url": clean_url,
                        "domain": domain_from_url(clean_url),
                        "snippet": "",
                    }
                )

        return results

    def _clean_duckduckgo_redirect(self, href: str) -> str:
        """Clean DuckDuckGo redirect links."""
        href = html.unescape(href or "").strip()
        if not href:
            return ""

        parsed = urllib.parse.urlparse(href)
        query = urllib.parse.parse_qs(parsed.query)

        if "uddg" in query and query["uddg"]:
            return query["uddg"][0]

        if href.startswith("//duckduckgo.com/l/"):
            href = "https:" + href
            parsed = urllib.parse.urlparse(href)
            query = urllib.parse.parse_qs(parsed.query)
            if "uddg" in query and query["uddg"]:
                return query["uddg"][0]

        if href.startswith("/"):
            return make_absolute_url("https://duckduckgo.com", href)

        return href

    # ==================================================================================
    # HTML parsing helpers
    # ==================================================================================

    def _html_to_text(self, raw_html: str) -> str:
        """Convert HTML into readable text."""
        if not raw_html:
            return ""

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")

            for tag in soup(["script", "style", "noscript", "svg", "canvas"]):
                tag.decompose()

            text = soup.get_text(" ")
            return compact_whitespace(html.unescape(text))

        cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw_html)
        cleaned = re.sub(r"(?s)<.*?>", " ", cleaned)
        return compact_whitespace(html.unescape(cleaned))

    def _extract_title(self, raw_html: str) -> str:
        """Extract page title."""
        if not raw_html:
            return ""

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            title = soup.find("title")
            if title:
                return compact_whitespace(title.get_text(" "))

        match = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw_html)
        if match:
            return compact_whitespace(html.unescape(re.sub(r"<.*?>", "", match.group(1))))

        return ""

    def _extract_meta(self, raw_html: str) -> Dict[str, Any]:
        """Extract common meta tags."""
        meta: Dict[str, Any] = {}

        if not raw_html:
            return meta

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            for node in soup.find_all("meta"):
                name = (
                    node.get("name")
                    or node.get("property")
                    or node.get("http-equiv")
                    or ""
                )
                content = node.get("content") or ""
                if name and content:
                    meta[str(name).strip().lower()] = compact_whitespace(str(content))
            return meta

        for match in re.findall(r"(?is)<meta\s+([^>]+)>", raw_html):
            name_match = re.search(
                r'(?:name|property|http-equiv)=["\']([^"\']+)["\']',
                match,
                re.IGNORECASE,
            )
            content_match = re.search(
                r'content=["\']([^"\']*)["\']',
                match,
                re.IGNORECASE,
            )
            if name_match and content_match:
                meta[name_match.group(1).lower()] = compact_whitespace(
                    html.unescape(content_match.group(1))
                )

        return meta

    def _extract_headings(self, raw_html: str) -> Dict[str, List[str]]:
        """Extract H1-H6 headings."""
        headings = {f"h{i}": [] for i in range(1, 7)}

        if not raw_html:
            return headings

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            for i in range(1, 7):
                for node in soup.find_all(f"h{i}"):
                    text = compact_whitespace(node.get_text(" "))
                    if text:
                        headings[f"h{i}"].append(text)
            return headings

        for i in range(1, 7):
            pattern = re.compile(rf"(?is)<h{i}[^>]*>(.*?)</h{i}>")
            for item in pattern.findall(raw_html):
                text = compact_whitespace(html.unescape(re.sub(r"<.*?>", "", item)))
                if text:
                    headings[f"h{i}"].append(text)

        return headings

    def _extract_canonical(self, raw_html: str) -> Optional[str]:
        """Extract canonical URL."""
        if not raw_html:
            return None

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            node = soup.find("link", rel=lambda value: value and "canonical" in value)
            if node and node.get("href"):
                return str(node.get("href")).strip()

        match = re.search(
            r'(?is)<link[^>]+rel=["\'][^"\']*canonical[^"\']*["\'][^>]+href=["\']([^"\']+)["\']',
            raw_html,
        )
        if match:
            return match.group(1).strip()

        return None

    def _extract_links_from_html(self, base_url: str, raw_html: str) -> List[Dict[str, Any]]:
        """Extract internal and external links."""
        links: List[Dict[str, Any]] = []
        base_domain = domain_from_url(base_url)

        if not raw_html:
            return links

        seen: set[str] = set()

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            anchors = soup.find_all("a")
            for node in anchors:
                href = str(node.get("href") or "").strip()
                text = compact_whitespace(node.get_text(" "))

                if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue

                absolute = make_absolute_url(base_url, href)
                link_domain = domain_from_url(absolute)
                link_type = "internal" if link_domain == base_domain else "external"

                if absolute in seen:
                    continue

                seen.add(absolute)
                links.append(
                    {
                        "url": absolute,
                        "domain": link_domain,
                        "text": text,
                        "type": link_type,
                    }
                )

                if len(links) >= self.config.max_links:
                    break

            return links

        pattern = re.compile(r'(?is)<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>')
        for href, text_html in pattern.findall(raw_html):
            href = html.unescape(href).strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            absolute = make_absolute_url(base_url, href)
            if absolute in seen:
                continue

            text = compact_whitespace(html.unescape(re.sub(r"<.*?>", "", text_html)))
            link_domain = domain_from_url(absolute)
            link_type = "internal" if link_domain == base_domain else "external"

            seen.add(absolute)
            links.append(
                {
                    "url": absolute,
                    "domain": link_domain,
                    "text": text,
                    "type": link_type,
                }
            )

            if len(links) >= self.config.max_links:
                break

        return links

    def _extract_images_from_html(self, base_url: str, raw_html: str) -> List[Dict[str, Any]]:
        """Extract images from HTML."""
        images: List[Dict[str, Any]] = []

        if not raw_html:
            return images

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            for node in soup.find_all("img"):
                src = str(node.get("src") or "").strip()
                if not src:
                    continue

                images.append(
                    {
                        "src": make_absolute_url(base_url, src),
                        "alt": compact_whitespace(str(node.get("alt") or "")),
                        "title": compact_whitespace(str(node.get("title") or "")),
                        "width": node.get("width"),
                        "height": node.get("height"),
                    }
                )

            return images

        pattern = re.compile(r"(?is)<img\s+([^>]+)>")
        for attrs in pattern.findall(raw_html):
            src_match = re.search(r'src=["\']([^"\']+)["\']', attrs)
            alt_match = re.search(r'alt=["\']([^"\']*)["\']', attrs)

            if src_match:
                images.append(
                    {
                        "src": make_absolute_url(base_url, html.unescape(src_match.group(1))),
                        "alt": compact_whitespace(
                            html.unescape(alt_match.group(1)) if alt_match else ""
                        ),
                        "title": "",
                        "width": None,
                        "height": None,
                    }
                )

        return images

    def _extract_schema_types(self, raw_html: str) -> List[str]:
        """Extract JSON-LD schema @type values."""
        schema_types: List[str] = []

        if not raw_html:
            return schema_types

        scripts: List[str] = []

        if BeautifulSoup is not None:
            soup = BeautifulSoup(raw_html, "html.parser")
            for node in soup.find_all("script", type="application/ld+json"):
                scripts.append(node.string or node.get_text() or "")
        else:
            scripts = re.findall(
                r'(?is)<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                raw_html,
            )

        def collect_types(obj: Any) -> None:
            if isinstance(obj, dict):
                t = obj.get("@type")
                if isinstance(t, str):
                    schema_types.append(t)
                elif isinstance(t, list):
                    for item in t:
                        if isinstance(item, str):
                            schema_types.append(item)

                for value in obj.values():
                    collect_types(value)

            elif isinstance(obj, list):
                for item in obj:
                    collect_types(item)

        for script in scripts:
            parsed = safe_json_loads(script)
            if parsed is not None:
                collect_types(parsed)

        return sorted(set(schema_types))

    def _extract_social_links(self, links: List[Dict[str, Any]]) -> List[str]:
        """Extract social profile links."""
        social_domains = [
            "facebook.com",
            "instagram.com",
            "linkedin.com",
            "twitter.com",
            "x.com",
            "youtube.com",
            "tiktok.com",
            "pinterest.com",
        ]

        found: List[str] = []

        for link in links:
            url = link.get("url", "")
            domain = domain_from_url(url)
            if any(domain.endswith(social) for social in social_domains):
                found.append(url)

        return sorted(set(found))

    # ==================================================================================
    # Analysis helpers
    # ==================================================================================

    def _build_page_analysis(self, url: str, raw_html: str) -> PageAnalysis:
        """Build complete page analysis."""
        text = self._html_to_text(raw_html)
        title = self._extract_title(raw_html)
        meta = self._extract_meta(raw_html)
        headings = self._extract_headings(raw_html)
        canonical = self._extract_canonical(raw_html)
        links = self._extract_links_from_html(url, raw_html)
        images = self._extract_images_from_html(url, raw_html)
        schema_types = self._extract_schema_types(raw_html)
        social_links = self._extract_social_links(links)

        internal_links = [link for link in links if link.get("type") == "internal"]
        external_links = [link for link in links if link.get("type") == "external"]
        missing_alt = [img for img in images if not img.get("alt")]

        meta_description = (
            meta.get("description")
            or meta.get("og:description")
            or meta.get("twitter:description")
            or ""
        )

        seo_score, seo_issues, seo_recommendations = self._score_seo(
            title=title,
            meta_description=meta_description,
            headings=headings,
            canonical=canonical,
            word_count=len(text.split()),
            images_count=len(images),
            images_missing_alt_count=len(missing_alt),
            schema_types=schema_types,
        )

        return PageAnalysis(
            url=url,
            title=title,
            meta_description=meta_description,
            h1=headings.get("h1", []),
            h2=headings.get("h2", []),
            h3=headings.get("h3", []),
            canonical=canonical,
            word_count=len(text.split()),
            links_internal_count=len(internal_links),
            links_external_count=len(external_links),
            images_count=len(images),
            images_missing_alt_count=len(missing_alt),
            schema_types=schema_types,
            emails=extract_emails(text),
            phones=extract_phone_numbers(text),
            social_links=social_links,
            page_summary=self._simple_summary(text, max_chars=self.config.max_summary_chars),
            seo_score=seo_score,
            seo_issues=seo_issues,
            seo_recommendations=seo_recommendations,
        )

    def _score_seo(
        self,
        title: str,
        meta_description: str,
        headings: Dict[str, List[str]],
        canonical: Optional[str],
        word_count: int,
        images_count: int,
        images_missing_alt_count: int,
        schema_types: List[str],
    ) -> Tuple[int, List[str], List[str]]:
        """
        Score page SEO from 0 to 100 with practical issues/recommendations.
        """
        score = 100
        issues: List[str] = []
        recommendations: List[str] = []

        if not title:
            score -= 15
            issues.append("Missing title tag.")
            recommendations.append("Add a clear SEO title around 50-60 characters.")
        elif len(title) < 25:
            score -= 6
            issues.append("Title tag is short.")
            recommendations.append("Expand the title with primary keyword and value proposition.")
        elif len(title) > 70:
            score -= 6
            issues.append("Title tag may be too long.")
            recommendations.append("Keep title close to 50-60 characters for cleaner SERP display.")

        if not meta_description:
            score -= 15
            issues.append("Missing meta description.")
            recommendations.append("Add a conversion-focused meta description around 140-160 characters.")
        elif len(meta_description) < 70:
            score -= 6
            issues.append("Meta description is short.")
            recommendations.append("Make the meta description more persuasive and complete.")
        elif len(meta_description) > 180:
            score -= 6
            issues.append("Meta description may be too long.")
            recommendations.append("Shorten meta description to improve SERP readability.")

        h1 = headings.get("h1", [])
        if not h1:
            score -= 12
            issues.append("Missing H1 heading.")
            recommendations.append("Add one clear H1 with the primary keyword.")
        elif len(h1) > 1:
            score -= 5
            issues.append("Multiple H1 headings found.")
            recommendations.append("Use one primary H1 and convert others to H2/H3.")

        if not headings.get("h2"):
            score -= 5
            issues.append("No H2 headings found.")
            recommendations.append("Add H2 sections to improve content structure.")

        if not canonical:
            score -= 5
            issues.append("Missing canonical URL.")
            recommendations.append("Add canonical tag to prevent duplicate URL confusion.")

        if word_count < 300:
            score -= 10
            issues.append("Low page word count.")
            recommendations.append("Add useful content, FAQs, proof points, and stronger service details.")

        if images_count > 0 and images_missing_alt_count > 0:
            penalty = min(10, images_missing_alt_count * 2)
            score -= penalty
            issues.append(f"{images_missing_alt_count} image(s) missing alt text.")
            recommendations.append("Add descriptive alt text to important images.")

        if not schema_types:
            score -= 5
            issues.append("No structured data detected.")
            recommendations.append("Add relevant schema such as Organization, LocalBusiness, FAQPage, or Service.")

        score = max(0, min(100, score))

        if not issues:
            recommendations.append("Page has solid basic SEO signals. Continue improving conversion copy and internal links.")

        return score, issues, recommendations

    def _simple_summary(self, text: str, max_chars: int = 2500) -> str:
        """
        Generate simple extractive summary.

        Keeps first useful sentences until max_chars.
        """
        text = compact_whitespace(text)
        if not text:
            return ""

        sentences = re.split(r"(?<=[.!?])\s+", text)
        selected: List[str] = []
        total = 0

        for sentence in sentences:
            sentence = compact_whitespace(sentence)
            if len(sentence) < 25:
                continue

            if total + len(sentence) + 1 > max_chars:
                break

            selected.append(sentence)
            total += len(sentence) + 1

            if total >= max_chars:
                break

        if not selected:
            return truncate_text(text, max_chars)

        return " ".join(selected)

    def _build_seo_opportunities(
        self,
        keyword: str,
        serp_results: List[Dict[str, Any]],
        target_analysis: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Build practical SEO opportunities from SERP and target page data.
        """
        opportunities: List[Dict[str, Any]] = []

        if serp_results:
            top_titles = [item.get("title", "") for item in serp_results[:5]]
            opportunities.append(
                {
                    "type": "serp_angle",
                    "priority": "high",
                    "title": "Match and improve SERP intent",
                    "detail": (
                        "Top results suggest the content should directly satisfy the search intent "
                        f"for '{keyword}'. Review competing titles and create a stronger, clearer angle."
                    ),
                    "examples": top_titles,
                }
            )

        if target_analysis:
            score = int(target_analysis.get("seo_score") or 0)
            if score < 80:
                opportunities.append(
                    {
                        "type": "on_page_seo",
                        "priority": "high",
                        "title": "Improve target page SEO score",
                        "detail": "Fix detected SEO issues on the target page.",
                        "issues": target_analysis.get("seo_issues", []),
                        "recommendations": target_analysis.get("seo_recommendations", []),
                    }
                )

            if not target_analysis.get("schema_types"):
                opportunities.append(
                    {
                        "type": "schema",
                        "priority": "medium",
                        "title": "Add structured data",
                        "detail": "Add relevant schema to improve search understanding and rich-result eligibility.",
                    }
                )

            if int(target_analysis.get("word_count") or 0) < 700:
                opportunities.append(
                    {
                        "type": "content_depth",
                        "priority": "medium",
                        "title": "Increase content depth",
                        "detail": "Add stronger service details, FAQs, benefits, proof, and conversion-focused sections.",
                    }
                )

        if not opportunities:
            opportunities.append(
                {
                    "type": "general",
                    "priority": "medium",
                    "title": "Build authority and conversion strength",
                    "detail": "Improve internal links, proof points, FAQs, case studies, and CTA placement.",
                }
            )

        return opportunities

    def _compare_competitors(
        self,
        keyword: Optional[str],
        reports: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Compare competitor page analysis results.
        """
        successful = [
            report for report in reports
            if report.get("success") and isinstance(report.get("analysis"), dict)
        ]

        if not successful:
            return {
                "keyword": keyword,
                "summary": "No successful competitor analysis available.",
                "best_seo_score": None,
                "average_word_count": None,
                "common_schema_types": [],
                "recommendations": [
                    "Check competitor URLs and try again.",
                    "Allow network access and ensure target pages are publicly reachable.",
                ],
            }

        scores = [
            int(report["analysis"].get("seo_score") or 0)
            for report in successful
        ]

        word_counts = [
            int(report["analysis"].get("word_count") or 0)
            for report in successful
        ]

        schema_counter: Dict[str, int] = {}
        for report in successful:
            for schema_type in report["analysis"].get("schema_types") or []:
                schema_counter[schema_type] = schema_counter.get(schema_type, 0) + 1

        common_schema = sorted(
            schema_counter.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        recommendations = [
            "Build a clearer above-the-fold offer than competitors.",
            "Use stronger headings with the primary keyword and service benefit.",
            "Add FAQ and Service schema where relevant.",
            "Improve CTA placement and trust proof throughout the page.",
        ]

        if keyword:
            recommendations.insert(
                0,
                f"Create content that satisfies search intent for '{keyword}' better than all compared competitors.",
            )

        return {
            "keyword": keyword,
            "competitors_analyzed": len(successful),
            "best_seo_score": max(scores) if scores else None,
            "average_seo_score": round(sum(scores) / len(scores), 2) if scores else None,
            "average_word_count": round(sum(word_counts) / len(word_counts), 2) if word_counts else None,
            "common_schema_types": [
                {"schema_type": item[0], "count": item[1]}
                for item in common_schema
            ],
            "recommendations": recommendations,
        }

    def _extract_prices(
        self,
        text: str,
        currency_symbols: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extract possible prices from text.
        """
        currency_symbols = currency_symbols or ["$", "£", "€", "AED", "USD", "GBP", "EUR"]

        escaped = [re.escape(symbol) for symbol in currency_symbols]
        symbol_pattern = "|".join(escaped)

        patterns = [
            rf"(?P<currency>{symbol_pattern})\s?(?P<amount>\d{{1,3}}(?:,\d{{3}})*(?:\.\d{{2}})?|\d+(?:\.\d{{2}})?)",
            rf"(?P<amount>\d{{1,3}}(?:,\d{{3}})*(?:\.\d{{2}})?|\d+(?:\.\d{{2}})?)\s?(?P<currency>{symbol_pattern})",
        ]

        found: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for pattern in patterns:
            for match in re.finditer(pattern, text or "", flags=re.IGNORECASE):
                currency = match.groupdict().get("currency") or ""
                amount = match.groupdict().get("amount") or ""
                raw = compact_whitespace(match.group(0))

                key = f"{currency}:{amount}:{match.start()}"
                if key in seen:
                    continue

                seen.add(key)

                context_start = max(0, match.start() - 80)
                context_end = min(len(text), match.end() + 80)

                found.append(
                    {
                        "raw": raw,
                        "currency": currency,
                        "amount": amount,
                        "context": compact_whitespace(text[context_start:context_end]),
                    }
                )

        return found[:50]


# ======================================================================================
# Local manual test helper
# ======================================================================================

if __name__ == "__main__":
    async def _demo() -> None:
        agent = BrowserAgent(
            config=BrowserAgentConfig(
                require_security_for_network=False,
                require_security_for_scrape=False,
                require_security_for_competitor_research=False,
            )
        )

        result = await agent.execute(
            {
                "action": "health_check",
                "user_id": "demo-user",
                "workspace_id": "demo-workspace",
                "payload": {},
            }
        )

        print(json.dumps(result, indent=2, default=str))

    asyncio.run(_demo())