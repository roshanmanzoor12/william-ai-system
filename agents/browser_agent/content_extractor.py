"""
William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File: agents/browser_agent/content_extractor.py
Agent/Module: Browser Agent
Purpose: Extract hero, headings, CTAs, pricing, testimonials, FAQs, links, tables.

This file is designed to be:
- Import-safe even if the complete William/Jarvis project is not created yet.
- Compatible with BaseAgent, Agent Registry, Agent Loader, Router, and Master Agent.
- SaaS-ready with strict user_id and workspace_id validation.
- Security-aware for content extraction workflows.
- Verification-ready for completed extraction payloads.
- Memory-compatible for safe summary storage.
- Dashboard/API-ready with structured dict/JSON-style responses.

Public Class:
- ContentExtractor

Main Public Methods:
- extract()
- extract_from_html()
- extract_from_scraped_data()
- extract_hero()
- extract_headings()
- extract_ctas()
- extract_pricing()
- extract_testimonials()
- extract_faqs()
- extract_links()
- extract_tables()
- health_check()
"""

from __future__ import annotations

import hashlib
import html
import logging
import re
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse


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

            This keeps content_extractor.py safe to import before the complete
            William/Jarvis project structure exists.
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

LOGGER = logging.getLogger("William.BrowserAgent.ContentExtractor")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_TEXT_CHARS = 150_000
DEFAULT_MAX_HEADINGS = 250
DEFAULT_MAX_CTAS = 150
DEFAULT_MAX_PRICING_BLOCKS = 80
DEFAULT_MAX_TESTIMONIALS = 120
DEFAULT_MAX_FAQS = 150
DEFAULT_MAX_LINKS = 300
DEFAULT_MAX_TABLES = 80
DEFAULT_MAX_TABLE_ROWS = 200
DEFAULT_MAX_TABLE_COLUMNS = 40

CTA_KEYWORDS = {
    "get started",
    "start now",
    "start today",
    "try now",
    "try free",
    "free trial",
    "book now",
    "book a call",
    "schedule a call",
    "contact us",
    "contact sales",
    "request demo",
    "get demo",
    "see demo",
    "learn more",
    "read more",
    "download",
    "buy now",
    "subscribe",
    "sign up",
    "signup",
    "register",
    "join now",
    "apply now",
    "claim offer",
    "get quote",
    "request quote",
    "talk to sales",
    "call now",
    "shop now",
    "order now",
}

PRICING_KEYWORDS = {
    "pricing",
    "price",
    "plans",
    "package",
    "packages",
    "starter",
    "basic",
    "standard",
    "premium",
    "enterprise",
    "monthly",
    "yearly",
    "annual",
    "per month",
    "per year",
    "billed",
    "subscription",
}

TESTIMONIAL_KEYWORDS = {
    "testimonial",
    "testimonials",
    "review",
    "reviews",
    "customer story",
    "case study",
    "trusted by",
    "what our clients say",
    "what customers say",
    "success story",
    "rating",
    "stars",
}

FAQ_KEYWORDS = {
    "faq",
    "faqs",
    "frequently asked questions",
    "question",
    "questions",
    "help center",
    "support",
}

HERO_CLASS_HINTS = {
    "hero",
    "banner",
    "masthead",
    "above-fold",
    "above_the_fold",
    "intro",
    "jumbotron",
    "headline",
    "landing",
}

COMMON_HIDDEN_ATTRS = {
    "hidden",
    "aria-hidden",
}

NOISE_TAGS = {
    "script",
    "style",
    "noscript",
    "template",
    "svg",
    "canvas",
    "iframe",
    "object",
    "embed",
}


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ContentExtractorConfig:
    """
    Runtime configuration for safe page content extraction.

    Defaults are conservative and dashboard/API friendly.
    """

    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
    max_headings: int = DEFAULT_MAX_HEADINGS
    max_ctas: int = DEFAULT_MAX_CTAS
    max_pricing_blocks: int = DEFAULT_MAX_PRICING_BLOCKS
    max_testimonials: int = DEFAULT_MAX_TESTIMONIALS
    max_faqs: int = DEFAULT_MAX_FAQS
    max_links: int = DEFAULT_MAX_LINKS
    max_tables: int = DEFAULT_MAX_TABLES
    max_table_rows: int = DEFAULT_MAX_TABLE_ROWS
    max_table_columns: int = DEFAULT_MAX_TABLE_COLUMNS
    normalize_whitespace: bool = True
    include_raw_html: bool = False
    include_section_html: bool = False
    include_debug_signals: bool = False
    collect_links: bool = True
    collect_tables: bool = True
    collect_faqs: bool = True
    collect_pricing: bool = True
    collect_testimonials: bool = True
    collect_ctas: bool = True
    collect_headings: bool = True
    collect_hero: bool = True


@dataclass
class ExtractorContext:
    """
    SaaS execution context.

    Every user-specific task must include user_id and workspace_id.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    task_id: Optional[str] = None
    agent_run_id: Optional[str] = None
    request_id: Optional[str] = None
    source: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractionItem:
    """
    Standard extracted content item.
    """

    text: str
    type: str
    tag: Optional[str] = None
    url: Optional[str] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Content Extractor
# ---------------------------------------------------------------------------

class ContentExtractor(BaseAgent):
    """
    Browser Agent helper responsible for extracting structured visible content.

    This class does not fetch pages directly, click links, submit forms,
    authenticate, bypass protections, or perform browser automation. It only
    parses supplied HTML or already-scraped data.

    It is safe to route through:
    - Master Agent
    - Browser Agent
    - Agent Registry
    - Agent Loader
    - Agent Router
    - Future FastAPI/dashboard endpoints
    """

    public_methods = [
        "extract",
        "extract_from_html",
        "extract_from_scraped_data",
        "extract_hero",
        "extract_headings",
        "extract_ctas",
        "extract_pricing",
        "extract_testimonials",
        "extract_faqs",
        "extract_links",
        "extract_tables",
        "health_check",
    ]

    def __init__(
        self,
        config: Optional[ContentExtractorConfig] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", "BrowserContentExtractor"),
            agent_type=kwargs.pop("agent_type", "browser_agent"),
            *args,
            **kwargs,
        )

        self.config = config or ContentExtractorConfig()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.logger = logging.getLogger("William.BrowserAgent.ContentExtractor")

    # -----------------------------------------------------------------------
    # BaseAgent / Router compatible entry point
    # -----------------------------------------------------------------------

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Generic router-compatible entry point.

        Expected task examples:
        {
            "action": "extract",
            "html": "<html>...</html>",
            "url": "https://example.com",
            "user_id": "1",
            "workspace_id": "default"
        }

        {
            "action": "extract_from_scraped_data",
            "scraped_data": {...},
            "user_id": "1",
            "workspace_id": "default"
        }
        """

        task = task or {}
        merged = {**task, **kwargs}
        action = str(merged.get("action", "extract")).strip().lower()

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

        if action in {"extract", "extract_from_html", "content_extract"}:
            return self.extract_from_html(
                html_text=str(merged.get("html") or merged.get("html_text") or ""),
                url=self._optional_str(merged.get("url")) or "",
                context=context,
                options=merged.get("options") or {},
            )

        if action in {"extract_from_scraped_data", "extract_scraped"}:
            return self.extract_from_scraped_data(
                scraped_data=merged.get("scraped_data") or merged.get("data") or {},
                context=context,
                options=merged.get("options") or {},
            )

        if action in {"health", "health_check"}:
            return self.health_check(context=context)

        return self._error_result(
            message=f"Unsupported ContentExtractor action: {action}",
            error="UNSUPPORTED_ACTION",
            metadata={"action": action},
        )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def extract(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Alias for extract_from_html().

        Kept for simpler Master Agent / Router integration.
        """

        return self.extract_from_html(
            html_text=html_text,
            url=url,
            context=context,
            options=options,
        )

    def extract_from_html(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract structured content from raw HTML.

        Extracted content:
        - Page metadata
        - Hero content
        - Headings
        - CTAs
        - Pricing blocks
        - Testimonials/reviews
        - FAQs
        - Links
        - Tables
        """

        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        if not isinstance(html_text, str) or not html_text.strip():
            return self._error_result(
                message="HTML text is empty or invalid.",
                error="INVALID_HTML_TEXT",
                metadata={"url": url},
            )

        security_result = self._request_security_approval(
            action="browser.content_extract",
            context=ctx_result["data"]["context"],
            target=url,
            options=options,
        )
        if not security_result["success"]:
            return security_result

        self._emit_agent_event(
            event_name="content_extractor.extract.started",
            context=ctx_result["data"]["context"],
            payload={"url": url, "html_chars": len(html_text)},
        )

        self._log_audit_event(
            action="browser.content_extract.started",
            context=ctx_result["data"]["context"],
            payload={"url": url, "html_chars": len(html_text)},
        )

        try:
            soup = self._create_soup(html_text)
            if soup is None:
                return self._error_result(
                    message="BeautifulSoup is required for content extraction.",
                    error="BEAUTIFULSOUP_NOT_AVAILABLE",
                    metadata={"dependency": "beautifulsoup4"},
                )

            self._remove_noise(soup)

            data = self._extract_all(
                soup=soup,
                url=url,
                html_text=html_text,
                options=options,
            )

            result = self._safe_result(
                message="Content extracted successfully.",
                data=data,
                metadata={
                    "agent": "ContentExtractor",
                    "verification": self._prepare_verification_payload(
                        action="browser.content_extract",
                        context=ctx_result["data"]["context"],
                        data=data,
                    ),
                    "memory": self._prepare_memory_payload(
                        action="browser.content_extract",
                        context=ctx_result["data"]["context"],
                        data=data,
                    ),
                },
            )

            self._emit_agent_event(
                event_name="content_extractor.extract.completed",
                context=ctx_result["data"]["context"],
                payload={
                    "url": url,
                    "headings_count": len(data.get("headings", [])),
                    "ctas_count": len(data.get("ctas", [])),
                    "pricing_count": len(data.get("pricing", [])),
                    "faq_count": len(data.get("faqs", [])),
                },
            )

            self._log_audit_event(
                action="browser.content_extract.completed",
                context=ctx_result["data"]["context"],
                payload={
                    "url": url,
                    "content_hash": data.get("content_hash"),
                    "summary": data.get("summary", {}),
                },
            )

            return result

        except Exception as exc:
            self.logger.warning("Content extraction failed: %s", exc)
            self._log_audit_event(
                action="browser.content_extract.failed",
                context=ctx_result["data"]["context"],
                payload={"url": url, "error": str(exc)},
            )
            return self._error_result(
                message="Content extraction failed.",
                error=str(exc),
                metadata={
                    "url": url,
                    "trace": traceback.format_exc(limit=3),
                },
            )

    def extract_from_scraped_data(
        self,
        scraped_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract content from Scraper output.

        Supports common structures from agents/browser_agent/scraper.py:
        {
            "text": "<html>...</html>"
        }

        or:

        {
            "extracted": {
                "visible_text": "...",
                "headings": [...],
                "links": [...]
            }
        }
        """

        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        if not isinstance(scraped_data, dict):
            return self._error_result(
                message="scraped_data must be a dictionary.",
                error="INVALID_SCRAPED_DATA",
                metadata={},
            )

        url = (
            scraped_data.get("final_url")
            or scraped_data.get("url")
            or scraped_data.get("data", {}).get("final_url")
            or scraped_data.get("data", {}).get("url")
            or ""
        )

        html_text = (
            scraped_data.get("text")
            or scraped_data.get("html")
            or scraped_data.get("raw_html")
            or scraped_data.get("data", {}).get("text")
            or scraped_data.get("data", {}).get("html")
            or scraped_data.get("data", {}).get("raw_html")
            or ""
        )

        if html_text:
            return self.extract_from_html(
                html_text=str(html_text),
                url=str(url),
                context=ctx_result["data"]["context"],
                options=options,
            )

        extracted = (
            scraped_data.get("extracted")
            or scraped_data.get("data", {}).get("extracted")
            or scraped_data
        )

        if not isinstance(extracted, dict):
            return self._error_result(
                message="No extractable HTML or structured scraped content found.",
                error="NO_EXTRACTABLE_CONTENT",
                metadata={"url": url},
            )

        security_result = self._request_security_approval(
            action="browser.content_extract_from_structured_data",
            context=ctx_result["data"]["context"],
            target=str(url),
            options=options,
        )
        if not security_result["success"]:
            return security_result

        data = self._normalize_structured_scraped_content(extracted, str(url), options)

        return self._safe_result(
            message="Structured scraped content normalized successfully.",
            data=data,
            metadata={
                "agent": "ContentExtractor",
                "verification": self._prepare_verification_payload(
                    action="browser.content_extract_from_structured_data",
                    context=ctx_result["data"]["context"],
                    data=data,
                ),
                "memory": self._prepare_memory_payload(
                    action="browser.content_extract_from_structured_data",
                    context=ctx_result["data"]["context"],
                    data=data,
                ),
            },
        )

    def extract_hero(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract hero/above-the-fold content only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "hero")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_hero(soup, url, options or {})

        return self._safe_result(
            message="Hero content extracted successfully.",
            data={"hero": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_headings(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract page headings only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "headings")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_headings(soup)

        return self._safe_result(
            message="Headings extracted successfully.",
            data={"headings": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_ctas(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract calls-to-action only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "ctas")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_ctas(soup, url)

        return self._safe_result(
            message="CTAs extracted successfully.",
            data={"ctas": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_pricing(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract pricing blocks only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "pricing")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_pricing(soup, url)

        return self._safe_result(
            message="Pricing content extracted successfully.",
            data={"pricing": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_testimonials(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract testimonials/reviews only.
        """

        soup_result = self._prepare_single_extraction(
            html_text,
            url,
            context,
            options,
            "testimonials",
        )
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_testimonials(soup)

        return self._safe_result(
            message="Testimonials extracted successfully.",
            data={"testimonials": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_faqs(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract FAQs only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "faqs")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_faqs(soup)

        return self._safe_result(
            message="FAQs extracted successfully.",
            data={"faqs": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_links(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract links only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "links")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_links(soup, url)

        return self._safe_result(
            message="Links extracted successfully.",
            data={"links": data},
            metadata={"agent": "ContentExtractor"},
        )

    def extract_tables(
        self,
        html_text: str,
        url: str = "",
        context: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract tables only.
        """

        soup_result = self._prepare_single_extraction(html_text, url, context, options, "tables")
        if not soup_result["success"]:
            return soup_result

        soup = soup_result["data"]["soup"]
        data = self._extract_tables(soup)

        return self._safe_result(
            message="Tables extracted successfully.",
            data={"tables": data},
            metadata={"agent": "ContentExtractor"},
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
            "agent": "ContentExtractor",
            "status": "healthy",
            "beautifulsoup_available": BeautifulSoup is not None,
            "config": {
                "max_text_chars": self.config.max_text_chars,
                "max_headings": self.config.max_headings,
                "max_ctas": self.config.max_ctas,
                "max_pricing_blocks": self.config.max_pricing_blocks,
                "max_testimonials": self.config.max_testimonials,
                "max_faqs": self.config.max_faqs,
                "max_links": self.config.max_links,
                "max_tables": self.config.max_tables,
            },
            "public_methods": self.public_methods,
            "timestamp": self._utc_now(),
        }

        return self._safe_result(
            message="ContentExtractor health check completed.",
            data=data,
            metadata={"agent": "ContentExtractor"},
        )

    # -----------------------------------------------------------------------
    # Core extraction workflow
    # -----------------------------------------------------------------------

    def _extract_all(
        self,
        soup: Any,
        url: str,
        html_text: str,
        options: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Extract all supported content sections.
        """

        metadata = self._extract_metadata(soup, url)
        visible_text = self._extract_visible_text(soup)
        visible_text = self._truncate_text(
            visible_text,
            int(options.get("max_text_chars", self.config.max_text_chars)),
        )

        hero = {}
        if self.config.collect_hero and options.get("collect_hero", True):
            hero = self._extract_hero(soup, url, options)

        headings = []
        if self.config.collect_headings and options.get("collect_headings", True):
            headings = self._extract_headings(soup)

        ctas = []
        if self.config.collect_ctas and options.get("collect_ctas", True):
            ctas = self._extract_ctas(soup, url)

        pricing = []
        if self.config.collect_pricing and options.get("collect_pricing", True):
            pricing = self._extract_pricing(soup, url)

        testimonials = []
        if self.config.collect_testimonials and options.get("collect_testimonials", True):
            testimonials = self._extract_testimonials(soup)

        faqs = []
        if self.config.collect_faqs and options.get("collect_faqs", True):
            faqs = self._extract_faqs(soup)

        links = []
        if self.config.collect_links and options.get("collect_links", True):
            links = self._extract_links(soup, url)

        tables = []
        if self.config.collect_tables and options.get("collect_tables", True):
            tables = self._extract_tables(soup)

        content_hash = self._hash_text(
            " ".join(
                [
                    metadata.get("title") or "",
                    metadata.get("description") or "",
                    hero.get("headline") or "",
                    visible_text,
                ]
            )
        )

        summary = {
            "hero_found": bool(hero.get("headline") or hero.get("text")),
            "headings_count": len(headings),
            "ctas_count": len(ctas),
            "pricing_blocks_count": len(pricing),
            "testimonials_count": len(testimonials),
            "faqs_count": len(faqs),
            "links_count": len(links),
            "tables_count": len(tables),
            "visible_text_length": len(visible_text),
        }

        data: Dict[str, Any] = {
            "url": url,
            "metadata": metadata,
            "hero": hero,
            "headings": headings,
            "ctas": ctas,
            "pricing": pricing,
            "testimonials": testimonials,
            "faqs": faqs,
            "links": links,
            "tables": tables,
            "visible_text": visible_text,
            "summary": summary,
            "content_hash": content_hash,
            "extracted_at": self._utc_now(),
            "extractor": "ContentExtractor",
        }

        if bool(options.get("include_raw_html", self.config.include_raw_html)):
            data["raw_html"] = self._truncate_text(
                html_text,
                int(options.get("max_raw_html_chars", 250_000)),
            )

        return data

    def _extract_metadata(self, soup: Any, url: str) -> Dict[str, Any]:
        """
        Extract common page metadata.
        """

        title = None
        title_tag = soup.find("title")
        if title_tag:
            title = self._clean_text(title_tag.get_text(" ", strip=True))

        description = self._meta_content(
            soup,
            [
                {"name": "description"},
                {"property": "og:description"},
                {"name": "twitter:description"},
            ],
        )

        og_title = self._meta_content(soup, [{"property": "og:title"}])
        og_image = self._meta_content(soup, [{"property": "og:image"}])
        twitter_title = self._meta_content(soup, [{"name": "twitter:title"}])

        canonical = None
        canonical_tag = soup.find(
            "link",
            attrs={"rel": lambda value: value and "canonical" in value},
        )
        if canonical_tag and canonical_tag.get("href"):
            canonical = self._safe_join_url(url, str(canonical_tag.get("href")))

        lang = None
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            lang = self._clean_text(str(html_tag.get("lang")))

        return {
            "title": title,
            "description": description,
            "og_title": og_title,
            "twitter_title": twitter_title,
            "og_image": self._safe_join_url(url, og_image) if og_image else None,
            "canonical_url": canonical,
            "language": lang,
        }

    def _extract_hero(
        self,
        soup: Any,
        url: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract likely hero/above-the-fold section.

        Uses semantic tags, class/id hints, and first meaningful section signals.
        """

        options = options or {}
        candidates: List[Tuple[float, Any]] = []

        body = soup.find("body") or soup

        for tag in body.find_all(["section", "header", "main", "div"], recursive=True):
            if self._is_hidden(tag):
                continue

            score = self._hero_score(tag)
            if score <= 0:
                continue

            text = self._clean_text(tag.get_text(" ", strip=True))
            if len(text) < 20:
                continue

            candidates.append((score, tag))

        if not candidates:
            first_main = self._first_meaningful_container(body)
            if first_main is not None:
                candidates.append((0.45, first_main))

        if not candidates:
            return {}

        candidates.sort(key=lambda item: item[0], reverse=True)
        best_score, best = candidates[0]

        headline = self._first_heading_text(best)
        subheadline = self._hero_subheadline(best, headline)
        ctas = self._extract_ctas_from_scope(best, url, max_items=8)
        images = self._extract_images_from_scope(best, url, max_items=5)

        hero_text = self._truncate_text(
            self._clean_text(best.get_text(" ", strip=True)),
            2500,
        )

        data: Dict[str, Any] = {
            "headline": headline,
            "subheadline": subheadline,
            "text": hero_text,
            "ctas": ctas,
            "images": images,
            "confidence": round(min(best_score, 1.0), 2),
            "signals": self._element_signals(best),
        }

        if bool(options.get("include_section_html", self.config.include_section_html)):
            data["html"] = self._truncate_text(str(best), 20_000)

        return data

    def _extract_headings(self, soup: Any) -> List[Dict[str, Any]]:
        """
        Extract H1-H6 headings.
        """

        headings: List[Dict[str, Any]] = []

        for tag in soup.find_all(re.compile("^h[1-6]$")):
            if self._is_hidden(tag):
                continue

            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text:
                continue

            headings.append(
                {
                    "level": str(tag.name).lower(),
                    "text": self._truncate_text(text, 700),
                    "id": self._optional_str(tag.get("id")),
                    "classes": self._class_list(tag),
                }
            )

            if len(headings) >= self.config.max_headings:
                break

        return headings

    def _extract_ctas(self, soup: Any, url: str) -> List[Dict[str, Any]]:
        """
        Extract CTA buttons/links.
        """

        return self._extract_ctas_from_scope(
            scope=soup,
            base_url=url,
            max_items=self.config.max_ctas,
        )

    def _extract_pricing(self, soup: Any, url: str) -> List[Dict[str, Any]]:
        """
        Extract likely pricing blocks/plans.
        """

        candidates: List[Tuple[float, Any]] = []
        seen_text = set()

        for tag in soup.find_all(["section", "div", "article", "li", "table"]):
            if self._is_hidden(tag):
                continue

            text = self._clean_text(tag.get_text(" ", strip=True))
            if len(text) < 20:
                continue

            score = self._pricing_score(tag, text)
            if score <= 0:
                continue

            text_key = self._hash_text(text[:500])
            if text_key in seen_text:
                continue
            seen_text.add(text_key)

            candidates.append((score, tag))

        candidates.sort(key=lambda item: item[0], reverse=True)

        pricing: List[Dict[str, Any]] = []
        used_hashes = set()

        for score, tag in candidates:
            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text:
                continue

            compact_hash = self._hash_text(self._normalize_space(text)[:800])
            if compact_hash in used_hashes:
                continue
            used_hashes.add(compact_hash)

            plan_name = self._extract_plan_name(tag)
            price_values = self._extract_price_values(text)
            features = self._extract_feature_lines(tag)
            ctas = self._extract_ctas_from_scope(tag, url, max_items=5)

            pricing.append(
                {
                    "plan_name": plan_name,
                    "prices": price_values,
                    "features": features,
                    "ctas": ctas,
                    "text": self._truncate_text(text, 2500),
                    "confidence": round(min(score, 1.0), 2),
                    "signals": self._element_signals(tag),
                }
            )

            if len(pricing) >= self.config.max_pricing_blocks:
                break

        return pricing

    def _extract_testimonials(self, soup: Any) -> List[Dict[str, Any]]:
        """
        Extract likely testimonials, reviews, and customer quote blocks.
        """

        candidates: List[Tuple[float, Any]] = []
        seen = set()

        for tag in soup.find_all(["section", "div", "article", "blockquote", "li"]):
            if self._is_hidden(tag):
                continue

            text = self._clean_text(tag.get_text(" ", strip=True))
            if len(text) < 25:
                continue

            score = self._testimonial_score(tag, text)
            if score <= 0:
                continue

            key = self._hash_text(text[:700])
            if key in seen:
                continue
            seen.add(key)

            candidates.append((score, tag))

        candidates.sort(key=lambda item: item[0], reverse=True)

        testimonials: List[Dict[str, Any]] = []
        used = set()

        for score, tag in candidates:
            text = self._clean_text(tag.get_text(" ", strip=True))
            key = self._hash_text(text[:500])
            if key in used:
                continue
            used.add(key)

            author = self._extract_testimonial_author(tag)
            rating = self._extract_rating(text, tag)

            testimonials.append(
                {
                    "text": self._truncate_text(text, 1800),
                    "author": author,
                    "rating": rating,
                    "confidence": round(min(score, 1.0), 2),
                    "signals": self._element_signals(tag),
                }
            )

            if len(testimonials) >= self.config.max_testimonials:
                break

        return testimonials

    def _extract_faqs(self, soup: Any) -> List[Dict[str, Any]]:
        """
        Extract FAQ question/answer pairs.

        Supports:
        - details/summary
        - FAQ schema-like blocks
        - headings followed by paragraphs
        - question-looking text blocks
        """

        faqs: List[Dict[str, Any]] = []
        seen_questions = set()

        for detail in soup.find_all("details"):
            if self._is_hidden(detail):
                continue

            summary = detail.find("summary")
            if not summary:
                continue

            question = self._clean_text(summary.get_text(" ", strip=True))
            answer_parts = []
            for child in detail.find_all(["p", "div", "span", "li"], recursive=True):
                if child == summary:
                    continue
                value = self._clean_text(child.get_text(" ", strip=True))
                if value and value != question:
                    answer_parts.append(value)

            answer = self._clean_text(" ".join(answer_parts))
            if self._add_faq_item(faqs, seen_questions, question, answer, "details"):
                if len(faqs) >= self.config.max_faqs:
                    return faqs

        question_tags = soup.find_all(
            ["h2", "h3", "h4", "button", "strong", "p", "div", "span"]
        )

        for tag in question_tags:
            if self._is_hidden(tag):
                continue

            question = self._clean_text(tag.get_text(" ", strip=True))
            if not self._looks_like_question(question):
                continue

            answer = self._find_answer_near_question(tag)
            source = str(tag.name).lower()

            if self._add_faq_item(faqs, seen_questions, question, answer, source):
                if len(faqs) >= self.config.max_faqs:
                    break

        return faqs

    def _extract_links(self, soup: Any, url: str) -> List[Dict[str, Any]]:
        """
        Extract links with simple classification.
        """

        links: List[Dict[str, Any]] = []
        seen = set()

        for tag in soup.find_all("a", href=True):
            if self._is_hidden(tag):
                continue

            href = str(tag.get("href", "")).strip()
            if not href or href.startswith("#"):
                continue

            full_url = self._safe_join_url(url, href)
            if not full_url:
                continue

            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text:
                text = self._clean_text(tag.get("aria-label") or tag.get("title") or "")

            key = (full_url, text)
            if key in seen:
                continue
            seen.add(key)

            links.append(
                {
                    "url": full_url,
                    "text": self._truncate_text(text, 400),
                    "type": self._classify_link(full_url, text),
                    "is_cta": self._is_cta_text(text) or self._is_cta_element(tag),
                    "target": self._optional_str(tag.get("target")),
                    "rel": self._attr_list(tag.get("rel")),
                }
            )

            if len(links) >= self.config.max_links:
                break

        return links

    def _extract_tables(self, soup: Any) -> List[Dict[str, Any]]:
        """
        Extract HTML tables.
        """

        tables: List[Dict[str, Any]] = []

        for table_index, table in enumerate(soup.find_all("table")):
            if self._is_hidden(table):
                continue

            caption_tag = table.find("caption")
            caption = (
                self._clean_text(caption_tag.get_text(" ", strip=True))
                if caption_tag
                else None
            )

            headers: List[str] = []
            rows: List[List[str]] = []

            header_row = table.find("tr")
            if header_row:
                ths = header_row.find_all("th")
                if ths:
                    headers = [
                        self._truncate_text(
                            self._clean_text(th.get_text(" ", strip=True)),
                            300,
                        )
                        for th in ths[: self.config.max_table_columns]
                    ]

            for tr in table.find_all("tr"):
                cells = tr.find_all(["td", "th"])
                if not cells:
                    continue

                row = [
                    self._truncate_text(
                        self._clean_text(cell.get_text(" ", strip=True)),
                        600,
                    )
                    for cell in cells[: self.config.max_table_columns]
                ]

                if any(row):
                    rows.append(row)

                if len(rows) >= self.config.max_table_rows:
                    break

            if not rows:
                continue

            tables.append(
                {
                    "index": table_index,
                    "caption": caption,
                    "headers": headers,
                    "rows": rows,
                    "row_count": len(rows),
                    "column_count": max((len(row) for row in rows), default=0),
                }
            )

            if len(tables) >= self.config.max_tables:
                break

        return tables

    # -----------------------------------------------------------------------
    # Single extraction helper
    # -----------------------------------------------------------------------

    def _prepare_single_extraction(
        self,
        html_text: str,
        url: str,
        context: Optional[Dict[str, Any]],
        options: Optional[Dict[str, Any]],
        extraction_type: str,
    ) -> Dict[str, Any]:
        """
        Shared setup for public single-section extraction methods.
        """

        options = options or {}

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        if not html_text or not isinstance(html_text, str):
            return self._error_result(
                message="HTML text is empty or invalid.",
                error="INVALID_HTML_TEXT",
                metadata={"extraction_type": extraction_type},
            )

        security_result = self._request_security_approval(
            action=f"browser.content_extract.{extraction_type}",
            context=ctx_result["data"]["context"],
            target=url,
            options=options,
        )
        if not security_result["success"]:
            return security_result

        soup = self._create_soup(html_text)
        if soup is None:
            return self._error_result(
                message="BeautifulSoup is required for content extraction.",
                error="BEAUTIFULSOUP_NOT_AVAILABLE",
                metadata={"dependency": "beautifulsoup4"},
            )

        self._remove_noise(soup)

        return self._safe_result(
            message="Single extraction prepared.",
            data={
                "soup": soup,
                "context": ctx_result["data"]["context"],
            },
            metadata={"extraction_type": extraction_type},
        )

    # -----------------------------------------------------------------------
    # Normalization for already-scraped structured data
    # -----------------------------------------------------------------------

    def _normalize_structured_scraped_content(
        self,
        extracted: Dict[str, Any],
        url: str,
        options: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Normalize data returned by Scraper when raw HTML is not available.
        """

        headings = extracted.get("headings") or []
        links = extracted.get("links") or []
        visible_text = extracted.get("visible_text") or ""
        paragraphs = extracted.get("paragraphs") or []

        if isinstance(headings, list):
            normalized_headings = []
            for item in headings:
                if isinstance(item, dict):
                    normalized_headings.append(
                        {
                            "level": item.get("level"),
                            "text": self._clean_text(item.get("text", "")),
                            "id": item.get("id"),
                            "classes": item.get("classes", []),
                        }
                    )
                else:
                    normalized_headings.append(
                        {
                            "level": None,
                            "text": self._clean_text(str(item)),
                            "id": None,
                            "classes": [],
                        }
                    )
            headings = normalized_headings

        if isinstance(links, list):
            normalized_links = []
            for item in links:
                if isinstance(item, dict):
                    link_url = item.get("url") or item.get("href") or ""
                    text = self._clean_text(item.get("text", ""))
                    normalized_links.append(
                        {
                            "url": link_url,
                            "text": text,
                            "type": self._classify_link(str(link_url), text),
                            "is_cta": self._is_cta_text(text),
                            "target": item.get("target"),
                            "rel": item.get("rel", []),
                        }
                    )
            links = normalized_links

        text_blob = self._clean_text(" ".join([visible_text] + [str(p) for p in paragraphs]))

        ctas = []
        for link in links:
            if link.get("is_cta"):
                ctas.append(
                    {
                        "text": link.get("text"),
                        "url": link.get("url"),
                        "tag": "a",
                        "type": "link_cta",
                        "confidence": 0.75,
                        "signals": ["structured_link_cta"],
                    }
                )

        data = {
            "url": url or extracted.get("url") or extracted.get("final_url"),
            "metadata": {
                "title": extracted.get("title"),
                "description": extracted.get("description"),
                "canonical_url": extracted.get("canonical_url"),
                "language": extracted.get("language"),
            },
            "hero": {
                "headline": self._first_heading_from_structured(headings),
                "subheadline": None,
                "text": self._truncate_text(text_blob, 1200),
                "ctas": ctas[:8],
                "images": extracted.get("images", [])[:5],
                "confidence": 0.45 if text_blob else 0.0,
                "signals": ["structured_scraper_output"],
            },
            "headings": headings[: self.config.max_headings],
            "ctas": ctas[: self.config.max_ctas],
            "pricing": self._extract_pricing_from_text(text_blob),
            "testimonials": self._extract_testimonials_from_text(text_blob),
            "faqs": self._extract_faqs_from_text(text_blob),
            "links": links[: self.config.max_links],
            "tables": [],
            "visible_text": self._truncate_text(text_blob, self.config.max_text_chars),
            "summary": {
                "hero_found": bool(text_blob),
                "headings_count": len(headings),
                "ctas_count": len(ctas),
                "pricing_blocks_count": 0,
                "testimonials_count": 0,
                "faqs_count": 0,
                "links_count": len(links),
                "tables_count": 0,
                "visible_text_length": len(text_blob),
            },
            "content_hash": self._hash_text(text_blob),
            "extracted_at": self._utc_now(),
            "extractor": "ContentExtractor",
            "source": "structured_scraped_data",
        }

        data["summary"]["pricing_blocks_count"] = len(data["pricing"])
        data["summary"]["testimonials_count"] = len(data["testimonials"])
        data["summary"]["faqs_count"] = len(data["faqs"])

        return data

    # -----------------------------------------------------------------------
    # Scoring / Detection
    # -----------------------------------------------------------------------

    def _hero_score(self, tag: Any) -> float:
        """
        Score element as likely hero.
        """

        score = 0.0
        signals = self._element_signals(tag)
        text = self._clean_text(tag.get_text(" ", strip=True)).lower()

        tag_name = str(tag.name).lower()
        if tag_name in {"header", "main", "section"}:
            score += 0.15

        if any(signal in HERO_CLASS_HINTS for signal in signals):
            score += 0.35

        if tag.find(["h1", "h2"]):
            score += 0.2

        if any(keyword in text for keyword in CTA_KEYWORDS):
            score += 0.1

        if tag.find("a") or tag.find("button"):
            score += 0.08

        if tag.find("img"):
            score += 0.06

        if 50 <= len(text) <= 2500:
            score += 0.06

        return score

    def _pricing_score(self, tag: Any, text: str) -> float:
        """
        Score element as likely pricing block.
        """

        score = 0.0
        lower = text.lower()
        signals = self._element_signals(tag)

        if any(keyword in lower for keyword in PRICING_KEYWORDS):
            score += 0.25

        if any(keyword in signals for keyword in PRICING_KEYWORDS):
            score += 0.25

        if re.search(r"([$€£AEDPKR]|USD|GBP|EUR|AUD|CAD)\s?\d+", text, re.I):
            score += 0.3

        if re.search(r"\d+\s?(/\s?mo|/month|per month|monthly)", text, re.I):
            score += 0.2

        if tag.find(["ul", "ol"]):
            score += 0.1

        if self._extract_ctas_from_scope(tag, "", max_items=2):
            score += 0.08

        return score

    def _testimonial_score(self, tag: Any, text: str) -> float:
        """
        Score element as likely testimonial/review.
        """

        score = 0.0
        lower = text.lower()
        signals = self._element_signals(tag)

        if str(tag.name).lower() == "blockquote":
            score += 0.35

        if any(keyword in lower for keyword in TESTIMONIAL_KEYWORDS):
            score += 0.2

        if any(keyword in signals for keyword in TESTIMONIAL_KEYWORDS):
            score += 0.25

        if "★" in text or "⭐" in text:
            score += 0.2

        if re.search(r"\b[1-5](\.\d)?\s?(stars?|/5)\b", text, re.I):
            score += 0.2

        if re.search(r"\b(client|customer|founder|ceo|owner|manager)\b", lower):
            score += 0.1

        if 40 <= len(text) <= 1600:
            score += 0.05

        return score

    def _is_cta_text(self, text: str) -> bool:
        """
        Detect CTA text by keyword and action pattern.
        """

        cleaned = self._clean_text(text).lower()
        if not cleaned:
            return False

        if cleaned in CTA_KEYWORDS:
            return True

        return any(keyword in cleaned for keyword in CTA_KEYWORDS)

    def _is_cta_element(self, tag: Any) -> bool:
        """
        Detect CTA element using class/id/role/type signals.
        """

        signals = self._element_signals(tag)
        tag_name = str(tag.name).lower()

        if tag_name == "button":
            return True

        if "button" in signals or "btn" in signals or "cta" in signals:
            return True

        role = self._optional_str(tag.get("role"))
        if role and role.lower() == "button":
            return True

        return False

    def _looks_like_question(self, text: str) -> bool:
        """
        Detect question-like text.
        """

        cleaned = self._clean_text(text)
        lower = cleaned.lower()

        if not cleaned or len(cleaned) < 8 or len(cleaned) > 300:
            return False

        if cleaned.endswith("?"):
            return True

        question_starters = (
            "what ",
            "why ",
            "how ",
            "when ",
            "where ",
            "who ",
            "which ",
            "can ",
            "do ",
            "does ",
            "is ",
            "are ",
            "will ",
            "should ",
        )

        return lower.startswith(question_starters)

    # -----------------------------------------------------------------------
    # Extraction helper methods
    # -----------------------------------------------------------------------

    def _extract_ctas_from_scope(
        self,
        scope: Any,
        base_url: str,
        max_items: int,
    ) -> List[Dict[str, Any]]:
        """
        Extract CTA links/buttons from a specific scope.
        """

        ctas: List[Dict[str, Any]] = []
        seen = set()

        for tag in scope.find_all(["a", "button", "input"], recursive=True):
            if self._is_hidden(tag):
                continue

            tag_name = str(tag.name).lower()

            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text:
                text = self._clean_text(
                    tag.get("value")
                    or tag.get("aria-label")
                    or tag.get("title")
                    or tag.get("placeholder")
                    or ""
                )

            if not text:
                continue

            is_cta = self._is_cta_text(text) or self._is_cta_element(tag)
            if not is_cta:
                continue

            href = str(tag.get("href", "")).strip() if tag_name == "a" else ""
            full_url = self._safe_join_url(base_url, href) if href else None

            key = (text.lower(), full_url or "", tag_name)
            if key in seen:
                continue
            seen.add(key)

            confidence = 0.65
            if self._is_cta_text(text):
                confidence += 0.2
            if self._is_cta_element(tag):
                confidence += 0.1

            ctas.append(
                {
                    "text": self._truncate_text(text, 300),
                    "url": full_url,
                    "tag": tag_name,
                    "type": "button_cta" if tag_name in {"button", "input"} else "link_cta",
                    "confidence": round(min(confidence, 1.0), 2),
                    "signals": self._element_signals(tag),
                }
            )

            if len(ctas) >= max_items:
                break

        return ctas

    def _extract_images_from_scope(
        self,
        scope: Any,
        base_url: str,
        max_items: int,
    ) -> List[Dict[str, Any]]:
        """
        Extract image data from a scope.
        """

        images: List[Dict[str, Any]] = []
        seen = set()

        for tag in scope.find_all("img"):
            if self._is_hidden(tag):
                continue

            src = str(tag.get("src", "")).strip()
            if not src:
                src = str(tag.get("data-src", "")).strip()

            if not src:
                continue

            full_url = self._safe_join_url(base_url, src)
            if not full_url or full_url in seen:
                continue

            seen.add(full_url)

            images.append(
                {
                    "url": full_url,
                    "alt": self._truncate_text(
                        self._clean_text(tag.get("alt") or ""),
                        300,
                    ),
                    "title": self._truncate_text(
                        self._clean_text(tag.get("title") or ""),
                        300,
                    ),
                }
            )

            if len(images) >= max_items:
                break

        return images

    def _extract_plan_name(self, tag: Any) -> Optional[str]:
        """
        Extract likely plan/package name from pricing block.
        """

        for selector in ["h1", "h2", "h3", "h4", "strong"]:
            found = tag.find(selector)
            if found:
                text = self._clean_text(found.get_text(" ", strip=True))
                if text and len(text) <= 120:
                    return text

        return None

    def _extract_price_values(self, text: str) -> List[str]:
        """
        Extract price-looking values from text.
        """

        patterns = [
            r"(?:[$€£]\s?\d+(?:[,.]\d+)*(?:\.\d{1,2})?)",
            r"(?:\d+(?:[,.]\d+)*(?:\.\d{1,2})?\s?(?:USD|GBP|EUR|AUD|CAD|AED|PKR))",
            r"(?:(?:USD|GBP|EUR|AUD|CAD|AED|PKR)\s?\d+(?:[,.]\d+)*(?:\.\d{1,2})?)",
            r"(?:\d+\s?(?:/mo|/month|per month|monthly|/yr|/year|yearly))",
        ]

        found: List[str] = []
        seen = set()

        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.I):
                value = self._clean_text(match)
                key = value.lower()
                if value and key not in seen:
                    seen.add(key)
                    found.append(value)

        return found[:20]

    def _extract_feature_lines(self, tag: Any) -> List[str]:
        """
        Extract plan/package feature lines.
        """

        features: List[str] = []
        seen = set()

        for li in tag.find_all("li"):
            text = self._clean_text(li.get_text(" ", strip=True))
            if not text or len(text) > 300:
                continue

            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            features.append(text)

            if len(features) >= 40:
                break

        return features

    def _extract_testimonial_author(self, tag: Any) -> Optional[str]:
        """
        Extract likely testimonial author.
        """

        author_selectors = [
            "[class*=author]",
            "[class*=name]",
            "[class*=client]",
            "[class*=customer]",
            "cite",
            "strong",
        ]

        for selector in author_selectors:
            try:
                found = tag.select_one(selector)
            except Exception:
                found = None

            if found:
                text = self._clean_text(found.get_text(" ", strip=True))
                if text and 2 <= len(text) <= 120:
                    return text

        return None

    def _extract_rating(self, text: str, tag: Any) -> Optional[Dict[str, Any]]:
        """
        Extract likely rating from testimonial/review text.
        """

        star_count = text.count("★") + text.count("⭐")
        if star_count:
            return {"value": min(star_count, 5), "scale": 5, "source": "star_symbols"}

        match = re.search(r"\b([1-5](?:\.\d)?)\s?(?:stars?|/5)\b", text, flags=re.I)
        if match:
            try:
                return {
                    "value": float(match.group(1)),
                    "scale": 5,
                    "source": "text_pattern",
                }
            except Exception:
                return None

        aria = self._clean_text(tag.get("aria-label") or "")
        match = re.search(r"\b([1-5](?:\.\d)?)\s?(?:stars?|/5)\b", aria, flags=re.I)
        if match:
            try:
                return {
                    "value": float(match.group(1)),
                    "scale": 5,
                    "source": "aria_label",
                }
            except Exception:
                return None

        return None

    def _add_faq_item(
        self,
        faqs: List[Dict[str, Any]],
        seen_questions: set,
        question: str,
        answer: str,
        source: str,
    ) -> bool:
        """
        Add FAQ pair if valid and not duplicated.
        """

        question = self._clean_text(question)
        answer = self._clean_text(answer)

        if not question or not self._looks_like_question(question):
            return False

        key = question.lower()
        if key in seen_questions:
            return False

        seen_questions.add(key)

        faqs.append(
            {
                "question": self._truncate_text(question, 400),
                "answer": self._truncate_text(answer, 2500),
                "source": source,
                "confidence": 0.85 if answer else 0.55,
            }
        )

        return True

    def _find_answer_near_question(self, tag: Any) -> str:
        """
        Find likely answer near a question element.
        """

        answers: List[str] = []

        for sibling in tag.find_next_siblings(limit=4):
            if getattr(sibling, "name", None) in {"h1", "h2", "h3", "h4"}:
                break

            text = self._clean_text(sibling.get_text(" ", strip=True))
            if text and text != self._clean_text(tag.get_text(" ", strip=True)):
                answers.append(text)

            if len(" ".join(answers)) > 1200:
                break

        if answers:
            return self._clean_text(" ".join(answers))

        parent = tag.parent
        if parent:
            text = self._clean_text(parent.get_text(" ", strip=True))
            question = self._clean_text(tag.get_text(" ", strip=True))
            if text and question in text:
                text = text.replace(question, "", 1)
                return self._clean_text(text)

        return ""

    def _first_heading_text(self, scope: Any) -> Optional[str]:
        """
        Return first heading text in scope.
        """

        heading = scope.find(["h1", "h2", "h3"])
        if not heading:
            return None

        text = self._clean_text(heading.get_text(" ", strip=True))
        return text or None

    def _hero_subheadline(self, scope: Any, headline: Optional[str]) -> Optional[str]:
        """
        Find likely hero subheadline.
        """

        candidates = []

        for tag in scope.find_all(["p", "span", "div"], recursive=True):
            text = self._clean_text(tag.get_text(" ", strip=True))
            if not text:
                continue
            if headline and text == headline:
                continue
            if 20 <= len(text) <= 350:
                candidates.append(text)

        return candidates[0] if candidates else None

    def _first_meaningful_container(self, body: Any) -> Optional[Any]:
        """
        Return first meaningful above-fold-like container.
        """

        for tag in body.find_all(["section", "header", "main", "div"], recursive=False):
            text = self._clean_text(tag.get_text(" ", strip=True))
            if len(text) >= 40:
                return tag

        for tag in body.find_all(["section", "header", "main", "div"], recursive=True):
            text = self._clean_text(tag.get_text(" ", strip=True))
            if len(text) >= 40:
                return tag

        return None

    # -----------------------------------------------------------------------
    # Text-only fallback structured detection
    # -----------------------------------------------------------------------

    def _extract_pricing_from_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Minimal text-only pricing detection from structured scraped data.
        """

        if not text:
            return []

        if not any(keyword in text.lower() for keyword in PRICING_KEYWORDS):
            if not self._extract_price_values(text):
                return []

        prices = self._extract_price_values(text)
        if not prices:
            return []

        return [
            {
                "plan_name": None,
                "prices": prices,
                "features": [],
                "ctas": [],
                "text": self._truncate_text(text, 1800),
                "confidence": 0.45,
                "signals": ["text_only_pricing_detection"],
            }
        ]

    def _extract_testimonials_from_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Minimal text-only testimonial detection.
        """

        if not text:
            return []

        lower = text.lower()
        if not any(keyword in lower for keyword in TESTIMONIAL_KEYWORDS):
            return []

        return [
            {
                "text": self._truncate_text(text, 1600),
                "author": None,
                "rating": None,
                "confidence": 0.35,
                "signals": ["text_only_testimonial_detection"],
            }
        ]

    def _extract_faqs_from_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Minimal text-only FAQ detection.
        """

        if not text:
            return []

        sentences = re.split(r"(?<=[?.!])\s+", text)
        faqs: List[Dict[str, Any]] = []

        for index, sentence in enumerate(sentences):
            question = self._clean_text(sentence)
            if not self._looks_like_question(question):
                continue

            answer = ""
            if index + 1 < len(sentences):
                answer = self._clean_text(sentences[index + 1])

            faqs.append(
                {
                    "question": self._truncate_text(question, 400),
                    "answer": self._truncate_text(answer, 1000),
                    "source": "text_only",
                    "confidence": 0.35,
                }
            )

            if len(faqs) >= self.config.max_faqs:
                break

        return faqs

    # -----------------------------------------------------------------------
    # Soup / DOM utilities
    # -----------------------------------------------------------------------

    def _create_soup(self, html_text: str) -> Optional[Any]:
        """
        Create BeautifulSoup object.
        """

        if BeautifulSoup is None:
            return None

        return BeautifulSoup(html_text, "html.parser")

    def _remove_noise(self, soup: Any) -> None:
        """
        Remove scripts, styles, hidden templates, comments, and non-visible tags.
        """

        for tag in soup(list(NOISE_TAGS)):
            tag.decompose()

        if Comment is not None:
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                comment.extract()

    def _is_hidden(self, tag: Any) -> bool:
        """
        Detect hidden elements.
        """

        try:
            for attr in COMMON_HIDDEN_ATTRS:
                if tag.has_attr(attr):
                    value = str(tag.get(attr, "")).lower()
                    if attr == "hidden" or value in {"true", "1", "yes"}:
                        return True

            style = str(tag.get("style", "")).lower()
            if "display:none" in style.replace(" ", ""):
                return True
            if "visibility:hidden" in style.replace(" ", ""):
                return True

            classes = " ".join(self._class_list(tag)).lower()
            if any(word in classes for word in ["hidden", "d-none", "sr-only"]):
                return True

        except Exception:
            return False

        return False

    def _element_signals(self, tag: Any) -> List[str]:
        """
        Return normalized class/id/data-role signals.
        """

        signals: List[str] = []

        for value in self._class_list(tag):
            signals.extend(self._split_signal(value))

        element_id = self._optional_str(tag.get("id"))
        if element_id:
            signals.extend(self._split_signal(element_id))

        role = self._optional_str(tag.get("role"))
        if role:
            signals.extend(self._split_signal(role))

        data_section = self._optional_str(tag.get("data-section"))
        if data_section:
            signals.extend(self._split_signal(data_section))

        clean = []
        seen = set()

        for signal in signals:
            signal = signal.lower().strip()
            if not signal or signal in seen:
                continue
            seen.add(signal)
            clean.append(signal)

        return clean

    def _class_list(self, tag: Any) -> List[str]:
        """
        Return class list from element.
        """

        classes = tag.get("class") if tag is not None else None

        if isinstance(classes, list):
            return [str(c).strip() for c in classes if str(c).strip()]

        if isinstance(classes, str):
            return [c.strip() for c in classes.split() if c.strip()]

        return []

    def _split_signal(self, value: str) -> List[str]:
        """
        Split class/id signals into searchable tokens.
        """

        value = str(value).replace("_", "-")
        parts = re.split(r"[-\s]+", value)
        combined = [value.lower()]
        combined.extend(part.lower() for part in parts if part)
        return combined

    def _extract_visible_text(self, soup: Any) -> str:
        """
        Extract normalized visible page text.
        """

        body = soup.find("body") or soup
        text = body.get_text("\n", strip=True)
        return self._clean_text(text, multiline=True)

    # -----------------------------------------------------------------------
    # URL / Link utilities
    # -----------------------------------------------------------------------

    def _safe_join_url(self, base_url: str, href: Optional[str]) -> Optional[str]:
        """
        Safely join relative URLs.
        """

        if not href:
            return None

        href = str(href).strip()

        if not href or href.startswith("#"):
            return None

        parsed = urlparse(href)
        blocked_schemes = {
            "javascript",
            "data",
            "blob",
            "file",
            "chrome",
            "about",
        }

        if parsed.scheme and parsed.scheme.lower() in blocked_schemes:
            return None

        try:
            if base_url:
                return urljoin(base_url, href)
            return href
        except Exception:
            return None

    def _classify_link(self, link_url: str, text: str) -> str:
        """
        Classify link type for dashboard/API usage.
        """

        lower_url = str(link_url).lower()
        lower_text = str(text).lower()

        if lower_url.startswith("tel:"):
            return "phone"

        if lower_url.startswith("mailto:"):
            return "email"

        if self._is_cta_text(lower_text):
            return "cta"

        if any(word in lower_url for word in ["pricing", "plans", "package"]):
            return "pricing"

        if any(word in lower_url for word in ["contact", "demo", "quote"]):
            return "lead_generation"

        if any(word in lower_url for word in ["blog", "article", "news"]):
            return "content"

        return "standard"

    # -----------------------------------------------------------------------
    # Metadata helper
    # -----------------------------------------------------------------------

    def _meta_content(self, soup: Any, selectors: Iterable[Dict[str, str]]) -> Optional[str]:
        """
        Extract first matching meta content.
        """

        for selector in selectors:
            tag = soup.find("meta", attrs=selector)
            if tag and tag.get("content"):
                return self._clean_text(str(tag.get("content")))

        return None

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

        safe_context = ExtractorContext(
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
        Content extraction actions require security review.
        """

        return action.startswith("browser.content_extract")

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        target: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when available.

        If Security Agent is not wired yet, this method applies local safe
        defaults and approves only non-destructive content parsing.
        """

        options = options or {}

        if not self._requires_security_check(action):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "mode": "not_required"},
                metadata={"action": action},
            )

        local_policy = self._local_security_policy(action, target, options)
        if not local_policy["success"]:
            return local_policy

        if self.security_agent is not None:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    approval = self.security_agent.approve_action(
                        action=action,
                        context=context,
                        target=target,
                        metadata=options,
                    )
                elif hasattr(self.security_agent, "run"):
                    approval = self.security_agent.run(
                        {
                            "action": "approve_action",
                            "requested_action": action,
                            "target": target,
                            "context": context,
                            "metadata": options,
                        }
                    )
                else:
                    approval = None

                if isinstance(approval, dict):
                    if approval.get("success") is False or approval.get("approved") is False:
                        return self._error_result(
                            message="Security Agent rejected this content extraction action.",
                            error="SECURITY_AGENT_REJECTED",
                            metadata={
                                "action": action,
                                "target": target,
                                "security_response": approval,
                            },
                        )

                    return self._safe_result(
                        message="Security Agent approved content extraction action.",
                        data={"approved": True, "mode": "security_agent"},
                        metadata={
                            "action": action,
                            "target": target,
                            "security_response": approval,
                        },
                    )

            except Exception as exc:
                return self._error_result(
                    message="Security Agent approval failed.",
                    error=str(exc),
                    metadata={
                        "action": action,
                        "target": target,
                        "trace": traceback.format_exc(limit=3),
                    },
                )

        return self._safe_result(
            message="Local security policy approved content extraction action.",
            data={"approved": True, "mode": "local_policy"},
            metadata={"action": action, "target": target},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This creates a clean payload Master Agent or Router can forward.
        """

        summary = data.get("summary", {})

        return {
            "verification_type": "browser_content_extraction_result",
            "agent": "ContentExtractor",
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
                "content_hash_present": bool(data.get("content_hash")),
            },
            "summary": {
                "url": data.get("url"),
                "title": data.get("metadata", {}).get("title"),
                "hero_found": summary.get("hero_found"),
                "headings_count": summary.get("headings_count"),
                "ctas_count": summary.get("ctas_count"),
                "pricing_blocks_count": summary.get("pricing_blocks_count"),
                "testimonials_count": summary.get("testimonials_count"),
                "faqs_count": summary.get("faqs_count"),
                "links_count": summary.get("links_count"),
                "tables_count": summary.get("tables_count"),
                "content_hash": data.get("content_hash"),
            },
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Avoids storing raw HTML and focuses on safe metadata/summaries.
        """

        metadata = data.get("metadata", {})
        hero = data.get("hero", {})
        summary = data.get("summary", {})

        safe_summary = self._truncate_text(
            self._clean_text(
                " ".join(
                    [
                        metadata.get("title") or "",
                        metadata.get("description") or "",
                        hero.get("headline") or "",
                        hero.get("subheadline") or "",
                        hero.get("text") or "",
                    ]
                )
            ),
            1500,
        )

        return {
            "memory_type": "browser_content_context",
            "agent": "ContentExtractor",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "timestamp": self._utc_now(),
            "safe_to_store": True,
            "data": {
                "url": data.get("url"),
                "title": metadata.get("title"),
                "description": metadata.get("description"),
                "hero_headline": hero.get("headline"),
                "summary": safe_summary,
                "content_hash": data.get("content_hash"),
                "counts": summary,
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
            "agent": "ContentExtractor",
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
        """

        audit_payload = {
            "action": action,
            "agent": "ContentExtractor",
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
    # Local security
    # -----------------------------------------------------------------------

    def _local_security_policy(
        self,
        action: str,
        target: Optional[str],
        options: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Conservative local security approval.

        ContentExtractor only parses supplied content. It rejects requests that
        imply active browser behavior or private/authenticated scraping.
        """

        if not action.startswith("browser.content_extract"):
            return self._error_result(
                message="Local security policy rejected unknown action.",
                error="ACTION_NOT_ALLOWED",
                metadata={"action": action},
            )

        if options.get("fetch_url") is True:
            return self._error_result(
                message="ContentExtractor does not fetch URLs directly.",
                error="FETCH_NOT_ALLOWED_IN_CONTENT_EXTRACTOR",
                metadata={"action": action, "target": target},
            )

        if options.get("submit_forms") is True:
            return self._error_result(
                message="Form submission is not allowed by ContentExtractor.",
                error="FORM_SUBMISSION_BLOCKED",
                metadata={"action": action},
            )

        if options.get("click") is True or options.get("automate_browser") is True:
            return self._error_result(
                message="Browser automation/clicking is not allowed by ContentExtractor.",
                error="BROWSER_AUTOMATION_BLOCKED",
                metadata={"action": action},
            )

        if options.get("login") is True or options.get("authenticated") is True:
            return self._error_result(
                message="Authenticated/private extraction is not allowed by ContentExtractor.",
                error="AUTHENTICATED_EXTRACTION_BLOCKED",
                metadata={"action": action},
            )

        return self._safe_result(
            message="Local security policy approved.",
            data={"approved": True},
            metadata={"action": action, "mode": "read_only_content_parsing"},
        )

    # -----------------------------------------------------------------------
    # General utilities
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

    def _optional_str(self, value: Any) -> Optional[str]:
        """
        Convert optional value to clean string.
        """

        if value is None:
            return None

        cleaned = self._clean_text(value)
        return cleaned or None

    def _attr_list(self, value: Any) -> List[str]:
        """
        Normalize attribute list values.
        """

        if value is None:
            return []

        if isinstance(value, list):
            return [self._clean_text(v) for v in value if self._clean_text(v)]

        return [self._clean_text(value)] if self._clean_text(value) else []

    def _first_heading_from_structured(
        self,
        headings: List[Dict[str, Any]],
    ) -> Optional[str]:
        """
        Return first structured H1/H2/H3 heading.
        """

        for level in ["h1", "h2", "h3"]:
            for heading in headings:
                if str(heading.get("level", "")).lower() == level:
                    return self._clean_text(heading.get("text", ""))

        if headings:
            return self._clean_text(headings[0].get("text", ""))

        return None

    def _utc_now(self) -> str:
        """
        Current UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_content_extractor(
    config: Optional[ContentExtractorConfig] = None,
    **kwargs: Any,
) -> ContentExtractor:
    """
    Factory helper for Agent Loader / Registry integration.
    """

    return ContentExtractor(config=config, **kwargs)


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    extractor = ContentExtractor()

    sample_html = """
    <html>
      <head>
        <title>Example SaaS Page</title>
        <meta name="description" content="A test SaaS landing page.">
      </head>
      <body>
        <section class="hero">
          <h1>Grow Your Business Faster</h1>
          <p>Powerful automation tools for serious teams.</p>
          <a href="/demo" class="btn cta">Book a Demo</a>
        </section>

        <section class="pricing">
          <h2>Pricing</h2>
          <div class="plan">
            <h3>Starter</h3>
            <p>$29/month</p>
            <ul>
              <li>Basic dashboard</li>
              <li>Email support</li>
            </ul>
            <a href="/start">Get Started</a>
          </div>
        </section>

        <section class="faq">
          <h2>Frequently Asked Questions</h2>
          <details>
            <summary>What is included?</summary>
            <p>You get dashboard access, reporting, and support.</p>
          </details>
        </section>
      </body>
    </html>
    """

    result = extractor.extract_from_html(
        html_text=sample_html,
        url="https://example.com",
        context={
            "user_id": "local_test_user",
            "workspace_id": "local_test_workspace",
            "source": "manual_smoke_test",
        },
    )

    print(result)