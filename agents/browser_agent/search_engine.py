"""
agents/browser_agent/search_engine.py

William / Jarvis Multi-Agent AI SaaS System - Browser Agent Search Engine
Digital Promotix

Purpose:
    Builds safe search queries, searches Google/Bing through official API providers
    when credentials are configured, optionally supports a safe development fallback,
    then filters, de-duplicates, and ranks search results.

Architecture Connections:
    - Master Agent / Router:
        The SearchEngine exposes public async/sync methods returning structured
        dict results so the Master Agent and Agent Router can call it safely.
    - Security Agent:
        Search actions are permission-aware through _requires_security_check()
        and _request_security_approval(). This file does not bypass approvals.
    - Memory Agent:
        Useful search context can be exported through _prepare_memory_payload().
    - Verification Agent:
        Completed search actions prepare verification payloads through
        _prepare_verification_payload().
    - Dashboard / API:
        All responses are JSON/dict friendly and include metadata, audit hooks,
        user_id, workspace_id, provider, query, result counts, and ranking data.
    - Registry / Loader:
        The file is import-safe even if BaseAgent or other William modules are
        not created yet, thanks to fallback stubs and optional imports.

Important Safety Notes:
    - This file does not hardcode secrets.
    - Google and Bing search are performed through official APIs only when keys
      are provided through environment variables or config.
    - No destructive browser/system action is performed here.
    - User/workspace context is validated for SaaS isolation.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qs, quote_plus, urlencode, urlparse, urlunparse

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    requests = None  # type: ignore

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - optional fallback parser
    BeautifulSoup = None  # type: ignore

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - William modules may not exist yet
    class BaseAgent:  # type: ignore
        """Import-safe fallback BaseAgent.

        Real William deployments should replace this with agents/base_agent.py.
        The fallback intentionally stays minimal so this file can be imported and
        tested before the full system is generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None


LOGGER = logging.getLogger(__name__)


class SearchProvider(str, Enum):
    """Supported provider names."""

    GOOGLE = "google"
    BING = "bing"
    DEV_FALLBACK = "dev_fallback"


class SearchIntent(str, Enum):
    """Semantic intent used to build and rank queries."""

    GENERAL = "general"
    NEWS = "news"
    RESEARCH = "research"
    LOCAL = "local"
    SHOPPING = "shopping"
    TECHNICAL = "technical"
    SEO = "seo"
    COMPETITOR = "competitor"
    PRICE = "price"


@dataclass
class SearchEngineConfig:
    """Runtime configuration for SearchEngine.

    Credentials should be supplied through environment variables or injected
    config. Never hardcode API keys in this file.
    """

    google_api_key: Optional[str] = None
    google_cx: Optional[str] = None
    bing_api_key: Optional[str] = None
    bing_endpoint: str = "https://api.bing.microsoft.com/v7.0/search"
    google_endpoint: str = "https://www.googleapis.com/customsearch/v1"
    request_timeout_seconds: int = 12
    max_results: int = 10
    safe_search: str = "moderate"
    language: str = "en"
    market: str = "en-US"
    enable_dev_fallback: bool = True
    enable_html_fallback: bool = False
    user_agent: str = "WilliamJarvisBrowserAgent/1.0 (+https://digitalpromotix.dev)"
    min_rank_score: float = 0.0
    blocked_domains: List[str] = field(default_factory=list)
    preferred_domains: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    audit_enabled: bool = True

    @classmethod
    def from_env(cls, **overrides: Any) -> "SearchEngineConfig":
        """Create config from environment variables plus optional overrides."""

        cfg = cls(
            google_api_key=os.getenv("WILLIAM_GOOGLE_SEARCH_API_KEY") or os.getenv("GOOGLE_SEARCH_API_KEY"),
            google_cx=os.getenv("WILLIAM_GOOGLE_SEARCH_CX") or os.getenv("GOOGLE_SEARCH_CX"),
            bing_api_key=os.getenv("WILLIAM_BING_SEARCH_API_KEY") or os.getenv("BING_SEARCH_API_KEY"),
            bing_endpoint=os.getenv("WILLIAM_BING_SEARCH_ENDPOINT", cls.bing_endpoint),
            google_endpoint=os.getenv("WILLIAM_GOOGLE_SEARCH_ENDPOINT", cls.google_endpoint),
            safe_search=os.getenv("WILLIAM_SEARCH_SAFE", "moderate"),
            language=os.getenv("WILLIAM_SEARCH_LANGUAGE", "en"),
            market=os.getenv("WILLIAM_SEARCH_MARKET", "en-US"),
            enable_dev_fallback=os.getenv("WILLIAM_SEARCH_DEV_FALLBACK", "true").lower() in {"1", "true", "yes"},
            enable_html_fallback=os.getenv("WILLIAM_SEARCH_HTML_FALLBACK", "false").lower() in {"1", "true", "yes"},
        )
        for key, value in overrides.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg


@dataclass
class SearchQuery:
    """Normalized query object passed between Browser Agent components."""

    raw_query: str
    built_query: str
    intent: str = SearchIntent.GENERAL.value
    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    provider: Optional[str] = None
    location: Optional[str] = None
    language: str = "en"
    market: str = "en-US"
    max_results: int = 10
    filters: Dict[str, Any] = field(default_factory=dict)
    include_terms: List[str] = field(default_factory=list)
    exclude_terms: List[str] = field(default_factory=list)
    site: Optional[str] = None
    freshness: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SearchResult:
    """Single normalized search result."""

    title: str
    url: str
    snippet: str = ""
    provider: str = "unknown"
    rank: int = 0
    score: float = 0.0
    display_url: str = ""
    domain: str = ""
    published_at: Optional[str] = None
    content_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SearchEngine(BaseAgent):
    """Browser Agent search engine.

    Responsibilities:
        1. Validate SaaS task context.
        2. Build clean provider-ready search queries.
        3. Search Google/Bing through official APIs when configured.
        4. Filter unsafe, duplicate, blocked, or irrelevant results.
        5. Rank results using transparent scoring signals.
        6. Return structured payloads for Master Agent, Dashboard/API,
           Verification Agent, Memory Agent, and Audit Logs.
    """

    DEFAULT_BLOCKED_DOMAINS = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "example.com",
        "example.org",
        "example.net",
    ]

    LOW_VALUE_TITLE_PATTERNS = [
        re.compile(r"^untitled$", re.I),
        re.compile(r"^home\s*page$", re.I),
        re.compile(r"^index\s*of", re.I),
        re.compile(r"error\s*404", re.I),
        re.compile(r"access\s*denied", re.I),
    ]

    TRACKING_QUERY_PARAMS = {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "msclkid",
        "yclid",
        "igshid",
        "mc_cid",
        "mc_eid",
    }

    def __init__(
        self,
        config: Optional[Union[SearchEngineConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="BrowserSearchEngine", agent_id="browser.search_engine", **kwargs)

        if config is None:
            self.config = SearchEngineConfig.from_env()
        elif isinstance(config, SearchEngineConfig):
            self.config = config
        else:
            self.config = SearchEngineConfig.from_env(**dict(config))

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER
        self._last_results: List[SearchResult] = []

        self.config.blocked_domains = self._normalize_domain_list(
            self.DEFAULT_BLOCKED_DOMAINS + list(self.config.blocked_domains or [])
        )
        self.config.preferred_domains = self._normalize_domain_list(self.config.preferred_domains or [])
        self.config.allowed_domains = self._normalize_domain_list(self.config.allowed_domains or [])

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        provider: Union[str, SearchProvider, Sequence[Union[str, SearchProvider]]] = "auto",
        intent: Union[str, SearchIntent] = SearchIntent.GENERAL,
        max_results: Optional[int] = None,
        filters: Optional[Mapping[str, Any]] = None,
        include_terms: Optional[Sequence[str]] = None,
        exclude_terms: Optional[Sequence[str]] = None,
        site: Optional[str] = None,
        location: Optional[str] = None,
        language: Optional[str] = None,
        market: Optional[str] = None,
        freshness: Optional[str] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Build, execute, filter, and rank a search request.

        This synchronous method is friendly for FastAPI sync handlers, workers,
        tests, and Master Agent calls. Use async_search() in async pipelines.
        """

        started_at = time.time()
        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": "browser_agent",
            "module": "search_engine",
            "action": "search",
        }

        try:
            validation = self._validate_task_context(context, query=query)
            if not validation["success"]:
                return validation

            normalized_filters = dict(filters or {})
            max_count = self._safe_int(max_results, self.config.max_results, minimum=1, maximum=50)
            intent_value = self._normalize_intent(intent)

            search_query = self.build_query(
                query,
                user_id=user_id,
                workspace_id=workspace_id,
                provider=None if provider == "auto" else self._provider_label(provider),
                intent=intent_value,
                max_results=max_count,
                filters=normalized_filters,
                include_terms=list(include_terms or []),
                exclude_terms=list(exclude_terms or []),
                site=site,
                location=location,
                language=language or self.config.language,
                market=market or self.config.market,
                freshness=freshness,
            )

            requires_security = (
                bool(require_security)
                if require_security is not None
                else self._requires_security_check(search_query, context)
            )
            if requires_security:
                approval = self._request_security_approval(search_query, context)
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Search request blocked by security approval policy.",
                        error="SECURITY_APPROVAL_DENIED",
                        data={"approval": approval},
                        metadata={"context": context, "query": asdict(search_query)},
                    )

            self._emit_agent_event(
                "browser.search.started",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "query": search_query.built_query,
                    "intent": intent_value,
                    "provider": self._provider_label(provider),
                },
            )

            provider_names = self._resolve_providers(provider)
            raw_results: List[SearchResult] = []
            provider_errors: Dict[str, Any] = {}

            for provider_name in provider_names:
                try:
                    raw_results.extend(self._search_provider(provider_name, search_query))
                except Exception as exc:
                    provider_errors[provider_name] = str(exc)
                    self.logger.warning("Search provider failed: %s | %s", provider_name, exc)

            filtered = self.filter_results(raw_results, search_query)
            ranked = self.rank_results(filtered, search_query)
            final_results = ranked[:max_count]
            self._last_results = final_results

            verification_payload = self._prepare_verification_payload(search_query, final_results, provider_errors)
            memory_payload = self._prepare_memory_payload(search_query, final_results)
            elapsed_ms = round((time.time() - started_at) * 1000, 2)

            metadata = {
                "context": context,
                "query": asdict(search_query),
                "providers_requested": provider_names,
                "provider_errors": provider_errors,
                "raw_result_count": len(raw_results),
                "filtered_result_count": len(filtered),
                "returned_result_count": len(final_results),
                "elapsed_ms": elapsed_ms,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            }

            self._log_audit_event(
                {
                    "event": "browser.search.completed",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "query_hash": self._hash_text(search_query.built_query),
                    "providers": provider_names,
                    "returned_result_count": len(final_results),
                    "elapsed_ms": elapsed_ms,
                    "success": True,
                }
            )
            self._emit_agent_event("browser.search.completed", metadata)

            return self._safe_result(
                message="Search completed successfully.",
                data={
                    "query": search_query.built_query,
                    "raw_query": search_query.raw_query,
                    "intent": search_query.intent,
                    "results": [item.to_dict() for item in final_results],
                },
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("Search failed unexpectedly")
            return self._error_result(
                message="Search failed unexpectedly.",
                error=str(exc),
                data={},
                metadata={"context": context, "elapsed_ms": round((time.time() - started_at) * 1000, 2)},
            )

    async def async_search(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Async wrapper for search()."""

        return await asyncio.to_thread(self.search, *args, **kwargs)

    def build_query(
        self,
        query: str,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        provider: Optional[str] = None,
        intent: Union[str, SearchIntent] = SearchIntent.GENERAL,
        max_results: Optional[int] = None,
        filters: Optional[Mapping[str, Any]] = None,
        include_terms: Optional[Sequence[str]] = None,
        exclude_terms: Optional[Sequence[str]] = None,
        site: Optional[str] = None,
        location: Optional[str] = None,
        language: Optional[str] = None,
        market: Optional[str] = None,
        freshness: Optional[str] = None,
    ) -> SearchQuery:
        """Build a normalized provider-ready search query."""

        cleaned = self._clean_query(query)
        if not cleaned:
            raise ValueError("Search query cannot be empty.")

        include_terms_list = [self._clean_term(term) for term in include_terms or [] if self._clean_term(term)]
        exclude_terms_list = [self._clean_term(term) for term in exclude_terms or [] if self._clean_term(term)]
        filters_dict = dict(filters or {})

        parts: List[str] = [cleaned]

        if intent:
            parts.extend(self._intent_query_boosts(self._normalize_intent(intent)))

        for term in include_terms_list:
            if " " in term:
                parts.append(f'"{term}"')
            else:
                parts.append(term)

        for term in exclude_terms_list:
            safe_term = term.replace('"', "").strip()
            if safe_term:
                parts.append(f"-{safe_term}")

        if site:
            domain = self._extract_domain(site)
            if domain:
                parts.append(f"site:{domain}")

        if location:
            parts.append(str(location).strip())

        if filters_dict.get("filetype"):
            filetype = re.sub(r"[^a-zA-Z0-9]", "", str(filters_dict["filetype"]))
            if filetype:
                parts.append(f"filetype:{filetype}")

        if filters_dict.get("exact_phrase"):
            exact_phrase = self._clean_term(str(filters_dict["exact_phrase"]))
            if exact_phrase:
                parts.append(f'"{exact_phrase}"')

        built_query = self._compact_spaces(" ".join(parts))

        return SearchQuery(
            raw_query=query,
            built_query=built_query,
            intent=self._normalize_intent(intent),
            user_id=user_id,
            workspace_id=workspace_id,
            provider=provider,
            location=location,
            language=language or self.config.language,
            market=market or self.config.market,
            max_results=self._safe_int(max_results, self.config.max_results, minimum=1, maximum=50),
            filters=filters_dict,
            include_terms=include_terms_list,
            exclude_terms=exclude_terms_list,
            site=site,
            freshness=freshness,
        )

    def filter_results(self, results: Sequence[SearchResult], search_query: SearchQuery) -> List[SearchResult]:
        """Filter invalid, duplicate, blocked, or low-value results."""

        filtered: List[SearchResult] = []
        seen_urls: set[str] = set()
        seen_titles_domains: set[str] = set()

        for item in results:
            normalized = self._normalize_result(item)
            if not normalized:
                continue

            url_key = self._canonical_url(normalized.url)
            title_domain_key = f"{self._normalize_text(normalized.title)}|{normalized.domain}"

            if url_key in seen_urls or title_domain_key in seen_titles_domains:
                continue
            if self._is_blocked_domain(normalized.domain):
                continue
            if self.config.allowed_domains and normalized.domain not in self.config.allowed_domains:
                continue
            if self._is_low_value_result(normalized):
                continue
            if not self._matches_search_filters(normalized, search_query):
                continue

            seen_urls.add(url_key)
            seen_titles_domains.add(title_domain_key)
            filtered.append(normalized)

        return filtered

    def rank_results(self, results: Sequence[SearchResult], search_query: SearchQuery) -> List[SearchResult]:
        """Rank results with transparent scoring signals."""

        scored: List[SearchResult] = []
        query_tokens = self._tokenize(search_query.raw_query)
        built_tokens = self._tokenize(search_query.built_query)
        important_tokens = set(query_tokens[:]) or set(built_tokens[:])

        for index, item in enumerate(results, start=1):
            title_tokens = self._tokenize(item.title)
            snippet_tokens = self._tokenize(item.snippet)
            domain = item.domain or self._extract_domain(item.url)

            score = 0.0

            if important_tokens:
                title_overlap = len(important_tokens.intersection(title_tokens)) / max(len(important_tokens), 1)
                snippet_overlap = len(important_tokens.intersection(snippet_tokens)) / max(len(important_tokens), 1)
                score += title_overlap * 45.0
                score += snippet_overlap * 25.0

            if domain in self.config.preferred_domains:
                score += 15.0

            if search_query.site and domain == self._extract_domain(search_query.site):
                score += 20.0

            if item.snippet and len(item.snippet) >= 80:
                score += 5.0

            if self._looks_authoritative(domain):
                score += 6.0

            if item.published_at and self._is_recent_date(item.published_at):
                if search_query.intent in {SearchIntent.NEWS.value, SearchIntent.PRICE.value} or search_query.freshness:
                    score += 10.0
                else:
                    score += 3.0

            provider_bonus = {SearchProvider.GOOGLE.value: 2.5, SearchProvider.BING.value: 2.0}.get(item.provider, 0.0)
            score += provider_bonus

            original_rank = item.rank or index
            score += max(0.0, 12.0 - min(original_rank, 12))

            item.score = round(score, 4)
            if item.score >= self.config.min_rank_score:
                scored.append(item)

        scored.sort(key=lambda result: (result.score, -result.rank), reverse=True)
        for idx, item in enumerate(scored, start=1):
            item.metadata["final_rank"] = idx
        return scored

    def available_providers(self) -> Dict[str, Any]:
        """Return provider availability for dashboard/API display."""

        return self._safe_result(
            message="Provider availability loaded.",
            data={
                SearchProvider.GOOGLE.value: bool(self.config.google_api_key and self.config.google_cx),
                SearchProvider.BING.value: bool(self.config.bing_api_key),
                SearchProvider.DEV_FALLBACK.value: bool(self.config.enable_dev_fallback),
            },
            metadata={"module": "browser_agent.search_engine"},
        )

    def get_last_results(self) -> Dict[str, Any]:
        """Return last search results kept in memory for the current engine instance."""

        return self._safe_result(
            message="Last search results loaded.",
            data={"results": [item.to_dict() for item in self._last_results]},
            metadata={"count": len(self._last_results)},
        )

    # ---------------------------------------------------------------------
    # Provider execution
    # ---------------------------------------------------------------------

    def _resolve_providers(
        self, provider: Union[str, SearchProvider, Sequence[Union[str, SearchProvider]]]
    ) -> List[str]:
        if isinstance(provider, (list, tuple, set)):
            labels = [self._provider_label(item) for item in provider]
        else:
            label = self._provider_label(provider)
            if label == "auto":
                labels = []
                if self.config.google_api_key and self.config.google_cx:
                    labels.append(SearchProvider.GOOGLE.value)
                if self.config.bing_api_key:
                    labels.append(SearchProvider.BING.value)
                if not labels and self.config.enable_dev_fallback:
                    labels.append(SearchProvider.DEV_FALLBACK.value)
            else:
                labels = [label]

        allowed = {SearchProvider.GOOGLE.value, SearchProvider.BING.value, SearchProvider.DEV_FALLBACK.value}
        resolved = [label for label in labels if label in allowed]
        if not resolved:
            raise ValueError("No valid search provider available. Configure Google/Bing keys or enable dev fallback.")
        return resolved

    def _search_provider(self, provider: str, search_query: SearchQuery) -> List[SearchResult]:
        if provider == SearchProvider.GOOGLE.value:
            return self._search_google(search_query)
        if provider == SearchProvider.BING.value:
            return self._search_bing(search_query)
        if provider == SearchProvider.DEV_FALLBACK.value:
            return self._search_dev_fallback(search_query)
        raise ValueError(f"Unsupported search provider: {provider}")

    def _search_google(self, search_query: SearchQuery) -> List[SearchResult]:
        """Search Google through Google Custom Search JSON API."""

        if not self.config.google_api_key or not self.config.google_cx:
            raise RuntimeError("Google Search API key/CX is not configured.")
        if requests is None:
            raise RuntimeError("The 'requests' package is required for Google search.")

        params = {
            "key": self.config.google_api_key,
            "cx": self.config.google_cx,
            "q": search_query.built_query,
            "num": min(search_query.max_results, 10),
            "safe": self._google_safe_value(self.config.safe_search),
            "hl": search_query.language or self.config.language,
        }
        if search_query.freshness:
            date_restrict = self._google_date_restrict(search_query.freshness)
            if date_restrict:
                params["dateRestrict"] = date_restrict

        response = requests.get(
            self.config.google_endpoint,
            params=params,
            timeout=self.config.request_timeout_seconds,
            headers={"User-Agent": self.config.user_agent},
        )
        response.raise_for_status()
        payload = response.json()

        results: List[SearchResult] = []
        for idx, item in enumerate(payload.get("items", []) or [], start=1):
            url = str(item.get("link") or "").strip()
            title = html.unescape(str(item.get("title") or "").strip())
            snippet = html.unescape(str(item.get("snippet") or "").strip())
            pagemap = item.get("pagemap") or {}
            published_at = self._extract_published_at_from_pagemap(pagemap)
            domain = self._extract_domain(url)
            results.append(
                SearchResult(
                    title=title,
                    url=url,
                    snippet=snippet,
                    provider=SearchProvider.GOOGLE.value,
                    rank=idx,
                    display_url=str(item.get("displayLink") or domain),
                    domain=domain,
                    published_at=published_at,
                    metadata={
                        "source_payload_keys": sorted(list(item.keys())),
                        "cache_id": item.get("cacheId"),
                        "mime": item.get("mime"),
                    },
                )
            )
        return results

    def _search_bing(self, search_query: SearchQuery) -> List[SearchResult]:
        """Search Bing through Microsoft Bing Web Search API."""

        if not self.config.bing_api_key:
            raise RuntimeError("Bing Search API key is not configured.")
        if requests is None:
            raise RuntimeError("The 'requests' package is required for Bing search.")

        params = {
            "q": search_query.built_query,
            "count": min(search_query.max_results, 50),
            "mkt": search_query.market or self.config.market,
            "safeSearch": self._bing_safe_value(self.config.safe_search),
            "textDecorations": False,
            "textFormat": "Raw",
        }
        freshness = self._bing_freshness_value(search_query.freshness)
        if freshness:
            params["freshness"] = freshness

        response = requests.get(
            self.config.bing_endpoint,
            params=params,
            timeout=self.config.request_timeout_seconds,
            headers={
                "Ocp-Apim-Subscription-Key": self.config.bing_api_key,
                "User-Agent": self.config.user_agent,
            },
        )
        response.raise_for_status()
        payload = response.json()

        results: List[SearchResult] = []
        values = ((payload.get("webPages") or {}).get("value") or [])
        for idx, item in enumerate(values, start=1):
            url = str(item.get("url") or "").strip()
            title = html.unescape(str(item.get("name") or "").strip())
            snippet = html.unescape(str(item.get("snippet") or "").strip())
            domain = self._extract_domain(url)
            results.append(
                SearchResult(
                    title=title,
                    url=url,
                    snippet=snippet,
                    provider=SearchProvider.BING.value,
                    rank=idx,
                    display_url=domain,
                    domain=domain,
                    published_at=item.get("dateLastCrawled"),
                    metadata={
                        "id": item.get("id"),
                        "is_family_friendly": item.get("isFamilyFriendly"),
                        "language": item.get("language"),
                    },
                )
            )
        return results

    def _search_dev_fallback(self, search_query: SearchQuery) -> List[SearchResult]:
        """Safe deterministic fallback for local development and tests.

        This fallback does not impersonate a browser, does not scrape Google/Bing,
        and does not perform hidden browser automation. It returns predictable
        public-style results so the rest of the pipeline can be tested before
        provider API keys are configured.
        """

        seed = self._hash_text(search_query.built_query)[:10]
        base_domain = "digitalpromotix.dev"
        encoded = quote_plus(search_query.built_query)
        samples = [
            {
                "title": f"Search overview for {search_query.raw_query}",
                "url": f"https://{base_domain}/search/overview?q={encoded}&ref={seed}",
                "snippet": "Development fallback result for testing William Browser Agent search ranking and filtering.",
            },
            {
                "title": f"Research notes: {search_query.raw_query}",
                "url": f"https://docs.{base_domain}/research?q={encoded}&ref={seed}",
                "snippet": "Structured research-style fallback result with useful context for local tests and dashboard previews.",
            },
            {
                "title": f"Browser Agent source list for {search_query.raw_query}",
                "url": f"https://browser-agent.{base_domain}/sources?q={encoded}&ref={seed}",
                "snippet": "Safe provider-free result used when Google or Bing API keys are not configured.",
            },
        ]
        results: List[SearchResult] = []
        for idx, item in enumerate(samples, start=1):
            domain = self._extract_domain(item["url"])
            results.append(
                SearchResult(
                    title=item["title"],
                    url=item["url"],
                    snippet=item["snippet"],
                    provider=SearchProvider.DEV_FALLBACK.value,
                    rank=idx,
                    display_url=domain,
                    domain=domain,
                    metadata={"dev_fallback": True, "seed": seed},
                )
            )
        return results

    # ---------------------------------------------------------------------
    # William compatibility hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any], query: Optional[str] = None) -> Dict[str, Any]:
        """Validate user/workspace context for SaaS isolation."""

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing user_id. Search must be tied to a SaaS user.",
                error="MISSING_USER_ID",
                data={},
                metadata={"context": dict(context)},
            )
        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing workspace_id. Search must be tied to a workspace.",
                error="MISSING_WORKSPACE_ID",
                data={},
                metadata={"context": dict(context)},
            )
        if query is not None and not self._clean_query(query):
            return self._error_result(
                message="Search query cannot be empty.",
                error="EMPTY_QUERY",
                data={},
                metadata={"context": dict(context)},
            )
        return self._safe_result(
            message="Task context validated.",
            data={"valid": True},
            metadata={"context": dict(context)},
        )

    def _requires_security_check(self, search_query: SearchQuery, context: Mapping[str, Any]) -> bool:
        """Decide whether Security Agent approval is required."""

        sensitive_terms = {
            "password",
            "private key",
            "secret key",
            "token dump",
            "credential leak",
            "exploit",
            "malware",
            "phishing kit",
            "stolen database",
        }
        query_text = search_query.built_query.lower()
        if any(term in query_text for term in sensitive_terms):
            return True
        if search_query.filters.get("force_security_check") is True:
            return True
        return False

    def _request_security_approval(self, search_query: SearchQuery, context: Mapping[str, Any]) -> Dict[str, Any]:
        """Request approval from Security Agent if available.

        The fallback is conservative for obviously sensitive queries and safe for
        normal public web searches.
        """

        payload = {
            "action": "browser.search",
            "query": search_query.built_query,
            "user_id": search_query.user_id,
            "workspace_id": search_query.workspace_id,
            "context": dict(context),
            "risk": "medium",
        }

        if self.security_agent is not None:
            for method_name in ("approve_action", "request_approval", "check_permission", "authorize"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = method(payload)
                        if isinstance(response, dict):
                            return {
                                "approved": bool(response.get("approved") or response.get("success") or response.get("allowed")),
                                "source": f"security_agent.{method_name}",
                                "raw": response,
                            }
                        return {"approved": bool(response), "source": f"security_agent.{method_name}", "raw": response}
                    except Exception as exc:
                        return {"approved": False, "source": f"security_agent.{method_name}", "error": str(exc)}

        return {
            "approved": not self._requires_security_check(search_query, context),
            "source": "fallback_policy",
            "raw": payload,
        }

    def _prepare_verification_payload(
        self,
        search_query: SearchQuery,
        results: Sequence[SearchResult],
        provider_errors: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create Verification Agent compatible payload."""

        return {
            "type": "browser_search_verification",
            "agent": "browser_agent",
            "module": "search_engine",
            "user_id": search_query.user_id,
            "workspace_id": search_query.workspace_id,
            "query_hash": self._hash_text(search_query.built_query),
            "result_count": len(results),
            "top_domains": [item.domain for item in results[:5]],
            "provider_errors": dict(provider_errors or {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _prepare_memory_payload(self, search_query: SearchQuery, results: Sequence[SearchResult]) -> Dict[str, Any]:
        """Create Memory Agent compatible payload."""

        return {
            "type": "browser_search_context",
            "user_id": search_query.user_id,
            "workspace_id": search_query.workspace_id,
            "query": search_query.built_query,
            "intent": search_query.intent,
            "top_results": [
                {
                    "title": item.title,
                    "url": item.url,
                    "domain": item.domain,
                    "score": item.score,
                }
                for item in results[:5]
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Emit event to William event bus/dashboard if available."""

        safe_payload = self._json_safe(payload)
        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return
            emit = getattr(super(), "emit_event", None)
            if callable(emit):
                emit(event_name, safe_payload)
        except Exception as exc:
            self.logger.debug("Agent event emit failed: %s", exc)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """Write audit event through injected logger or normal logger."""

        if not self.config.audit_enabled:
            return
        safe_payload = self._json_safe(payload)
        try:
            if self.audit_logger:
                self.audit_logger(safe_payload)
            else:
                self.logger.info("AUDIT %s", json.dumps(safe_payload, sort_keys=True))
        except Exception as exc:
            self.logger.debug("Audit log failed: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard success response."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard error response."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "UNKNOWN_ERROR",
            "metadata": metadata or {},
        }

    # ---------------------------------------------------------------------
    # Filtering/ranking helpers
    # ---------------------------------------------------------------------

    def _normalize_result(self, item: SearchResult) -> Optional[SearchResult]:
        title = html.unescape(str(item.title or "")).strip()
        url = str(item.url or "").strip()
        snippet = html.unescape(str(item.snippet or "")).strip()

        if not title or not url:
            return None
        if not self._is_http_url(url):
            return None

        canonical = self._canonical_url(url)
        domain = self._extract_domain(canonical)
        if not domain:
            return None

        return SearchResult(
            title=title,
            url=canonical,
            snippet=snippet,
            provider=item.provider,
            rank=item.rank,
            score=item.score,
            display_url=item.display_url or domain,
            domain=domain,
            published_at=item.published_at,
            content_type=item.content_type,
            metadata=dict(item.metadata or {}),
        )

    def _matches_search_filters(self, item: SearchResult, search_query: SearchQuery) -> bool:
        text = f"{item.title} {item.snippet} {item.url}".lower()

        for term in search_query.include_terms:
            if term.lower() not in text:
                return False
        for term in search_query.exclude_terms:
            if term.lower() in text:
                return False

        filters = search_query.filters or {}
        required_domain = filters.get("domain") or filters.get("required_domain")
        if required_domain and item.domain != self._extract_domain(str(required_domain)):
            return False

        blocked_terms = [str(t).lower() for t in filters.get("blocked_terms", []) or []]
        if any(term and term in text for term in blocked_terms):
            return False

        required_terms = [str(t).lower() for t in filters.get("required_terms", []) or []]
        if any(term and term not in text for term in required_terms):
            return False

        return True

    def _is_low_value_result(self, item: SearchResult) -> bool:
        if len(item.title.strip()) < 3:
            return True
        if any(pattern.search(item.title.strip()) for pattern in self.LOW_VALUE_TITLE_PATTERNS):
            return True
        if item.url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico')):
            return True
        return False

    def _is_blocked_domain(self, domain: str) -> bool:
        normalized = self._normalize_domain(domain)
        if not normalized:
            return True
        for blocked in self.config.blocked_domains:
            if normalized == blocked or normalized.endswith(f".{blocked}"):
                return True
        return False

    def _looks_authoritative(self, domain: str) -> bool:
        if not domain:
            return False
        authoritative_suffixes = (".gov", ".edu", ".org", ".int")
        if domain.endswith(authoritative_suffixes):
            return True
        known_sources = {
            "wikipedia.org",
            "github.com",
            "developer.mozilla.org",
            "docs.python.org",
            "microsoft.com",
            "google.com",
            "openai.com",
        }
        return domain in known_sources or any(domain.endswith(f".{source}") for source in known_sources)

    # ---------------------------------------------------------------------
    # Query/text/url helpers
    # ---------------------------------------------------------------------

    def _clean_query(self, query: str) -> str:
        value = str(query or "")
        value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
        value = value.replace("\n", " ").replace("\r", " ").strip()
        return self._compact_spaces(value)[:500]

    def _clean_term(self, term: str) -> str:
        value = str(term or "").strip()
        value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
        value = value.replace("site:", "").replace("filetype:", "")
        return self._compact_spaces(value)[:120]

    def _compact_spaces(self, value: str) -> str:
        return re.sub(r"\s+", " ", value or "").strip()

    def _normalize_intent(self, intent: Union[str, SearchIntent]) -> str:
        value = intent.value if isinstance(intent, SearchIntent) else str(intent or SearchIntent.GENERAL.value)
        value = value.strip().lower()
        valid = {item.value for item in SearchIntent}
        return value if value in valid else SearchIntent.GENERAL.value

    def _intent_query_boosts(self, intent: str) -> List[str]:
        boosts = {
            SearchIntent.NEWS.value: ["latest", "news"],
            SearchIntent.RESEARCH.value: ["research", "analysis"],
            SearchIntent.LOCAL.value: ["near me"],
            SearchIntent.SHOPPING.value: ["price", "review"],
            SearchIntent.TECHNICAL.value: ["documentation", "guide"],
            SearchIntent.SEO.value: ["SEO", "organic search"],
            SearchIntent.COMPETITOR.value: ["competitors", "comparison"],
            SearchIntent.PRICE.value: ["pricing", "cost"],
        }
        return boosts.get(intent, [])

    def _provider_label(self, provider: Any) -> str:
        if isinstance(provider, SearchProvider):
            return provider.value
        return str(provider or "auto").strip().lower()

    def _safe_int(self, value: Any, default: int, *, minimum: int, maximum: int) -> int:
        try:
            number = int(value)
        except Exception:
            number = int(default)
        return max(minimum, min(maximum, number))

    def _tokenize(self, value: str) -> List[str]:
        tokens = re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_-]{1,}", (value or "").lower())
        stop_words = {
            "the", "and", "for", "with", "from", "that", "this", "into", "your", "you", "are",
            "near", "best", "latest", "news", "guide", "how", "what", "where", "when", "why",
        }
        return [token for token in tokens if token not in stop_words]

    def _normalize_text(self, value: str) -> str:
        return self._compact_spaces(re.sub(r"[^a-zA-Z0-9]+", " ", (value or "").lower()))

    def _is_http_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
        except Exception:
            return False

    def _canonical_url(self, url: str) -> str:
        parsed = urlparse(str(url).strip())
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]

        query_pairs = parse_qs(parsed.query, keep_blank_values=False)
        clean_pairs: Dict[str, str] = {}
        for key, values in query_pairs.items():
            if key.lower() in self.TRACKING_QUERY_PARAMS:
                continue
            if values:
                clean_pairs[key] = values[0]
        clean_query = urlencode(clean_pairs, doseq=False)
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/")
        return urlunparse((scheme, netloc, path, "", clean_query, ""))

    def _extract_domain(self, url_or_domain: str) -> str:
        value = str(url_or_domain or "").strip().lower()
        if not value:
            return ""
        if "://" not in value:
            value = f"https://{value}"
        try:
            parsed = urlparse(value)
            domain = parsed.netloc or parsed.path
            return self._normalize_domain(domain)
        except Exception:
            return ""

    def _normalize_domain(self, domain: str) -> str:
        value = str(domain or "").strip().lower()
        value = value.split("@")[ -1 ]
        value = value.split(":")[0]
        value = value.strip("/.")
        if value.startswith("www."):
            value = value[4:]
        value = re.sub(r"[^a-z0-9.-]", "", value)
        return value

    def _normalize_domain_list(self, domains: Iterable[str]) -> List[str]:
        output: List[str] = []
        seen: set[str] = set()
        for item in domains:
            domain = self._extract_domain(item)
            if domain and domain not in seen:
                seen.add(domain)
                output.append(domain)
        return output

    def _hash_text(self, value: str) -> str:
        return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()

    def _json_safe(self, payload: Any) -> Any:
        try:
            json.dumps(payload)
            return payload
        except Exception:
            if isinstance(payload, dict):
                return {str(k): self._json_safe(v) for k, v in payload.items()}
            if isinstance(payload, (list, tuple, set)):
                return [self._json_safe(v) for v in payload]
            return str(payload)

    # ---------------------------------------------------------------------
    # Provider-specific helpers
    # ---------------------------------------------------------------------

    def _google_safe_value(self, safe_search: str) -> str:
        value = str(safe_search or "moderate").lower()
        if value in {"off", "none", "false"}:
            return "off"
        return "active"

    def _bing_safe_value(self, safe_search: str) -> str:
        value = str(safe_search or "moderate").lower()
        if value in {"strict", "high"}:
            return "Strict"
        if value in {"off", "none", "false"}:
            return "Off"
        return "Moderate"

    def _google_date_restrict(self, freshness: Optional[str]) -> Optional[str]:
        if not freshness:
            return None
        value = freshness.lower().strip()
        mapping = {
            "day": "d1",
            "daily": "d1",
            "week": "w1",
            "weekly": "w1",
            "month": "m1",
            "monthly": "m1",
            "year": "y1",
            "yearly": "y1",
        }
        if value in mapping:
            return mapping[value]
        if re.fullmatch(r"[dwmy]\d+", value):
            return value
        return None

    def _bing_freshness_value(self, freshness: Optional[str]) -> Optional[str]:
        if not freshness:
            return None
        value = freshness.lower().strip()
        if value in {"day", "daily", "d1", "24h", "today"}:
            return "Day"
        if value in {"week", "weekly", "w1", "7d"}:
            return "Week"
        if value in {"month", "monthly", "m1", "30d"}:
            return "Month"
        return None

    def _extract_published_at_from_pagemap(self, pagemap: Mapping[str, Any]) -> Optional[str]:
        candidates: List[Any] = []
        for key in ("metatags", "newsarticle", "article"):
            values = pagemap.get(key) if isinstance(pagemap, Mapping) else None
            if isinstance(values, list):
                candidates.extend(values)
            elif isinstance(values, dict):
                candidates.append(values)
        date_keys = [
            "article:published_time",
            "datepublished",
            "datePublished",
            "pubdate",
            "publishdate",
            "timestamp",
            "og:updated_time",
        ]
        for item in candidates:
            if not isinstance(item, Mapping):
                continue
            for key in date_keys:
                value = item.get(key)
                if value:
                    return str(value)
        return None

    def _is_recent_date(self, value: str) -> bool:
        if not value:
            return False
        text = str(value)
        match = re.search(r"(20\d{2}|19\d{2})", text)
        if not match:
            return False
        try:
            year = int(match.group(1))
            current_year = datetime.now(timezone.utc).year
            return year >= current_year - 1
        except Exception:
            return False


__all__ = [
    "SearchEngine",
    "SearchEngineConfig",
    "SearchProvider",
    "SearchIntent",
    "SearchQuery",
    "SearchResult",
]


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    logging.basicConfig(level=logging.INFO)
    engine = SearchEngine(config={"enable_dev_fallback": True})
    result = engine.search(
        "AI click fraud protection",
        user_id="demo-user",
        workspace_id="demo-workspace",
        provider="dev_fallback",
        intent="research",
        max_results=3,
    )
    print(json.dumps(result, indent=2))
