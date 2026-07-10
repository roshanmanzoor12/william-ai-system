"""
agents/browser_agent/competitor_analyzer.py

William / Jarvis Multi-Agent AI SaaS System - Browser Agent helper.

Purpose:
    Compare websites, pricing, features, CTAs, trust signals, funnel structure,
    positioning gaps, and improvement opportunities in a SaaS-safe, import-safe,
    dashboard/API-ready format.

Design goals:
    - Safe to import even when the rest of William/Jarvis is still being built.
    - Compatible with Master Agent routing, Agent Registry, Agent Loader, and
      BaseAgent-style execution.
    - Supports user_id/workspace_id isolation for SaaS multi-tenant operation.
    - Never performs sensitive/browser/network actions unless permission checks
      are satisfied.
    - Returns structured dict payloads:
      {success, message, data, error, metadata}

Notes:
    This file intentionally works with either:
      1) pre-fetched page records from Scraper/PageAnalyzer/ContentExtractor, or
      2) optional direct URL fetching when allow_network=True and security permits.

    Direct fetching is conservative and uses only public HTTP GET requests.
    It should still be routed through the Security Agent in production.
"""

from __future__ import annotations

import dataclasses
import hashlib
import html
import json
import logging
import re
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent import
# ---------------------------------------------------------------------------
try:  # pragma: no cover - depends on future William/Jarvis file availability
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback keeps this file import-safe
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent can replace this automatically when
        available. This fallback exists only so this file can be imported and
        tested independently while the full system is still under construction.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)


# ---------------------------------------------------------------------------
# Optional requests import
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional runtime dependency
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGER = logging.getLogger("william.browser_agent.competitor_analyzer")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_HTML_CHARS = 350_000
DEFAULT_MAX_COMPETITORS = 12

PRICE_REGEX = re.compile(
    r"(?:(?:USD|EUR|GBP|AED|CAD|AUD)\s*)?(?:\$|€|£|د\.إ|CA\$|A\$)?\s?\d+(?:[,.]\d{2})?(?:\s*/\s*(?:mo|month|monthly|yr|year|annually|user|seat))?",
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(r"[\w.\-+%]+@[\w.\-]+\.[A-Za-z]{2,}")
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}"
)

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

CTA_KEYWORDS = [
    "get started",
    "start free",
    "free trial",
    "book a demo",
    "schedule demo",
    "request demo",
    "contact sales",
    "contact us",
    "sign up",
    "try now",
    "buy now",
    "subscribe",
    "start now",
    "learn more",
    "talk to sales",
    "get a quote",
    "request quote",
    "download",
    "join now",
    "claim",
    "protect now",
    "scan now",
]

TRUST_KEYWORDS = [
    "reviews",
    "testimonial",
    "testimonials",
    "case study",
    "case studies",
    "trusted by",
    "certified",
    "certification",
    "secure",
    "security",
    "gdpr",
    "hipaa",
    "soc 2",
    "iso",
    "ssl",
    "privacy",
    "compliance",
    "award",
    "partner",
    "guarantee",
    "money back",
    "rating",
    "stars",
]

FEATURE_HINTS = [
    "dashboard",
    "analytics",
    "reporting",
    "automation",
    "integration",
    "integrations",
    "api",
    "real-time",
    "real time",
    "monitoring",
    "alerts",
    "detection",
    "protection",
    "blocking",
    "workflow",
    "export",
    "import",
    "team",
    "roles",
    "permissions",
    "audit",
    "logs",
    "ai",
    "machine learning",
    "crm",
    "white label",
    "custom",
    "support",
    "onboarding",
]

FUNNEL_KEYWORDS = {
    "awareness": ["blog", "guide", "resources", "learn", "insights", "education"],
    "consideration": ["features", "solutions", "compare", "case study", "demo", "webinar"],
    "conversion": ["pricing", "checkout", "trial", "quote", "contact sales", "sign up", "book"],
    "retention": ["help", "docs", "support", "academy", "community", "knowledge base"],
}

RISKY_BROWSER_ACTION_TERMS = [
    "login",
    "checkout",
    "purchase",
    "submit",
    "send",
    "post",
    "delete",
    "click ad",
    "automated click",
    "credentials",
    "payment",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class CompetitorPage:
    """
    Normalized page input for competitor analysis.

    Can be created from:
      - URL + HTML/text fetched by Browser Agent scraper/content extractor.
      - Raw text pasted/uploaded by user.
      - Optional direct fetch through this analyzer when allowed.
    """

    url: str
    title: str = ""
    html_content: str = ""
    text_content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def domain(self) -> str:
        parsed = urllib.parse.urlparse(self.url or "")
        host = parsed.netloc or parsed.path
        host = host.lower().replace("www.", "")
        return host.strip("/")


@dataclass
class CompetitorSignals:
    """Extracted competitor marketing/funnel signals."""

    url: str
    domain: str
    title: str
    word_count: int
    headings: List[str]
    prices: List[str]
    ctas: List[str]
    features: List[str]
    trust_signals: List[str]
    funnel_signals: Dict[str, List[str]]
    contact_signals: Dict[str, List[str]]
    positioning_terms: List[str]
    content_hash: str
    raw_score: Dict[str, float]


@dataclass
class CompetitorAnalyzerConfig:
    """
    Configuration for competitor analysis.

    max_competitors:
        Limits how many competitor pages can be analyzed in a single call.

    allow_network:
        Direct HTTP fetching is disabled by default. In production this should be
        controlled by Security Agent policy and subscription/role permissions.

    require_security_for_network:
        Network fetch requests are considered sensitive browser actions and
        should be approved by Security Agent.

    max_html_chars:
        Caps response size to avoid memory spikes and unsafe huge payloads.
    """

    max_competitors: int = DEFAULT_MAX_COMPETITORS
    allow_network: bool = False
    require_security_for_network: bool = True
    request_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_html_chars: int = DEFAULT_MAX_HTML_CHARS
    user_agent: str = (
        "WilliamJarvisBrowserAgent/1.0 "
        "(safe competitor analysis; contact admin for policy details)"
    )
    redact_contacts: bool = False
    enable_audit_log: bool = True
    enable_agent_events: bool = True


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------
class CompetitorAnalyzer(BaseAgent):
    """
    Compare websites, pricing, features, CTAs, trust, funnels, and market gaps.

    Master Agent connection:
        The Master Agent can route requests like "compare my landing page with
        these competitor URLs" to this class through analyze_competitors().

    Security Agent connection:
        Any optional network fetching, or analysis request that implies risky
        browser actions, is gated by _requires_security_check() and
        _request_security_approval().

    Memory Agent connection:
        Useful summarized context is prepared by _prepare_memory_payload() so
        the Memory Agent can store project-level insights per user/workspace.

    Verification Agent connection:
        Every completed analysis prepares a verification payload containing
        the inputs, extracted signals, scoring, and confidence notes.

    Dashboard/API connection:
        All public methods return structured dict payloads that can be rendered
        by FastAPI endpoints, SaaS dashboards, task history, and analytics.
    """

    agent_key = "browser.competitor_analyzer"
    agent_name = "Browser Competitor Analyzer"
    agent_version = "1.0.0"

    def __init__(
        self,
        config: Optional[CompetitorAnalyzerConfig] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, **kwargs)
        self.config = config or CompetitorAnalyzerConfig()
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.logger = logger or LOGGER

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze_competitors(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        target: Optional[Union[CompetitorPage, Mapping[str, Any], str]] = None,
        competitors: Optional[Sequence[Union[CompetitorPage, Mapping[str, Any], str]]] = None,
        objective: str = "Improve website conversion and competitive positioning.",
        industry: Optional[str] = None,
        allow_network: Optional[bool] = None,
        requested_by: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a target website/page against competitor pages.

        Args:
            user_id: SaaS user id. Required for isolation.
            workspace_id: SaaS workspace id. Required for isolation.
            target: Optional target page to compare against competitors.
            competitors: Competitor pages, records, URLs, or raw text.
            objective: Business objective used to prioritize recommendations.
            industry: Optional niche/industry label for dashboard reporting.
            allow_network: Per-call override for direct URL fetching.
            requested_by: User/email/system actor for audit trail.
            metadata: Additional safe metadata for task tracking.

        Returns:
            Structured dict with extracted signals, comparison table, gaps,
            recommendations, verification payload, and memory payload.
        """
        start_ts = time.time()
        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "requested_by": requested_by,
            "metadata": dict(metadata or {}),
        }

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        competitors = list(competitors or [])
        if not competitors:
            return self._error_result(
                "No competitor pages were provided.",
                code="NO_COMPETITORS",
                metadata=self._base_metadata(context),
            )

        if len(competitors) > self.config.max_competitors:
            return self._error_result(
                f"Too many competitors. Maximum allowed is {self.config.max_competitors}.",
                code="TOO_MANY_COMPETITORS",
                metadata={
                    **self._base_metadata(context),
                    "provided_count": len(competitors),
                    "max_competitors": self.config.max_competitors,
                },
            )

        effective_allow_network = self.config.allow_network if allow_network is None else bool(allow_network)
        task_description = {
            "action": "competitor_analysis",
            "objective": objective,
            "industry": industry,
            "allow_network": effective_allow_network,
            "target_present": target is not None,
            "competitor_count": len(competitors),
        }

        if self._requires_security_check(task_description):
            approval = self._request_security_approval(context=context, task=task_description)
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied or unavailable for competitor analysis.",
                    code="SECURITY_APPROVAL_DENIED",
                    error=approval,
                    metadata=self._base_metadata(context),
                )

        self._emit_agent_event(
            "competitor_analysis.started",
            context=context,
            data={"objective": objective, "competitor_count": len(competitors)},
        )

        try:
            normalized_target = (
                self._normalize_page_input(target, allow_network=effective_allow_network, context=context)
                if target is not None
                else None
            )
            normalized_competitors = [
                self._normalize_page_input(item, allow_network=effective_allow_network, context=context)
                for item in competitors
            ]

            target_signals = self.extract_signals(normalized_target).get("data") if normalized_target else None
            competitor_signals = [
                self.extract_signals(page).get("data")
                for page in normalized_competitors
            ]
            competitor_signals = [sig for sig in competitor_signals if sig]

            if not competitor_signals:
                return self._error_result(
                    "Competitor pages could not be analyzed.",
                    code="ANALYSIS_EMPTY",
                    metadata=self._base_metadata(context),
                )

            comparison = self.compare_signals(
                target_signals=target_signals,
                competitor_signals=competitor_signals,
                objective=objective,
                industry=industry,
            )

            recommendations = self.generate_recommendations(
                comparison=comparison,
                target_signals=target_signals,
                competitor_signals=competitor_signals,
                objective=objective,
            )

            data = {
                "objective": objective,
                "industry": industry,
                "target": target_signals,
                "competitors": competitor_signals,
                "comparison": comparison,
                "recommendations": recommendations,
                "summary": self._build_executive_summary(
                    target_signals=target_signals,
                    competitor_signals=competitor_signals,
                    comparison=comparison,
                    recommendations=recommendations,
                ),
            }

            verification_payload = self._prepare_verification_payload(
                context=context,
                task=task_description,
                result_data=data,
            )
            memory_payload = self._prepare_memory_payload(
                context=context,
                task=task_description,
                result_data=data,
            )

            result = self._safe_result(
                message="Competitor analysis completed successfully.",
                data={
                    **data,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    **self._base_metadata(context),
                    "duration_ms": round((time.time() - start_ts) * 1000, 2),
                    "analyzed_competitors": len(competitor_signals),
                    "target_analyzed": bool(target_signals),
                },
            )

            self._log_audit_event(
                context=context,
                action="competitor_analysis.completed",
                details={
                    "objective": objective,
                    "industry": industry,
                    "competitor_count": len(competitor_signals),
                    "target_analyzed": bool(target_signals),
                },
            )
            self._emit_agent_event(
                "competitor_analysis.completed",
                context=context,
                data={"competitor_count": len(competitor_signals)},
            )
            return result

        except Exception as exc:
            self.logger.exception("Competitor analysis failed.")
            self._emit_agent_event(
                "competitor_analysis.failed",
                context=context,
                data={"error": str(exc)},
            )
            return self._error_result(
                "Competitor analysis failed.",
                code="COMPETITOR_ANALYSIS_FAILED",
                error=str(exc),
                metadata={
                    **self._base_metadata(context),
                    "duration_ms": round((time.time() - start_ts) * 1000, 2),
                },
            )

    def extract_signals(
        self,
        page: CompetitorPage,
    ) -> Dict[str, Any]:
        """
        Extract pricing, features, CTAs, trust signals, funnel signals, and
        positioning terms from a page.

        This public method is useful for unit tests, dashboard previews, and
        upstream Browser Agent modules that need raw signal extraction only.
        """
        try:
            text = self._page_to_text(page)
            text_lower = text.lower()
            headings = self._extract_headings(page.html_content, text)
            prices = self._extract_prices(text)
            ctas = self._extract_keyword_phrases(text_lower, CTA_KEYWORDS)
            features = self._extract_keyword_phrases(text_lower, FEATURE_HINTS)
            trust_signals = self._extract_keyword_phrases(text_lower, TRUST_KEYWORDS)
            funnel_signals = self._extract_funnel_signals(text_lower)
            contact_signals = self._extract_contact_signals(text)
            positioning_terms = self._extract_positioning_terms(text)
            raw_score = self._score_page(
                word_count=len(text.split()),
                prices=prices,
                ctas=ctas,
                features=features,
                trust_signals=trust_signals,
                funnel_signals=funnel_signals,
                contact_signals=contact_signals,
                headings=headings,
            )

            signals = CompetitorSignals(
                url=page.url,
                domain=page.domain(),
                title=page.title or self._guess_title(page.html_content, text),
                word_count=len(text.split()),
                headings=headings,
                prices=prices,
                ctas=ctas,
                features=features,
                trust_signals=trust_signals,
                funnel_signals=funnel_signals,
                contact_signals=contact_signals,
                positioning_terms=positioning_terms,
                content_hash=self._content_hash(text),
                raw_score=raw_score,
            )

            return self._safe_result(
                message="Signals extracted successfully.",
                data=dataclasses.asdict(signals),
                metadata={
                    "agent": self.agent_key,
                    "domain": signals.domain,
                    "word_count": signals.word_count,
                },
            )
        except Exception as exc:
            self.logger.exception("Signal extraction failed.")
            return self._error_result(
                "Signal extraction failed.",
                code="SIGNAL_EXTRACTION_FAILED",
                error=str(exc),
            )

    def compare_signals(
        self,
        *,
        target_signals: Optional[Mapping[str, Any]],
        competitor_signals: Sequence[Mapping[str, Any]],
        objective: str = "",
        industry: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compare normalized signal dictionaries.

        Returns:
            A comparison matrix with leaders, averages, common patterns, gaps,
            and target-vs-market deltas when a target is provided.
        """
        competitors = [dict(item) for item in competitor_signals]
        target = dict(target_signals) if target_signals else None

        market_patterns = self._market_patterns(competitors)
        leaders = self._rank_competitors(competitors)
        averages = self._average_scores(competitors)
        gaps = self._find_market_gaps(target, competitors, market_patterns)
        target_delta = self._target_delta(target, averages, market_patterns) if target else None

        return {
            "objective": objective,
            "industry": industry,
            "competitor_count": len(competitors),
            "leaders": leaders,
            "averages": averages,
            "market_patterns": market_patterns,
            "target_delta": target_delta,
            "gaps": gaps,
            "comparison_table": self._build_comparison_table(target, competitors),
        }

    def generate_recommendations(
        self,
        *,
        comparison: Mapping[str, Any],
        target_signals: Optional[Mapping[str, Any]],
        competitor_signals: Sequence[Mapping[str, Any]],
        objective: str,
    ) -> List[Dict[str, Any]]:
        """
        Generate prioritized recommendations based on observed competitor gaps.

        Recommendations are deterministic, safe, and dashboard-ready.
        """
        recommendations: List[Dict[str, Any]] = []
        target = dict(target_signals) if target_signals else {}
        market_patterns = dict(comparison.get("market_patterns", {}))
        target_delta = comparison.get("target_delta") or {}
        gaps = comparison.get("gaps") or []

        def add(priority: str, category: str, title: str, action: str, evidence: Any) -> None:
            recommendations.append(
                {
                    "priority": priority,
                    "category": category,
                    "title": title,
                    "recommended_action": action,
                    "evidence": evidence,
                    "owner_agent": "browser_agent",
                    "verification_needed": True,
                }
            )

        if not target:
            add(
                "high",
                "strategy",
                "Create a target benchmark before final decisions",
                "Provide the user's own landing page/page content so William can produce exact target-vs-competitor deltas.",
                "No target page was provided.",
            )

        if target_delta:
            missing_ctas = target_delta.get("missing_common_ctas", [])
            if missing_ctas:
                add(
                    "high",
                    "conversion",
                    "Strengthen conversion CTAs",
                    "Add or test high-intent CTAs that competitors commonly use, such as: "
                    + ", ".join(missing_ctas[:5]),
                    {"missing_common_ctas": missing_ctas},
                )

            missing_trust = target_delta.get("missing_common_trust_signals", [])
            if missing_trust:
                add(
                    "high",
                    "trust",
                    "Add stronger proof and trust signals",
                    "Add visible testimonials, certifications, compliance badges, case studies, or review proof where relevant.",
                    {"missing_common_trust_signals": missing_trust},
                )

            missing_features = target_delta.get("missing_common_features", [])
            if missing_features:
                add(
                    "medium",
                    "features",
                    "Close feature communication gaps",
                    "Clarify important features competitors mention but the target does not emphasize.",
                    {"missing_common_features": missing_features},
                )

        if gaps:
            add(
                "medium",
                "market_gap",
                "Use competitor gaps as differentiation angles",
                "Turn weak competitor coverage into page sections, comparison claims, FAQs, or demo talking points.",
                gaps[:8],
            )

        common_funnel = market_patterns.get("common_funnel_stages", {})
        if common_funnel and "conversion" not in common_funnel:
            add(
                "medium",
                "funnel",
                "Make the conversion path more direct",
                "Competitor content appears weak around conversion language; use clearer pricing/demo/contact paths.",
                common_funnel,
            )

        if not recommendations:
            add(
                "low",
                "optimization",
                "Run controlled CTA and proof testing",
                "Competitors show similar baseline coverage. Improve results through A/B testing headlines, CTAs, proof blocks, and pricing placement.",
                {"objective": objective},
            )

        priority_order = {"high": 0, "medium": 1, "low": 2}
        return sorted(recommendations, key=lambda item: priority_order.get(item["priority"], 9))

    def compare_pages_from_text(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        target_text: Optional[str],
        competitor_texts: Sequence[str],
        objective: str = "Improve conversion.",
        industry: Optional[str] = None,
        requested_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convenience wrapper for uploaded/pasted text without URLs.
        """
        target = (
            CompetitorPage(url="local://target", title="Target Page", text_content=target_text or "")
            if target_text
            else None
        )
        competitors = [
            CompetitorPage(url=f"local://competitor-{idx + 1}", title=f"Competitor {idx + 1}", text_content=text)
            for idx, text in enumerate(competitor_texts)
        ]
        return self.analyze_competitors(
            user_id=user_id,
            workspace_id=workspace_id,
            target=target,
            competitors=competitors,
            objective=objective,
            industry=industry,
            allow_network=False,
            requested_by=requested_by,
        )

    # ------------------------------------------------------------------
    # Compatibility hooks required by William/Jarvis prompt bible
    # ------------------------------------------------------------------
    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate SaaS isolation context before any work is performed."""
        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                "user_id is required for SaaS-safe competitor analysis.",
                code="MISSING_USER_ID",
            )
        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                "workspace_id is required for SaaS-safe competitor analysis.",
                code="MISSING_WORKSPACE_ID",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
            metadata=self._base_metadata(context),
        )

    def _requires_security_check(self, task: Mapping[str, Any]) -> bool:
        """
        Decide whether Security Agent approval is required.

        Network fetching and risky action wording are gated. Pure analysis of
        provided content does not need an external permission by default.
        """
        if bool(task.get("allow_network")) and self.config.require_security_for_network:
            return True

        task_blob = json.dumps(task, default=str).lower()
        return any(term in task_blob for term in RISKY_BROWSER_ACTION_TERMS)

    def _request_security_approval(
        self,
        *,
        context: Mapping[str, Any],
        task: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval when available.

        Fallback behavior:
            - Allows non-network analysis.
            - Denies network fetch if config requires security but no security
              client is attached.
        """
        if self.security_client is not None:
            for method_name in ("approve_action", "request_approval", "validate_action"):
                method = getattr(self.security_client, method_name, None)
                if callable(method):
                    try:
                        response = method(
                            user_id=context.get("user_id"),
                            workspace_id=context.get("workspace_id"),
                            agent=self.agent_key,
                            action=task.get("action", "competitor_analysis"),
                            payload=dict(task),
                        )
                        if isinstance(response, Mapping):
                            approved = bool(
                                response.get("approved")
                                or response.get("success")
                                or response.get("allowed")
                            )
                            return {"approved": approved, "source": method_name, "raw": dict(response)}
                        return {"approved": bool(response), "source": method_name, "raw": response}
                    except Exception as exc:
                        self.logger.warning("Security client approval failed: %s", exc)
                        return {"approved": False, "source": method_name, "error": str(exc)}

        if bool(task.get("allow_network")) and self.config.require_security_for_network:
            return {
                "approved": False,
                "source": "fallback",
                "reason": "Network access requires Security Agent approval.",
            }

        return {
            "approved": True,
            "source": "fallback",
            "reason": "Pure provided-content analysis is allowed.",
        }

    def _prepare_verification_payload(
        self,
        *,
        context: Mapping[str, Any],
        task: Mapping[str, Any],
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent compatible payload."""
        return {
            "verification_type": "browser_competitor_analysis",
            "agent": self.agent_key,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "task": dict(task),
            "checks": [
                "context_validated",
                "competitor_count_checked",
                "signals_extracted",
                "comparison_generated",
                "recommendations_prioritized",
                "sensitive_actions_gated",
            ],
            "artifacts": {
                "competitor_count": len(result_data.get("competitors", []) or []),
                "target_present": result_data.get("target") is not None,
                "summary": result_data.get("summary"),
            },
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        context: Mapping[str, Any],
        task: Mapping[str, Any],
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prepare summarized insights for Memory Agent storage."""
        summary = result_data.get("summary") or {}
        comparison = result_data.get("comparison") or {}
        recommendations = result_data.get("recommendations") or []

        return {
            "memory_type": "competitor_research_summary",
            "agent": self.agent_key,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "title": "Competitor analysis summary",
            "summary": summary,
            "key_patterns": comparison.get("market_patterns", {}),
            "top_recommendations": recommendations[:5],
            "tags": ["browser_agent", "competitor_analysis", "conversion", "market_research"],
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Emit dashboard/API event if an event emitter is attached."""
        if not self.config.enable_agent_events:
            return

        payload = {
            "event": event_name,
            "agent": self.agent_key,
            "user_id": str((context or {}).get("user_id", "")),
            "workspace_id": str((context or {}).get("workspace_id", "")),
            "data": dict(data or {}),
            "created_at": self._utc_now(),
        }

        if callable(self.event_emitter):
            try:
                self.event_emitter(payload)
                return
            except Exception as exc:
                self.logger.warning("Agent event emitter failed: %s", exc)

        self.logger.debug("Agent event: %s", payload)

    def _log_audit_event(
        self,
        *,
        context: Mapping[str, Any],
        action: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Log audit event without mixing users/workspaces."""
        if not self.config.enable_audit_log:
            return

        payload = {
            "action": action,
            "agent": self.agent_key,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "requested_by": context.get("requested_by"),
            "details": dict(details or {}),
            "created_at": self._utc_now(),
        }

        if callable(self.audit_logger):
            try:
                self.audit_logger(payload)
                return
            except Exception as exc:
                self.logger.warning("Audit logger failed: %s", exc)

        self.logger.info("Audit event: %s", payload)

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard success response."""
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        *,
        code: str = "ERROR",
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard error response."""
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "details": error,
            },
            "metadata": dict(metadata or {}),
        }

    # ------------------------------------------------------------------
    # Normalization and fetching
    # ------------------------------------------------------------------
    def _normalize_page_input(
        self,
        item: Union[CompetitorPage, Mapping[str, Any], str],
        *,
        allow_network: bool,
        context: Mapping[str, Any],
    ) -> CompetitorPage:
        """Normalize page input from object/dict/url/raw text."""
        if isinstance(item, CompetitorPage):
            return item

        if isinstance(item, Mapping):
            return CompetitorPage(
                url=str(item.get("url") or item.get("source_url") or item.get("id") or "local://page"),
                title=str(item.get("title") or item.get("page_title") or ""),
                html_content=str(item.get("html_content") or item.get("html") or ""),
                text_content=str(item.get("text_content") or item.get("text") or item.get("content") or ""),
                metadata=dict(item.get("metadata") or {}),
            )

        if isinstance(item, str):
            value = item.strip()
            if self._looks_like_url(value):
                if allow_network:
                    return self._fetch_page(value, context=context)
                return CompetitorPage(url=value, title="", text_content="")
            return CompetitorPage(url="local://raw-text", title="Raw Text Page", text_content=value)

        raise TypeError(f"Unsupported page input type: {type(item)!r}")

    def _fetch_page(self, url: str, *, context: Mapping[str, Any]) -> CompetitorPage:
        """
        Fetch a public web page if allowed and approved.

        This method never submits forms, logs in, clicks ads, or performs
        destructive actions. It only performs a single HTTP GET.
        """
        if requests is None:
            raise RuntimeError("The optional dependency 'requests' is not installed.")

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs can be fetched.")

        headers = {"User-Agent": self.config.user_agent}
        response = requests.get(
            url,
            headers=headers,
            timeout=self.config.request_timeout_seconds,
            allow_redirects=True,
        )
        response.raise_for_status()

        html_content = response.text[: self.config.max_html_chars]
        title = self._guess_title(html_content, "")

        self._log_audit_event(
            context=context,
            action="competitor_page.fetched",
            details={"url": url, "status_code": response.status_code, "chars": len(html_content)},
        )

        return CompetitorPage(
            url=response.url or url,
            title=title,
            html_content=html_content,
            text_content="",
            metadata={
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "fetched_at": self._utc_now(),
            },
        )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------
    def _page_to_text(self, page: CompetitorPage) -> str:
        if page.text_content:
            return self._clean_text(page.text_content)

        html_content = page.html_content or ""
        text = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", html_content)
        text = re.sub(r"(?s)<br\s*/?>", "\n", text)
        text = re.sub(r"(?s)</p\s*>", "\n", text)
        text = re.sub(r"(?s)<.*?>", " ", text)
        text = html.unescape(text)
        return self._clean_text(text)

    def _extract_headings(self, html_content: str, text: str) -> List[str]:
        headings: List[str] = []
        if html_content:
            for match in re.finditer(r"(?is)<h[1-3][^>]*>(.*?)</h[1-3]>", html_content):
                heading = self._clean_text(re.sub(r"(?s)<.*?>", " ", match.group(1)))
                if heading and heading.lower() not in {h.lower() for h in headings}:
                    headings.append(heading[:160])
        if not headings and text:
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            headings.extend(lines[:5])
        return headings[:12]

    def _extract_prices(self, text: str) -> List[str]:
        prices = []
        for match in PRICE_REGEX.findall(text):
            cleaned = self._clean_text(match)
            if cleaned and any(char.isdigit() for char in cleaned):
                prices.append(cleaned)
        return self._unique_keep_order(prices)[:20]

    def _extract_keyword_phrases(self, text_lower: str, phrases: Sequence[str]) -> List[str]:
        found = []
        for phrase in phrases:
            if phrase.lower() in text_lower:
                found.append(phrase)
        return self._unique_keep_order(found)

    def _extract_funnel_signals(self, text_lower: str) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for stage, keywords in FUNNEL_KEYWORDS.items():
            hits = self._extract_keyword_phrases(text_lower, keywords)
            if hits:
                result[stage] = hits
        return result

    def _extract_contact_signals(self, text: str) -> Dict[str, List[str]]:
        emails = self._unique_keep_order(EMAIL_REGEX.findall(text))[:10]
        phones = self._unique_keep_order(PHONE_REGEX.findall(text))[:10]
        urls = self._unique_keep_order(URL_REGEX.findall(text))[:10]

        if self.config.redact_contacts:
            emails = [self._redact_email(item) for item in emails]
            phones = [self._redact_phone(item) for item in phones]

        return {
            "emails": emails,
            "phones": phones,
            "urls": urls,
        }

    def _extract_positioning_terms(self, text: str) -> List[str]:
        """
        Extract simple repeated positioning terms.

        Avoids heavy NLP dependencies. Prioritizes meaningful words often used
        in landing-page positioning.
        """
        words = re.findall(r"[A-Za-z][A-Za-z\-]{3,}", text.lower())
        stop_words = {
            "with", "from", "that", "this", "your", "have", "will", "more", "about",
            "their", "there", "what", "when", "where", "which", "also", "into", "than",
            "then", "them", "they", "were", "been", "being", "over", "under", "home",
            "page", "click", "learn", "contact", "privacy", "terms", "cookie",
        }
        filtered = [w for w in words if w not in stop_words]
        counts = Counter(filtered)
        terms = [word for word, count in counts.most_common(30) if count >= 2]
        return terms[:20]

    # ------------------------------------------------------------------
    # Scoring and comparison helpers
    # ------------------------------------------------------------------
    def _score_page(
        self,
        *,
        word_count: int,
        prices: Sequence[str],
        ctas: Sequence[str],
        features: Sequence[str],
        trust_signals: Sequence[str],
        funnel_signals: Mapping[str, Sequence[str]],
        contact_signals: Mapping[str, Sequence[str]],
        headings: Sequence[str],
    ) -> Dict[str, float]:
        conversion_score = min(100.0, len(ctas) * 14 + (10 if prices else 0) + (8 if headings else 0))
        trust_score = min(100.0, len(trust_signals) * 12 + len(contact_signals.get("emails", [])) * 3 + len(contact_signals.get("phones", [])) * 3)
        feature_score = min(100.0, len(features) * 8)
        funnel_score = min(100.0, len(funnel_signals) * 22)
        content_depth_score = min(100.0, word_count / 12)
        pricing_score = min(100.0, len(prices) * 20)

        overall = round(
            conversion_score * 0.25
            + trust_score * 0.20
            + feature_score * 0.20
            + funnel_score * 0.15
            + content_depth_score * 0.10
            + pricing_score * 0.10,
            2,
        )

        return {
            "overall": overall,
            "conversion": round(conversion_score, 2),
            "trust": round(trust_score, 2),
            "features": round(feature_score, 2),
            "funnel": round(funnel_score, 2),
            "content_depth": round(content_depth_score, 2),
            "pricing_clarity": round(pricing_score, 2),
        }

    def _rank_competitors(self, competitors: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        ranked = sorted(
            competitors,
            key=lambda item: float((item.get("raw_score") or {}).get("overall", 0)),
            reverse=True,
        )
        return [
            {
                "rank": idx + 1,
                "domain": item.get("domain"),
                "url": item.get("url"),
                "overall_score": (item.get("raw_score") or {}).get("overall", 0),
                "strongest_signals": self._strongest_score_categories(item.get("raw_score") or {}),
            }
            for idx, item in enumerate(ranked)
        ]

    def _average_scores(self, competitors: Sequence[Mapping[str, Any]]) -> Dict[str, float]:
        score_keys = ["overall", "conversion", "trust", "features", "funnel", "content_depth", "pricing_clarity"]
        if not competitors:
            return {key: 0.0 for key in score_keys}

        totals = {key: 0.0 for key in score_keys}
        for item in competitors:
            raw = item.get("raw_score") or {}
            for key in score_keys:
                totals[key] += float(raw.get(key, 0.0))

        return {key: round(value / len(competitors), 2) for key, value in totals.items()}

    def _market_patterns(self, competitors: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        ctas = Counter()
        features = Counter()
        trust = Counter()
        funnel = defaultdict(int)
        prices_found = 0

        for item in competitors:
            ctas.update(item.get("ctas") or [])
            features.update(item.get("features") or [])
            trust.update(item.get("trust_signals") or [])
            if item.get("prices"):
                prices_found += 1
            for stage in (item.get("funnel_signals") or {}).keys():
                funnel[stage] += 1

        competitor_count = max(1, len(competitors))
        return {
            "common_ctas": [x for x, count in ctas.most_common(10) if count >= 1],
            "common_features": [x for x, count in features.most_common(15) if count >= 1],
            "common_trust_signals": [x for x, count in trust.most_common(12) if count >= 1],
            "common_funnel_stages": dict(sorted(funnel.items(), key=lambda pair: pair[1], reverse=True)),
            "pricing_visibility_rate": round(prices_found / competitor_count, 3),
        }

    def _find_market_gaps(
        self,
        target: Optional[Mapping[str, Any]],
        competitors: Sequence[Mapping[str, Any]],
        market_patterns: Mapping[str, Any],
    ) -> List[Dict[str, Any]]:
        gaps: List[Dict[str, Any]] = []
        all_common = {
            "ctas": market_patterns.get("common_ctas", []),
            "features": market_patterns.get("common_features", []),
            "trust_signals": market_patterns.get("common_trust_signals", []),
        }

        if target:
            for category, common_items in all_common.items():
                target_items = set(target.get(category) or [])
                missing = [item for item in common_items if item not in target_items]
                if missing:
                    gaps.append(
                        {
                            "type": "target_missing_market_pattern",
                            "category": category,
                            "items": missing[:10],
                            "impact": "Target page may look weaker than competitors in this area.",
                        }
                    )

            if market_patterns.get("pricing_visibility_rate", 0) >= 0.5 and not target.get("prices"):
                gaps.append(
                    {
                        "type": "target_missing_pricing",
                        "category": "pricing",
                        "items": ["pricing visibility"],
                        "impact": "Many competitors show pricing; target may create friction if pricing is hidden.",
                    }
                )

        # Market-wide opportunity gaps
        weak_trust_count = sum(1 for item in competitors if len(item.get("trust_signals") or []) <= 1)
        if weak_trust_count >= max(1, len(competitors) // 2):
            gaps.append(
                {
                    "type": "market_weakness",
                    "category": "trust",
                    "items": ["competitors show limited proof/trust content"],
                    "impact": "Strong reviews, case studies, certifications, and proof blocks can differentiate the target.",
                }
            )

        weak_cta_count = sum(1 for item in competitors if len(item.get("ctas") or []) <= 1)
        if weak_cta_count >= max(1, len(competitors) // 2):
            gaps.append(
                {
                    "type": "market_weakness",
                    "category": "conversion",
                    "items": ["competitors use weak or few CTAs"],
                    "impact": "A sharper CTA path can outperform generic competitor pages.",
                }
            )

        return gaps

    def _target_delta(
        self,
        target: Mapping[str, Any],
        averages: Mapping[str, float],
        market_patterns: Mapping[str, Any],
    ) -> Dict[str, Any]:
        target_scores = target.get("raw_score") or {}

        def missing(key: str, common_key: str) -> List[str]:
            target_items = set(target.get(key) or [])
            return [item for item in market_patterns.get(common_key, []) if item not in target_items]

        return {
            "score_delta_vs_average": {
                key: round(float(target_scores.get(key, 0)) - float(avg), 2)
                for key, avg in averages.items()
            },
            "missing_common_ctas": missing("ctas", "common_ctas"),
            "missing_common_features": missing("features", "common_features"),
            "missing_common_trust_signals": missing("trust_signals", "common_trust_signals"),
            "target_has_pricing": bool(target.get("prices")),
            "market_pricing_visibility_rate": market_patterns.get("pricing_visibility_rate", 0),
        }

    def _build_comparison_table(
        self,
        target: Optional[Mapping[str, Any]],
        competitors: Sequence[Mapping[str, Any]],
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []

        def row(label: str, item: Mapping[str, Any], is_target: bool) -> Dict[str, Any]:
            raw = item.get("raw_score") or {}
            return {
                "label": label,
                "is_target": is_target,
                "domain": item.get("domain"),
                "url": item.get("url"),
                "overall_score": raw.get("overall", 0),
                "cta_count": len(item.get("ctas") or []),
                "feature_count": len(item.get("features") or []),
                "trust_signal_count": len(item.get("trust_signals") or []),
                "pricing_visible": bool(item.get("prices")),
                "funnel_stages": list((item.get("funnel_signals") or {}).keys()),
                "word_count": item.get("word_count", 0),
            }

        if target:
            rows.append(row("Target", target, True))
        for idx, competitor in enumerate(competitors, start=1):
            rows.append(row(f"Competitor {idx}", competitor, False))
        return rows

    def _build_executive_summary(
        self,
        *,
        target_signals: Optional[Mapping[str, Any]],
        competitor_signals: Sequence[Mapping[str, Any]],
        comparison: Mapping[str, Any],
        recommendations: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        leaders = comparison.get("leaders") or []
        top_leader = leaders[0] if leaders else None
        high_priority = [item for item in recommendations if item.get("priority") == "high"]

        return {
            "competitors_analyzed": len(competitor_signals),
            "target_analyzed": target_signals is not None,
            "strongest_competitor": top_leader,
            "market_pricing_visibility_rate": (comparison.get("market_patterns") or {}).get("pricing_visibility_rate", 0),
            "high_priority_recommendation_count": len(high_priority),
            "top_recommendation": recommendations[0] if recommendations else None,
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _base_metadata(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "agent": self.agent_key,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "created_at": self._utc_now(),
        }

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _looks_like_url(self, value: str) -> bool:
        parsed = urllib.parse.urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _guess_title(self, html_content: str, text: str) -> str:
        if html_content:
            match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_content)
            if match:
                return self._clean_text(match.group(1))[:180]
        if text:
            first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
            return first_line[:180]
        return ""

    def _clean_text(self, value: str) -> str:
        value = html.unescape(value or "")
        value = re.sub(r"\s+", " ", value)
        return value.strip()

    def _content_hash(self, text: str) -> str:
        return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()

    def _unique_keep_order(self, items: Iterable[str]) -> List[str]:
        seen = set()
        result = []
        for item in items:
            cleaned = self._clean_text(str(item))
            key = cleaned.lower()
            if cleaned and key not in seen:
                seen.add(key)
                result.append(cleaned)
        return result

    def _strongest_score_categories(self, raw_score: Mapping[str, Any]) -> List[str]:
        ignored = {"overall"}
        sorted_items = sorted(
            [(key, float(value)) for key, value in raw_score.items() if key not in ignored],
            key=lambda pair: pair[1],
            reverse=True,
        )
        return [key for key, value in sorted_items[:3] if value > 0]

    def _redact_email(self, email_value: str) -> str:
        if "@" not in email_value:
            return "***"
        name, domain = email_value.split("@", 1)
        safe_name = (name[:2] + "***") if len(name) > 2 else "***"
        return f"{safe_name}@{domain}"

    def _redact_phone(self, phone_value: str) -> str:
        digits = re.sub(r"\D", "", phone_value)
        if len(digits) <= 4:
            return "***"
        return f"***{digits[-4:]}"


# ---------------------------------------------------------------------------
# Convenience factory for Agent Loader / Registry
# ---------------------------------------------------------------------------
def build_competitor_analyzer(**kwargs: Any) -> CompetitorAnalyzer:
    """
    Factory used by Agent Loader / Registry.

    Example:
        analyzer = build_competitor_analyzer()
        result = analyzer.analyze_competitors(...)
    """
    return CompetitorAnalyzer(**kwargs)


# ---------------------------------------------------------------------------
# Module metadata for registry/dashboard discovery
# ---------------------------------------------------------------------------
AGENT_MODULE_INFO: Dict[str, Any] = {
    "agent_module": "Browser Agent",
    "file": "competitor_analyzer.py",
    "class": "CompetitorAnalyzer",
    "agent_key": CompetitorAnalyzer.agent_key,
    "version": CompetitorAnalyzer.agent_version,
    "capabilities": [
        "compare_websites",
        "extract_pricing_signals",
        "extract_feature_signals",
        "extract_cta_signals",
        "extract_trust_signals",
        "analyze_funnel_gaps",
        "generate_competitor_recommendations",
    ],
    "requires_user_context": True,
    "requires_workspace_context": True,
    "safe_import": True,
}


"""
Agent/Module: Browser Agent
File Completed: competitor_analyzer.py
Completion: 57.9%
Completed Files: ['browser_agent.py', 'search_engine.py', 'scraper.py', 'page_analyzer.py', 'multi_tab_planner.py', 'automation.py', 'browser_session.py', 'tab_manager.py', 'content_extractor.py', 'seo_analyzer.py', 'competitor_analyzer.py']
Remaining Files: ['price_monitor.py', 'workflow_learner.py', 'form_handler.py', 'download_manager.py', 'screenshot_tool.py', 'browser_memory.py', 'permissions.py', 'config.py']
Next Recommended File: agents/browser_agent/price_monitor.py
FILE COMPLETE
"""
