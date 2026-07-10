"""
agents/browser_agent/page_analyzer.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Agent/Module: Browser Agent
File: page_analyzer.py
Required Class: PageAnalyzer

Purpose:
    Detects page type, offers, CTAs, trust signals, UX and conversion problems.

This file is designed to be:
    - Production-ready
    - Import-safe
    - SaaS multi-user/workspace compatible
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent
    - Safe for future FastAPI/dashboard integration
    - Structured-result friendly for JSON/API usage

Core responsibilities:
    1. Analyze webpage text / HTML / extracted content.
    2. Detect likely page type.
    3. Extract and score CTA signals.
    4. Detect offer/pricing/lead-generation signals.
    5. Detect trust signals.
    6. Identify UX and conversion issues.
    7. Prepare structured payloads for Security, Memory, Verification, Audit, and Dashboard systems.

Security note:
    This file does NOT perform live browser actions, scraping, form submission,
    financial actions, messaging, calling, destructive operations, or external requests.
    It only analyzes provided content safely.
"""

from __future__ import annotations

import html
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse


# ======================================================================================
# Safe optional BaseAgent import
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early file generation stage
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        This fallback allows page_analyzer.py to be imported before the real
        William/Jarvis BaseAgent exists. Once agents/base_agent.py is available,
        the real BaseAgent will be used automatically.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "browser_agent")
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() not implemented.",
                "data": {},
                "error": "BASE_AGENT_FALLBACK",
                "metadata": {},
            }


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger("PageAnalyzer")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Data structures
# ======================================================================================

@dataclass
class PageAnalyzerConfig:
    """
    Configuration for PageAnalyzer.

    These defaults are intentionally safe and conservative.
    """

    min_content_length: int = 25
    max_content_chars: int = 250_000
    max_findings_per_category: int = 50
    include_raw_matches: bool = False
    enable_html_cleanup: bool = True
    enable_conversion_score: bool = True
    enable_ux_score: bool = True
    enable_trust_score: bool = True
    enable_offer_score: bool = True
    strict_context_validation: bool = True


@dataclass
class PageContext:
    """
    SaaS-safe task context.

    user_id and workspace_id are required whenever the analysis belongs
    to a user/workspace execution.
    """

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectedSignal:
    """
    Represents one detected page signal.
    """

    label: str
    value: Any
    confidence: float = 0.0
    category: str = "general"
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PageAnalysisInput:
    """
    Normalized analysis input.

    PageAnalyzer accepts dicts, strings, or this dataclass.
    """

    url: Optional[str] = None
    title: Optional[str] = None
    html_content: Optional[str] = None
    text_content: Optional[str] = None
    headings: List[str] = field(default_factory=list)
    links: List[Dict[str, Any]] = field(default_factory=list)
    buttons: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    images: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ======================================================================================
# PageAnalyzer
# ======================================================================================

class PageAnalyzer(BaseAgent):
    """
    Browser Agent page analysis helper.

    Connects to William/Jarvis architecture:
        - Master Agent:
            Can route webpage analysis tasks here.
        - Browser Agent:
            Uses this file after page content is collected by scraper/content extractor.
        - Security Agent:
            Sensitive action hooks are provided, although this file only analyzes content.
        - Memory Agent:
            Useful page insights can be converted into memory payloads.
        - Verification Agent:
            Completed analysis generates verification payloads.
        - Dashboard/API:
            All outputs are structured dicts with stable keys.
        - Registry/Loader:
            Class is import-safe and exposes clear public methods.
    """

    AGENT_NAME = "PageAnalyzer"
    AGENT_TYPE = "browser_agent"
    VERSION = "1.0.0"

    PAGE_TYPE_KEYWORDS: Dict[str, Sequence[str]] = {
        "landing_page": (
            "get started",
            "start free",
            "book a demo",
            "request a quote",
            "free consultation",
            "limited time",
            "claim offer",
            "schedule a call",
            "hero",
            "benefits",
            "features",
        ),
        "homepage": (
            "welcome",
            "home",
            "our services",
            "who we are",
            "about us",
            "trusted by",
            "solutions",
            "explore",
        ),
        "pricing_page": (
            "pricing",
            "plans",
            "starter",
            "pro",
            "enterprise",
            "per month",
            "monthly",
            "annually",
            "billing",
            "subscribe",
        ),
        "product_page": (
            "product",
            "add to cart",
            "buy now",
            "specifications",
            "shipping",
            "reviews",
            "sku",
            "in stock",
        ),
        "service_page": (
            "services",
            "service",
            "solutions",
            "what we offer",
            "consulting",
            "management",
            "development",
            "implementation",
        ),
        "blog_article": (
            "blog",
            "article",
            "posted on",
            "author",
            "read more",
            "table of contents",
            "related posts",
            "comments",
        ),
        "contact_page": (
            "contact",
            "contact us",
            "email",
            "phone",
            "address",
            "send message",
            "location",
            "map",
        ),
        "about_page": (
            "about us",
            "our story",
            "mission",
            "vision",
            "team",
            "company",
            "values",
        ),
        "checkout_page": (
            "checkout",
            "payment",
            "billing address",
            "shipping address",
            "place order",
            "cart",
            "coupon",
        ),
        "lead_capture_page": (
            "download now",
            "free guide",
            "ebook",
            "webinar",
            "join now",
            "enter your email",
            "lead magnet",
            "subscribe",
        ),
    }

    CTA_KEYWORDS: Sequence[str] = (
        "get started",
        "start now",
        "start free",
        "try free",
        "book a demo",
        "schedule a call",
        "request a quote",
        "contact us",
        "call now",
        "buy now",
        "add to cart",
        "subscribe",
        "sign up",
        "join now",
        "download now",
        "learn more",
        "read more",
        "claim offer",
        "get quote",
        "free consultation",
        "talk to sales",
        "get protected",
        "protect my ads",
        "see pricing",
        "create account",
    )

    OFFER_KEYWORDS: Sequence[str] = (
        "free",
        "discount",
        "offer",
        "deal",
        "limited time",
        "save",
        "bonus",
        "trial",
        "guarantee",
        "money back",
        "no credit card",
        "cancel anytime",
        "exclusive",
        "special",
        "bundle",
        "promotion",
        "coupon",
        "starting at",
        "from $",
        "per month",
        "monthly",
        "annually",
    )

    TRUST_KEYWORDS: Sequence[str] = (
        "trusted by",
        "reviews",
        "testimonials",
        "case studies",
        "certified",
        "secure",
        "ssl",
        "privacy",
        "guarantee",
        "money back",
        "award",
        "featured in",
        "clients",
        "partners",
        "verified",
        "licensed",
        "insured",
        "years of experience",
        "rating",
        "stars",
        "gdpr",
        "hipaa",
        "iso",
        "soc 2",
    )

    UX_PROBLEM_PATTERNS: Dict[str, Sequence[str]] = {
        "weak_cta": (
            "submit",
            "click here",
            "more",
        ),
        "friction_words": (
            "required",
            "mandatory",
            "long form",
            "create account first",
            "sign in required",
        ),
        "confusing_copy": (
            "lorem ipsum",
            "coming soon",
            "under construction",
            "sample text",
            "placeholder",
        ),
        "risk_or_objection": (
            "non-refundable",
            "no refunds",
            "cancelation fee",
            "hidden fee",
            "processing fee",
        ),
    }

    CONVERSION_PROBLEM_RULES: Sequence[Tuple[str, str]] = (
        ("missing_primary_cta", "No strong primary CTA was detected."),
        ("low_trust_signals", "Few trust signals were found."),
        ("unclear_offer", "Offer/value proposition appears weak or unclear."),
        ("form_friction", "Forms may create friction or ask for too much information."),
        ("weak_above_fold_message", "Hero/above-fold message may not clearly communicate value."),
        ("no_urgency_or_reason_to_act", "No urgency, incentive, or strong reason to act was detected."),
    )

    STRONG_CTA_WORDS: Sequence[str] = (
        "free",
        "now",
        "demo",
        "quote",
        "call",
        "start",
        "buy",
        "protect",
        "schedule",
        "trial",
    )

    def __init__(
        self,
        config: Optional[Union[PageAnalyzerConfig, Dict[str, Any]]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            agent_type=self.AGENT_TYPE,
            *args,
            **kwargs,
        )

        if isinstance(config, PageAnalyzerConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = PageAnalyzerConfig(**{
                key: value
                for key, value in config.items()
                if key in PageAnalyzerConfig.__dataclass_fields__
            })
        else:
            self.config = PageAnalyzerConfig()

        self.logger = logging.getLogger(self.AGENT_NAME)

    # ==================================================================================
    # Public API
    # ==================================================================================

    def analyze(
        self,
        page: Union[str, Dict[str, Any], PageAnalysisInput],
        context: Optional[Union[PageContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Main public analysis method.

        Args:
            page:
                Can be:
                    - raw text/html string
                    - dict containing url/title/html_content/text_content/etc.
                    - PageAnalysisInput object

            context:
                SaaS-safe context containing user_id/workspace_id/task_id/etc.

        Returns:
            Structured result:
                {
                    "success": bool,
                    "message": str,
                    "data": {...},
                    "error": Optional[str],
                    "metadata": {...}
                }
        """

        started_at = time.time()
        normalized_context = self._normalize_context(context)

        context_check = self._validate_task_context(normalized_context)
        if not context_check["success"]:
            return context_check

        if self._requires_security_check("analyze_page", normalized_context):
            approval = self._request_security_approval(
                action="analyze_page",
                context=normalized_context,
                payload={"operation": "content_analysis_only"},
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for page analysis.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "approval": approval,
                        "context": self._safe_context_metadata(normalized_context),
                    },
                )

        try:
            normalized_page = self._normalize_page_input(page)
            validation_error = self._validate_page_input(normalized_page)
            if validation_error:
                return self._error_result(
                    message="Invalid page input.",
                    error=validation_error,
                    metadata={"context": self._safe_context_metadata(normalized_context)},
                )

            combined_text = self._build_combined_text(normalized_page)
            cleaned_text = self._clean_text(combined_text)
            lower_text = cleaned_text.lower()

            page_type_result = self.detect_page_type(normalized_page, cleaned_text)
            cta_result = self.detect_ctas(normalized_page, cleaned_text)
            offer_result = self.detect_offers(normalized_page, cleaned_text)
            trust_result = self.detect_trust_signals(normalized_page, cleaned_text)
            ux_result = self.detect_ux_issues(normalized_page, cleaned_text)
            conversion_result = self.detect_conversion_problems(
                page=normalized_page,
                text=cleaned_text,
                page_type_result=page_type_result,
                cta_result=cta_result,
                offer_result=offer_result,
                trust_result=trust_result,
                ux_result=ux_result,
            )

            scores = self.calculate_scores(
                page_type_result=page_type_result,
                cta_result=cta_result,
                offer_result=offer_result,
                trust_result=trust_result,
                ux_result=ux_result,
                conversion_result=conversion_result,
                text=cleaned_text,
            )

            recommendations = self.generate_recommendations(
                page_type=page_type_result,
                ctas=cta_result,
                offers=offer_result,
                trust=trust_result,
                ux=ux_result,
                conversion=conversion_result,
                scores=scores,
            )

            analysis_id = str(uuid.uuid4())
            finished_at = time.time()

            data = {
                "analysis_id": analysis_id,
                "url": normalized_page.url,
                "domain": self._extract_domain(normalized_page.url),
                "title": normalized_page.title,
                "page_type": page_type_result,
                "ctas": cta_result,
                "offers": offer_result,
                "trust_signals": trust_result,
                "ux_issues": ux_result,
                "conversion_problems": conversion_result,
                "scores": scores,
                "recommendations": recommendations,
                "content_summary": {
                    "character_count": len(cleaned_text),
                    "word_count": self._word_count(cleaned_text),
                    "heading_count": len(normalized_page.headings),
                    "link_count": len(normalized_page.links),
                    "button_count": len(normalized_page.buttons),
                    "form_count": len(normalized_page.forms),
                    "image_count": len(normalized_page.images),
                    "has_html": bool(normalized_page.html_content),
                    "has_text": bool(normalized_page.text_content),
                },
                "verification_payload": self._prepare_verification_payload(
                    action="analyze_page",
                    success=True,
                    context=normalized_context,
                    data_preview={
                        "analysis_id": analysis_id,
                        "page_type": page_type_result.get("primary_type"),
                        "conversion_score": scores.get("conversion_score"),
                    },
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=normalized_context,
                    normalized_page=normalized_page,
                    analysis_summary={
                        "analysis_id": analysis_id,
                        "page_type": page_type_result.get("primary_type"),
                        "top_recommendations": recommendations[:5],
                        "scores": scores,
                    },
                ),
            }

            metadata = {
                "agent": self.AGENT_NAME,
                "agent_type": self.AGENT_TYPE,
                "version": self.VERSION,
                "duration_ms": round((finished_at - started_at) * 1000, 2),
                "timestamp": self._utc_now(),
                "context": self._safe_context_metadata(normalized_context),
            }

            self._emit_agent_event(
                event_name="page_analysis_completed",
                context=normalized_context,
                payload={
                    "analysis_id": analysis_id,
                    "url": normalized_page.url,
                    "page_type": page_type_result.get("primary_type"),
                    "scores": scores,
                },
            )

            self._log_audit_event(
                action="analyze_page",
                context=normalized_context,
                payload={
                    "analysis_id": analysis_id,
                    "url": normalized_page.url,
                    "domain": self._extract_domain(normalized_page.url),
                    "success": True,
                },
            )

            return self._safe_result(
                success=True,
                message="Page analysis completed successfully.",
                data=data,
                error=None,
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("Page analysis failed: %s", exc)

            self._log_audit_event(
                action="analyze_page",
                context=normalized_context,
                payload={
                    "success": False,
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="Page analysis failed.",
                error=str(exc),
                metadata={
                    "agent": self.AGENT_NAME,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                    "context": self._safe_context_metadata(normalized_context),
                },
            )

    def run(
        self,
        page: Union[str, Dict[str, Any], PageAnalysisInput],
        context: Optional[Union[PageContext, Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        BaseAgent-compatible run method.

        Master Agent / Router can call this method directly.
        """

        if kwargs:
            if isinstance(page, dict):
                merged_page = dict(page)
                merged_page.update(kwargs.get("page_overrides", {}))
                page = merged_page

            if context is None and "context" in kwargs:
                context = kwargs["context"]

        return self.analyze(page=page, context=context)

    def detect_page_type(
        self,
        page: PageAnalysisInput,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect likely page type based on URL, title, headings, buttons, and content.
        """

        combined = text if text is not None else self._build_combined_text(page)
        combined_lower = combined.lower()

        url_path = ""
        if page.url:
            parsed = urlparse(page.url)
            url_path = f"{parsed.path} {parsed.query}".lower()

        title_lower = (page.title or "").lower()
        headings_lower = " ".join(page.headings).lower()
        button_text = " ".join(page.buttons).lower()

        weighted_source = " ".join([
            combined_lower,
            title_lower * 3,
            headings_lower * 3,
            button_text * 2,
            url_path * 4,
        ])

        scores: Dict[str, float] = {}
        evidence: Dict[str, List[str]] = {}

        for page_type, keywords in self.PAGE_TYPE_KEYWORDS.items():
            score = 0.0
            found: List[str] = []

            for keyword in keywords:
                keyword_lower = keyword.lower()
                count = weighted_source.count(keyword_lower)
                if count > 0:
                    score += min(count, 5) * self._keyword_weight(keyword_lower)
                    found.append(keyword)

            if page_type in url_path:
                score += 5.0
                found.append(f"url_contains:{page_type}")

            scores[page_type] = round(score, 3)
            evidence[page_type] = found[: self.config.max_findings_per_category]

        sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        primary_type = sorted_scores[0][0] if sorted_scores and sorted_scores[0][1] > 0 else "unknown"
        primary_score = sorted_scores[0][1] if sorted_scores else 0.0
        total_score = sum(scores.values()) or 1.0
        confidence = round(min(primary_score / total_score + min(primary_score / 20.0, 0.35), 0.99), 3)

        alternatives = [
            {"page_type": key, "score": value, "evidence": evidence.get(key, [])}
            for key, value in sorted_scores[1:5]
            if value > 0
        ]

        return {
            "primary_type": primary_type,
            "confidence": confidence if primary_type != "unknown" else 0.0,
            "scores": scores,
            "evidence": evidence.get(primary_type, []),
            "alternatives": alternatives,
        }

    def detect_ctas(
        self,
        page: PageAnalysisInput,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect call-to-action signals.
        """

        combined = text if text is not None else self._build_combined_text(page)
        combined_lower = combined.lower()

        candidates: List[DetectedSignal] = []

        for button in page.buttons:
            normalized_button = self._normalize_space(button)
            if not normalized_button:
                continue

            confidence = self._score_cta_text(normalized_button)
            category = "strong_cta" if confidence >= 0.65 else "weak_cta"

            candidates.append(
                DetectedSignal(
                    label=normalized_button,
                    value=normalized_button,
                    confidence=confidence,
                    category=category,
                    evidence=["button_text"],
                    metadata={"source": "buttons"},
                )
            )

        for link in page.links:
            link_text = self._normalize_space(str(link.get("text", "") or ""))
            href = str(link.get("href", "") or "")

            if not link_text:
                continue

            confidence = self._score_cta_text(link_text)
            if confidence >= 0.35:
                candidates.append(
                    DetectedSignal(
                        label=link_text,
                        value={"text": link_text, "href": href},
                        confidence=confidence,
                        category="link_cta" if confidence >= 0.55 else "soft_cta",
                        evidence=["link_text"],
                        metadata={"source": "links"},
                    )
                )

        for keyword in self.CTA_KEYWORDS:
            count = combined_lower.count(keyword)
            if count > 0:
                candidates.append(
                    DetectedSignal(
                        label=keyword,
                        value={"keyword": keyword, "count": count},
                        confidence=min(0.45 + (count * 0.08), 0.88),
                        category="content_cta",
                        evidence=self._extract_evidence_snippets(combined, keyword),
                        metadata={"source": "content"},
                    )
                )

        deduped = self._dedupe_signals(candidates)
        deduped = sorted(deduped, key=lambda item: item.confidence, reverse=True)
        limited = deduped[: self.config.max_findings_per_category]

        strong_count = len([item for item in limited if item.confidence >= 0.65])
        weak_count = len([item for item in limited if item.confidence < 0.5])

        primary_cta = asdict(limited[0]) if limited else None

        return {
            "found": bool(limited),
            "primary_cta": primary_cta,
            "total_count": len(limited),
            "strong_count": strong_count,
            "weak_count": weak_count,
            "items": [asdict(item) for item in limited],
            "summary": self._summarize_ctas(limited),
        }

    def detect_offers(
        self,
        page: PageAnalysisInput,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect offers, discounts, guarantees, trials, pricing, and value proposition signals.
        """

        combined = text if text is not None else self._build_combined_text(page)
        combined_lower = combined.lower()

        offers: List[DetectedSignal] = []

        price_matches = self._find_price_patterns(combined)
        for match in price_matches:
            offers.append(
                DetectedSignal(
                    label="price_signal",
                    value=match,
                    confidence=0.72,
                    category="pricing",
                    evidence=[match],
                    metadata={"source": "regex_price"},
                )
            )

        for keyword in self.OFFER_KEYWORDS:
            count = combined_lower.count(keyword)
            if count > 0:
                offers.append(
                    DetectedSignal(
                        label=keyword,
                        value={"keyword": keyword, "count": count},
                        confidence=min(0.45 + count * 0.07, 0.9),
                        category=self._classify_offer_keyword(keyword),
                        evidence=self._extract_evidence_snippets(combined, keyword),
                        metadata={"source": "content"},
                    )
                )

        headline_offer_signals = self._detect_headline_offer_signals(page.headings)
        offers.extend(headline_offer_signals)

        deduped = self._dedupe_signals(offers)
        deduped = sorted(deduped, key=lambda item: item.confidence, reverse=True)
        limited = deduped[: self.config.max_findings_per_category]

        return {
            "found": bool(limited),
            "total_count": len(limited),
            "items": [asdict(item) for item in limited],
            "has_price": any(item.category == "pricing" for item in limited),
            "has_free_offer": any("free" in item.label.lower() for item in limited),
            "has_guarantee": any("guarantee" in item.label.lower() for item in limited),
            "has_urgency": any(
                item.label.lower() in {"limited time", "exclusive", "special", "promotion"}
                for item in limited
            ),
            "summary": self._summarize_offers(limited),
        }

    def detect_trust_signals(
        self,
        page: PageAnalysisInput,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect trust-building elements.
        """

        combined = text if text is not None else self._build_combined_text(page)
        combined_lower = combined.lower()

        trust_signals: List[DetectedSignal] = []

        for keyword in self.TRUST_KEYWORDS:
            count = combined_lower.count(keyword)
            if count > 0:
                trust_signals.append(
                    DetectedSignal(
                        label=keyword,
                        value={"keyword": keyword, "count": count},
                        confidence=min(0.45 + count * 0.08, 0.92),
                        category=self._classify_trust_keyword(keyword),
                        evidence=self._extract_evidence_snippets(combined, keyword),
                        metadata={"source": "content"},
                    )
                )

        if self._has_contact_information(combined):
            trust_signals.append(
                DetectedSignal(
                    label="contact_information",
                    value=True,
                    confidence=0.8,
                    category="contact_trust",
                    evidence=["Detected email, phone, or contact details."],
                    metadata={"source": "regex"},
                )
            )

        if self._has_policy_links(page):
            trust_signals.append(
                DetectedSignal(
                    label="policy_links",
                    value=True,
                    confidence=0.72,
                    category="policy_trust",
                    evidence=["Detected privacy/terms/refund/security policy links."],
                    metadata={"source": "links"},
                )
            )

        if self._has_social_proof_numbers(combined):
            trust_signals.append(
                DetectedSignal(
                    label="social_proof_numbers",
                    value=True,
                    confidence=0.7,
                    category="social_proof",
                    evidence=["Detected numeric proof such as clients, reviews, users, or ratings."],
                    metadata={"source": "regex"},
                )
            )

        deduped = self._dedupe_signals(trust_signals)
        deduped = sorted(deduped, key=lambda item: item.confidence, reverse=True)
        limited = deduped[: self.config.max_findings_per_category]

        return {
            "found": bool(limited),
            "total_count": len(limited),
            "items": [asdict(item) for item in limited],
            "has_testimonials": any(item.category == "testimonials" for item in limited),
            "has_security_trust": any(item.category == "security" for item in limited),
            "has_contact_trust": any(item.category == "contact_trust" for item in limited),
            "has_policy_trust": any(item.category == "policy_trust" for item in limited),
            "summary": self._summarize_trust(limited),
        }

    def detect_ux_issues(
        self,
        page: PageAnalysisInput,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect UX issues from available page content.
        """

        combined = text if text is not None else self._build_combined_text(page)
        combined_lower = combined.lower()

        issues: List[DetectedSignal] = []

        if len(combined) < 300:
            issues.append(
                DetectedSignal(
                    label="thin_content",
                    value=True,
                    confidence=0.78,
                    category="content_depth",
                    evidence=["Page content appears very short."],
                )
            )

        if not page.headings:
            issues.append(
                DetectedSignal(
                    label="missing_headings",
                    value=True,
                    confidence=0.7,
                    category="structure",
                    evidence=["No headings were provided or detected."],
                )
            )

        if len(page.forms) > 0:
            form_issue_signals = self._analyze_form_friction(page.forms)
            issues.extend(form_issue_signals)

        if len(page.links) > 80:
            issues.append(
                DetectedSignal(
                    label="too_many_links",
                    value=len(page.links),
                    confidence=0.62,
                    category="navigation_clutter",
                    evidence=[f"Detected {len(page.links)} links."],
                )
            )

        if page.images:
            images_without_alt = [
                img for img in page.images
                if not str(img.get("alt", "") or "").strip()
            ]
            if len(images_without_alt) > max(3, len(page.images) * 0.4):
                issues.append(
                    DetectedSignal(
                        label="many_images_missing_alt",
                        value=len(images_without_alt),
                        confidence=0.68,
                        category="accessibility",
                        evidence=[f"{len(images_without_alt)} images appear to be missing alt text."],
                    )
                )

        for category, patterns in self.UX_PROBLEM_PATTERNS.items():
            for pattern in patterns:
                count = combined_lower.count(pattern.lower())
                if count > 0:
                    issues.append(
                        DetectedSignal(
                            label=pattern,
                            value={"keyword": pattern, "count": count},
                            confidence=min(0.4 + count * 0.08, 0.82),
                            category=category,
                            evidence=self._extract_evidence_snippets(combined, pattern),
                            metadata={"source": "content"},
                        )
                    )

        if self._looks_like_placeholder_page(combined):
            issues.append(
                DetectedSignal(
                    label="placeholder_or_unfinished_content",
                    value=True,
                    confidence=0.9,
                    category="content_quality",
                    evidence=["Detected placeholder or unfinished page copy."],
                )
            )

        deduped = self._dedupe_signals(issues)
        deduped = sorted(deduped, key=lambda item: item.confidence, reverse=True)
        limited = deduped[: self.config.max_findings_per_category]

        severity = self._estimate_ux_severity(limited)

        return {
            "found": bool(limited),
            "total_count": len(limited),
            "severity": severity,
            "items": [asdict(item) for item in limited],
            "summary": self._summarize_ux(limited, severity),
        }

    def detect_conversion_problems(
        self,
        page: PageAnalysisInput,
        text: str,
        page_type_result: Dict[str, Any],
        cta_result: Dict[str, Any],
        offer_result: Dict[str, Any],
        trust_result: Dict[str, Any],
        ux_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Detect conversion problems using combined analysis outputs.
        """

        problems: List[DetectedSignal] = []

        if not cta_result.get("found"):
            problems.append(
                DetectedSignal(
                    label="missing_primary_cta",
                    value=True,
                    confidence=0.88,
                    category="cta",
                    evidence=["No CTA was detected."],
                )
            )
        elif int(cta_result.get("strong_count", 0)) == 0:
            problems.append(
                DetectedSignal(
                    label="weak_primary_cta",
                    value=True,
                    confidence=0.72,
                    category="cta",
                    evidence=["CTA exists but no strong CTA was detected."],
                )
            )

        if int(trust_result.get("total_count", 0)) < 2:
            problems.append(
                DetectedSignal(
                    label="low_trust_signals",
                    value=True,
                    confidence=0.76,
                    category="trust",
                    evidence=["Less than two trust signals detected."],
                )
            )

        if not offer_result.get("found"):
            problems.append(
                DetectedSignal(
                    label="unclear_offer",
                    value=True,
                    confidence=0.74,
                    category="offer",
                    evidence=["No clear offer, discount, pricing, or value incentive detected."],
                )
            )

        if len(page.forms) > 0:
            total_fields = self._count_form_fields(page.forms)
            if total_fields >= 7:
                problems.append(
                    DetectedSignal(
                        label="form_friction",
                        value={"field_count": total_fields},
                        confidence=0.78,
                        category="forms",
                        evidence=[f"Detected approximately {total_fields} form fields."],
                    )
                )

        hero_text = self._estimate_hero_text(page, text)
        if hero_text and not self._hero_has_clear_value(hero_text):
            problems.append(
                DetectedSignal(
                    label="weak_above_fold_message",
                    value=True,
                    confidence=0.68,
                    category="messaging",
                    evidence=[hero_text[:220]],
                )
            )

        if not offer_result.get("has_urgency") and not offer_result.get("has_free_offer"):
            problems.append(
                DetectedSignal(
                    label="no_urgency_or_reason_to_act",
                    value=True,
                    confidence=0.57,
                    category="offer",
                    evidence=["No urgency or strong incentive signal detected."],
                )
            )

        if ux_result.get("severity") in {"high", "critical"}:
            problems.append(
                DetectedSignal(
                    label="ux_blockers",
                    value=ux_result.get("severity"),
                    confidence=0.72,
                    category="ux",
                    evidence=["UX issue severity is high."],
                )
            )

        page_type = page_type_result.get("primary_type")
        if page_type in {"pricing_page", "product_page", "landing_page"} and not trust_result.get("has_policy_trust"):
            problems.append(
                DetectedSignal(
                    label="missing_risk_reversal_or_policy_links",
                    value=True,
                    confidence=0.62,
                    category="trust",
                    evidence=["Commercial page lacks visible policy/security/risk-reversal signals."],
                )
            )

        deduped = self._dedupe_signals(problems)
        deduped = sorted(deduped, key=lambda item: item.confidence, reverse=True)
        limited = deduped[: self.config.max_findings_per_category]

        return {
            "found": bool(limited),
            "total_count": len(limited),
            "items": [asdict(item) for item in limited],
            "summary": self._summarize_conversion(limited),
        }

    def calculate_scores(
        self,
        page_type_result: Dict[str, Any],
        cta_result: Dict[str, Any],
        offer_result: Dict[str, Any],
        trust_result: Dict[str, Any],
        ux_result: Dict[str, Any],
        conversion_result: Dict[str, Any],
        text: str,
    ) -> Dict[str, Any]:
        """
        Calculate simple dashboard-friendly scores.

        Scores are heuristic, transparent, and safe for future replacement
        with ML/rules engine scoring.
        """

        cta_score = 0
        if cta_result.get("found"):
            cta_score += 35
            cta_score += min(int(cta_result.get("strong_count", 0)) * 15, 45)
            cta_score -= min(int(cta_result.get("weak_count", 0)) * 3, 15)
        cta_score = self._clamp_score(cta_score)

        trust_score = min(int(trust_result.get("total_count", 0)) * 15, 90)
        if trust_result.get("has_contact_trust"):
            trust_score += 5
        if trust_result.get("has_policy_trust"):
            trust_score += 5
        trust_score = self._clamp_score(trust_score)

        offer_score = 0
        if offer_result.get("found"):
            offer_score += 35
        if offer_result.get("has_price"):
            offer_score += 15
        if offer_result.get("has_free_offer"):
            offer_score += 15
        if offer_result.get("has_guarantee"):
            offer_score += 15
        if offer_result.get("has_urgency"):
            offer_score += 10
        offer_score = self._clamp_score(offer_score)

        ux_score = 100
        ux_severity = ux_result.get("severity")
        issue_count = int(ux_result.get("total_count", 0))
        ux_score -= min(issue_count * 8, 50)
        if ux_severity == "medium":
            ux_score -= 10
        elif ux_severity == "high":
            ux_score -= 25
        elif ux_severity == "critical":
            ux_score -= 40
        ux_score = self._clamp_score(ux_score)

        conversion_score = int(
            (cta_score * 0.30)
            + (trust_score * 0.22)
            + (offer_score * 0.23)
            + (ux_score * 0.25)
        )

        conversion_problem_count = int(conversion_result.get("total_count", 0))
        conversion_score -= min(conversion_problem_count * 5, 25)
        conversion_score = self._clamp_score(conversion_score)

        content_quality_score = self._calculate_content_quality_score(text)

        return {
            "conversion_score": conversion_score,
            "cta_score": cta_score,
            "trust_score": trust_score,
            "offer_score": offer_score,
            "ux_score": ux_score,
            "content_quality_score": content_quality_score,
            "page_type_confidence": page_type_result.get("confidence", 0.0),
            "grade": self._score_to_grade(conversion_score),
            "risk_level": self._score_to_risk_level(conversion_score),
        }

    def generate_recommendations(
        self,
        page_type: Dict[str, Any],
        ctas: Dict[str, Any],
        offers: Dict[str, Any],
        trust: Dict[str, Any],
        ux: Dict[str, Any],
        conversion: Dict[str, Any],
        scores: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Generate practical CRO recommendations.
        """

        recommendations: List[Dict[str, Any]] = []

        if not ctas.get("found"):
            recommendations.append({
                "priority": "high",
                "category": "cta",
                "title": "Add a clear primary CTA above the fold",
                "detail": "Use a direct CTA such as 'Get Free Quote', 'Book a Demo', or 'Start Free Trial'.",
                "expected_impact": "higher lead generation and clearer user action",
            })
        elif int(ctas.get("strong_count", 0)) == 0:
            recommendations.append({
                "priority": "high",
                "category": "cta",
                "title": "Strengthen your CTA wording",
                "detail": "Replace weak CTAs like 'Submit' or 'Learn More' with action-driven copy tied to value.",
                "expected_impact": "improved click-through and intent clarity",
            })

        if not offers.get("found"):
            recommendations.append({
                "priority": "high",
                "category": "offer",
                "title": "Clarify the offer",
                "detail": "Add a strong value proposition, guarantee, free consultation, trial, discount, or clear pricing anchor.",
                "expected_impact": "stronger motivation to act",
            })

        if int(trust.get("total_count", 0)) < 2:
            recommendations.append({
                "priority": "high",
                "category": "trust",
                "title": "Add more trust signals",
                "detail": "Include testimonials, ratings, client logos, certifications, policies, security badges, or case studies.",
                "expected_impact": "lower buyer hesitation",
            })

        if ux.get("severity") in {"high", "critical"}:
            recommendations.append({
                "priority": "high",
                "category": "ux",
                "title": "Fix UX blockers",
                "detail": "Reduce clutter, improve headings, simplify forms, and remove confusing placeholder copy.",
                "expected_impact": "better engagement and conversion rate",
            })

        if scores.get("content_quality_score", 0) < 55:
            recommendations.append({
                "priority": "medium",
                "category": "copy",
                "title": "Improve page copy depth and clarity",
                "detail": "Add benefit-focused sections, objections handling, FAQs, and proof points.",
                "expected_impact": "stronger SEO, trust, and conversion clarity",
            })

        if not trust.get("has_contact_trust"):
            recommendations.append({
                "priority": "medium",
                "category": "trust",
                "title": "Make contact information visible",
                "detail": "Show phone, email, contact form, or support channel clearly.",
                "expected_impact": "increased credibility",
            })

        if not trust.get("has_policy_trust") and page_type.get("primary_type") in {
            "pricing_page",
            "product_page",
            "checkout_page",
            "landing_page",
        }:
            recommendations.append({
                "priority": "medium",
                "category": "risk_reversal",
                "title": "Add policy and risk-reversal links",
                "detail": "Add privacy policy, refund policy, terms, security, guarantee, or cancellation details.",
                "expected_impact": "reduced purchase anxiety",
            })

        if not offers.get("has_urgency") and page_type.get("primary_type") in {
            "landing_page",
            "pricing_page",
            "lead_capture_page",
        }:
            recommendations.append({
                "priority": "low",
                "category": "offer",
                "title": "Add a reason to act now",
                "detail": "Use ethical urgency such as limited bonus, limited consultation slots, or time-sensitive onboarding.",
                "expected_impact": "higher action rate",
            })

        problem_items = conversion.get("items", [])
        for problem in problem_items[:5]:
            label = problem.get("label")
            if label == "form_friction":
                recommendations.append({
                    "priority": "medium",
                    "category": "forms",
                    "title": "Reduce form friction",
                    "detail": "Ask only for essential fields first. Move optional details to a second step.",
                    "expected_impact": "higher form completion rate",
                })

        return self._dedupe_recommendations(recommendations)

    # ==================================================================================
    # Compatibility hooks
    # ==================================================================================

    def _validate_task_context(self, context: PageContext) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Rule:
            Every task must support user_id and workspace_id where user-specific
            execution is involved.
        """

        if not self.config.strict_context_validation:
            return self._safe_result(
                success=True,
                message="Context validation skipped by config.",
                data={"valid": True},
                error=None,
                metadata={},
            )

        missing: List[str] = []

        if context.user_id in (None, ""):
            missing.append("user_id")

        if context.workspace_id in (None, ""):
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message=f"Missing required SaaS context: {', '.join(missing)}.",
                error="INVALID_TASK_CONTEXT",
                metadata={
                    "missing": missing,
                    "agent": self.AGENT_NAME,
                },
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "valid": True,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            error=None,
            metadata={},
        )

    def _requires_security_check(self, action: str, context: PageContext) -> bool:
        """
        Decide whether Security Agent approval is required.

        Current file only performs passive content analysis.
        No real browser, financial, message, call, or destructive action is executed.

        Hook remains available so MasterAgent/SecurityAgent can enforce policy later.
        """

        sensitive_actions = {
            "submit_form",
            "click_button",
            "make_purchase",
            "send_message",
            "place_call",
            "download_file",
            "upload_file",
            "delete_data",
            "modify_page",
            "external_browser_action",
        }

        if action in sensitive_actions:
            return True

        permissions = context.permissions or {}
        if permissions.get("force_security_check") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: PageContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        This fallback does not call external systems. It returns approval for passive
        content analysis only.
        """

        passive_allowed_actions = {"analyze_page", "detect_ctas", "detect_offers", "detect_trust_signals"}

        approved = action in passive_allowed_actions

        return {
            "approved": approved,
            "action": action,
            "reason": (
                "Passive analysis action approved by local fallback policy."
                if approved
                else "Action requires real Security Agent approval."
            ),
            "context": self._safe_context_metadata(context),
            "payload_preview": self._safe_payload_preview(payload or {}),
            "timestamp": self._utc_now(),
        }

    def _prepare_verification_payload(
        self,
        action: str,
        success: bool,
        context: PageContext,
        data_preview: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload compatible with Verification Agent.

        Verification Agent can later validate:
            - action
            - result integrity
            - expected output shape
            - task ownership
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "action": action,
            "success": success,
            "data_preview": data_preview or {},
            "context": self._safe_context_metadata(context),
            "checks": {
                "structured_result": True,
                "user_workspace_isolated": bool(context.user_id and context.workspace_id),
                "no_external_action_executed": True,
                "safe_for_dashboard": True,
            },
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        context: PageContext,
        normalized_page: PageAnalysisInput,
        analysis_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare useful context for Memory Agent.

        This does not store memory directly.
        It only prepares a payload that Memory Agent may choose to persist.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "type": "page_analysis_summary",
            "scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "source": {
                "url": normalized_page.url,
                "domain": self._extract_domain(normalized_page.url),
                "title": normalized_page.title,
            },
            "summary": analysis_summary,
            "safe_to_store": True,
            "contains_secrets": False,
            "timestamp": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: PageContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit agent event hook.

        In the final system, this can connect to:
            - event bus
            - dashboard websocket
            - analytics stream
            - task history
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "context": self._safe_context_metadata(context),
            "payload": self._safe_payload_preview(payload or {}),
            "timestamp": self._utc_now(),
        }

        self.logger.info("Agent event emitted: %s", event)

    def _log_audit_event(
        self,
        action: str,
        context: PageContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Audit log hook.

        In the final system, this can write to a database audit table.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "action": action,
            "context": self._safe_context_metadata(context),
            "payload": self._safe_payload_preview(payload or {}),
            "timestamp": self._utc_now(),
        }

        self.logger.info("Audit event: %s", audit_event)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured result.
        """

        return {
            "success": success,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result.
        """

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error or "UNKNOWN_ERROR",
            metadata=metadata or {},
        )

    # ==================================================================================
    # Normalization helpers
    # ==================================================================================

    def _normalize_context(
        self,
        context: Optional[Union[PageContext, Dict[str, Any]]],
    ) -> PageContext:
        if isinstance(context, PageContext):
            return context

        if isinstance(context, dict):
            valid_keys = set(PageContext.__dataclass_fields__.keys())
            clean = {key: value for key, value in context.items() if key in valid_keys}
            return PageContext(**clean)

        return PageContext()

    def _normalize_page_input(
        self,
        page: Union[str, Dict[str, Any], PageAnalysisInput],
    ) -> PageAnalysisInput:
        if isinstance(page, PageAnalysisInput):
            return page

        if isinstance(page, str):
            if self._looks_like_html(page):
                return PageAnalysisInput(
                    html_content=page,
                    text_content=self._html_to_text(page),
                    headings=self._extract_headings_from_html(page),
                    links=self._extract_links_from_html(page),
                    buttons=self._extract_buttons_from_html(page),
                    forms=self._extract_forms_from_html(page),
                    images=self._extract_images_from_html(page),
                )

            return PageAnalysisInput(text_content=page)

        if isinstance(page, dict):
            return PageAnalysisInput(
                url=page.get("url"),
                title=page.get("title"),
                html_content=page.get("html_content") or page.get("html") or page.get("raw_html"),
                text_content=page.get("text_content") or page.get("text") or page.get("content"),
                headings=list(page.get("headings") or []),
                links=list(page.get("links") or []),
                buttons=list(page.get("buttons") or []),
                forms=list(page.get("forms") or []),
                images=list(page.get("images") or []),
                metadata=dict(page.get("metadata") or {}),
            )

        raise TypeError(f"Unsupported page input type: {type(page).__name__}")

    def _validate_page_input(self, page: PageAnalysisInput) -> Optional[str]:
        combined = self._build_combined_text(page)

        if len(combined.strip()) < self.config.min_content_length:
            return "PAGE_CONTENT_TOO_SHORT"

        if len(combined) > self.config.max_content_chars:
            return "PAGE_CONTENT_TOO_LARGE"

        return None

    def _build_combined_text(self, page: PageAnalysisInput) -> str:
        parts: List[str] = []

        if page.title:
            parts.append(str(page.title))

        if page.url:
            parts.append(str(page.url))

        if page.headings:
            parts.extend([str(item) for item in page.headings if item])

        if page.buttons:
            parts.extend([str(item) for item in page.buttons if item])

        if page.links:
            for link in page.links:
                if isinstance(link, dict):
                    parts.append(str(link.get("text", "") or ""))
                    parts.append(str(link.get("href", "") or ""))

        if page.forms:
            for form in page.forms:
                parts.append(str(form))

        if page.images:
            for img in page.images:
                if isinstance(img, dict):
                    parts.append(str(img.get("alt", "") or ""))
                    parts.append(str(img.get("title", "") or ""))

        if page.text_content:
            parts.append(str(page.text_content))

        if page.html_content:
            parts.append(self._html_to_text(str(page.html_content)))

        return self._normalize_space(" ".join(parts))

    def _clean_text(self, text: str) -> str:
        text = html.unescape(text or "")
        text = re.sub(r"\s+", " ", text).strip()
        return text[: self.config.max_content_chars]

    def _normalize_space(self, value: str) -> str:
        return re.sub(r"\s+", " ", value or "").strip()

    def _looks_like_html(self, value: str) -> bool:
        return bool(re.search(r"<\s*(html|body|div|section|main|header|footer|a|button|form|h1|h2)", value, re.I))

    def _html_to_text(self, html_content: str) -> str:
        if not html_content:
            return ""

        text = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", html_content)
        text = re.sub(r"(?s)<br\s*/?>", " ", text)
        text = re.sub(r"(?s)</p\s*>", " ", text)
        text = re.sub(r"(?s)<.*?>", " ", text)
        text = html.unescape(text)
        return self._normalize_space(text)

    def _extract_headings_from_html(self, html_content: str) -> List[str]:
        headings: List[str] = []
        for match in re.finditer(r"(?is)<h[1-6][^>]*>(.*?)</h[1-6]>", html_content or ""):
            headings.append(self._html_to_text(match.group(1)))
        return [item for item in headings if item]

    def _extract_links_from_html(self, html_content: str) -> List[Dict[str, Any]]:
        links: List[Dict[str, Any]] = []

        pattern = re.compile(
            r"""(?is)<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>"""
        )

        for match in pattern.finditer(html_content or ""):
            href = html.unescape(match.group(1)).strip()
            text = self._html_to_text(match.group(2))
            links.append({"text": text, "href": href})

        return links

    def _extract_buttons_from_html(self, html_content: str) -> List[str]:
        buttons: List[str] = []

        for match in re.finditer(r"(?is)<button[^>]*>(.*?)</button>", html_content or ""):
            text = self._html_to_text(match.group(1))
            if text:
                buttons.append(text)

        input_button_pattern = re.compile(
            r"""(?is)<input[^>]+type=["']?(submit|button)["']?[^>]*>"""
        )
        value_pattern = re.compile(r"""value=["']([^"']+)["']""", re.I)

        for match in input_button_pattern.finditer(html_content or ""):
            tag = match.group(0)
            value_match = value_pattern.search(tag)
            if value_match:
                buttons.append(html.unescape(value_match.group(1)).strip())

        return buttons

    def _extract_forms_from_html(self, html_content: str) -> List[Dict[str, Any]]:
        forms: List[Dict[str, Any]] = []

        for form_match in re.finditer(r"(?is)<form[^>]*>(.*?)</form>", html_content or ""):
            form_html = form_match.group(0)
            field_count = len(re.findall(r"(?is)<(input|select|textarea)\b", form_html))
            submit_count = len(re.findall(r"(?is)type=['\"]?submit|<button", form_html))
            labels = [
                self._html_to_text(label_match.group(1))
                for label_match in re.finditer(r"(?is)<label[^>]*>(.*?)</label>", form_html)
            ]

            forms.append({
                "field_count": field_count,
                "submit_count": submit_count,
                "labels": [label for label in labels if label],
                "has_password": bool(re.search(r"(?is)type=['\"]?password", form_html)),
                "has_email": bool(re.search(r"(?is)type=['\"]?email|name=['\"]?email", form_html)),
                "has_phone": bool(re.search(r"(?is)type=['\"]?tel|name=['\"]?phone", form_html)),
            })

        return forms

    def _extract_images_from_html(self, html_content: str) -> List[Dict[str, Any]]:
        images: List[Dict[str, Any]] = []

        for match in re.finditer(r"(?is)<img[^>]*>", html_content or ""):
            tag = match.group(0)
            src = self._extract_attr(tag, "src")
            alt = self._extract_attr(tag, "alt")
            title = self._extract_attr(tag, "title")
            images.append({"src": src, "alt": alt, "title": title})

        return images

    def _extract_attr(self, tag: str, attr: str) -> str:
        match = re.search(rf"""{re.escape(attr)}=["']([^"']*)["']""", tag or "", re.I)
        return html.unescape(match.group(1)).strip() if match else ""

    # ==================================================================================
    # Detection helpers
    # ==================================================================================

    def _keyword_weight(self, keyword: str) -> float:
        if len(keyword) >= 14:
            return 2.0
        if " " in keyword:
            return 1.6
        return 1.0

    def _score_cta_text(self, text: str) -> float:
        lower = text.lower().strip()
        if not lower:
            return 0.0

        score = 0.0

        for keyword in self.CTA_KEYWORDS:
            if keyword in lower:
                score += 0.48

        for strong_word in self.STRONG_CTA_WORDS:
            if strong_word in lower:
                score += 0.12

        if 2 <= len(lower.split()) <= 5:
            score += 0.13

        if lower in {"submit", "click here", "more", "next"}:
            score -= 0.25

        return round(max(0.0, min(score, 0.98)), 3)

    def _find_price_patterns(self, text: str) -> List[str]:
        patterns = [
            r"\$\s?\d+(?:,\d{3})*(?:\.\d{2})?",
            r"USD\s?\d+(?:,\d{3})*(?:\.\d{2})?",
            r"\d+(?:\.\d{2})?\s?(?:/month|per month|monthly|/mo)",
            r"\d+(?:\.\d{2})?\s?(?:/year|per year|annually|/yr)",
            r"starting at\s+\$?\d+(?:\.\d{2})?",
            r"from\s+\$?\d+(?:\.\d{2})?",
        ]

        matches: List[str] = []
        for pattern in patterns:
            matches.extend(re.findall(pattern, text or "", flags=re.I))

        return list(dict.fromkeys([self._normalize_space(str(item)) for item in matches]))[:25]

    def _classify_offer_keyword(self, keyword: str) -> str:
        lower = keyword.lower()

        if lower in {"free", "trial", "no credit card", "cancel anytime"}:
            return "trial_or_free_offer"
        if lower in {"discount", "deal", "save", "coupon", "promotion"}:
            return "discount"
        if lower in {"guarantee", "money back"}:
            return "risk_reversal"
        if lower in {"limited time", "exclusive", "special"}:
            return "urgency"
        if lower in {"per month", "monthly", "annually", "starting at", "from $"}:
            return "pricing"

        return "offer"

    def _classify_trust_keyword(self, keyword: str) -> str:
        lower = keyword.lower()

        if lower in {"reviews", "testimonials", "case studies", "rating", "stars"}:
            return "testimonials"
        if lower in {"secure", "ssl", "privacy", "gdpr", "hipaa", "iso", "soc 2"}:
            return "security"
        if lower in {"certified", "licensed", "insured", "verified"}:
            return "credentials"
        if lower in {"trusted by", "clients", "partners", "featured in"}:
            return "social_proof"
        if lower in {"guarantee", "money back"}:
            return "risk_reversal"

        return "trust"

    def _detect_headline_offer_signals(self, headings: Iterable[str]) -> List[DetectedSignal]:
        signals: List[DetectedSignal] = []

        for heading in headings:
            clean = self._normalize_space(str(heading))
            lower = clean.lower()

            if any(keyword in lower for keyword in self.OFFER_KEYWORDS):
                signals.append(
                    DetectedSignal(
                        label="headline_offer",
                        value=clean,
                        confidence=0.76,
                        category="headline_offer",
                        evidence=[clean],
                        metadata={"source": "heading"},
                    )
                )

        return signals

    def _has_contact_information(self, text: str) -> bool:
        email = re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text or "", re.I)
        phone = re.search(r"(\+?\d[\d\s().-]{7,}\d)", text or "")
        contact_words = re.search(r"\b(contact|support|phone|email|address)\b", text or "", re.I)
        return bool(email or phone or contact_words)

    def _has_policy_links(self, page: PageAnalysisInput) -> bool:
        policy_words = ("privacy", "terms", "refund", "security", "cookie", "policy", "guarantee")
        for link in page.links:
            text = str(link.get("text", "") or "").lower()
            href = str(link.get("href", "") or "").lower()
            if any(word in text or word in href for word in policy_words):
                return True
        return False

    def _has_social_proof_numbers(self, text: str) -> bool:
        patterns = [
            r"\b\d{2,}\+?\s+(clients|customers|users|businesses|companies)\b",
            r"\b\d(?:\.\d)?\s?(stars|star rating)\b",
            r"\b\d{2,}\+?\s+(reviews|testimonials)\b",
            r"\btrusted by\s+\d{2,}",
        ]

        return any(re.search(pattern, text or "", flags=re.I) for pattern in patterns)

    def _analyze_form_friction(self, forms: List[Dict[str, Any]]) -> List[DetectedSignal]:
        issues: List[DetectedSignal] = []

        for index, form in enumerate(forms):
            field_count = self._safe_int(form.get("field_count", 0))

            if field_count >= 7:
                issues.append(
                    DetectedSignal(
                        label="long_form",
                        value={"form_index": index, "field_count": field_count},
                        confidence=0.78,
                        category="form_friction",
                        evidence=[f"Form {index + 1} has approximately {field_count} fields."],
                    )
                )

            if form.get("has_password") and not form.get("has_email"):
                issues.append(
                    DetectedSignal(
                        label="unclear_account_form",
                        value={"form_index": index},
                        confidence=0.55,
                        category="form_friction",
                        evidence=["Password field detected without clear email field."],
                    )
                )

            if field_count == 0:
                issues.append(
                    DetectedSignal(
                        label="empty_or_unparsed_form",
                        value={"form_index": index},
                        confidence=0.42,
                        category="form_structure",
                        evidence=["Form detected but no fields were parsed."],
                    )
                )

        return issues

    def _looks_like_placeholder_page(self, text: str) -> bool:
        placeholder_patterns = (
            "lorem ipsum",
            "dummy text",
            "sample text",
            "coming soon",
            "under construction",
            "placeholder",
            "your title here",
            "your text here",
        )
        lower = (text or "").lower()
        return any(pattern in lower for pattern in placeholder_patterns)

    def _count_form_fields(self, forms: List[Dict[str, Any]]) -> int:
        total = 0
        for form in forms:
            total += self._safe_int(form.get("field_count", 0))
            fields = form.get("fields")
            if isinstance(fields, list):
                total += len(fields)
        return total

    def _estimate_hero_text(self, page: PageAnalysisInput, text: str) -> str:
        if page.headings:
            return self._normalize_space(" ".join(page.headings[:3]))

        words = (text or "").split()
        return " ".join(words[:40])

    def _hero_has_clear_value(self, hero_text: str) -> bool:
        lower = hero_text.lower()

        value_words = (
            "increase",
            "grow",
            "save",
            "protect",
            "reduce",
            "improve",
            "automate",
            "faster",
            "better",
            "trusted",
            "free",
            "expert",
            "solution",
            "service",
            "results",
            "leads",
            "sales",
            "revenue",
            "secure",
        )

        return any(word in lower for word in value_words) and len(lower.split()) >= 4

    # ==================================================================================
    # Summaries and scoring helpers
    # ==================================================================================

    def _summarize_ctas(self, items: List[DetectedSignal]) -> str:
        if not items:
            return "No CTA signals detected."

        strong = len([item for item in items if item.confidence >= 0.65])
        return f"Detected {len(items)} CTA signal(s), including {strong} strong CTA(s)."

    def _summarize_offers(self, items: List[DetectedSignal]) -> str:
        if not items:
            return "No clear offer or pricing signal detected."

        categories = sorted(set(item.category for item in items))
        return f"Detected {len(items)} offer signal(s): {', '.join(categories[:6])}."

    def _summarize_trust(self, items: List[DetectedSignal]) -> str:
        if not items:
            return "No strong trust signals detected."

        categories = sorted(set(item.category for item in items))
        return f"Detected {len(items)} trust signal(s): {', '.join(categories[:6])}."

    def _summarize_ux(self, items: List[DetectedSignal], severity: str) -> str:
        if not items:
            return "No major UX issues detected from available content."

        return f"Detected {len(items)} UX issue(s). Estimated severity: {severity}."

    def _summarize_conversion(self, items: List[DetectedSignal]) -> str:
        if not items:
            return "No major conversion problem detected from available content."

        labels = [item.label for item in items[:5]]
        return f"Detected conversion problems: {', '.join(labels)}."

    def _estimate_ux_severity(self, items: List[DetectedSignal]) -> str:
        if not items:
            return "none"

        max_confidence = max(item.confidence for item in items)
        count = len(items)

        if count >= 8 or max_confidence >= 0.9:
            return "critical"
        if count >= 5 or max_confidence >= 0.75:
            return "high"
        if count >= 2 or max_confidence >= 0.55:
            return "medium"

        return "low"

    def _calculate_content_quality_score(self, text: str) -> int:
        word_count = self._word_count(text)
        score = 0

        if word_count >= 100:
            score += 25
        if word_count >= 300:
            score += 20
        if word_count >= 700:
            score += 15

        lower = (text or "").lower()

        benefit_words = ("benefit", "save", "grow", "increase", "reduce", "protect", "improve", "results")
        proof_words = ("trusted", "review", "case study", "testimonial", "clients", "rating")
        clarity_words = ("how it works", "features", "pricing", "faq", "contact")

        if any(word in lower for word in benefit_words):
            score += 15
        if any(word in lower for word in proof_words):
            score += 15
        if any(word in lower for word in clarity_words):
            score += 10

        if self._looks_like_placeholder_page(text):
            score -= 35

        return self._clamp_score(score)

    def _score_to_grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def _score_to_risk_level(self, score: int) -> str:
        if score >= 80:
            return "low"
        if score >= 65:
            return "medium"
        if score >= 45:
            return "high"
        return "critical"

    def _clamp_score(self, value: Union[int, float]) -> int:
        return int(max(0, min(100, round(float(value)))))

    # ==================================================================================
    # Utility helpers
    # ==================================================================================

    def _dedupe_signals(self, signals: List[DetectedSignal]) -> List[DetectedSignal]:
        seen: Dict[str, DetectedSignal] = {}

        for signal in signals:
            key = f"{signal.category}:{str(signal.label).lower()}:{str(signal.value).lower()[:80]}"
            existing = seen.get(key)

            if existing is None or signal.confidence > existing.confidence:
                seen[key] = signal

        return list(seen.values())

    def _dedupe_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        deduped: List[Dict[str, Any]] = []

        priority_order = {"high": 0, "medium": 1, "low": 2}

        for rec in sorted(
            recommendations,
            key=lambda item: priority_order.get(str(item.get("priority", "low")), 3),
        ):
            key = f"{rec.get('category')}:{rec.get('title')}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(rec)

        return deduped

    def _extract_evidence_snippets(
        self,
        text: str,
        keyword: str,
        radius: int = 80,
        limit: int = 3,
    ) -> List[str]:
        if not self.config.include_raw_matches:
            return [f"Detected keyword: {keyword}"]

        snippets: List[str] = []
        lower_text = text.lower()
        lower_keyword = keyword.lower()

        start = 0
        while len(snippets) < limit:
            index = lower_text.find(lower_keyword, start)
            if index == -1:
                break

            left = max(index - radius, 0)
            right = min(index + len(keyword) + radius, len(text))
            snippets.append(self._normalize_space(text[left:right]))
            start = index + len(keyword)

        return snippets or [f"Detected keyword: {keyword}"]

    def _extract_domain(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return None

        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed.netloc.lower().strip()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain or None
        except Exception:
            return None

    def _safe_context_metadata(self, context: PageContext) -> Dict[str, Any]:
        return {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "source_agent": context.source_agent,
            "target_agent": context.target_agent,
        }

    def _safe_payload_preview(self, payload: Dict[str, Any], max_chars: int = 2000) -> Dict[str, Any]:
        safe_payload: Dict[str, Any] = {}

        blocked_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "authorization",
            "cookie",
            "set_cookie",
            "private_key",
        }

        for key, value in payload.items():
            key_lower = str(key).lower()
            if any(blocked in key_lower for blocked in blocked_keys):
                safe_payload[key] = "[REDACTED]"
                continue

            rendered = repr(value)
            if len(rendered) > max_chars:
                safe_payload[key] = rendered[:max_chars] + "...[truncated]"
            else:
                safe_payload[key] = value

        return safe_payload

    def _word_count(self, text: str) -> int:
        return len(re.findall(r"\b\w+\b", text or ""))

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ======================================================================================
# Standalone helper for quick testing
# ======================================================================================

def analyze_page(
    page: Union[str, Dict[str, Any], PageAnalysisInput],
    context: Optional[Union[PageContext, Dict[str, Any]]] = None,
    config: Optional[Union[PageAnalyzerConfig, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Convenience function for tests, scripts, and future API usage.
    """

    analyzer = PageAnalyzer(config=config)
    return analyzer.analyze(page=page, context=context)


# ======================================================================================
# Local smoke test
# ======================================================================================

if __name__ == "__main__":
    sample_page = {
        "url": "https://example.com/pricing",
        "title": "Simple Pricing for Growing Teams",
        "headings": [
            "Grow faster with transparent pricing",
            "Start your free trial today",
            "Trusted by 500+ businesses",
        ],
        "buttons": ["Start Free Trial", "Book a Demo"],
        "links": [
            {"text": "Privacy Policy", "href": "/privacy"},
            {"text": "Terms", "href": "/terms"},
            {"text": "Contact Us", "href": "/contact"},
        ],
        "forms": [
            {
                "field_count": 4,
                "has_email": True,
                "has_phone": True,
            }
        ],
        "images": [
            {"src": "/logo.png", "alt": "Company logo"},
            {"src": "/hero.png", "alt": "Dashboard preview"},
        ],
        "text_content": """
        Start your free trial with no credit card required. Our platform helps teams
        save time, increase conversions, and protect revenue. Pricing starts at $29
        per month. Cancel anytime. Trusted by 500+ businesses with verified reviews.
        """,
    }

    sample_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
        "source_agent": "browser_agent",
    }

    result = analyze_page(sample_page, sample_context)
    print(result)