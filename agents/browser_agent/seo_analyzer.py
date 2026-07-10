"""
agents/browser_agent/seo_analyzer.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Agent/Module: Browser Agent
File: seo_analyzer.py
Required Class: SEOAnalyzer

Purpose:
    Analyze title, meta, headings, schema, links, alts, keywords, local SEO.

This file is designed to be:
    - Production-ready
    - Import-safe
    - SaaS multi-user/workspace compatible
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent
    - Safe for future FastAPI/dashboard integration
    - Structured-result friendly for JSON/API usage

Core responsibilities:
    1. Analyze SEO title quality.
    2. Analyze meta description and meta keywords.
    3. Analyze headings hierarchy.
    4. Detect schema / JSON-LD / structured data.
    5. Analyze internal and external links.
    6. Analyze image alt attributes.
    7. Analyze keyword usage and density.
    8. Analyze local SEO signals.
    9. Generate SEO score, issues, opportunities, and recommendations.

Security note:
    This file does NOT perform live crawling, browser automation, form submission,
    external requests, destructive actions, financial operations, messaging, or calls.
    It only analyzes provided page content safely.
"""

from __future__ import annotations

import html
import json
import logging
import re
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse


# ======================================================================================
# Safe optional BaseAgent import
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        This fallback allows seo_analyzer.py to be imported before the real
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

logger = logging.getLogger("SEOAnalyzer")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Data structures
# ======================================================================================

@dataclass
class SEOAnalyzerConfig:
    """
    Configuration for SEOAnalyzer.

    Defaults are safe, conservative, and suitable for dashboard scoring.
    """

    min_content_length: int = 25
    max_content_chars: int = 300_000
    max_findings_per_category: int = 100
    max_keywords_to_report: int = 30
    include_raw_matches: bool = False
    strict_context_validation: bool = True
    target_title_min_length: int = 30
    target_title_max_length: int = 60
    target_meta_min_length: int = 120
    target_meta_max_length: int = 160
    target_h1_count: int = 1
    ideal_keyword_density_min: float = 0.4
    ideal_keyword_density_max: float = 3.5
    analyze_stopwords: bool = False


@dataclass
class SEOContext:
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
class SEOAnalysisInput:
    """
    Normalized SEO analysis input.

    SEOAnalyzer accepts dicts, strings, or this dataclass.
    """

    url: Optional[str] = None
    title: Optional[str] = None
    meta_description: Optional[str] = None
    meta_keywords: List[str] = field(default_factory=list)
    canonical_url: Optional[str] = None
    robots: Optional[str] = None
    html_content: Optional[str] = None
    text_content: Optional[str] = None
    headings: Dict[str, List[str]] = field(default_factory=dict)
    links: List[Dict[str, Any]] = field(default_factory=list)
    images: List[Dict[str, Any]] = field(default_factory=list)
    schema: List[Dict[str, Any]] = field(default_factory=list)
    target_keywords: List[str] = field(default_factory=list)
    business_name: Optional[str] = None
    location: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SEOFinding:
    """
    Represents one SEO signal, issue, or opportunity.
    """

    label: str
    value: Any
    severity: str = "info"
    category: str = "general"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ======================================================================================
# SEOAnalyzer
# ======================================================================================

class SEOAnalyzer(BaseAgent):
    """
    Browser Agent SEO analysis helper.

    Connects to William/Jarvis architecture:
        - Master Agent:
            Can route SEO analysis tasks here.
        - Browser Agent:
            Uses this file after scraper/content_extractor collects page data.
        - Security Agent:
            Sensitive action hooks exist, but this file only analyzes provided content.
        - Memory Agent:
            Useful SEO insights are prepared as memory payloads.
        - Verification Agent:
            Completed analysis generates verification payloads.
        - Dashboard/API:
            All outputs use structured dicts with stable keys.
        - Registry/Loader:
            Class is import-safe and exposes clear public methods.
    """

    AGENT_NAME = "SEOAnalyzer"
    AGENT_TYPE = "browser_agent"
    VERSION = "1.0.0"

    STOPWORDS: Sequence[str] = (
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
        "has", "he", "in", "is", "it", "its", "of", "on", "that", "the",
        "to", "was", "were", "will", "with", "you", "your", "we", "our",
        "or", "if", "this", "these", "those", "they", "their", "but",
        "can", "not", "all", "more", "new", "about", "into", "than",
    )

    LOCAL_SEO_KEYWORDS: Sequence[str] = (
        "near me",
        "local",
        "location",
        "service area",
        "serving",
        "address",
        "phone",
        "call",
        "directions",
        "map",
        "hours",
        "open",
        "appointment",
        "book",
        "city",
        "state",
        "zip",
        "reviews",
        "google business profile",
        "licensed",
        "insured",
    )

    SCHEMA_TYPES_IMPORTANT: Sequence[str] = (
        "Organization",
        "LocalBusiness",
        "Product",
        "Service",
        "Article",
        "BlogPosting",
        "FAQPage",
        "BreadcrumbList",
        "WebPage",
        "WebSite",
        "Review",
        "AggregateRating",
        "Offer",
        "PostalAddress",
    )

    TECHNICAL_META_NAMES: Sequence[str] = (
        "viewport",
        "robots",
        "description",
        "keywords",
        "author",
    )

    def __init__(
        self,
        config: Optional[Union[SEOAnalyzerConfig, Dict[str, Any]]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            agent_type=self.AGENT_TYPE,
            *args,
            **kwargs,
        )

        if isinstance(config, SEOAnalyzerConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = SEOAnalyzerConfig(**{
                key: value
                for key, value in config.items()
                if key in SEOAnalyzerConfig.__dataclass_fields__
            })
        else:
            self.config = SEOAnalyzerConfig()

        self.logger = logging.getLogger(self.AGENT_NAME)

    # ==================================================================================
    # Public API
    # ==================================================================================

    def analyze(
        self,
        page: Union[str, Dict[str, Any], SEOAnalysisInput],
        context: Optional[Union[SEOContext, Dict[str, Any]]] = None,
        target_keywords: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Main public SEO analysis method.

        Args:
            page:
                Can be:
                    - raw text/html string
                    - dict containing url/title/meta/headings/links/images/schema/etc.
                    - SEOAnalysisInput object

            context:
                SaaS-safe context containing user_id/workspace_id/task_id/etc.

            target_keywords:
                Optional keywords to check against the page.

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

        if self._requires_security_check("analyze_seo", normalized_context):
            approval = self._request_security_approval(
                action="analyze_seo",
                context=normalized_context,
                payload={"operation": "passive_seo_content_analysis_only"},
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for SEO analysis.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "approval": approval,
                        "context": self._safe_context_metadata(normalized_context),
                    },
                )

        try:
            normalized_page = self._normalize_page_input(page)

            if target_keywords:
                normalized_page.target_keywords = target_keywords

            validation_error = self._validate_page_input(normalized_page)
            if validation_error:
                return self._error_result(
                    message="Invalid SEO page input.",
                    error=validation_error,
                    metadata={"context": self._safe_context_metadata(normalized_context)},
                )

            combined_text = self._build_combined_text(normalized_page)
            cleaned_text = self._clean_text(combined_text)

            title_result = self.analyze_title(normalized_page)
            meta_result = self.analyze_meta(normalized_page)
            headings_result = self.analyze_headings(normalized_page)
            schema_result = self.analyze_schema(normalized_page)
            links_result = self.analyze_links(normalized_page)
            images_result = self.analyze_images(normalized_page)
            keywords_result = self.analyze_keywords(normalized_page, cleaned_text)
            local_result = self.analyze_local_seo(normalized_page, cleaned_text)
            technical_result = self.analyze_technical_basics(normalized_page)
            content_result = self.analyze_content_quality(normalized_page, cleaned_text)

            scores = self.calculate_scores(
                title_result=title_result,
                meta_result=meta_result,
                headings_result=headings_result,
                schema_result=schema_result,
                links_result=links_result,
                images_result=images_result,
                keywords_result=keywords_result,
                local_result=local_result,
                technical_result=technical_result,
                content_result=content_result,
            )

            issues = self.collect_issues(
                title_result=title_result,
                meta_result=meta_result,
                headings_result=headings_result,
                schema_result=schema_result,
                links_result=links_result,
                images_result=images_result,
                keywords_result=keywords_result,
                local_result=local_result,
                technical_result=technical_result,
                content_result=content_result,
            )

            recommendations = self.generate_recommendations(
                scores=scores,
                issues=issues,
                title_result=title_result,
                meta_result=meta_result,
                headings_result=headings_result,
                schema_result=schema_result,
                links_result=links_result,
                images_result=images_result,
                keywords_result=keywords_result,
                local_result=local_result,
                technical_result=technical_result,
                content_result=content_result,
            )

            analysis_id = str(uuid.uuid4())
            finished_at = time.time()

            data = {
                "analysis_id": analysis_id,
                "url": normalized_page.url,
                "domain": self._extract_domain(normalized_page.url),
                "title": normalized_page.title,
                "meta_description": normalized_page.meta_description,
                "canonical_url": normalized_page.canonical_url,
                "robots": normalized_page.robots,
                "title_analysis": title_result,
                "meta_analysis": meta_result,
                "headings_analysis": headings_result,
                "schema_analysis": schema_result,
                "links_analysis": links_result,
                "images_analysis": images_result,
                "keywords_analysis": keywords_result,
                "local_seo_analysis": local_result,
                "technical_analysis": technical_result,
                "content_analysis": content_result,
                "scores": scores,
                "issues": issues,
                "recommendations": recommendations,
                "content_summary": {
                    "character_count": len(cleaned_text),
                    "word_count": self._word_count(cleaned_text),
                    "sentence_count": self._sentence_count(cleaned_text),
                    "paragraph_count": self._paragraph_count(normalized_page),
                    "heading_count": sum(len(v) for v in normalized_page.headings.values()),
                    "link_count": len(normalized_page.links),
                    "image_count": len(normalized_page.images),
                    "schema_count": len(normalized_page.schema),
                    "has_html": bool(normalized_page.html_content),
                    "has_text": bool(normalized_page.text_content),
                },
                "verification_payload": self._prepare_verification_payload(
                    action="analyze_seo",
                    success=True,
                    context=normalized_context,
                    data_preview={
                        "analysis_id": analysis_id,
                        "url": normalized_page.url,
                        "seo_score": scores.get("seo_score"),
                        "grade": scores.get("grade"),
                        "issue_count": len(issues),
                    },
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=normalized_context,
                    normalized_page=normalized_page,
                    analysis_summary={
                        "analysis_id": analysis_id,
                        "url": normalized_page.url,
                        "domain": self._extract_domain(normalized_page.url),
                        "seo_score": scores.get("seo_score"),
                        "grade": scores.get("grade"),
                        "top_recommendations": recommendations[:5],
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
                event_name="seo_analysis_completed",
                context=normalized_context,
                payload={
                    "analysis_id": analysis_id,
                    "url": normalized_page.url,
                    "seo_score": scores.get("seo_score"),
                    "grade": scores.get("grade"),
                },
            )

            self._log_audit_event(
                action="analyze_seo",
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
                message="SEO analysis completed successfully.",
                data=data,
                error=None,
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("SEO analysis failed: %s", exc)

            self._log_audit_event(
                action="analyze_seo",
                context=normalized_context,
                payload={
                    "success": False,
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="SEO analysis failed.",
                error=str(exc),
                metadata={
                    "agent": self.AGENT_NAME,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                    "context": self._safe_context_metadata(normalized_context),
                },
            )

    def run(
        self,
        page: Union[str, Dict[str, Any], SEOAnalysisInput],
        context: Optional[Union[SEOContext, Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        BaseAgent-compatible run method.

        Master Agent / Router can call this directly.
        """

        target_keywords = kwargs.get("target_keywords")

        if context is None and "context" in kwargs:
            context = kwargs["context"]

        return self.analyze(
            page=page,
            context=context,
            target_keywords=target_keywords,
        )

    # ==================================================================================
    # SEO analysis sections
    # ==================================================================================

    def analyze_title(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze SEO title quality.
        """

        title = self._normalize_space(page.title or "")
        findings: List[SEOFinding] = []

        length = len(title)

        if not title:
            findings.append(SEOFinding(
                label="missing_title",
                value=True,
                severity="critical",
                category="title",
                confidence=1.0,
                evidence=["No page title detected."],
                recommendation="Add a unique, keyword-focused title tag.",
            ))
        else:
            if length < self.config.target_title_min_length:
                findings.append(SEOFinding(
                    label="title_too_short",
                    value=length,
                    severity="medium",
                    category="title",
                    confidence=0.9,
                    evidence=[title],
                    recommendation=f"Expand title to at least {self.config.target_title_min_length} characters.",
                ))

            if length > self.config.target_title_max_length:
                findings.append(SEOFinding(
                    label="title_too_long",
                    value=length,
                    severity="medium",
                    category="title",
                    confidence=0.9,
                    evidence=[title],
                    recommendation=f"Shorten title to under {self.config.target_title_max_length} characters.",
                ))

            if page.target_keywords and not self._contains_any_keyword(title, page.target_keywords):
                findings.append(SEOFinding(
                    label="target_keyword_missing_from_title",
                    value=page.target_keywords,
                    severity="high",
                    category="title",
                    confidence=0.82,
                    evidence=[title],
                    recommendation="Include the primary target keyword naturally in the title.",
                ))

            if self._looks_duplicate_or_generic_title(title):
                findings.append(SEOFinding(
                    label="generic_title",
                    value=title,
                    severity="medium",
                    category="title",
                    confidence=0.75,
                    evidence=[title],
                    recommendation="Make the title more specific, benefit-driven, and page-relevant.",
                ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "title": title,
            "length": length,
            "has_title": bool(title),
            "target_range": {
                "min": self.config.target_title_min_length,
                "max": self.config.target_title_max_length,
            },
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("title", findings, score),
        }

    def analyze_meta(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze meta description, meta keywords, robots, canonical.
        """

        description = self._normalize_space(page.meta_description or "")
        keywords = page.meta_keywords or []
        robots = self._normalize_space(page.robots or "")
        canonical = self._normalize_space(page.canonical_url or "")

        findings: List[SEOFinding] = []

        description_length = len(description)

        if not description:
            findings.append(SEOFinding(
                label="missing_meta_description",
                value=True,
                severity="high",
                category="meta",
                confidence=1.0,
                evidence=["No meta description detected."],
                recommendation="Add a compelling meta description with the main keyword and clear benefit.",
            ))
        else:
            if description_length < self.config.target_meta_min_length:
                findings.append(SEOFinding(
                    label="meta_description_too_short",
                    value=description_length,
                    severity="medium",
                    category="meta",
                    confidence=0.86,
                    evidence=[description],
                    recommendation=f"Expand meta description to around {self.config.target_meta_min_length}-{self.config.target_meta_max_length} characters.",
                ))

            if description_length > self.config.target_meta_max_length:
                findings.append(SEOFinding(
                    label="meta_description_too_long",
                    value=description_length,
                    severity="medium",
                    category="meta",
                    confidence=0.86,
                    evidence=[description],
                    recommendation=f"Shorten meta description to under {self.config.target_meta_max_length} characters.",
                ))

            if page.target_keywords and not self._contains_any_keyword(description, page.target_keywords):
                findings.append(SEOFinding(
                    label="target_keyword_missing_from_meta_description",
                    value=page.target_keywords,
                    severity="medium",
                    category="meta",
                    confidence=0.75,
                    evidence=[description],
                    recommendation="Use the primary keyword naturally in the meta description.",
                ))

        if robots and self._robots_blocks_indexing(robots):
            findings.append(SEOFinding(
                label="robots_may_block_indexing",
                value=robots,
                severity="critical",
                category="technical_meta",
                confidence=0.95,
                evidence=[robots],
                recommendation="Review robots meta tag. Remove noindex if the page should rank.",
            ))

        if page.url and canonical:
            domain = self._extract_domain(page.url)
            canonical_domain = self._extract_domain(canonical)
            if domain and canonical_domain and domain != canonical_domain:
                findings.append(SEOFinding(
                    label="canonical_points_to_different_domain",
                    value=canonical,
                    severity="high",
                    category="canonical",
                    confidence=0.84,
                    evidence=[canonical],
                    recommendation="Confirm canonical URL is intentional and points to the preferred page.",
                ))

        if not canonical:
            findings.append(SEOFinding(
                label="missing_canonical",
                value=True,
                severity="low",
                category="canonical",
                confidence=0.68,
                evidence=["No canonical URL detected."],
                recommendation="Add a canonical URL to reduce duplicate-content ambiguity.",
            ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "meta_description": description,
            "meta_description_length": description_length,
            "meta_keywords": keywords,
            "meta_keywords_count": len(keywords),
            "robots": robots,
            "canonical_url": canonical,
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("meta", findings, score),
        }

    def analyze_headings(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze heading hierarchy and keyword usage.
        """

        headings = self._normalize_headings(page.headings)
        findings: List[SEOFinding] = []

        h1s = headings.get("h1", [])
        all_headings = []
        for level in ("h1", "h2", "h3", "h4", "h5", "h6"):
            all_headings.extend(headings.get(level, []))

        if len(h1s) == 0:
            findings.append(SEOFinding(
                label="missing_h1",
                value=True,
                severity="high",
                category="headings",
                confidence=1.0,
                evidence=["No H1 detected."],
                recommendation="Add one clear H1 that describes the page and includes the primary keyword.",
            ))

        if len(h1s) > 1:
            findings.append(SEOFinding(
                label="multiple_h1",
                value=len(h1s),
                severity="medium",
                category="headings",
                confidence=0.9,
                evidence=h1s[:5],
                recommendation="Use one main H1 and move secondary headings to H2/H3.",
            ))

        if page.target_keywords and h1s and not any(
            self._contains_any_keyword(h1, page.target_keywords) for h1 in h1s
        ):
            findings.append(SEOFinding(
                label="target_keyword_missing_from_h1",
                value=page.target_keywords,
                severity="high",
                category="headings",
                confidence=0.8,
                evidence=h1s[:3],
                recommendation="Include the primary keyword naturally in the H1.",
            ))

        if not headings.get("h2"):
            findings.append(SEOFinding(
                label="missing_h2_structure",
                value=True,
                severity="medium",
                category="headings",
                confidence=0.75,
                evidence=["No H2 headings detected."],
                recommendation="Add H2 sections to organize page content and support SEO relevance.",
            ))

        hierarchy_issues = self._detect_heading_hierarchy_issues(headings)
        findings.extend(hierarchy_issues)

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "headings": headings,
            "h1_count": len(h1s),
            "h2_count": len(headings.get("h2", [])),
            "total_heading_count": len(all_headings),
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("headings", findings, score),
        }

    def analyze_schema(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze schema / structured data.
        """

        schema_items = page.schema or []
        findings: List[SEOFinding] = []

        schema_types = self._extract_schema_types(schema_items)

        if not schema_items:
            findings.append(SEOFinding(
                label="missing_schema",
                value=True,
                severity="medium",
                category="schema",
                confidence=0.82,
                evidence=["No structured data detected."],
                recommendation="Add relevant JSON-LD schema such as Organization, LocalBusiness, Service, Product, FAQPage, or BreadcrumbList.",
            ))

        if schema_items and not schema_types:
            findings.append(SEOFinding(
                label="schema_type_not_detected",
                value=True,
                severity="low",
                category="schema",
                confidence=0.55,
                evidence=["Schema found but @type was not detected."],
                recommendation="Ensure structured data contains valid @type fields.",
            ))

        important_detected = [
            schema_type
            for schema_type in schema_types
            if schema_type in self.SCHEMA_TYPES_IMPORTANT
        ]

        if schema_items and not important_detected:
            findings.append(SEOFinding(
                label="schema_not_commercially_relevant",
                value=schema_types,
                severity="low",
                category="schema",
                confidence=0.6,
                evidence=schema_types[:10],
                recommendation="Add commercially useful schema types matching the page purpose.",
            ))

        if page.business_name or page.address or page.phone or page.location:
            if "LocalBusiness" not in schema_types and "Organization" not in schema_types:
                findings.append(SEOFinding(
                    label="local_business_schema_missing",
                    value=True,
                    severity="medium",
                    category="local_schema",
                    confidence=0.76,
                    evidence=["Local business signals exist but LocalBusiness/Organization schema not detected."],
                    recommendation="Add LocalBusiness or Organization schema with NAP details.",
                ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "schema_count": len(schema_items),
            "schema_types": schema_types,
            "important_schema_types_detected": important_detected,
            "has_schema": bool(schema_items),
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("schema", findings, score),
        }

    def analyze_links(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze internal and external links.
        """

        links = page.links or []
        findings: List[SEOFinding] = []

        page_domain = self._extract_domain(page.url)

        internal_links: List[Dict[str, Any]] = []
        external_links: List[Dict[str, Any]] = []
        empty_anchor_links: List[Dict[str, Any]] = []
        suspicious_links: List[Dict[str, Any]] = []

        for link in links:
            href = self._normalize_space(str(link.get("href", "") or ""))
            text = self._normalize_space(str(link.get("text", "") or link.get("anchor", "") or ""))

            if not href:
                continue

            if not text or text.lower() in {"click here", "read more", "learn more", "more"}:
                empty_anchor_links.append(link)

            link_domain = self._extract_domain(href)

            if page_domain and link_domain and page_domain == link_domain:
                internal_links.append(link)
            elif href.startswith("/") or href.startswith("#"):
                internal_links.append(link)
            elif link_domain:
                external_links.append(link)

            if href.lower().startswith(("javascript:", "mailto:", "tel:")):
                continue

            if self._looks_suspicious_link(href):
                suspicious_links.append(link)

        if not internal_links:
            findings.append(SEOFinding(
                label="no_internal_links_detected",
                value=True,
                severity="medium",
                category="links",
                confidence=0.75,
                evidence=["No internal links detected."],
                recommendation="Add relevant internal links to important service, blog, and conversion pages.",
            ))

        if len(empty_anchor_links) > 5:
            findings.append(SEOFinding(
                label="many_weak_anchor_texts",
                value=len(empty_anchor_links),
                severity="medium",
                category="links",
                confidence=0.72,
                evidence=[str(item)[:160] for item in empty_anchor_links[:5]],
                recommendation="Replace generic anchor text with descriptive keyword-rich anchors.",
            ))

        if len(external_links) > 50:
            findings.append(SEOFinding(
                label="too_many_external_links",
                value=len(external_links),
                severity="low",
                category="links",
                confidence=0.65,
                evidence=[str(item)[:160] for item in external_links[:5]],
                recommendation="Review external links and keep only useful, trusted references.",
            ))

        if suspicious_links:
            findings.append(SEOFinding(
                label="suspicious_links_detected",
                value=len(suspicious_links),
                severity="high",
                category="links",
                confidence=0.8,
                evidence=[str(item)[:160] for item in suspicious_links[:5]],
                recommendation="Review suspicious links for SEO, trust, and security risks.",
            ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "total_links": len(links),
            "internal_links_count": len(internal_links),
            "external_links_count": len(external_links),
            "weak_anchor_count": len(empty_anchor_links),
            "suspicious_link_count": len(suspicious_links),
            "internal_links_sample": internal_links[:10],
            "external_links_sample": external_links[:10],
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("links", findings, score),
        }

    def analyze_images(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze image alt attributes.
        """

        images = page.images or []
        findings: List[SEOFinding] = []

        missing_alt: List[Dict[str, Any]] = []
        weak_alt: List[Dict[str, Any]] = []
        keyword_alt_count = 0

        for image in images:
            alt = self._normalize_space(str(image.get("alt", "") or ""))
            src = self._normalize_space(str(image.get("src", "") or ""))

            if not alt:
                missing_alt.append(image)
                continue

            if len(alt) < 5 or alt.lower() in {"image", "photo", "picture", "logo"}:
                weak_alt.append(image)

            if page.target_keywords and self._contains_any_keyword(alt, page.target_keywords):
                keyword_alt_count += 1

        if images and missing_alt:
            ratio = len(missing_alt) / max(len(images), 1)
            severity = "high" if ratio >= 0.5 else "medium"
            findings.append(SEOFinding(
                label="images_missing_alt",
                value=len(missing_alt),
                severity=severity,
                category="images",
                confidence=0.88,
                evidence=[str(item)[:160] for item in missing_alt[:5]],
                recommendation="Add descriptive alt text to important images.",
            ))

        if weak_alt:
            findings.append(SEOFinding(
                label="weak_image_alt_text",
                value=len(weak_alt),
                severity="low",
                category="images",
                confidence=0.68,
                evidence=[str(item)[:160] for item in weak_alt[:5]],
                recommendation="Improve weak alt text with clear image descriptions.",
            ))

        if images and page.target_keywords and keyword_alt_count == 0:
            findings.append(SEOFinding(
                label="target_keyword_missing_from_image_alts",
                value=page.target_keywords,
                severity="low",
                category="images",
                confidence=0.58,
                evidence=["No target keyword found in image alt text."],
                recommendation="Use keywords naturally in image alt text only where relevant.",
            ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "total_images": len(images),
            "missing_alt_count": len(missing_alt),
            "weak_alt_count": len(weak_alt),
            "keyword_alt_count": keyword_alt_count,
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("images", findings, score),
        }

    def analyze_keywords(self, page: SEOAnalysisInput, text: str) -> Dict[str, Any]:
        """
        Analyze keyword usage, density, and top terms.
        """

        findings: List[SEOFinding] = []
        words = self._tokenize_words(text)

        if not self.config.analyze_stopwords:
            words = [word for word in words if word not in self.STOPWORDS]

        word_count = max(len(words), 1)
        counter = Counter(words)
        top_keywords = counter.most_common(self.config.max_keywords_to_report)

        target_keyword_results: List[Dict[str, Any]] = []

        for keyword in page.target_keywords:
            normalized_keyword = self._normalize_space(keyword.lower())
            count = self._count_keyword_occurrences(text, normalized_keyword)
            density = round((count / word_count) * 100, 3)
            in_title = bool(page.title and normalized_keyword in page.title.lower())
            in_meta = bool(page.meta_description and normalized_keyword in page.meta_description.lower())
            in_h1 = any(
                normalized_keyword in heading.lower()
                for heading in self._normalize_headings(page.headings).get("h1", [])
            )

            target_keyword_results.append({
                "keyword": keyword,
                "count": count,
                "density_percent": density,
                "in_title": in_title,
                "in_meta_description": in_meta,
                "in_h1": in_h1,
            })

            if count == 0:
                findings.append(SEOFinding(
                    label="target_keyword_not_found",
                    value=keyword,
                    severity="high",
                    category="keywords",
                    confidence=0.88,
                    evidence=[keyword],
                    recommendation="Use the target keyword naturally in the page body, title, H1, and meta description.",
                ))
            elif density < self.config.ideal_keyword_density_min:
                findings.append(SEOFinding(
                    label="target_keyword_density_low",
                    value={"keyword": keyword, "density": density},
                    severity="medium",
                    category="keywords",
                    confidence=0.72,
                    evidence=[keyword],
                    recommendation="Increase keyword relevance naturally with supporting sections and related phrases.",
                ))
            elif density > self.config.ideal_keyword_density_max:
                findings.append(SEOFinding(
                    label="target_keyword_density_high",
                    value={"keyword": keyword, "density": density},
                    severity="medium",
                    category="keywords",
                    confidence=0.72,
                    evidence=[keyword],
                    recommendation="Reduce repetitive keyword usage and use natural variations.",
                ))

        if not page.target_keywords:
            findings.append(SEOFinding(
                label="no_target_keywords_provided",
                value=True,
                severity="info",
                category="keywords",
                confidence=0.75,
                evidence=["No target keywords were provided for focused SEO matching."],
                recommendation="Provide primary and secondary keywords for more precise SEO analysis.",
            ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "word_count_after_filter": word_count,
            "top_keywords": [{"keyword": key, "count": value} for key, value in top_keywords],
            "target_keywords": page.target_keywords,
            "target_keyword_results": target_keyword_results,
            "density_target_range": {
                "min": self.config.ideal_keyword_density_min,
                "max": self.config.ideal_keyword_density_max,
            },
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("keywords", findings, score),
        }

    def analyze_local_seo(self, page: SEOAnalysisInput, text: str) -> Dict[str, Any]:
        """
        Analyze local SEO signals such as NAP, location terms, local schema,
        phone/address visibility, and local intent wording.
        """

        findings: List[SEOFinding] = []
        lower_text = text.lower()

        detected_local_terms = [
            keyword
            for keyword in self.LOCAL_SEO_KEYWORDS
            if keyword in lower_text
        ]

        phone_detected = bool(page.phone or self._detect_phone(text))
        address_detected = bool(page.address or self._detect_address_like_text(text))
        location_detected = bool(page.location or self._detect_location_like_text(text))
        business_name_detected = bool(page.business_name)

        schema_types = self._extract_schema_types(page.schema)
        has_local_schema = "LocalBusiness" in schema_types or "PostalAddress" in schema_types

        if detected_local_terms and not phone_detected:
            findings.append(SEOFinding(
                label="local_intent_without_phone",
                value=True,
                severity="medium",
                category="local_seo",
                confidence=0.76,
                evidence=detected_local_terms[:5],
                recommendation="Add a visible phone number for local conversion and local SEO trust.",
            ))

        if detected_local_terms and not address_detected and not location_detected:
            findings.append(SEOFinding(
                label="local_intent_without_location",
                value=True,
                severity="medium",
                category="local_seo",
                confidence=0.76,
                evidence=detected_local_terms[:5],
                recommendation="Add city, service area, address, or location details.",
            ))

        if (phone_detected or address_detected or location_detected) and not has_local_schema:
            findings.append(SEOFinding(
                label="local_schema_missing",
                value=True,
                severity="medium",
                category="local_seo",
                confidence=0.72,
                evidence=["NAP/local signals detected but LocalBusiness schema missing."],
                recommendation="Add LocalBusiness schema with business name, phone, address, and service area.",
            ))

        if phone_detected and address_detected and location_detected and has_local_schema:
            status = "strong"
        elif phone_detected or address_detected or location_detected or detected_local_terms:
            status = "partial"
        else:
            status = "weak"

        score = 100
        if status == "weak":
            score -= 30
        elif status == "partial":
            score -= 12

        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "status": status,
            "detected_local_terms": detected_local_terms[:30],
            "phone_detected": phone_detected,
            "address_detected": address_detected,
            "location_detected": location_detected,
            "business_name_detected": business_name_detected,
            "has_local_schema": has_local_schema,
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("local SEO", findings, score),
        }

    def analyze_technical_basics(self, page: SEOAnalysisInput) -> Dict[str, Any]:
        """
        Analyze basic technical SEO signals available from provided content.
        """

        findings: List[SEOFinding] = []
        html_content = page.html_content or ""

        has_viewport = bool(re.search(r'<meta[^>]+name=["\']viewport["\']', html_content, re.I))
        has_lang = bool(re.search(r'<html[^>]+lang=["\'][^"\']+["\']', html_content, re.I))
        has_canonical = bool(page.canonical_url)
        has_robots = bool(page.robots)

        if html_content and not has_viewport:
            findings.append(SEOFinding(
                label="missing_viewport_meta",
                value=True,
                severity="medium",
                category="technical",
                confidence=0.82,
                evidence=["Viewport meta tag not detected."],
                recommendation="Add a viewport meta tag for mobile-friendly rendering.",
            ))

        if html_content and not has_lang:
            findings.append(SEOFinding(
                label="missing_html_lang",
                value=True,
                severity="low",
                category="technical",
                confidence=0.7,
                evidence=["HTML lang attribute not detected."],
                recommendation="Add a valid lang attribute to the html tag.",
            ))

        if page.url and page.url.startswith("http://"):
            findings.append(SEOFinding(
                label="non_https_url",
                value=page.url,
                severity="high",
                category="technical",
                confidence=0.94,
                evidence=[page.url],
                recommendation="Use HTTPS for security, trust, and SEO best practice.",
            ))

        if page.robots and self._robots_blocks_indexing(page.robots):
            findings.append(SEOFinding(
                label="noindex_detected",
                value=page.robots,
                severity="critical",
                category="technical",
                confidence=0.95,
                evidence=[page.robots],
                recommendation="Remove noindex if this page should appear in search results.",
            ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "has_viewport_meta": has_viewport,
            "has_html_lang": has_lang,
            "has_canonical": has_canonical,
            "has_robots": has_robots,
            "https_detected": bool(page.url and page.url.startswith("https://")),
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("technical SEO", findings, score),
        }

    def analyze_content_quality(self, page: SEOAnalysisInput, text: str) -> Dict[str, Any]:
        """
        Analyze content quality basics for SEO.
        """

        findings: List[SEOFinding] = []

        word_count = self._word_count(text)
        sentence_count = self._sentence_count(text)
        paragraph_count = self._paragraph_count(page)
        avg_sentence_length = round(word_count / max(sentence_count, 1), 2)

        if word_count < 250:
            findings.append(SEOFinding(
                label="thin_content",
                value=word_count,
                severity="medium",
                category="content",
                confidence=0.82,
                evidence=[f"Detected only {word_count} words."],
                recommendation="Add more useful, relevant, original content to satisfy search intent.",
            ))

        if avg_sentence_length > 28:
            findings.append(SEOFinding(
                label="long_average_sentence_length",
                value=avg_sentence_length,
                severity="low",
                category="readability",
                confidence=0.65,
                evidence=[f"Average sentence length is {avg_sentence_length} words."],
                recommendation="Use shorter sentences for readability.",
            ))

        if self._looks_like_placeholder_page(text):
            findings.append(SEOFinding(
                label="placeholder_content_detected",
                value=True,
                severity="critical",
                category="content",
                confidence=0.95,
                evidence=["Placeholder text detected."],
                recommendation="Replace placeholder text with final SEO copy.",
            ))

        duplicate_phrase_count = self._detect_repetitive_phrases(text)
        if duplicate_phrase_count >= 5:
            findings.append(SEOFinding(
                label="repetitive_phrases_detected",
                value=duplicate_phrase_count,
                severity="low",
                category="content",
                confidence=0.6,
                evidence=[f"Detected {duplicate_phrase_count} repeated phrase patterns."],
                recommendation="Reduce repetitive copy and use natural variations.",
            ))

        score = 100
        for finding in findings:
            score -= self._severity_penalty(finding.severity)
        score = self._clamp_score(score)

        return {
            "word_count": word_count,
            "sentence_count": sentence_count,
            "paragraph_count": paragraph_count,
            "average_sentence_length": avg_sentence_length,
            "score": score,
            "findings": [asdict(item) for item in findings],
            "summary": self._summarize_findings("content", findings, score),
        }

    # ==================================================================================
    # Scoring and recommendations
    # ==================================================================================

    def calculate_scores(
        self,
        title_result: Dict[str, Any],
        meta_result: Dict[str, Any],
        headings_result: Dict[str, Any],
        schema_result: Dict[str, Any],
        links_result: Dict[str, Any],
        images_result: Dict[str, Any],
        keywords_result: Dict[str, Any],
        local_result: Dict[str, Any],
        technical_result: Dict[str, Any],
        content_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculate dashboard-friendly SEO scores.
        """

        title_score = int(title_result.get("score", 0))
        meta_score = int(meta_result.get("score", 0))
        headings_score = int(headings_result.get("score", 0))
        schema_score = int(schema_result.get("score", 0))
        links_score = int(links_result.get("score", 0))
        images_score = int(images_result.get("score", 0))
        keywords_score = int(keywords_result.get("score", 0))
        local_score = int(local_result.get("score", 0))
        technical_score = int(technical_result.get("score", 0))
        content_score = int(content_result.get("score", 0))

        seo_score = int(
            (title_score * 0.12)
            + (meta_score * 0.12)
            + (headings_score * 0.11)
            + (schema_score * 0.10)
            + (links_score * 0.10)
            + (images_score * 0.08)
            + (keywords_score * 0.12)
            + (local_score * 0.08)
            + (technical_score * 0.09)
            + (content_score * 0.08)
        )

        seo_score = self._clamp_score(seo_score)

        return {
            "seo_score": seo_score,
            "grade": self._score_to_grade(seo_score),
            "risk_level": self._score_to_risk_level(seo_score),
            "title_score": title_score,
            "meta_score": meta_score,
            "headings_score": headings_score,
            "schema_score": schema_score,
            "links_score": links_score,
            "images_score": images_score,
            "keywords_score": keywords_score,
            "local_score": local_score,
            "technical_score": technical_score,
            "content_score": content_score,
        }

    def collect_issues(self, **sections: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Collect all findings from every SEO section into one issue list.
        """

        issues: List[Dict[str, Any]] = []

        for section_name, section in sections.items():
            for finding in section.get("findings", []):
                issue = dict(finding)
                issue["section"] = section_name
                issues.append(issue)

        severity_rank = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }

        issues.sort(
            key=lambda item: (
                severity_rank.get(str(item.get("severity", "info")), 9),
                -float(item.get("confidence", 0) or 0),
            )
        )

        return issues

    def generate_recommendations(
        self,
        scores: Dict[str, Any],
        issues: List[Dict[str, Any]],
        title_result: Dict[str, Any],
        meta_result: Dict[str, Any],
        headings_result: Dict[str, Any],
        schema_result: Dict[str, Any],
        links_result: Dict[str, Any],
        images_result: Dict[str, Any],
        keywords_result: Dict[str, Any],
        local_result: Dict[str, Any],
        technical_result: Dict[str, Any],
        content_result: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Generate prioritized SEO recommendations.
        """

        recommendations: List[Dict[str, Any]] = []

        for issue in issues[:20]:
            recommendation = issue.get("recommendation")
            if not recommendation:
                continue

            recommendations.append({
                "priority": self._severity_to_priority(str(issue.get("severity", "info"))),
                "category": issue.get("category", "seo"),
                "title": self._humanize_label(str(issue.get("label", "seo_issue"))),
                "detail": recommendation,
                "evidence": issue.get("evidence", [])[:3],
                "expected_impact": self._expected_impact_for_category(str(issue.get("category", "seo"))),
            })

        if scores.get("seo_score", 0) < 70:
            recommendations.append({
                "priority": "high",
                "category": "seo_strategy",
                "title": "Improve core on-page SEO before scaling content",
                "detail": "Fix title, meta, H1, internal linking, schema, and keyword targeting before publishing more pages.",
                "evidence": [f"SEO score: {scores.get('seo_score')}"],
                "expected_impact": "stronger ranking foundation and better search visibility",
            })

        if schema_result.get("score", 100) < 75:
            recommendations.append({
                "priority": "medium",
                "category": "schema",
                "title": "Add structured data for richer search results",
                "detail": "Use JSON-LD schema matching the page type, such as LocalBusiness, Organization, Service, Product, FAQPage, or BreadcrumbList.",
                "evidence": schema_result.get("schema_types", []),
                "expected_impact": "better search understanding and possible rich result eligibility",
            })

        if local_result.get("status") in {"weak", "partial"}:
            recommendations.append({
                "priority": "medium",
                "category": "local_seo",
                "title": "Strengthen local SEO signals",
                "detail": "Add business name, service area, phone, address, city/state terms, reviews, and LocalBusiness schema where relevant.",
                "evidence": local_result.get("detected_local_terms", [])[:5],
                "expected_impact": "better local relevance and stronger local lead generation",
            })

        return self._dedupe_recommendations(recommendations)

    # ==================================================================================
    # Compatibility hooks
    # ==================================================================================

    def _validate_task_context(self, context: SEOContext) -> Dict[str, Any]:
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

    def _requires_security_check(self, action: str, context: SEOContext) -> bool:
        """
        Decide whether Security Agent approval is required.

        Current file only performs passive SEO analysis.
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
            "live_crawl",
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
        context: SEOContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        This local fallback approves passive SEO analysis only.
        """

        passive_allowed_actions = {
            "analyze_seo",
            "analyze_title",
            "analyze_meta",
            "analyze_headings",
            "analyze_schema",
            "analyze_links",
            "analyze_images",
            "analyze_keywords",
            "analyze_local_seo",
        }

        approved = action in passive_allowed_actions

        return {
            "approved": approved,
            "action": action,
            "reason": (
                "Passive SEO analysis approved by local fallback policy."
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
        context: SEOContext,
        data_preview: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload compatible with Verification Agent.
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
        context: SEOContext,
        normalized_page: SEOAnalysisInput,
        analysis_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare useful SEO context for Memory Agent.

        This does not store memory directly.
        It only prepares a payload that Memory Agent may choose to persist.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "type": "seo_analysis_summary",
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
        context: SEOContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit agent event hook.

        Future integrations:
            - dashboard websocket
            - event bus
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
        context: SEOContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Audit log hook.

        Future integration can write this to database audit logs.
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
        context: Optional[Union[SEOContext, Dict[str, Any]]],
    ) -> SEOContext:
        if isinstance(context, SEOContext):
            return context

        if isinstance(context, dict):
            valid_keys = set(SEOContext.__dataclass_fields__.keys())
            clean = {key: value for key, value in context.items() if key in valid_keys}
            return SEOContext(**clean)

        return SEOContext()

    def _normalize_page_input(
        self,
        page: Union[str, Dict[str, Any], SEOAnalysisInput],
    ) -> SEOAnalysisInput:
        if isinstance(page, SEOAnalysisInput):
            return page

        if isinstance(page, str):
            if self._looks_like_html(page):
                return self._page_from_html(page)
            return SEOAnalysisInput(text_content=page)

        if isinstance(page, dict):
            html_content = page.get("html_content") or page.get("html") or page.get("raw_html")
            text_content = page.get("text_content") or page.get("text") or page.get("content")

            normalized = SEOAnalysisInput(
                url=page.get("url"),
                title=page.get("title"),
                meta_description=page.get("meta_description") or page.get("description"),
                meta_keywords=self._normalize_keywords(page.get("meta_keywords") or page.get("keywords") or []),
                canonical_url=page.get("canonical_url") or page.get("canonical"),
                robots=page.get("robots"),
                html_content=html_content,
                text_content=text_content,
                headings=self._normalize_headings(page.get("headings") or {}),
                links=list(page.get("links") or []),
                images=list(page.get("images") or []),
                schema=list(page.get("schema") or page.get("schemas") or []),
                target_keywords=self._normalize_keywords(page.get("target_keywords") or []),
                business_name=page.get("business_name"),
                location=page.get("location"),
                phone=page.get("phone"),
                address=page.get("address"),
                metadata=dict(page.get("metadata") or {}),
            )

            if html_content:
                extracted = self._page_from_html(str(html_content))

                normalized.title = normalized.title or extracted.title
                normalized.meta_description = normalized.meta_description or extracted.meta_description
                normalized.meta_keywords = normalized.meta_keywords or extracted.meta_keywords
                normalized.canonical_url = normalized.canonical_url or extracted.canonical_url
                normalized.robots = normalized.robots or extracted.robots
                normalized.text_content = normalized.text_content or extracted.text_content
                normalized.headings = normalized.headings or extracted.headings
                normalized.links = normalized.links or extracted.links
                normalized.images = normalized.images or extracted.images
                normalized.schema = normalized.schema or extracted.schema

            return normalized

        raise TypeError(f"Unsupported page input type: {type(page).__name__}")

    def _page_from_html(self, html_content: str) -> SEOAnalysisInput:
        return SEOAnalysisInput(
            title=self._extract_title_from_html(html_content),
            meta_description=self._extract_meta_content(html_content, "description"),
            meta_keywords=self._normalize_keywords(self._extract_meta_content(html_content, "keywords")),
            canonical_url=self._extract_canonical_from_html(html_content),
            robots=self._extract_meta_content(html_content, "robots"),
            html_content=html_content,
            text_content=self._html_to_text(html_content),
            headings=self._extract_headings_from_html(html_content),
            links=self._extract_links_from_html(html_content),
            images=self._extract_images_from_html(html_content),
            schema=self._extract_schema_from_html(html_content),
        )

    def _validate_page_input(self, page: SEOAnalysisInput) -> Optional[str]:
        combined = self._build_combined_text(page)

        if len(combined.strip()) < self.config.min_content_length:
            return "PAGE_CONTENT_TOO_SHORT"

        if len(combined) > self.config.max_content_chars:
            return "PAGE_CONTENT_TOO_LARGE"

        return None

    def _build_combined_text(self, page: SEOAnalysisInput) -> str:
        parts: List[str] = []

        for value in [
            page.title,
            page.meta_description,
            page.canonical_url,
            page.robots,
            page.business_name,
            page.location,
            page.phone,
            page.address,
        ]:
            if value:
                parts.append(str(value))

        for keyword in page.meta_keywords:
            parts.append(str(keyword))

        for keyword in page.target_keywords:
            parts.append(str(keyword))

        for level_values in self._normalize_headings(page.headings).values():
            parts.extend(level_values)

        for link in page.links:
            if isinstance(link, dict):
                parts.append(str(link.get("text", "") or link.get("anchor", "") or ""))
                parts.append(str(link.get("href", "") or ""))

        for image in page.images:
            if isinstance(image, dict):
                parts.append(str(image.get("alt", "") or ""))
                parts.append(str(image.get("title", "") or ""))
                parts.append(str(image.get("src", "") or ""))

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

    def _normalize_keywords(self, value: Any) -> List[str]:
        if value is None:
            return []

        if isinstance(value, str):
            parts = re.split(r"[,|\n]", value)
            return [self._normalize_space(part) for part in parts if self._normalize_space(part)]

        if isinstance(value, Iterable):
            return [self._normalize_space(str(item)) for item in value if self._normalize_space(str(item))]

        return []

    def _normalize_headings(self, headings: Any) -> Dict[str, List[str]]:
        normalized = {f"h{i}": [] for i in range(1, 7)}

        if isinstance(headings, dict):
            for key, values in headings.items():
                level = str(key).lower()
                if not level.startswith("h"):
                    level = f"h{level}"
                if level not in normalized:
                    continue
                if isinstance(values, str):
                    normalized[level].append(self._normalize_space(values))
                elif isinstance(values, Iterable):
                    normalized[level].extend(
                        self._normalize_space(str(item))
                        for item in values
                        if self._normalize_space(str(item))
                    )

        elif isinstance(headings, list):
            for item in headings:
                if isinstance(item, dict):
                    level = str(item.get("level", "h2")).lower()
                    text = self._normalize_space(str(item.get("text", "") or ""))
                    if level.isdigit():
                        level = f"h{level}"
                    if level in normalized and text:
                        normalized[level].append(text)
                elif isinstance(item, str):
                    normalized["h2"].append(self._normalize_space(item))

        return normalized

    # ==================================================================================
    # HTML extraction helpers
    # ==================================================================================

    def _looks_like_html(self, value: str) -> bool:
        return bool(re.search(r"<\s*(html|head|body|title|meta|div|section|main|h1|h2|a|img|script)", value, re.I))

    def _html_to_text(self, html_content: str) -> str:
        if not html_content:
            return ""

        text = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", html_content)
        text = re.sub(r"(?is)<br\s*/?>", " ", text)
        text = re.sub(r"(?is)</p\s*>", " ", text)
        text = re.sub(r"(?is)<.*?>", " ", text)
        text = html.unescape(text)
        return self._normalize_space(text)

    def _extract_title_from_html(self, html_content: str) -> Optional[str]:
        match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_content or "")
        if not match:
            return None
        return self._html_to_text(match.group(1))

    def _extract_meta_content(self, html_content: str, name: str) -> Optional[str]:
        patterns = [
            rf"""(?is)<meta[^>]+name=["']{re.escape(name)}["'][^>]+content=["']([^"']*)["'][^>]*>""",
            rf"""(?is)<meta[^>]+content=["']([^"']*)["'][^>]+name=["']{re.escape(name)}["'][^>]*>""",
            rf"""(?is)<meta[^>]+property=["']og:{re.escape(name)}["'][^>]+content=["']([^"']*)["'][^>]*>""",
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content or "")
            if match:
                return html.unescape(match.group(1)).strip()

        return None

    def _extract_canonical_from_html(self, html_content: str) -> Optional[str]:
        match = re.search(
            r"""(?is)<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["'][^>]*>""",
            html_content or "",
        )
        if match:
            return html.unescape(match.group(1)).strip()
        return None

    def _extract_headings_from_html(self, html_content: str) -> Dict[str, List[str]]:
        headings = {f"h{i}": [] for i in range(1, 7)}

        for level in range(1, 7):
            pattern = rf"(?is)<h{level}[^>]*>(.*?)</h{level}>"
            for match in re.finditer(pattern, html_content or ""):
                text = self._html_to_text(match.group(1))
                if text:
                    headings[f"h{level}"].append(text)

        return headings

    def _extract_links_from_html(self, html_content: str) -> List[Dict[str, Any]]:
        links: List[Dict[str, Any]] = []
        pattern = re.compile(r"""(?is)<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""")

        for match in pattern.finditer(html_content or ""):
            href = html.unescape(match.group(1)).strip()
            text = self._html_to_text(match.group(2))
            links.append({"text": text, "href": href})

        return links

    def _extract_images_from_html(self, html_content: str) -> List[Dict[str, Any]]:
        images: List[Dict[str, Any]] = []

        for match in re.finditer(r"(?is)<img[^>]*>", html_content or ""):
            tag = match.group(0)
            images.append({
                "src": self._extract_attr(tag, "src"),
                "alt": self._extract_attr(tag, "alt"),
                "title": self._extract_attr(tag, "title"),
                "width": self._extract_attr(tag, "width"),
                "height": self._extract_attr(tag, "height"),
                "loading": self._extract_attr(tag, "loading"),
            })

        return images

    def _extract_schema_from_html(self, html_content: str) -> List[Dict[str, Any]]:
        schemas: List[Dict[str, Any]] = []

        pattern = re.compile(
            r"""(?is)<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>"""
        )

        for match in pattern.finditer(html_content or ""):
            raw_json = self._normalize_space(match.group(1))
            try:
                parsed = json.loads(html.unescape(raw_json))
                if isinstance(parsed, list):
                    schemas.extend([item for item in parsed if isinstance(item, dict)])
                elif isinstance(parsed, dict):
                    schemas.append(parsed)
            except Exception:
                schemas.append({
                    "_parse_error": True,
                    "_raw_preview": raw_json[:300],
                })

        return schemas

    def _extract_attr(self, tag: str, attr: str) -> str:
        match = re.search(rf"""{re.escape(attr)}=["']([^"']*)["']""", tag or "", re.I)
        return html.unescape(match.group(1)).strip() if match else ""

    # ==================================================================================
    # Detection helpers
    # ==================================================================================

    def _contains_any_keyword(self, text: str, keywords: List[str]) -> bool:
        lower = (text or "").lower()
        return any(keyword.lower() in lower for keyword in keywords if keyword)

    def _count_keyword_occurrences(self, text: str, keyword: str) -> int:
        if not keyword:
            return 0

        pattern = r"\b" + re.escape(keyword.lower()) + r"\b"
        return len(re.findall(pattern, (text or "").lower()))

    def _tokenize_words(self, text: str) -> List[str]:
        return [
            word.lower()
            for word in re.findall(r"\b[a-zA-Z][a-zA-Z0-9'-]{2,}\b", text or "")
        ]

    def _word_count(self, text: str) -> int:
        return len(re.findall(r"\b\w+\b", text or ""))

    def _sentence_count(self, text: str) -> int:
        sentences = re.split(r"[.!?]+", text or "")
        return len([sentence for sentence in sentences if sentence.strip()])

    def _paragraph_count(self, page: SEOAnalysisInput) -> int:
        if page.html_content:
            paragraphs = re.findall(r"(?is)<p[^>]*>.*?</p>", page.html_content)
            return len(paragraphs)

        if page.text_content:
            paragraphs = re.split(r"\n\s*\n", page.text_content)
            return len([paragraph for paragraph in paragraphs if paragraph.strip()])

        return 0

    def _extract_schema_types(self, schemas: List[Dict[str, Any]]) -> List[str]:
        types: List[str] = []

        def collect_type(item: Any) -> None:
            if isinstance(item, dict):
                schema_type = item.get("@type")
                if isinstance(schema_type, str):
                    types.append(schema_type)
                elif isinstance(schema_type, list):
                    types.extend(str(value) for value in schema_type)

                graph = item.get("@graph")
                if isinstance(graph, list):
                    for graph_item in graph:
                        collect_type(graph_item)

            elif isinstance(item, list):
                for nested in item:
                    collect_type(nested)

        for schema in schemas:
            collect_type(schema)

        return list(dict.fromkeys(types))

    def _robots_blocks_indexing(self, robots: str) -> bool:
        lower = (robots or "").lower()
        return "noindex" in lower or "none" in lower

    def _looks_duplicate_or_generic_title(self, title: str) -> bool:
        lower = title.lower().strip()
        generic_titles = {
            "home",
            "homepage",
            "untitled",
            "new page",
            "document",
            "page",
            "welcome",
            "index",
        }
        return lower in generic_titles or lower.startswith("just another")

    def _detect_heading_hierarchy_issues(self, headings: Dict[str, List[str]]) -> List[SEOFinding]:
        findings: List[SEOFinding] = []

        levels_present = [
            int(level[1])
            for level, values in headings.items()
            if values and level.startswith("h") and level[1:].isdigit()
        ]

        if not levels_present:
            return findings

        sorted_levels = sorted(set(levels_present))
        previous = sorted_levels[0]

        for level in sorted_levels[1:]:
            if level - previous > 1:
                findings.append(SEOFinding(
                    label="heading_level_skip_detected",
                    value={"from": f"h{previous}", "to": f"h{level}"},
                    severity="low",
                    category="headings",
                    confidence=0.62,
                    evidence=[f"Heading jumps from H{previous} to H{level}."],
                    recommendation="Keep heading hierarchy logical, such as H1 > H2 > H3.",
                ))
            previous = level

        return findings

    def _looks_suspicious_link(self, href: str) -> bool:
        lower = href.lower()
        suspicious_parts = (
            "casino",
            "gambling",
            "payday",
            "viagra",
            "adult",
            "loan-offer",
            "free-money",
        )
        return any(part in lower for part in suspicious_parts)

    def _detect_phone(self, text: str) -> Optional[str]:
        match = re.search(r"(\+?\d[\d\s().-]{7,}\d)", text or "")
        return match.group(1) if match else None

    def _detect_address_like_text(self, text: str) -> bool:
        patterns = [
            r"\b\d{1,6}\s+[A-Za-z0-9\s.,'-]+(?:street|st|road|rd|avenue|ave|drive|dr|lane|ln|blvd|boulevard)\b",
            r"\b(?:suite|ste|floor|unit)\s+\w+\b",
            r"\b\d{5}(?:-\d{4})?\b",
        ]
        return any(re.search(pattern, text or "", flags=re.I) for pattern in patterns)

    def _detect_location_like_text(self, text: str) -> bool:
        patterns = [
            r"\bserving\s+[A-Z][a-zA-Z\s]+",
            r"\bin\s+[A-Z][a-zA-Z\s]+,\s?[A-Z]{2}\b",
            r"\bnear\s+[A-Z][a-zA-Z\s]+",
        ]
        return any(re.search(pattern, text or "") for pattern in patterns)

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

    def _detect_repetitive_phrases(self, text: str) -> int:
        words = self._tokenize_words(text)
        if len(words) < 12:
            return 0

        phrases = []
        for i in range(0, len(words) - 2):
            phrases.append(" ".join(words[i:i + 3]))

        counts = Counter(phrases)
        return len([phrase for phrase, count in counts.items() if count >= 3])

    # ==================================================================================
    # Summary and utility helpers
    # ==================================================================================

    def _summarize_findings(self, section: str, findings: List[SEOFinding], score: int) -> str:
        if not findings:
            return f"{section.title()} looks good. Score: {score}/100."

        critical = len([item for item in findings if item.severity == "critical"])
        high = len([item for item in findings if item.severity == "high"])
        medium = len([item for item in findings if item.severity == "medium"])

        return (
            f"{section.title()} has {len(findings)} finding(s). "
            f"Critical: {critical}, High: {high}, Medium: {medium}. "
            f"Score: {score}/100."
        )

    def _severity_penalty(self, severity: str) -> int:
        penalties = {
            "critical": 35,
            "high": 22,
            "medium": 13,
            "low": 6,
            "info": 0,
        }
        return penalties.get(severity, 5)

    def _severity_to_priority(self, severity: str) -> str:
        if severity in {"critical", "high"}:
            return "high"
        if severity == "medium":
            return "medium"
        return "low"

    def _expected_impact_for_category(self, category: str) -> str:
        mapping = {
            "title": "better click-through rate and keyword relevance",
            "meta": "better SERP snippet quality and search intent matching",
            "headings": "clearer page structure and improved topical relevance",
            "schema": "better search understanding and rich result eligibility",
            "links": "stronger crawl paths and internal authority flow",
            "images": "better accessibility and image SEO",
            "keywords": "stronger relevance for target search terms",
            "local_seo": "better local visibility and lead generation",
            "technical": "better crawlability, indexing, and mobile compatibility",
            "content": "stronger search intent satisfaction",
        }
        return mapping.get(category, "improved SEO performance")

    def _humanize_label(self, label: str) -> str:
        return label.replace("_", " ").strip().title()

    def _dedupe_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
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

    def _safe_context_metadata(self, context: SEOContext) -> Dict[str, Any]:
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

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ======================================================================================
# Standalone helper for quick testing
# ======================================================================================

def analyze_seo(
    page: Union[str, Dict[str, Any], SEOAnalysisInput],
    context: Optional[Union[SEOContext, Dict[str, Any]]] = None,
    target_keywords: Optional[List[str]] = None,
    config: Optional[Union[SEOAnalyzerConfig, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Convenience function for tests, scripts, and future API usage.
    """

    analyzer = SEOAnalyzer(config=config)
    return analyzer.analyze(
        page=page,
        context=context,
        target_keywords=target_keywords,
    )


# ======================================================================================
# Local smoke test
# ======================================================================================

if __name__ == "__main__":
    sample_html = """
    <!doctype html>
    <html lang="en">
    <head>
        <title>AI Click Fraud Protection Software for Google Ads</title>
        <meta name="description" content="Protect your Google Ads budget with AI click fraud detection, bot blocking, traffic monitoring, and real-time invalid click protection.">
        <meta name="keywords" content="click fraud protection, google ads protection, invalid click detection">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="canonical" href="https://example.com/click-fraud-protection">
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Service",
            "name": "AI Click Fraud Protection"
        }
        </script>
    </head>
    <body>
        <h1>AI Click Fraud Protection for Google Ads</h1>
        <h2>Stop Invalid Clicks Before They Waste Your Budget</h2>
        <p>
            Our click fraud protection software helps local businesses and agencies
            detect bots, block invalid traffic, monitor campaigns, and improve ad ROI.
        </p>
        <a href="/pricing">See Pricing</a>
        <a href="/contact">Contact Us</a>
        <img src="/dashboard.png" alt="AI click fraud protection dashboard">
    </body>
    </html>
    """

    sample_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
        "source_agent": "browser_agent",
    }

    result = analyze_seo(
        page={
            "url": "https://example.com/click-fraud-protection",
            "html_content": sample_html,
            "target_keywords": ["click fraud protection", "google ads protection"],
            "business_name": "Example Protection",
            "location": "United States",
        },
        context=sample_context,
    )

    print(json.dumps(result, indent=2))