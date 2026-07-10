"""
agents/super_agents/creator_agent/thumbnail_designer.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Thumbnail concepts, text, composition, and prompt ideas for Creator Agent workflows.

This module is designed to be:
    - Import-safe even when other William/Jarvis modules are not available yet.
    - Compatible with BaseAgent-style execution.
    - Compatible with Master Agent routing, Agent Registry, Agent Loader, Dashboard/API use.
    - Safe for SaaS multi-user and multi-workspace isolation.
    - Structured around security, verification, audit, and memory handoff hooks.

Core Responsibilities:
    - Generate thumbnail concept options for videos, shorts, ads, campaigns, and content pieces.
    - Recommend thumbnail text overlays and hook variations.
    - Recommend visual composition, focal points, contrast, layout, style, emotion, and platform fit.
    - Build prompt ideas for image generation or design tools.
    - Create A/B testing variants.
    - Return structured dict/JSON-style results:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[str],
            "metadata": dict
        }

Important Safety Boundaries:
    - This file does not generate or edit images directly.
    - This file does not perform real browser, file, message, system, financial, or destructive actions.
    - Sensitive or risky creative requests are flagged for Security Agent review.
    - User/workspace isolation is enforced in context validation and metadata.
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        Real William/Jarvis deployments should provide agents.base_agent.BaseAgent.
        This fallback keeps the file import-safe during isolated testing.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def execute(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement execute().")


try:
    from agents.super_agents.creator_agent.config import CREATOR_AGENT_VERSION  # type: ignore
except Exception:  # pragma: no cover
    CREATOR_AGENT_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("ThumbnailDesigner")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "ThumbnailDesigner"
DEFAULT_AGENT_ID = "creator.thumbnail_designer"
DEFAULT_MODULE = "Creator Agent"
DEFAULT_FILE_PATH = "agents/super_agents/creator_agent/thumbnail_designer.py"

SUPPORTED_PLATFORMS = {
    "youtube": {
        "label": "YouTube",
        "recommended_ratio": "16:9",
        "recommended_size": "1280x720",
        "text_density": "low",
        "notes": [
            "Use high contrast, large text, expressive face or strong subject.",
            "Make the promise visible in under one second.",
            "Keep text short enough to read on mobile.",
        ],
    },
    "youtube_shorts": {
        "label": "YouTube Shorts",
        "recommended_ratio": "9:16",
        "recommended_size": "1080x1920",
        "text_density": "very low",
        "notes": [
            "Vertical-first composition.",
            "Keep central subject inside safe area.",
            "Use one strong phrase instead of a full sentence.",
        ],
    },
    "tiktok": {
        "label": "TikTok",
        "recommended_ratio": "9:16",
        "recommended_size": "1080x1920",
        "text_density": "very low",
        "notes": [
            "Fast emotional read.",
            "Use bold curiosity or transformation framing.",
            "Avoid clutter because the UI overlays compete with the design.",
        ],
    },
    "instagram_reels": {
        "label": "Instagram Reels",
        "recommended_ratio": "9:16",
        "recommended_size": "1080x1920",
        "text_density": "very low",
        "notes": [
            "Lifestyle-friendly visual style works well.",
            "Keep the main subject centered.",
            "Use clean typography and strong contrast.",
        ],
    },
    "facebook": {
        "label": "Facebook",
        "recommended_ratio": "1.91:1 or 4:5",
        "recommended_size": "1200x628 or 1080x1350",
        "text_density": "medium",
        "notes": [
            "Use clear benefit-led headline.",
            "Design should work in feed and preview cards.",
            "Avoid too much tiny text.",
        ],
    },
    "linkedin": {
        "label": "LinkedIn",
        "recommended_ratio": "1.91:1 or 4:5",
        "recommended_size": "1200x628 or 1080x1350",
        "text_density": "medium",
        "notes": [
            "Use professional, credible composition.",
            "Show outcome, insight, chart, product, or authority cue.",
            "Avoid clickbait that weakens trust.",
        ],
    },
    "generic": {
        "label": "Generic",
        "recommended_ratio": "16:9",
        "recommended_size": "1280x720",
        "text_density": "low",
        "notes": [
            "Use one strong focal point.",
            "Use clear visual hierarchy.",
            "Keep the main promise readable at small sizes.",
        ],
    },
}

DEFAULT_BRAND_STYLE = {
    "primary_color": "#6400B3",
    "dark_color": "#101010",
    "light_color": "#D9D9D9",
    "heading_color": "#FFFFFF",
    "font_style": "bold modern sans-serif",
    "tone": "premium, sharp, conversion-focused",
    "visual_style": "high contrast, clean digital agency style",
}

HIGH_RISK_CREATIVE_TERMS = {
    "deepfake",
    "fake celebrity",
    "impersonate",
    "misleading",
    "scam",
    "guaranteed income",
    "before after medical",
    "miracle cure",
    "political persuasion",
    "election",
    "voter",
    "weapon",
    "adult explicit",
    "hate",
    "harassment",
    "private person",
    "personal data",
}

SENSITIVE_AUDIENCE_TERMS = {
    "religion",
    "race",
    "ethnicity",
    "medical condition",
    "mental health",
    "political affiliation",
    "sexual orientation",
    "criminal record",
    "financial hardship",
}

NEGATIVE_PROMPT_DEFAULTS = [
    "blurry",
    "low resolution",
    "messy composition",
    "tiny unreadable text",
    "distorted typography",
    "extra fingers",
    "deformed face",
    "watermark",
    "logo artifacts",
    "overcrowded design",
    "poor contrast",
    "washed out colors",
]


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class ThumbnailTone(str, Enum):
    """Supported creative tones for thumbnail concepts."""

    PREMIUM = "premium"
    DRAMATIC = "dramatic"
    EDUCATIONAL = "educational"
    CURIOSITY = "curiosity"
    URGENT = "urgent"
    CLEAN = "clean"
    CINEMATIC = "cinematic"
    FUN = "fun"
    AUTHORITY = "authority"
    TRANSFORMATION = "transformation"


class ThumbnailGoal(str, Enum):
    """Supported thumbnail goals."""

    CLICK_THROUGH = "click_through"
    BRAND_TRUST = "brand_trust"
    LEAD_GENERATION = "lead_generation"
    EDUCATION = "education"
    PRODUCT_DEMO = "product_demo"
    AWARENESS = "awareness"
    RETENTION = "retention"


class LayoutPattern(str, Enum):
    """Common thumbnail layout patterns."""

    FACE_REACTION_TEXT = "face_reaction_text"
    BEFORE_AFTER = "before_after"
    SPLIT_SCREEN = "split_screen"
    PRODUCT_CLOSEUP = "product_closeup"
    PROBLEM_SOLUTION = "problem_solution"
    BIG_NUMBER = "big_number"
    AUTHORITY_FRAME = "authority_frame"
    MINIMAL_PROMISE = "minimal_promise"
    SHOCK_REVEAL = "shock_reveal"
    CHECKLIST = "checklist"


@dataclass
class ThumbnailRequest:
    """
    Normalized request object.

    The Master Agent, Creator Agent, dashboard, or API layer may pass raw task data.
    This dataclass turns that task into a predictable internal structure.
    """

    user_id: str
    workspace_id: str
    title: str
    topic: str
    platform: str = "youtube"
    audience: str = "general audience"
    video_type: str = "educational"
    goal: str = ThumbnailGoal.CLICK_THROUGH.value
    tone: str = ThumbnailTone.CURIOSITY.value
    brand_name: Optional[str] = None
    brand_style: Dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULT_BRAND_STYLE))
    keywords: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    existing_assets: List[Dict[str, Any]] = field(default_factory=list)
    competitor_notes: List[str] = field(default_factory=list)
    variants: int = 5
    language: str = "English"
    include_prompts: bool = True
    include_ab_test_plan: bool = True
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ThumbnailConcept:
    """Single thumbnail concept."""

    concept_id: str
    name: str
    strategic_angle: str
    recommended_text: str
    alternate_text: List[str]
    composition: Dict[str, Any]
    visual_elements: List[str]
    color_direction: Dict[str, Any]
    typography: Dict[str, Any]
    emotion: str
    image_prompt: Optional[str]
    negative_prompt: List[str]
    platform_notes: List[str]
    risk_notes: List[str]
    expected_strengths: List[str]
    testing_hypothesis: str


@dataclass
class SecurityAssessment:
    """Security and policy assessment for a request."""

    requires_security: bool
    risk_level: str
    reasons: List[str]
    recommended_action: str


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    """Convert a value into a safe stripped string."""

    if value is None:
        return default
    return str(value).strip()


def _safe_list(value: Any) -> List[Any]:
    """Normalize value into a list."""

    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _clean_text(value: Any, max_length: int = 300) -> str:
    """
    Clean user-provided text for internal creative use.

    This is not a security sanitizer for HTML rendering. Dashboard/API layers
    should still escape output according to their rendering context.
    """

    text = _safe_str(value)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_length:
        text = text[: max_length - 1].rstrip() + "…"
    return text


def _slugify(value: str) -> str:
    """Create a stable slug-like identifier."""

    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "item"


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """Deduplicate strings while preserving order."""

    seen = set()
    output: List[str] = []
    for item in items:
        normalized = _safe_str(item)
        if not normalized:
            continue
        key = normalized.lower()
        if key not in seen:
            seen.add(key)
            output.append(normalized)
    return output


def _limit_words(text: str, max_words: int) -> str:
    """Limit text to a maximum word count."""

    words = _safe_str(text).split()
    if len(words) <= max_words:
        return _safe_str(text)
    return " ".join(words[:max_words]).rstrip()


def _compact_phrase(text: str, max_chars: int = 28, max_words: int = 5) -> str:
    """Create thumbnail-friendly short text."""

    text = _clean_text(text, max_length=120)
    text = re.sub(r"[.?!]+$", "", text)
    text = _limit_words(text, max_words=max_words)
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    return text


def _extract_numbers(text: str) -> List[str]:
    """Extract visible numbers from a title/topic."""

    return re.findall(r"\b\d+(?:[\.,]\d+)?%?x?\b", text)


def _contains_any(text: str, terms: Iterable[str]) -> List[str]:
    """Return matched terms found in text."""

    lowered = text.lower()
    return [term for term in terms if term.lower() in lowered]


# ---------------------------------------------------------------------------
# ThumbnailDesigner
# ---------------------------------------------------------------------------

class ThumbnailDesigner(BaseAgent):
    """
    Creator Agent helper for thumbnail concepts, text, composition, and prompt ideas.

    Integration Notes:
        - Master Agent can route thumbnail tasks to this class by calling execute() or run().
        - Creator Agent can call generate_thumbnail_package() for end-to-end output.
        - Security Agent can review payloads created by _request_security_approval().
        - Verification Agent can consume _prepare_verification_payload().
        - Memory Agent can consume _prepare_memory_payload().
        - Dashboard/API can render structured concept dictionaries from returned data.
        - Agent Registry/Loader can discover this class by its stable class name.

    This class intentionally does not perform real design-tool actions. It prepares
    creative direction and prompt ideas only.
    """

    agent_name = DEFAULT_AGENT_NAME
    agent_id = DEFAULT_AGENT_ID
    module_name = DEFAULT_MODULE
    file_path = DEFAULT_FILE_PATH
    version = CREATOR_AGENT_VERSION

    def __init__(
        self,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_id: str = DEFAULT_AGENT_ID,
        logger: Optional[logging.Logger] = None,
        default_brand_style: Optional[Mapping[str, Any]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize ThumbnailDesigner.

        Args:
            agent_name: Human-readable agent/helper name.
            agent_id: Stable registry/routing identifier.
            logger: Optional logger.
            default_brand_style: Optional default brand style override.
            security_client: Optional Security Agent/service adapter.
            memory_client: Optional Memory Agent/service adapter.
            verification_client: Optional Verification Agent/service adapter.
            audit_client: Optional audit logging adapter.
            event_bus: Optional event bus adapter.
            **kwargs: Forward-compatible options.
        """

        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logger or LOGGER
        self.default_brand_style = self._merge_brand_style(default_brand_style or {})
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_client = audit_client
        self.event_bus = event_bus
        self.options = dict(kwargs)

    # ------------------------------------------------------------------
    # Public execution methods
    # ------------------------------------------------------------------

    async def execute(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entrypoint.

        Args:
            task: Task payload from Master Agent, Creator Agent, dashboard, or API.

        Returns:
            Structured result dict.
        """

        return self.run(task)

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Synchronous routing entrypoint.

        Supported actions:
            - generate_thumbnail_package
            - generate_concepts
            - generate_thumbnail_concepts
            - generate_text_options
            - build_image_prompt
            - create_ab_test_plan
            - evaluate_thumbnail_text
            - health_check

        Args:
            task: Task payload.

        Returns:
            Structured result dict.
        """

        action = _safe_str(task.get("action") or task.get("task_type") or "generate_thumbnail_package").lower()

        try:
            if action in {"health", "health_check", "ping"}:
                return self.health_check(task)

            if action in {
                "generate_thumbnail_package",
                "thumbnail_package",
                "design_thumbnail",
                "generate",
            }:
                return self.generate_thumbnail_package(task)

            if action in {"generate_concepts", "generate_thumbnail_concepts", "concepts"}:
                return self.generate_thumbnail_concepts(task)

            if action in {"generate_text_options", "text_options", "thumbnail_text"}:
                request = self._build_request(task)
                return self._safe_result(
                    message="Thumbnail text options generated successfully.",
                    data={
                        "text_options": self.generate_text_options(
                            title=request.title,
                            topic=request.topic,
                            audience=request.audience,
                            tone=request.tone,
                            keywords=request.keywords,
                            language=request.language,
                        )
                    },
                    metadata=self._metadata(request),
                )

            if action in {"build_image_prompt", "image_prompt", "prompt"}:
                request = self._build_request(task)
                concept_hint = task.get("concept_hint") or task.get("concept") or {}
                prompt = self.build_image_prompt(request, concept_hint=concept_hint)
                return self._safe_result(
                    message="Thumbnail image prompt generated successfully.",
                    data=prompt,
                    metadata=self._metadata(request),
                )

            if action in {"create_ab_test_plan", "ab_test_plan", "a_b_test"}:
                request = self._build_request(task)
                concepts_result = self.generate_thumbnail_concepts(task)
                if not concepts_result.get("success"):
                    return concepts_result
                concepts = concepts_result.get("data", {}).get("concepts", [])
                return self._safe_result(
                    message="Thumbnail A/B test plan generated successfully.",
                    data={"ab_test_plan": self.create_ab_test_plan(request, concepts)},
                    metadata=self._metadata(request),
                )

            if action in {"evaluate_thumbnail_text", "evaluate_text", "score_text"}:
                request = self._build_request(task)
                options = _safe_list(task.get("text_options") or task.get("options"))
                return self._safe_result(
                    message="Thumbnail text options evaluated successfully.",
                    data={
                        "evaluations": self.evaluate_thumbnail_text(
                            options=[_safe_str(item) for item in options],
                            title=request.title,
                            topic=request.topic,
                            platform=request.platform,
                        )
                    },
                    metadata=self._metadata(request),
                )

            return self._error_result(
                message="Unsupported ThumbnailDesigner action.",
                error=f"Unsupported action: {action}",
                metadata={
                    "agent_id": self.agent_id,
                    "supported_actions": [
                        "generate_thumbnail_package",
                        "generate_thumbnail_concepts",
                        "generate_text_options",
                        "build_image_prompt",
                        "create_ab_test_plan",
                        "evaluate_thumbnail_text",
                        "health_check",
                    ],
                },
            )

        except Exception as exc:
            self.logger.exception("ThumbnailDesigner run failed.")
            return self._error_result(
                message="ThumbnailDesigner failed to process task.",
                error=str(exc),
                metadata={
                    "agent_id": self.agent_id,
                    "action": action,
                    "timestamp": _utc_now_iso(),
                },
            )

    def health_check(self, task: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return import/runtime health information."""

        return self._safe_result(
            message="ThumbnailDesigner is available.",
            data={
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "module": self.module_name,
                "file_path": self.file_path,
                "version": self.version,
                "supported_platforms": sorted(SUPPORTED_PLATFORMS.keys()),
                "supports_security_hook": True,
                "supports_memory_payload": True,
                "supports_verification_payload": True,
                "supports_audit_event": True,
                "supports_dashboard_api": True,
            },
            metadata={
                "timestamp": _utc_now_iso(),
                "request_id": _safe_str((task or {}).get("request_id"), default=str(uuid.uuid4())),
            },
        )

    # ------------------------------------------------------------------
    # Main public creative methods
    # ------------------------------------------------------------------

    def generate_thumbnail_package(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate a complete thumbnail design package.

        The package includes:
            - normalized request
            - security assessment
            - concepts
            - text options
            - prompt ideas
            - A/B test plan
            - memory payload
            - verification payload
            - dashboard summary
        """

        request = self._build_request(task)
        context_error = self._validate_task_context(request)
        if context_error:
            return context_error

        security_assessment = self._requires_security_check(request)
        security_payload = None
        if security_assessment.requires_security:
            security_payload = self._request_security_approval(request, security_assessment)

        concepts_result = self.generate_thumbnail_concepts(asdict(request))
        if not concepts_result.get("success"):
            return concepts_result

        concepts = concepts_result.get("data", {}).get("concepts", [])
        text_options = self.generate_text_options(
            title=request.title,
            topic=request.topic,
            audience=request.audience,
            tone=request.tone,
            keywords=request.keywords,
            language=request.language,
        )

        ab_test_plan = self.create_ab_test_plan(request, concepts) if request.include_ab_test_plan else None
        memory_payload = self._prepare_memory_payload(request, concepts)
        verification_payload = self._prepare_verification_payload(
            request=request,
            concepts=concepts,
            security_assessment=security_assessment,
            ab_test_plan=ab_test_plan,
        )

        dashboard_summary = self._build_dashboard_summary(
            request=request,
            concepts=concepts,
            security_assessment=security_assessment,
        )

        self._emit_agent_event(
            event_name="creator.thumbnail.package.generated",
            request=request,
            payload={
                "concept_count": len(concepts),
                "requires_security": security_assessment.requires_security,
            },
        )

        self._log_audit_event(
            event_name="thumbnail_package_generated",
            request=request,
            payload={
                "title": request.title,
                "platform": request.platform,
                "concept_count": len(concepts),
                "risk_level": security_assessment.risk_level,
            },
        )

        return self._safe_result(
            message="Thumbnail design package generated successfully.",
            data={
                "request": asdict(request),
                "security_assessment": asdict(security_assessment),
                "security_payload": security_payload,
                "concepts": concepts,
                "text_options": text_options,
                "ab_test_plan": ab_test_plan,
                "dashboard_summary": dashboard_summary,
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
            },
            metadata=self._metadata(request),
        )

    def generate_thumbnail_concepts(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate thumbnail concept variants.

        Args:
            task: Raw task payload or normalized ThumbnailRequest dict.

        Returns:
            Structured result containing concept dictionaries.
        """

        request = self._build_request(task)
        context_error = self._validate_task_context(request)
        if context_error:
            return context_error

        security_assessment = self._requires_security_check(request)
        platform_profile = self._platform_profile(request.platform)
        concept_count = max(1, min(int(request.variants or 5), 12))

        layouts = self._select_layouts(request, concept_count)
        text_options = self.generate_text_options(
            title=request.title,
            topic=request.topic,
            audience=request.audience,
            tone=request.tone,
            keywords=request.keywords,
            language=request.language,
        )

        concepts: List[Dict[str, Any]] = []
        for index in range(concept_count):
            layout = layouts[index % len(layouts)]
            primary_text = text_options[index % len(text_options)]
            alternate_text = self._alternate_text_for(primary_text, text_options)

            concept = self._build_concept(
                request=request,
                platform_profile=platform_profile,
                layout=layout,
                primary_text=primary_text,
                alternate_text=alternate_text,
                index=index,
                security_assessment=security_assessment,
            )
            concepts.append(asdict(concept))

        self._emit_agent_event(
            event_name="creator.thumbnail.concepts.generated",
            request=request,
            payload={"concept_count": len(concepts)},
        )

        return self._safe_result(
            message="Thumbnail concepts generated successfully.",
            data={
                "concepts": concepts,
                "platform_profile": platform_profile,
                "security_assessment": asdict(security_assessment),
                "design_rules": self._thumbnail_design_rules(request),
            },
            metadata=self._metadata(request),
        )

    def generate_text_options(
        self,
        title: str,
        topic: str,
        audience: str = "general audience",
        tone: str = ThumbnailTone.CURIOSITY.value,
        keywords: Optional[Sequence[str]] = None,
        language: str = "English",
    ) -> List[str]:
        """
        Generate short thumbnail text overlay options.

        Args:
            title: Video/content title.
            topic: Topic or content angle.
            audience: Target audience.
            tone: Creative tone.
            keywords: Optional keywords.
            language: Output language label.

        Returns:
            List of short text options.
        """

        title = _clean_text(title, 180)
        topic = _clean_text(topic, 180)
        audience = _clean_text(audience, 120)
        tone = _safe_str(tone, ThumbnailTone.CURIOSITY.value).lower()
        keywords = [_clean_text(k, 50) for k in (keywords or []) if _clean_text(k, 50)]

        numbers = _extract_numbers(f"{title} {topic}")
        main_keyword = keywords[0] if keywords else self._derive_main_keyword(title, topic)
        compact_title = _compact_phrase(title, max_chars=30, max_words=5)
        compact_topic = _compact_phrase(topic, max_chars=30, max_words=5)

        templates = self._text_templates_for_tone(tone)

        raw_options = [
            template.format(
                title=compact_title,
                topic=compact_topic,
                keyword=_compact_phrase(main_keyword, max_chars=20, max_words=3),
                audience=_compact_phrase(audience, max_chars=18, max_words=3),
                number=numbers[0] if numbers else "1",
            )
            for template in templates
        ]

        if numbers:
            raw_options.extend(
                [
                    f"{numbers[0]} BIG LESSONS",
                    f"{numbers[0]} THINGS CHANGED",
                    f"ONLY {numbers[0]}?",
                ]
            )

        raw_options.extend(
            [
                compact_title,
                compact_topic,
                f"STOP DOING THIS",
                f"DO THIS INSTEAD",
                f"THE REAL REASON",
                f"NO ONE TELLS YOU",
                f"{_compact_phrase(main_keyword, 18, 3).upper()} FIX",
            ]
        )

        cleaned = []
        for option in raw_options:
            option = _clean_text(option.upper(), 42)
            option = re.sub(r"\s+", " ", option)
            option = option.replace("  ", " ").strip(" -:")
            if option:
                cleaned.append(option)

        # Keep text thumbnail-friendly.
        final_options = []
        for option in _dedupe_preserve_order(cleaned):
            if len(option) > 34:
                option = _compact_phrase(option, max_chars=34, max_words=5).upper()
            if len(option.split()) <= 6:
                final_options.append(option)

        # Basic language note without machine translation.
        # Translation belongs in a dedicated language/localization helper later.
        if language and language.lower() not in {"english", "en"}:
            final_options.append(f"[LOCALIZE TO {language.upper()}]")

        return _dedupe_preserve_order(final_options)[:16]

    def build_image_prompt(
        self,
        request: Union[ThumbnailRequest, Mapping[str, Any]],
        concept_hint: Optional[Union[Mapping[str, Any], str]] = None,
    ) -> Dict[str, Any]:
        """
        Build image-generation/design prompt ideas.

        This does not call an image model. It prepares prompts for Visual Agent,
        image-generation tools, designers, or dashboard workflows.
        """

        normalized = request if isinstance(request, ThumbnailRequest) else self._build_request(request)
        platform_profile = self._platform_profile(normalized.platform)
        style = self._merge_brand_style(normalized.brand_style)

        if isinstance(concept_hint, str):
            hint_text = concept_hint
            hint_dict: Dict[str, Any] = {}
        else:
            hint_dict = dict(concept_hint or {})
            hint_text = _safe_str(
                hint_dict.get("name")
                or hint_dict.get("strategic_angle")
                or hint_dict.get("layout")
                or "high-converting thumbnail concept"
            )

        subject = self._derive_subject(normalized)
        composition = hint_dict.get("composition") or {}
        layout = _safe_str(
            hint_dict.get("layout")
            or composition.get("layout")
            or LayoutPattern.FACE_REACTION_TEXT.value
        )

        prompt = (
            f"Create a {platform_profile.get('recommended_ratio', '16:9')} thumbnail design for "
            f"{platform_profile.get('label', normalized.platform)}. "
            f"Topic: {normalized.topic}. Title: {normalized.title}. "
            f"Main subject: {subject}. "
            f"Creative angle: {hint_text}. "
            f"Layout: {layout.replace('_', ' ')}. "
            f"Use a bold focal point, strong foreground/background separation, and clear mobile readability. "
            f"Brand style: primary color {style.get('primary_color')}, dark contrast {style.get('dark_color')}, "
            f"heading color {style.get('heading_color')}, {style.get('visual_style')}. "
            f"Typography direction: {style.get('font_style')}. "
            f"Mood: {normalized.tone}, designed for {normalized.audience}. "
            f"Leave clean space for short text overlay. "
            f"High contrast, crisp lighting, professional composition, no clutter."
        )

        design_tool_prompt = (
            f"Canvas: {platform_profile.get('recommended_size', '1280x720')} "
            f"({platform_profile.get('recommended_ratio', '16:9')}). "
            f"Place main subject on the left or center third. Add large text area on opposite side. "
            f"Use {style.get('primary_color')} as the accent color, {style.get('dark_color')} for depth, "
            f"and {style.get('heading_color')} for headline text. Keep text under 5 words."
        )

        return {
            "image_generation_prompt": prompt,
            "design_tool_prompt": design_tool_prompt,
            "negative_prompt": list(NEGATIVE_PROMPT_DEFAULTS),
            "recommended_size": platform_profile.get("recommended_size"),
            "recommended_ratio": platform_profile.get("recommended_ratio"),
            "safe_area_notes": self._safe_area_notes(normalized.platform),
            "handoff_target": "Visual Agent or external image/design tool",
            "does_not_execute_generation": True,
        }

    def create_ab_test_plan(
        self,
        request: Union[ThumbnailRequest, Mapping[str, Any]],
        concepts: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Create an A/B testing plan for thumbnail concepts.

        Args:
            request: Normalized request or raw request mapping.
            concepts: Concept dictionaries.

        Returns:
            A structured A/B testing plan.
        """

        normalized = request if isinstance(request, ThumbnailRequest) else self._build_request(request)
        clean_concepts = [dict(c) for c in concepts]

        if not clean_concepts:
            return {
                "recommended_test": "No concepts available.",
                "variants": [],
                "metrics": [],
                "decision_rule": "Generate concepts before testing.",
            }

        top_variants = clean_concepts[: min(4, len(clean_concepts))]
        variant_plan = []

        for idx, concept in enumerate(top_variants, start=1):
            variant_plan.append(
                {
                    "variant": f"Variant {chr(64 + idx)}",
                    "concept_id": concept.get("concept_id"),
                    "name": concept.get("name"),
                    "text": concept.get("recommended_text"),
                    "hypothesis": concept.get("testing_hypothesis"),
                    "what_changes": self._variant_difference_note(idx, concept),
                    "keep_constant": [
                        "Video title",
                        "Upload time",
                        "Target audience",
                        "Video content",
                    ],
                }
            )

        return {
            "recommended_test": "Test visual angle first, then text overlay.",
            "variants": variant_plan,
            "metrics": [
                {
                    "metric": "CTR",
                    "why_it_matters": "Primary signal for thumbnail/title pull.",
                },
                {
                    "metric": "Average view duration",
                    "why_it_matters": "Checks whether the thumbnail promise matches the video.",
                },
                {
                    "metric": "Impressions to views",
                    "why_it_matters": "Shows broad packaging effectiveness.",
                },
                {
                    "metric": "Audience retention first 30 seconds",
                    "why_it_matters": "Detects clickbait mismatch early.",
                },
            ],
            "decision_rule": (
                "Choose the variant with higher CTR only if retention is not materially worse. "
                "If CTR improves but retention drops, revise the promise to better match the video."
            ),
            "minimum_testing_guidance": {
                "youtube": "Wait for a meaningful impression sample before deciding.",
                "short_form": "Compare saves, profile visits, and average watch time, not only views.",
                "ads": "Compare cost per result and qualified lead quality, not only click rate.",
            },
            "iteration_steps": [
                "Round 1: Test composition angle.",
                "Round 2: Keep winning composition and test text.",
                "Round 3: Keep winning text and test color/emotion intensity.",
            ],
        }

    def evaluate_thumbnail_text(
        self,
        options: Sequence[str],
        title: str,
        topic: str,
        platform: str = "youtube",
    ) -> List[Dict[str, Any]]:
        """
        Score thumbnail text options using simple deterministic heuristics.

        This is useful for dashboards and API previews before human selection.
        """

        title_terms = set(re.findall(r"[a-z0-9]+", title.lower()))
        topic_terms = set(re.findall(r"[a-z0-9]+", topic.lower()))
        platform_profile = self._platform_profile(platform)

        evaluations: List[Dict[str, Any]] = []
        for option in options:
            text = _clean_text(option, 80)
            words = text.split()
            terms = set(re.findall(r"[a-z0-9]+", text.lower()))

            readability_score = 10 if len(words) <= 4 else max(2, 10 - (len(words) - 4) * 2)
            curiosity_score = self._curiosity_score(text)
            relevance_score = min(10, 4 + len(terms.intersection(title_terms.union(topic_terms))) * 2)
            mobile_score = 10 if len(text) <= 24 else max(3, 10 - int((len(text) - 24) / 4))
            platform_score = 10 if platform_profile.get("text_density") in {"low", "very low"} and len(words) <= 5 else 7

            total = round(
                readability_score * 0.25
                + curiosity_score * 0.25
                + relevance_score * 0.25
                + mobile_score * 0.15
                + platform_score * 0.10,
                2,
            )

            evaluations.append(
                {
                    "text": text,
                    "score": total,
                    "readability_score": readability_score,
                    "curiosity_score": curiosity_score,
                    "relevance_score": relevance_score,
                    "mobile_score": mobile_score,
                    "platform_score": platform_score,
                    "recommendation": self._text_recommendation(total),
                }
            )

        return sorted(evaluations, key=lambda item: item["score"], reverse=True)

    # ------------------------------------------------------------------
    # Compatibility hooks required by prompt
    # ------------------------------------------------------------------

    def _validate_task_context(self, request: ThumbnailRequest) -> Optional[Dict[str, Any]]:
        """
        Validate SaaS context.

        Every user-specific execution must include user_id and workspace_id.
        This prevents accidental mixing of memory, logs, files, analytics, or tasks
        across tenants.
        """

        errors: List[str] = []

        if not request.user_id:
            errors.append("Missing required user_id.")
        if not request.workspace_id:
            errors.append("Missing required workspace_id.")
        if not request.title:
            errors.append("Missing required title.")
        if not request.topic:
            errors.append("Missing required topic.")

        if request.platform not in SUPPORTED_PLATFORMS:
            errors.append(
                f"Unsupported platform '{request.platform}'. "
                f"Supported platforms: {sorted(SUPPORTED_PLATFORMS.keys())}"
            )

        if errors:
            return self._error_result(
                message="ThumbnailDesigner task context validation failed.",
                error="; ".join(errors),
                metadata={
                    "agent_id": self.agent_id,
                    "request_id": request.request_id,
                    "user_id_present": bool(request.user_id),
                    "workspace_id_present": bool(request.workspace_id),
                    "timestamp": _utc_now_iso(),
                },
            )

        return None

    def _requires_security_check(self, request: ThumbnailRequest) -> SecurityAssessment:
        """
        Decide whether the task should be reviewed by Security Agent.

        Thumbnail planning is generally low-risk, but requests involving deception,
        sensitive audiences, political/election targeting, impersonation, private
        individuals, or regulated claims should be reviewed.
        """

        combined = " ".join(
            [
                request.title,
                request.topic,
                request.audience,
                request.video_type,
                request.goal,
                request.tone,
                " ".join(request.keywords),
                " ".join(request.competitor_notes),
                str(request.constraints),
            ]
        ).lower()

        high_risk_matches = _contains_any(combined, HIGH_RISK_CREATIVE_TERMS)
        sensitive_matches = _contains_any(combined, SENSITIVE_AUDIENCE_TERMS)

        reasons: List[str] = []
        if high_risk_matches:
            reasons.append(f"High-risk creative terms detected: {', '.join(high_risk_matches)}")
        if sensitive_matches:
            reasons.append(f"Sensitive audience/attribute terms detected: {', '.join(sensitive_matches)}")

        asks_for_real_person = bool(
            re.search(r"\b(use|copy|imitate|impersonate|clone)\b.*\b(face|person|celebrity|influencer|politician)\b", combined)
        )
        if asks_for_real_person:
            reasons.append("Request may involve likeness, impersonation, or real-person depiction.")

        misleading_claim = bool(
            re.search(r"\bguarantee(?:d)?\b|\b100%\b|\binstant results\b|\bsecret trick\b", combined)
        )
        if misleading_claim:
            reasons.append("Request may involve exaggerated or misleading performance claims.")

        requires_security = bool(reasons)
        risk_level = "medium" if requires_security else "low"

        if high_risk_matches or asks_for_real_person:
            risk_level = "high"

        return SecurityAssessment(
            requires_security=requires_security,
            risk_level=risk_level,
            reasons=reasons,
            recommended_action=(
                "Route to Security Agent before publishing or generating assets."
                if requires_security
                else "No security review required for concept planning."
            ),
        )

    def _request_security_approval(
        self,
        request: ThumbnailRequest,
        assessment: SecurityAssessment,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally submit a Security Agent approval payload.

        This method is safe by default. If no security_client is injected, it only
        returns a payload that Master Agent or Creator Agent can route.
        """

        payload = {
            "type": "security_review_request",
            "source_agent": self.agent_id,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "module": self.module_name,
            "file_path": self.file_path,
            "risk_level": assessment.risk_level,
            "reasons": assessment.reasons,
            "recommended_action": assessment.recommended_action,
            "content_summary": {
                "title": request.title,
                "topic": request.topic,
                "audience": request.audience,
                "platform": request.platform,
                "goal": request.goal,
                "tone": request.tone,
            },
            "timestamp": _utc_now_iso(),
        }

        if self.security_client and hasattr(self.security_client, "review"):
            try:
                review_result = self.security_client.review(payload)
                payload["security_client_result"] = review_result
            except Exception as exc:
                self.logger.warning("Security client review failed: %s", exc)
                payload["security_client_error"] = str(exc)

        return payload

    def _prepare_verification_payload(
        self,
        request: ThumbnailRequest,
        concepts: Sequence[Mapping[str, Any]],
        security_assessment: SecurityAssessment,
        ab_test_plan: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can check:
            - output completeness
            - platform compatibility
            - text readability
            - risk flags
            - user/workspace isolation metadata
        """

        payload = {
            "type": "verification_payload",
            "source_agent": self.agent_id,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "module": self.module_name,
            "file_path": self.file_path,
            "checks_requested": [
                "validate_structured_result",
                "validate_platform_profile",
                "validate_thumbnail_text_readability",
                "validate_security_assessment",
                "validate_saas_isolation_fields",
            ],
            "content": {
                "title": request.title,
                "topic": request.topic,
                "platform": request.platform,
                "concept_count": len(concepts),
                "concept_ids": [c.get("concept_id") for c in concepts],
                "ab_test_plan_included": bool(ab_test_plan),
            },
            "security_assessment": asdict(security_assessment),
            "timestamp": _utc_now_iso(),
        }

        if self.verification_client and hasattr(self.verification_client, "prepare"):
            try:
                client_result = self.verification_client.prepare(payload)
                payload["verification_client_result"] = client_result
            except Exception as exc:
                self.logger.warning("Verification client prepare failed: %s", exc)
                payload["verification_client_error"] = str(exc)

        return payload

    def _prepare_memory_payload(
        self,
        request: ThumbnailRequest,
        concepts: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Only useful creative context is prepared. The Memory Agent should decide
        what to store according to user/workspace memory policy.
        """

        payload = {
            "type": "memory_payload",
            "source_agent": self.agent_id,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "memory_scope": "workspace",
            "suggested_memory_items": [
                {
                    "key": "creator.thumbnail.last_platform",
                    "value": request.platform,
                    "reason": "Helps future thumbnail requests use the same platform defaults.",
                },
                {
                    "key": "creator.thumbnail.last_brand_style",
                    "value": request.brand_style,
                    "reason": "Helps maintain consistent visual direction.",
                },
                {
                    "key": "creator.thumbnail.last_audience",
                    "value": request.audience,
                    "reason": "Helps future Creator Agent outputs stay audience-aware.",
                },
            ],
            "summary": {
                "title": request.title,
                "topic": request.topic,
                "concept_count": len(concepts),
                "top_concept": concepts[0].get("name") if concepts else None,
            },
            "store_raw_assets": False,
            "timestamp": _utc_now_iso(),
        }

        if self.memory_client and hasattr(self.memory_client, "prepare"):
            try:
                client_result = self.memory_client.prepare(payload)
                payload["memory_client_result"] = client_result
            except Exception as exc:
                self.logger.warning("Memory client prepare failed: %s", exc)
                payload["memory_client_error"] = str(exc)

        return payload

    def _emit_agent_event(
        self,
        event_name: str,
        request: ThumbnailRequest,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit event for dashboard, analytics, or internal event bus.

        Safe fallback returns event payload even when no event bus exists.
        """

        event = {
            "event_name": event_name,
            "source_agent": self.agent_id,
            "module": self.module_name,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "payload": dict(payload or {}),
            "timestamp": _utc_now_iso(),
        }

        if self.event_bus and hasattr(self.event_bus, "emit"):
            try:
                self.event_bus.emit(event_name, event)
                event["emitted"] = True
            except Exception as exc:
                self.logger.warning("Event bus emit failed: %s", exc)
                event["emitted"] = False
                event["error"] = str(exc)
        else:
            event["emitted"] = False
            event["reason"] = "No event bus configured."

        return event

    def _log_audit_event(
        self,
        event_name: str,
        request: ThumbnailRequest,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event.

        This supports future dashboard analytics, audit logs, task history, and
        tenant-safe traceability.
        """

        audit_event = {
            "event_name": event_name,
            "source_agent": self.agent_id,
            "module": self.module_name,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "payload": dict(payload or {}),
            "timestamp": _utc_now_iso(),
        }

        if self.audit_client and hasattr(self.audit_client, "log"):
            try:
                self.audit_client.log(audit_event)
                audit_event["logged"] = True
            except Exception as exc:
                self.logger.warning("Audit client log failed: %s", exc)
                audit_event["logged"] = False
                audit_event["error"] = str(exc)
        else:
            audit_event["logged"] = False
            audit_event["reason"] = "No audit client configured."

        return audit_event

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "module": self.module_name,
                "file_path": self.file_path,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": str(error),
            "metadata": {
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "module": self.module_name,
                "file_path": self.file_path,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_request(self, task: Mapping[str, Any]) -> ThumbnailRequest:
        """Build normalized ThumbnailRequest from raw task."""

        if isinstance(task, ThumbnailRequest):
            return task

        data = dict(task or {})
        nested = data.get("data")
        if isinstance(nested, Mapping):
            merged = dict(nested)
            merged.update({k: v for k, v in data.items() if k not in {"data"}})
            data = merged

        context = data.get("context") if isinstance(data.get("context"), Mapping) else {}
        brand_style = self._merge_brand_style(
            data.get("brand_style")
            or data.get("style")
            or context.get("brand_style")
            or {}
        )

        title = _clean_text(
            data.get("title")
            or data.get("video_title")
            or data.get("content_title")
            or data.get("headline")
            or ""
        )

        topic = _clean_text(
            data.get("topic")
            or data.get("video_topic")
            or data.get("subject")
            or data.get("brief")
            or title
        )

        platform = _slugify(_safe_str(data.get("platform") or data.get("channel") or "youtube"))
        platform_aliases = {
            "yt": "youtube",
            "youtube_video": "youtube",
            "shorts": "youtube_shorts",
            "youtube_short": "youtube_shorts",
            "reels": "instagram_reels",
            "instagram": "instagram_reels",
            "ig_reels": "instagram_reels",
            "fb": "facebook",
            "meta": "facebook",
        }
        platform = platform_aliases.get(platform, platform)
        if platform not in SUPPORTED_PLATFORMS:
            platform = "generic"

        keywords = [
            _clean_text(item, 50)
            for item in _safe_list(data.get("keywords") or data.get("tags") or [])
            if _clean_text(item, 50)
        ]

        existing_assets = [
            dict(item)
            for item in _safe_list(data.get("existing_assets") or data.get("assets") or [])
            if isinstance(item, Mapping)
        ]

        competitor_notes = [
            _clean_text(item, 200)
            for item in _safe_list(data.get("competitor_notes") or data.get("competitors") or [])
            if _clean_text(item, 200)
        ]

        variants_raw = data.get("variants") or data.get("count") or data.get("concept_count") or 5
        try:
            variants = int(variants_raw)
        except Exception:
            variants = 5

        return ThumbnailRequest(
            user_id=_safe_str(data.get("user_id") or context.get("user_id")),
            workspace_id=_safe_str(data.get("workspace_id") or context.get("workspace_id")),
            title=title,
            topic=topic,
            platform=platform,
            audience=_clean_text(data.get("audience") or data.get("target_audience") or "general audience", 140),
            video_type=_clean_text(data.get("video_type") or data.get("content_type") or "educational", 80),
            goal=_slugify(_safe_str(data.get("goal") or ThumbnailGoal.CLICK_THROUGH.value)),
            tone=_slugify(_safe_str(data.get("tone") or ThumbnailTone.CURIOSITY.value)),
            brand_name=_clean_text(data.get("brand_name") or data.get("brand") or "", 80) or None,
            brand_style=brand_style,
            keywords=keywords,
            constraints=dict(data.get("constraints") or {}),
            existing_assets=existing_assets,
            competitor_notes=competitor_notes,
            variants=variants,
            language=_clean_text(data.get("language") or "English", 60),
            include_prompts=bool(data.get("include_prompts", True)),
            include_ab_test_plan=bool(data.get("include_ab_test_plan", True)),
            request_id=_safe_str(data.get("request_id") or str(uuid.uuid4())),
        )

    def _build_concept(
        self,
        request: ThumbnailRequest,
        platform_profile: Mapping[str, Any],
        layout: LayoutPattern,
        primary_text: str,
        alternate_text: List[str],
        index: int,
        security_assessment: SecurityAssessment,
    ) -> ThumbnailConcept:
        """Build one thumbnail concept."""

        angle = self._strategic_angle(request, layout, index)
        composition = self._composition_for_layout(request, layout, index)
        color_direction = self._color_direction(request, index)
        typography = self._typography_direction(request, primary_text)
        visual_elements = self._visual_elements(request, layout, index)
        emotion = self._emotion_for(request, layout, index)
        risk_notes = self._risk_notes_for(request, security_assessment)

        prompt_data = None
        if request.include_prompts:
            prompt_data = self.build_image_prompt(
                request,
                concept_hint={
                    "name": f"{layout.value.replace('_', ' ').title()} Concept",
                    "strategic_angle": angle,
                    "layout": layout.value,
                    "composition": composition,
                },
            ).get("image_generation_prompt")

        concept_name = self._concept_name(layout, request, index)
        concept_id = f"thumb_{_slugify(request.platform)}_{index + 1}_{_slugify(concept_name)[:32]}"

        return ThumbnailConcept(
            concept_id=concept_id,
            name=concept_name,
            strategic_angle=angle,
            recommended_text=primary_text,
            alternate_text=alternate_text,
            composition=composition,
            visual_elements=visual_elements,
            color_direction=color_direction,
            typography=typography,
            emotion=emotion,
            image_prompt=prompt_data,
            negative_prompt=list(NEGATIVE_PROMPT_DEFAULTS),
            platform_notes=list(platform_profile.get("notes", [])),
            risk_notes=risk_notes,
            expected_strengths=self._expected_strengths(layout, request),
            testing_hypothesis=self._testing_hypothesis(layout, primary_text, request),
        )

    def _merge_brand_style(self, style: Mapping[str, Any]) -> Dict[str, Any]:
        """Merge supplied brand style with safe defaults."""

        merged = copy.deepcopy(DEFAULT_BRAND_STYLE)
        for key, value in dict(style or {}).items():
            if value is not None and _safe_str(value):
                merged[key] = value
        return merged

    def _metadata(self, request: ThumbnailRequest) -> Dict[str, Any]:
        """Build shared metadata."""

        return {
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "platform": request.platform,
            "tenant_isolated": True,
        }

    def _platform_profile(self, platform: str) -> Dict[str, Any]:
        """Return platform profile with fallback."""

        return copy.deepcopy(SUPPORTED_PLATFORMS.get(platform, SUPPORTED_PLATFORMS["generic"]))

    # ------------------------------------------------------------------
    # Creative logic
    # ------------------------------------------------------------------

    def _select_layouts(self, request: ThumbnailRequest, count: int) -> List[LayoutPattern]:
        """Select layout patterns based on goal, content type, and tone."""

        goal = request.goal.lower()
        tone = request.tone.lower()
        video_type = request.video_type.lower()
        title_topic = f"{request.title} {request.topic}".lower()

        layouts: List[LayoutPattern] = []

        if "tutorial" in video_type or "how" in title_topic:
            layouts.extend([LayoutPattern.PROBLEM_SOLUTION, LayoutPattern.CHECKLIST, LayoutPattern.BEFORE_AFTER])

        if "review" in video_type or "product" in title_topic or "demo" in goal:
            layouts.extend([LayoutPattern.PRODUCT_CLOSEUP, LayoutPattern.SPLIT_SCREEN, LayoutPattern.BIG_NUMBER])

        if tone in {"dramatic", "urgent", "curiosity"}:
            layouts.extend([LayoutPattern.SHOCK_REVEAL, LayoutPattern.FACE_REACTION_TEXT, LayoutPattern.PROBLEM_SOLUTION])

        if tone in {"premium", "authority", "clean"}:
            layouts.extend([LayoutPattern.AUTHORITY_FRAME, LayoutPattern.MINIMAL_PROMISE, LayoutPattern.PRODUCT_CLOSEUP])

        if "transformation" in tone or "before" in title_topic or "after" in title_topic:
            layouts.extend([LayoutPattern.BEFORE_AFTER, LayoutPattern.SPLIT_SCREEN])

        layouts.extend(
            [
                LayoutPattern.FACE_REACTION_TEXT,
                LayoutPattern.BIG_NUMBER,
                LayoutPattern.MINIMAL_PROMISE,
                LayoutPattern.PROBLEM_SOLUTION,
                LayoutPattern.AUTHORITY_FRAME,
                LayoutPattern.SPLIT_SCREEN,
            ]
        )

        unique_layouts: List[LayoutPattern] = []
        seen = set()
        for layout in layouts:
            if layout.value not in seen:
                seen.add(layout.value)
                unique_layouts.append(layout)

        while len(unique_layouts) < count:
            unique_layouts.extend(list(LayoutPattern))

        return unique_layouts[:count]

    def _text_templates_for_tone(self, tone: str) -> List[str]:
        """Return text templates for a tone."""

        tone = tone.lower()

        if tone == ThumbnailTone.PREMIUM.value:
            return [
                "THE SMART WAY",
                "PREMIUM {keyword}",
                "BETTER THAN BEFORE",
                "{keyword} THAT WORKS",
                "HIGH VALUE MOVE",
            ]

        if tone == ThumbnailTone.DRAMATIC.value:
            return [
                "THIS CHANGES EVERYTHING",
                "I WAS WRONG",
                "THE BIG PROBLEM",
                "DON'T IGNORE THIS",
                "IT'S WORSE THAN YOU THINK",
            ]

        if tone == ThumbnailTone.EDUCATIONAL.value:
            return [
                "LEARN THIS FIRST",
                "{keyword} EXPLAINED",
                "SIMPLE BREAKDOWN",
                "{number} KEY STEPS",
                "BEGINNER TO PRO",
            ]

        if tone == ThumbnailTone.URGENT.value:
            return [
                "FIX THIS NOW",
                "STOP WASTING TIME",
                "DON'T MISS THIS",
                "ACT BEFORE THIS",
                "URGENT {keyword}",
            ]

        if tone == ThumbnailTone.CLEAN.value:
            return [
                "SIMPLE {keyword}",
                "CLEAN METHOD",
                "LESS BUT BETTER",
                "THE CLEAR PLAN",
                "NO FLUFF",
            ]

        if tone == ThumbnailTone.CINEMATIC.value:
            return [
                "THE HIDDEN STORY",
                "WHAT REALLY HAPPENED",
                "BEHIND THE SCENES",
                "THE TURNING POINT",
                "THIS MOMENT MATTERS",
            ]

        if tone == ThumbnailTone.FUN.value:
            return [
                "I TRIED THIS",
                "THIS WAS WILD",
                "FUNNY BUT TRUE",
                "WAIT FOR IT",
                "CAN THIS WORK?",
            ]

        if tone == ThumbnailTone.AUTHORITY.value:
            return [
                "EXPERT BREAKDOWN",
                "PROVEN METHOD",
                "THE REAL STRATEGY",
                "WHAT PROS DO",
                "SMARTER {keyword}",
            ]

        if tone == ThumbnailTone.TRANSFORMATION.value:
            return [
                "BEFORE VS AFTER",
                "FROM THIS TO THIS",
                "THE TRANSFORMATION",
                "BIG CHANGE",
                "NEW RESULT",
            ]

        return [
            "NO ONE TELLS YOU",
            "THE TRUTH ABOUT {keyword}",
            "DON'T DO THIS",
            "WHY THIS WORKS",
            "{keyword} SECRET",
            "I TESTED THIS",
        ]

    def _derive_main_keyword(self, title: str, topic: str) -> str:
        """Derive a simple keyword from title/topic."""

        text = f"{title} {topic}".lower()
        stopwords = {
            "the", "a", "an", "and", "or", "but", "for", "with", "without", "to",
            "from", "in", "on", "of", "how", "why", "what", "when", "this", "that",
            "is", "are", "was", "were", "be", "by", "you", "your", "my", "our",
        }

        words = [
            word
            for word in re.findall(r"[a-zA-Z0-9]+", text)
            if len(word) > 2 and word not in stopwords
        ]

        if not words:
            return "RESULT"

        # Prefer repeated or early important words.
        frequency: Dict[str, int] = {}
        for word in words:
            frequency[word] = frequency.get(word, 0) + 1

        ranked = sorted(words, key=lambda word: (-frequency[word], words.index(word)))
        return ranked[0].upper()

    def _derive_subject(self, request: ThumbnailRequest) -> str:
        """Derive main thumbnail subject."""

        constraints_subject = request.constraints.get("subject") if isinstance(request.constraints, Mapping) else None
        if constraints_subject:
            return _clean_text(constraints_subject, 100)

        if request.brand_name:
            return f"{request.brand_name} visual/product/persona"

        topic = request.topic.lower()
        if "website" in topic:
            return "modern website screen mockup with conversion-focused UI"
        if "seo" in topic:
            return "search ranking graph, website page, and growth arrows"
        if "ads" in topic or "ppc" in topic:
            return "ad dashboard, performance chart, and bold warning symbol"
        if "ai" in topic or "automation" in topic:
            return "AI assistant interface, automation nodes, and glowing digital elements"
        if "business" in topic:
            return "business owner looking at growth dashboard"
        if "tutorial" in request.video_type.lower():
            return "clear step-by-step visual demonstration"

        return request.topic

    def _concept_name(self, layout: LayoutPattern, request: ThumbnailRequest, index: int) -> str:
        """Create human-friendly concept name."""

        names = {
            LayoutPattern.FACE_REACTION_TEXT: "Bold Reaction Hook",
            LayoutPattern.BEFORE_AFTER: "Before After Transformation",
            LayoutPattern.SPLIT_SCREEN: "Split Contrast Story",
            LayoutPattern.PRODUCT_CLOSEUP: "Product Proof Closeup",
            LayoutPattern.PROBLEM_SOLUTION: "Problem Solution Punch",
            LayoutPattern.BIG_NUMBER: "Big Number Curiosity",
            LayoutPattern.AUTHORITY_FRAME: "Authority Expert Frame",
            LayoutPattern.MINIMAL_PROMISE: "Minimal Premium Promise",
            LayoutPattern.SHOCK_REVEAL: "Shock Reveal Moment",
            LayoutPattern.CHECKLIST: "Checklist Clarity",
        }
        base = names.get(layout, "Thumbnail Concept")
        if request.brand_name and index == 0:
            return f"{request.brand_name} {base}"
        return base

    def _strategic_angle(self, request: ThumbnailRequest, layout: LayoutPattern, index: int) -> str:
        """Create strategic angle for concept."""

        topic = request.topic
        audience = request.audience

        mapping = {
            LayoutPattern.FACE_REACTION_TEXT: (
                f"Use a strong emotional reaction to make {audience} instantly curious about {topic}."
            ),
            LayoutPattern.BEFORE_AFTER: (
                f"Show the contrast between the current problem and the desired outcome around {topic}."
            ),
            LayoutPattern.SPLIT_SCREEN: (
                f"Compare the wrong way versus the smart way so the value is clear before reading the title."
            ),
            LayoutPattern.PRODUCT_CLOSEUP: (
                f"Make the product, result, dashboard, or visual proof the hero of the thumbnail."
            ),
            LayoutPattern.PROBLEM_SOLUTION: (
                f"Expose the pain point clearly and position the video as the simple fix."
            ),
            LayoutPattern.BIG_NUMBER: (
                f"Use a number, metric, or bold claim as the main curiosity trigger."
            ),
            LayoutPattern.AUTHORITY_FRAME: (
                f"Frame the content as expert guidance with trust-building visual cues."
            ),
            LayoutPattern.MINIMAL_PROMISE: (
                f"Use fewer elements and premium contrast to make the promise feel confident and valuable."
            ),
            LayoutPattern.SHOCK_REVEAL: (
                f"Reveal a surprising problem, mistake, or hidden truth that makes the click feel necessary."
            ),
            LayoutPattern.CHECKLIST: (
                f"Show practical steps or a clear framework so the viewer expects useful value."
            ),
        }

        return mapping.get(layout, f"Create a high-clarity concept for {topic}.")

    def _composition_for_layout(
        self,
        request: ThumbnailRequest,
        layout: LayoutPattern,
        index: int,
    ) -> Dict[str, Any]:
        """Build composition direction for layout."""

        platform_profile = self._platform_profile(request.platform)
        ratio = platform_profile.get("recommended_ratio", "16:9")

        base = {
            "layout": layout.value,
            "ratio": ratio,
            "focal_point": "one dominant subject",
            "text_area": "clear empty area with high contrast",
            "depth": "foreground subject separated from simple background",
            "mobile_readability": "text readable at small size",
            "safe_area": self._safe_area_notes(request.platform),
        }

        if layout == LayoutPattern.FACE_REACTION_TEXT:
            base.update(
                {
                    "subject_position": "left third or center-left",
                    "text_position": "right third",
                    "background": "blurred contextual background with glow or gradient",
                    "expression": "surprised, focused, skeptical, or confident",
                }
            )

        elif layout == LayoutPattern.BEFORE_AFTER:
            base.update(
                {
                    "subject_position": "split left/right",
                    "text_position": "top center or center divider",
                    "background": "left side darker/problem, right side brighter/result",
                    "divider": "bold vertical divider or arrow",
                }
            )

        elif layout == LayoutPattern.SPLIT_SCREEN:
            base.update(
                {
                    "subject_position": "two opposing panels",
                    "text_position": "center or top",
                    "background": "contrasting colors for each side",
                    "divider": "diagonal or vertical split",
                }
            )

        elif layout == LayoutPattern.PRODUCT_CLOSEUP:
            base.update(
                {
                    "subject_position": "large closeup center",
                    "text_position": "top-left or bottom-right",
                    "background": "clean gradient, dashboard, or product context",
                    "proof_cue": "visible result, stat, chart, or interface detail",
                }
            )

        elif layout == LayoutPattern.PROBLEM_SOLUTION:
            base.update(
                {
                    "subject_position": "problem icon or frustrated subject on one side",
                    "text_position": "large center-right",
                    "background": "dark problem area with bright solution cue",
                    "solution_cue": "arrow, checkmark, glow, or clean result card",
                }
            )

        elif layout == LayoutPattern.BIG_NUMBER:
            base.update(
                {
                    "subject_position": "number dominates center",
                    "text_position": "supporting text below or side",
                    "background": "simple high-contrast background",
                    "number_style": "oversized, bold, dimensional",
                }
            )

        elif layout == LayoutPattern.AUTHORITY_FRAME:
            base.update(
                {
                    "subject_position": "expert/persona or brand visual center-left",
                    "text_position": "right side in clean block",
                    "background": "premium office, dashboard, or clean studio look",
                    "trust_cues": "badge, chart, verified-style mark, or professional lighting",
                }
            )

        elif layout == LayoutPattern.MINIMAL_PROMISE:
            base.update(
                {
                    "subject_position": "single centered subject or icon",
                    "text_position": "large centered or bottom third",
                    "background": "minimal gradient with brand color accent",
                    "negative_space": "intentionally high",
                }
            )

        elif layout == LayoutPattern.SHOCK_REVEAL:
            base.update(
                {
                    "subject_position": "revealed object/result in center",
                    "text_position": "top or side with warning-like contrast",
                    "background": "dramatic lighting and shadow",
                    "reveal_cue": "circle, arrow, red flag, or magnifier",
                }
            )

        elif layout == LayoutPattern.CHECKLIST:
            base.update(
                {
                    "subject_position": "checklist card or steps on one side",
                    "text_position": "large headline above checklist",
                    "background": "clean workspace or digital dashboard",
                    "clarity_cue": "numbered steps or ticks",
                }
            )

        return base

    def _visual_elements(
        self,
        request: ThumbnailRequest,
        layout: LayoutPattern,
        index: int,
    ) -> List[str]:
        """Recommend visual elements."""

        subject = self._derive_subject(request)
        elements = [subject]

        topic = f"{request.title} {request.topic}".lower()

        if "seo" in topic:
            elements.extend(["ranking chart", "search bar", "green growth arrow", "website preview"])
        elif "ads" in topic or "ppc" in topic:
            elements.extend(["ad dashboard", "cost warning icon", "performance graph", "click indicator"])
        elif "website" in topic or "web" in topic:
            elements.extend(["website mockup", "laptop screen", "conversion section", "modern UI cards"])
        elif "ai" in topic or "automation" in topic:
            elements.extend(["AI interface", "automation nodes", "chat bubble", "glowing circuit pattern"])
        elif "video" in topic or "content" in topic:
            elements.extend(["timeline strip", "play button", "camera frame", "retention graph"])
        else:
            elements.extend(["bold icon", "context background", "result cue"])

        if layout in {LayoutPattern.BEFORE_AFTER, LayoutPattern.SPLIT_SCREEN}:
            elements.extend(["contrast divider", "before side", "after side"])

        if layout == LayoutPattern.BIG_NUMBER:
            numbers = _extract_numbers(f"{request.title} {request.topic}")
            elements.append(f"large number {numbers[0] if numbers else '1'}")

        if layout in {LayoutPattern.SHOCK_REVEAL, LayoutPattern.PROBLEM_SOLUTION}:
            elements.extend(["arrow annotation", "warning mark", "highlight circle"])

        return _dedupe_preserve_order(elements)

    def _color_direction(self, request: ThumbnailRequest, index: int) -> Dict[str, Any]:
        """Create color direction from brand style."""

        style = self._merge_brand_style(request.brand_style)
        alternates = [
            {
                "background": style.get("dark_color", "#101010"),
                "accent": style.get("primary_color", "#6400B3"),
                "text": style.get("heading_color", "#FFFFFF"),
                "support": style.get("light_color", "#D9D9D9"),
            },
            {
                "background": "deep gradient using brand dark color",
                "accent": style.get("primary_color", "#6400B3"),
                "text": "#FFFFFF",
                "support": "soft neutral highlight",
            },
            {
                "background": "clean light/dark split",
                "accent": style.get("primary_color", "#6400B3"),
                "text": "white or near-black depending on panel",
                "support": style.get("light_color", "#D9D9D9"),
            },
        ]

        selected = alternates[index % len(alternates)]
        return {
            **selected,
            "contrast_rule": "Keep headline and subject separated from background.",
            "brand_consistency": "Use brand accent as highlight, border, glow, underline, or shape.",
        }

    def _typography_direction(self, request: ThumbnailRequest, text: str) -> Dict[str, Any]:
        """Recommend typography treatment."""

        style = self._merge_brand_style(request.brand_style)
        word_count = len(text.split())

        return {
            "headline_style": style.get("font_style", "bold modern sans-serif"),
            "case": "uppercase",
            "max_words": 5,
            "current_word_count": word_count,
            "stroke_or_shadow": "Use subtle stroke or shadow for mobile readability.",
            "hierarchy": "Make one word visually dominant if the phrase has more than three words.",
            "spacing": "Tight but readable letter spacing.",
            "warning": None if word_count <= 5 else "Text may be too long for mobile thumbnail readability.",
        }

    def _emotion_for(
        self,
        request: ThumbnailRequest,
        layout: LayoutPattern,
        index: int,
    ) -> str:
        """Recommend emotional direction."""

        tone = request.tone.lower()

        if layout == LayoutPattern.SHOCK_REVEAL:
            return "surprise and urgency"
        if layout == LayoutPattern.PROBLEM_SOLUTION:
            return "pain relief and clarity"
        if layout == LayoutPattern.BEFORE_AFTER:
            return "transformation and satisfaction"
        if layout == LayoutPattern.AUTHORITY_FRAME:
            return "confidence and trust"
        if layout == LayoutPattern.MINIMAL_PROMISE:
            return "premium confidence"

        tone_map = {
            ThumbnailTone.PREMIUM.value: "confidence and exclusivity",
            ThumbnailTone.DRAMATIC.value: "shock and tension",
            ThumbnailTone.EDUCATIONAL.value: "clarity and usefulness",
            ThumbnailTone.CURIOSITY.value: "curiosity and open loop",
            ThumbnailTone.URGENT.value: "urgency and action",
            ThumbnailTone.CLEAN.value: "simplicity and trust",
            ThumbnailTone.CINEMATIC.value: "drama and story",
            ThumbnailTone.FUN.value: "playfulness and surprise",
            ThumbnailTone.AUTHORITY.value: "expertise and certainty",
            ThumbnailTone.TRANSFORMATION.value: "progress and achievement",
        }

        return tone_map.get(tone, "curiosity and clarity")

    def _expected_strengths(
        self,
        layout: LayoutPattern,
        request: ThumbnailRequest,
    ) -> List[str]:
        """Expected strengths by layout."""

        strengths = {
            LayoutPattern.FACE_REACTION_TEXT: [
                "Fast emotional recognition",
                "Strong mobile readability",
                "Works well for curiosity-led content",
            ],
            LayoutPattern.BEFORE_AFTER: [
                "Clear transformation promise",
                "Easy to understand without reading much",
                "Strong for tutorials, case studies, and improvements",
            ],
            LayoutPattern.SPLIT_SCREEN: [
                "Strong contrast between choices",
                "Good for mistake-versus-solution framing",
                "Creates visual tension",
            ],
            LayoutPattern.PRODUCT_CLOSEUP: [
                "Shows tangible proof",
                "Good for demos and offer-led videos",
                "Builds trust through specificity",
            ],
            LayoutPattern.PROBLEM_SOLUTION: [
                "Makes viewer pain obvious",
                "Clear reason to click",
                "Good for educational and business content",
            ],
            LayoutPattern.BIG_NUMBER: [
                "Simple curiosity trigger",
                "Numbers are easy to scan",
                "Good for lists, results, and case studies",
            ],
            LayoutPattern.AUTHORITY_FRAME: [
                "Builds credibility",
                "Fits B2B and mature audiences",
                "Less clickbait, more trust",
            ],
            LayoutPattern.MINIMAL_PROMISE: [
                "Premium feel",
                "Low clutter",
                "Strong brand consistency",
            ],
            LayoutPattern.SHOCK_REVEAL: [
                "High curiosity",
                "Strong pattern interruption",
                "Good for hidden mistake or warning topics",
            ],
            LayoutPattern.CHECKLIST: [
                "Clear practical value",
                "Good for educational content",
                "Signals structure and usefulness",
            ],
        }

        return strengths.get(layout, ["Clear visual direction", "Readable thumbnail promise"])

    def _testing_hypothesis(
        self,
        layout: LayoutPattern,
        text: str,
        request: ThumbnailRequest,
    ) -> str:
        """Create testing hypothesis."""

        if layout == LayoutPattern.AUTHORITY_FRAME:
            return f"Using a trust-led expert frame with '{text}' should attract higher-quality viewers."
        if layout == LayoutPattern.SHOCK_REVEAL:
            return f"Using a surprise-led reveal with '{text}' should increase curiosity-driven CTR."
        if layout == LayoutPattern.BEFORE_AFTER:
            return f"Showing transformation with '{text}' should make the outcome easier to understand."
        if layout == LayoutPattern.PROBLEM_SOLUTION:
            return f"Making the pain point obvious with '{text}' should improve relevance and clicks."
        return f"The '{layout.value.replace('_', ' ')}' layout with '{text}' should improve thumbnail clarity."

    def _alternate_text_for(self, primary_text: str, options: Sequence[str]) -> List[str]:
        """Pick alternate text options different from primary."""

        alternates = [option for option in options if option != primary_text]
        return list(alternates[:4])

    def _risk_notes_for(
        self,
        request: ThumbnailRequest,
        assessment: SecurityAssessment,
    ) -> List[str]:
        """Create risk notes for concept output."""

        notes = []
        if assessment.requires_security:
            notes.append("Security Agent review recommended before publishing or generating final asset.")
            notes.extend(assessment.reasons)
        else:
            notes.append("No obvious high-risk creative issue detected in thumbnail planning.")

        notes.append("Avoid misleading visual promises that the video does not fulfill.")
        notes.append("Avoid using real-person likeness without proper rights or consent.")
        return notes

    def _thumbnail_design_rules(self, request: ThumbnailRequest) -> Dict[str, Any]:
        """Return general design rules."""

        platform_profile = self._platform_profile(request.platform)

        return {
            "platform": request.platform,
            "recommended_ratio": platform_profile.get("recommended_ratio"),
            "recommended_size": platform_profile.get("recommended_size"),
            "rules": [
                "Use one main idea only.",
                "Keep text short, preferably 2 to 5 words.",
                "Make the subject recognizable at small size.",
                "Use strong contrast between text and background.",
                "Avoid clutter, tiny UI details, and long sentences.",
                "Match the thumbnail promise to the video content.",
                "Keep user/workspace assets isolated when passing to Asset Manager or Visual Agent.",
            ],
        }

    def _safe_area_notes(self, platform: str) -> List[str]:
        """Safe area guidance by platform."""

        if platform in {"youtube_shorts", "tiktok", "instagram_reels"}:
            return [
                "Keep face/product/text near center vertical safe area.",
                "Avoid placing key text at bottom where UI captions and controls may cover it.",
                "Avoid placing key details near the right edge where platform icons may overlap.",
            ]

        if platform == "youtube":
            return [
                "Keep headline large enough for mobile home feed.",
                "Avoid tiny text in corners.",
                "Leave edge padding so text is not cropped in previews.",
            ]

        return [
            "Keep important subject and text away from edges.",
            "Preview at small size before publishing.",
        ]

    def _build_dashboard_summary(
        self,
        request: ThumbnailRequest,
        concepts: Sequence[Mapping[str, Any]],
        security_assessment: SecurityAssessment,
    ) -> Dict[str, Any]:
        """Build concise dashboard/API summary."""

        top = concepts[0] if concepts else {}
        return {
            "title": request.title,
            "topic": request.topic,
            "platform": request.platform,
            "concept_count": len(concepts),
            "top_recommendation": {
                "concept_id": top.get("concept_id"),
                "name": top.get("name"),
                "recommended_text": top.get("recommended_text"),
                "strategic_angle": top.get("strategic_angle"),
            },
            "risk_level": security_assessment.risk_level,
            "requires_security_review": security_assessment.requires_security,
            "next_steps": [
                "Choose one or two concepts.",
                "Send selected concept to Visual Agent or designer.",
                "Generate final thumbnail image.",
                "Verify readability at mobile size.",
                "Run A/B test if platform supports it.",
            ],
        }

    def _variant_difference_note(self, idx: int, concept: Mapping[str, Any]) -> str:
        """Explain what changes in an A/B variant."""

        if idx == 1:
            return "Primary concept, strongest overall strategic fit."
        if idx == 2:
            return "Different visual layout and emotional trigger."
        if idx == 3:
            return "Different text promise and composition intensity."
        return "Alternative color, hierarchy, or curiosity angle."

    def _curiosity_score(self, text: str) -> int:
        """Score curiosity strength from text."""

        lowered = text.lower()
        score = 4

        curiosity_terms = [
            "why", "truth", "secret", "hidden", "stop", "don't", "wrong",
            "real", "tested", "changed", "before", "after", "fix",
        ]
        for term in curiosity_terms:
            if term in lowered:
                score += 1

        if "?" in text:
            score += 1

        if _extract_numbers(text):
            score += 1

        if len(text.split()) <= 4:
            score += 1

        return max(1, min(score, 10))

    def _text_recommendation(self, score: float) -> str:
        """Return recommendation label for text score."""

        if score >= 8:
            return "Strong option. Good candidate for first test."
        if score >= 6.5:
            return "Good option. Consider testing with stronger visual contrast."
        if score >= 5:
            return "Usable, but simplify or increase curiosity."
        return "Weak option. Rewrite for clarity and shorter mobile readability."


# ---------------------------------------------------------------------------
# Convenience functions for direct module use
# ---------------------------------------------------------------------------

def generate_thumbnail_package(task: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Convenience function for API routes, tests, or scripts.

    Example:
        result = generate_thumbnail_package({
            "user_id": "user_123",
            "workspace_id": "workspace_123",
            "title": "Why Your Website Is Not Getting Leads",
            "topic": "Website conversion mistakes",
            "platform": "youtube",
        })
    """

    return ThumbnailDesigner().generate_thumbnail_package(task)


def generate_thumbnail_concepts(task: Mapping[str, Any]) -> Dict[str, Any]:
    """Convenience function for concept-only generation."""

    return ThumbnailDesigner().generate_thumbnail_concepts(task)


def build_image_prompt(task: Mapping[str, Any]) -> Dict[str, Any]:
    """Convenience function for prompt-only generation."""

    designer = ThumbnailDesigner()
    request = designer._build_request(task)
    return designer._safe_result(
        message="Thumbnail image prompt generated successfully.",
        data=designer.build_image_prompt(request),
        metadata=designer._metadata(request),
    )


__all__ = [
    "ThumbnailDesigner",
    "ThumbnailRequest",
    "ThumbnailConcept",
    "SecurityAssessment",
    "ThumbnailTone",
    "ThumbnailGoal",
    "LayoutPattern",
    "generate_thumbnail_package",
    "generate_thumbnail_concepts",
    "build_image_prompt",
]


if __name__ == "__main__":
    # Safe local smoke test. Does not perform external actions.
    logging.basicConfig(level=logging.INFO)

    sample_task = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "title": "Why Your Website Is Not Getting Leads",
        "topic": "Website conversion mistakes for service businesses",
        "platform": "youtube",
        "audience": "mature business owners",
        "video_type": "educational",
        "goal": "lead_generation",
        "tone": "authority",
        "brand_name": "gronotix",
        "keywords": ["website leads", "conversion", "business growth"],
        "variants": 3,
    }

    result = generate_thumbnail_package(sample_task)
    print(result)