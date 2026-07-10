"""
agents/super_agents/creator_agent/creator_agent.py

Creator Agent for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Content and video production brain for scripts, VEO prompts, editing plans,
    captions, thumbnails, and content calendars.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent does not exist yet.
    - Agent Registry / Agent Loader compatible via AGENT_METADATA and create_agent().
    - Master Agent routing compatible via run(), handle_task(), route_task().
    - SaaS isolation enforced through user_id and workspace_id validation.
    - Security Agent handoff ready for sensitive, external, brand-risk, or publish-like actions.
    - Verification Agent payload prepared for every completed action.
    - Memory Agent payload prepared for safe reusable creative preferences only.
    - Dashboard/API ready through structured dict results.

Important Safety Rule:
    This agent prepares creative content and production plans only.
    It does not directly publish, upload, send, edit real files, call APIs,
    execute browser actions, or perform destructive actions.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Safe optional imports / fallback stubs
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent should provide richer lifecycle, telemetry,
        permissions, and routing features.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = kwargs.get("logger", logging.getLogger(self.agent_name))

        def run(self, task: Mapping[str, Any], *args: Any, **kwargs: Any) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.run() is not implemented.")


try:
    from agents.registry import register_agent  # type: ignore
except Exception:  # pragma: no cover
    def register_agent(*args: Any, **kwargs: Any) -> Callable[[Any], Any]:
        """Fallback decorator for future Agent Registry compatibility."""

        def decorator(cls: Any) -> Any:
            return cls

        return decorator


# ======================================================================================
# Constants and Metadata
# ======================================================================================

AGENT_NAME = "CreatorAgent"
AGENT_SLUG = "creator_agent"
AGENT_VERSION = "1.0.0"
AGENT_CATEGORY = "super_agent"
AGENT_DESCRIPTION = (
    "Content and video production brain for scripts, VEO prompts, editing plans, "
    "captions, thumbnails, and content calendars."
)

AGENT_METADATA: Dict[str, Any] = {
    "name": AGENT_NAME,
    "slug": AGENT_SLUG,
    "version": AGENT_VERSION,
    "category": AGENT_CATEGORY,
    "description": AGENT_DESCRIPTION,
    "file_path": "agents/super_agents/creator_agent/creator_agent.py",
    "class_name": "CreatorAgent",
    "capabilities": [
        "script_writing",
        "video_prompt_generation",
        "veo_prompt_generation",
        "editing_plan_generation",
        "caption_generation",
        "thumbnail_brief_generation",
        "content_calendar_generation",
        "creative_brief_generation",
        "brand_style_application",
        "short_form_content_planning",
        "production_checklist_generation",
    ],
    "safe_actions_only": True,
    "requires_user_context": True,
    "requires_workspace_context": True,
    "security_handoff_supported": True,
    "memory_payload_supported": True,
    "verification_payload_supported": True,
    "dashboard_ready": True,
    "router_keywords": [
        "creator",
        "content",
        "video",
        "script",
        "caption",
        "thumbnail",
        "veo",
        "shorts",
        "reels",
        "tiktok",
        "youtube",
        "calendar",
        "editing plan",
        "voiceover",
        "storyboard",
    ],
}

DEFAULT_CHANNELS = [
    "youtube_shorts",
    "youtube_long",
    "instagram_reels",
    "tiktok",
    "facebook_reels",
    "linkedin",
    "x_twitter",
    "blog",
]

DEFAULT_CONTENT_GOALS = [
    "awareness",
    "engagement",
    "lead_generation",
    "conversion",
    "education",
    "authority",
    "retention",
]

DEFAULT_TONES = [
    "professional",
    "friendly",
    "premium",
    "direct",
    "educational",
    "cinematic",
    "storytelling",
    "sales_focused",
]

SENSITIVE_CREATIVE_PATTERNS = [
    r"\bguarantee(d)?\s+(results?|income|ranking|profit|sales)\b",
    r"\b100%\s+(guarantee|safe|risk[- ]?free)\b",
    r"\bmedical\s+advice\b",
    r"\blegal\s+advice\b",
    r"\bfinancial\s+advice\b",
    r"\binvestment\s+advice\b",
    r"\bdeepfake\b",
    r"\bimpersonat(e|ion|ing)\b",
    r"\buse\s+someone'?s\s+face\b",
    r"\bcelebrity\b",
    r"\bpolitical\s+ad\b",
    r"\belection\b",
    r"\battack\s+ad\b",
    r"\bdefame\b",
    r"\bmislead(ing)?\b",
    r"\bfake\s+testimonial\b",
    r"\bfake\s+review\b",
    r"\bpublish\b",
    r"\bupload\b",
    r"\bpost\s+it\b",
    r"\bsend\s+it\b",
]

PROHIBITED_DIRECT_ACTIONS = {
    "publish",
    "upload",
    "post",
    "send",
    "delete",
    "remove_live",
    "modify_live_asset",
    "charge",
    "transfer",
    "call",
    "browser_execute",
}

SUPPORTED_TASK_TYPES = {
    "create_script",
    "write_script",
    "generate_script",
    "build_veo_prompt",
    "generate_veo_prompt",
    "video_prompt",
    "editing_plan",
    "create_editing_plan",
    "captions",
    "generate_captions",
    "thumbnail",
    "thumbnail_brief",
    "content_calendar",
    "create_content_calendar",
    "creative_brief",
    "production_plan",
    "short_form_plan",
    "repurpose_content",
    "brand_content_pack",
    "route",
}


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger(AGENT_NAME)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ======================================================================================
# Data Structures
# ======================================================================================

class CreatorTaskType(str, Enum):
    """Supported Creator Agent task types."""

    SCRIPT = "create_script"
    VEO_PROMPT = "build_veo_prompt"
    EDITING_PLAN = "editing_plan"
    CAPTIONS = "generate_captions"
    THUMBNAIL_BRIEF = "thumbnail_brief"
    CONTENT_CALENDAR = "content_calendar"
    CREATIVE_BRIEF = "creative_brief"
    PRODUCTION_PLAN = "production_plan"
    SHORT_FORM_PLAN = "short_form_plan"
    REPURPOSE_CONTENT = "repurpose_content"
    BRAND_CONTENT_PACK = "brand_content_pack"
    ROUTE = "route"


@dataclass
class CreatorContext:
    """
    SaaS context for safe per-user and per-workspace task execution.

    This object prevents accidental mixing of creative briefs, brand data,
    calendars, task history, memory, or audit logs between users/workspaces.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    locale: str = "en-US"
    timezone: str = "UTC"
    source: str = "api"
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BrandStyle:
    """Reusable brand style hints for content generation."""

    brand_name: str = "Digital Promotix"
    tone: str = "professional"
    audience: str = "business owners"
    primary_offer: Optional[str] = None
    unique_value: Optional[str] = None
    forbidden_terms: List[str] = field(default_factory=list)
    preferred_terms: List[str] = field(default_factory=list)
    colors: List[str] = field(default_factory=list)
    cta: Optional[str] = None
    compliance_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CreatorConfig:
    """Safe default configuration for Creator Agent."""

    max_calendar_days: int = 90
    default_calendar_days: int = 30
    max_caption_variants: int = 20
    default_caption_variants: int = 5
    max_script_scenes: int = 20
    max_hooks: int = 10
    default_video_duration_seconds: int = 30
    allow_sensitive_without_security: bool = False
    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True
    strict_context_validation: bool = True
    default_brand_style: BrandStyle = field(default_factory=BrandStyle)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class SecurityDecision:
    """Represents whether a task should be handed to Security Agent."""

    required: bool
    reason: str
    risk_level: str = "low"
    matched_patterns: List[str] = field(default_factory=list)
    blocked_direct_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ======================================================================================
# Utility helpers
# ======================================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    """Safely convert any value to stripped string."""
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


def _slugify(value: str) -> str:
    """Create safe slug text."""
    text = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower())
    return re.sub(r"_+", "_", text).strip("_") or "item"


def _hash_payload(payload: Mapping[str, Any]) -> str:
    """Create deterministic hash for payload references without exposing secrets."""
    try:
        serialized = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        serialized = str(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _truncate(text: str, limit: int = 5000) -> str:
    """Truncate long text safely."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 20)].rstrip() + "...[truncated]"


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """Deduplicate strings while preserving order."""
    seen = set()
    result = []
    for item in items:
        normalized = _safe_str(item)
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def _extract_task_text(task: Mapping[str, Any]) -> str:
    """Extract most useful text fields from a task for intent/risk checks."""
    parts: List[str] = []
    for key in (
        "task",
        "type",
        "intent",
        "prompt",
        "topic",
        "brief",
        "description",
        "source_content",
        "goal",
        "cta",
        "platform",
        "channel",
    ):
        if key in task:
            value = task.get(key)
            if isinstance(value, (str, int, float, bool)):
                parts.append(str(value))
            elif isinstance(value, Mapping):
                parts.append(json.dumps(value, default=str))
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                parts.extend(str(v) for v in value)
    return " ".join(parts)


def _normalize_task_type(task_type: str) -> str:
    """Normalize task type aliases into canonical CreatorTaskType values."""
    raw = _slugify(task_type)
    aliases = {
        "script": CreatorTaskType.SCRIPT.value,
        "write_script": CreatorTaskType.SCRIPT.value,
        "generate_script": CreatorTaskType.SCRIPT.value,
        "create_script": CreatorTaskType.SCRIPT.value,
        "veo": CreatorTaskType.VEO_PROMPT.value,
        "veo_prompt": CreatorTaskType.VEO_PROMPT.value,
        "generate_veo_prompt": CreatorTaskType.VEO_PROMPT.value,
        "video_prompt": CreatorTaskType.VEO_PROMPT.value,
        "editing": CreatorTaskType.EDITING_PLAN.value,
        "edit_plan": CreatorTaskType.EDITING_PLAN.value,
        "editing_plan": CreatorTaskType.EDITING_PLAN.value,
        "captions": CreatorTaskType.CAPTIONS.value,
        "caption": CreatorTaskType.CAPTIONS.value,
        "generate_captions": CreatorTaskType.CAPTIONS.value,
        "thumbnail": CreatorTaskType.THUMBNAIL_BRIEF.value,
        "thumbnail_brief": CreatorTaskType.THUMBNAIL_BRIEF.value,
        "content_calendar": CreatorTaskType.CONTENT_CALENDAR.value,
        "calendar": CreatorTaskType.CONTENT_CALENDAR.value,
        "creative_brief": CreatorTaskType.CREATIVE_BRIEF.value,
        "brief": CreatorTaskType.CREATIVE_BRIEF.value,
        "production_plan": CreatorTaskType.PRODUCTION_PLAN.value,
        "short_form": CreatorTaskType.SHORT_FORM_PLAN.value,
        "short_form_plan": CreatorTaskType.SHORT_FORM_PLAN.value,
        "repurpose": CreatorTaskType.REPURPOSE_CONTENT.value,
        "repurpose_content": CreatorTaskType.REPURPOSE_CONTENT.value,
        "brand_content_pack": CreatorTaskType.BRAND_CONTENT_PACK.value,
        "route": CreatorTaskType.ROUTE.value,
    }
    return aliases.get(raw, raw)


# ======================================================================================
# Creator Agent
# ======================================================================================

@register_agent(name=AGENT_SLUG, metadata=AGENT_METADATA)
class CreatorAgent(BaseAgent):
    """
    Main Creator Agent for William/Jarvis.

    Responsibilities:
        - Prepare scripts for videos, ads, social content, and voiceover.
        - Build VEO/video generation prompts.
        - Create editing plans and shot-by-shot production plans.
        - Generate captions and social copy variants.
        - Produce thumbnail creative briefs.
        - Build content calendars.
        - Prepare safe creative briefs and brand content packs.

    This class intentionally does not:
        - Publish content.
        - Upload media.
        - Edit real user files directly.
        - Call external browser/video/image APIs.
        - Make financial, legal, medical, or high-risk claims.
    """

    def __init__(
        self,
        config: Optional[Union[CreatorConfig, Mapping[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger_override: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(
                agent_name=AGENT_NAME,
                agent_id=AGENT_SLUG,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.agent_name = AGENT_NAME
        self.agent_id = AGENT_SLUG
        self.version = AGENT_VERSION
        self.metadata = copy.deepcopy(AGENT_METADATA)
        self.logger = logger_override or getattr(self, "logger", logger)

        self.config = self._build_config(config)
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

    # -------------------------------------------------------------------------
    # Public Master Agent / Router interfaces
    # -------------------------------------------------------------------------

    def run(self, task: Mapping[str, Any], *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Main entrypoint expected by BaseAgent, Agent Router, and Master Agent.

        Args:
            task: Structured task dictionary. Must include user_id and workspace_id.

        Returns:
            Structured result dict with success, message, data, error, metadata.
        """
        return self.handle_task(task=task, *args, **kwargs)

    def handle_task(self, task: Mapping[str, Any], *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Handle a Creator Agent task.

        Supported task types:
            - create_script
            - build_veo_prompt
            - editing_plan
            - generate_captions
            - thumbnail_brief
            - content_calendar
            - creative_brief
            - production_plan
            - short_form_plan
            - repurpose_content
            - brand_content_pack
        """
        started_at = _utc_now_iso()

        try:
            if not isinstance(task, Mapping):
                return self._error_result(
                    message="Task must be a mapping/dictionary.",
                    error="invalid_task_type",
                    metadata={"started_at": started_at},
                )

            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            context = context_result["data"]["context"]
            task_copy = dict(task)

            security_decision = self._requires_security_check(task_copy)
            if security_decision.required:
                approval_result = self._request_security_approval(
                    task=task_copy,
                    context=context,
                    decision=security_decision,
                )
                if not approval_result.get("success"):
                    return self._safe_result(
                        success=False,
                        message="Creator task requires Security Agent approval before continuing.",
                        data={
                            "security_required": True,
                            "security_decision": security_decision.to_dict(),
                            "approval": approval_result,
                        },
                        error="security_approval_required",
                        metadata=self._base_metadata(context, started_at),
                    )

            task_type = _normalize_task_type(
                _safe_str(task_copy.get("type") or task_copy.get("task_type") or task_copy.get("intent") or "route")
            )

            dispatch: Dict[str, Callable[[Mapping[str, Any], CreatorContext], Dict[str, Any]]] = {
                CreatorTaskType.SCRIPT.value: self.create_script,
                CreatorTaskType.VEO_PROMPT.value: self.build_veo_prompt,
                CreatorTaskType.EDITING_PLAN.value: self.create_editing_plan,
                CreatorTaskType.CAPTIONS.value: self.generate_captions,
                CreatorTaskType.THUMBNAIL_BRIEF.value: self.create_thumbnail_brief,
                CreatorTaskType.CONTENT_CALENDAR.value: self.create_content_calendar,
                CreatorTaskType.CREATIVE_BRIEF.value: self.create_creative_brief,
                CreatorTaskType.PRODUCTION_PLAN.value: self.create_production_plan,
                CreatorTaskType.SHORT_FORM_PLAN.value: self.create_short_form_plan,
                CreatorTaskType.REPURPOSE_CONTENT.value: self.repurpose_content,
                CreatorTaskType.BRAND_CONTENT_PACK.value: self.create_brand_content_pack,
                CreatorTaskType.ROUTE.value: self.route_task,
            }

            handler = dispatch.get(task_type)
            if handler is None:
                routed_type = self._infer_task_type(task_copy)
                handler = dispatch.get(routed_type, self.route_task)
                task_copy["type"] = routed_type

            self._emit_agent_event(
                event_type="creator_task_started",
                context=context,
                payload={"task_type": task_copy.get("type", task_type), "security": security_decision.to_dict()},
            )

            result = handler(task_copy, context)

            verification_payload = self._prepare_verification_payload(
                task=task_copy,
                context=context,
                result=result,
            )
            memory_payload = self._prepare_memory_payload(
                task=task_copy,
                context=context,
                result=result,
            )

            if result.get("success"):
                result.setdefault("data", {})
                result["data"]["verification_payload"] = verification_payload
                result["data"]["memory_payload"] = memory_payload

            self._log_audit_event(
                action="creator_task_completed" if result.get("success") else "creator_task_failed",
                context=context,
                payload={
                    "task_type": task_copy.get("type", task_type),
                    "success": result.get("success"),
                    "message": result.get("message"),
                    "error": result.get("error"),
                    "verification_payload_id": verification_payload.get("verification_id"),
                    "memory_payload_id": memory_payload.get("memory_id"),
                },
            )

            self._emit_agent_event(
                event_type="creator_task_completed" if result.get("success") else "creator_task_failed",
                context=context,
                payload={
                    "task_type": task_copy.get("type", task_type),
                    "success": result.get("success"),
                    "error": result.get("error"),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("CreatorAgent.handle_task failed.")
            return self._error_result(
                message="Creator Agent failed to handle task safely.",
                error=str(exc),
                metadata={"started_at": started_at, "agent": AGENT_SLUG},
            )

    def route_task(self, task: Mapping[str, Any], context: Optional[CreatorContext] = None) -> Dict[str, Any]:
        """
        Infer and route a task when Master Agent sends a broad creative request.
        """
        if context is None:
            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result
            context = context_result["data"]["context"]

        inferred = self._infer_task_type(task)
        routed_task = dict(task)
        routed_task["type"] = inferred

        if inferred == CreatorTaskType.SCRIPT.value:
            return self.create_script(routed_task, context)
        if inferred == CreatorTaskType.VEO_PROMPT.value:
            return self.build_veo_prompt(routed_task, context)
        if inferred == CreatorTaskType.EDITING_PLAN.value:
            return self.create_editing_plan(routed_task, context)
        if inferred == CreatorTaskType.CAPTIONS.value:
            return self.generate_captions(routed_task, context)
        if inferred == CreatorTaskType.THUMBNAIL_BRIEF.value:
            return self.create_thumbnail_brief(routed_task, context)
        if inferred == CreatorTaskType.CONTENT_CALENDAR.value:
            return self.create_content_calendar(routed_task, context)
        if inferred == CreatorTaskType.REPURPOSE_CONTENT.value:
            return self.repurpose_content(routed_task, context)

        return self.create_creative_brief(routed_task, context)

    # -------------------------------------------------------------------------
    # Creator-specific public methods
    # -------------------------------------------------------------------------

    def create_script(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a video/content script with hook, scenes, voiceover, on-screen text,
        CTA, and production notes.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "Untitled topic")
        platform = _safe_str(task.get("platform") or task.get("channel"), "youtube_shorts")
        goal = _safe_str(task.get("goal"), "lead_generation")
        duration = self._safe_int(task.get("duration_seconds"), self.config.default_video_duration_seconds, 5, 1800)
        audience = _safe_str(task.get("audience"), self.config.default_brand_style.audience)
        brand = self._brand_style_from_task(task)
        tone = _safe_str(task.get("tone"), brand.tone or "professional")
        offer = _safe_str(task.get("offer") or brand.primary_offer, "your offer")
        cta = _safe_str(task.get("cta") or brand.cta, "Contact us to learn more.")
        scene_count = self._safe_int(task.get("scene_count"), self._suggest_scene_count(duration), 1, self.config.max_script_scenes)

        hooks = self._generate_hooks(topic=topic, audience=audience, goal=goal, tone=tone)
        scenes = self._generate_script_scenes(
            topic=topic,
            platform=platform,
            goal=goal,
            duration=duration,
            audience=audience,
            brand=brand,
            offer=offer,
            cta=cta,
            scene_count=scene_count,
        )
        voiceover = self._compose_voiceover(scenes)
        shot_list = self._build_shot_list(scenes, platform)
        production_notes = self._build_production_notes(platform=platform, tone=tone, duration=duration)

        script = {
            "title": self._generate_title(topic, platform),
            "topic": topic,
            "platform": platform,
            "goal": goal,
            "duration_seconds": duration,
            "audience": audience,
            "brand": brand.to_dict(),
            "tone": tone,
            "offer": offer,
            "cta": cta,
            "hooks": hooks,
            "recommended_hook": hooks[0] if hooks else "",
            "scenes": scenes,
            "voiceover_script": voiceover,
            "shot_list": shot_list,
            "on_screen_text": [scene["on_screen_text"] for scene in scenes],
            "production_notes": production_notes,
            "compliance_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Script prepared successfully.",
            data={"script": script},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.SCRIPT.value),
        )

    def build_veo_prompt(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Build a structured VEO/video-generation prompt.

        This prepares prompt text only. It does not call VEO or any external model.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "cinematic product video")
        platform = _safe_str(task.get("platform") or task.get("channel"), "youtube_shorts")
        duration = self._safe_int(task.get("duration_seconds"), self.config.default_video_duration_seconds, 5, 120)
        style = _safe_str(task.get("visual_style") or task.get("style"), "cinematic, realistic, high-end commercial")
        aspect_ratio = _safe_str(task.get("aspect_ratio"), self._default_aspect_ratio(platform))
        brand = self._brand_style_from_task(task)
        mood = _safe_str(task.get("mood"), "confident, premium, energetic")
        camera = _safe_str(task.get("camera"), "smooth tracking shots, subtle handheld realism, natural motion blur")
        lighting = _safe_str(task.get("lighting"), "soft cinematic lighting with clean contrast")
        negative = _safe_str(
            task.get("negative_prompt"),
            "no distorted text, no extra limbs, no warped faces, no fake logos, no copyrighted characters",
        )

        scene_prompt = (
            f"Create a {duration}-second {aspect_ratio} video for {platform}. "
            f"Topic: {topic}. Visual style: {style}. Mood: {mood}. "
            f"Brand feel: {brand.tone}; audience: {brand.audience}. "
            f"Camera direction: {camera}. Lighting: {lighting}. "
            "Use clear subject focus, natural motion, realistic pacing, and clean transitions. "
            "Avoid unreadable text overlays; leave safe empty space for captions and logo placement."
        )

        veo_prompt = {
            "model_family": "veo_or_video_generation_model",
            "prompt": scene_prompt,
            "negative_prompt": negative,
            "duration_seconds": duration,
            "aspect_ratio": aspect_ratio,
            "platform": platform,
            "style": style,
            "mood": mood,
            "camera": camera,
            "lighting": lighting,
            "brand": brand.to_dict(),
            "shot_sequence": self._generate_veo_shot_sequence(topic, duration),
            "caption_safe_zones": self._caption_safe_zones(platform),
            "post_generation_editing_notes": [
                "Add final branded end card manually.",
                "Add captions in editing software for reliable readability.",
                "Check all generated text and faces before publishing.",
                "Run final output through Verification Agent before any external posting.",
            ],
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="VEO/video generation prompt prepared successfully.",
            data={"veo_prompt": veo_prompt},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.VEO_PROMPT.value),
        )

    def create_editing_plan(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a video editing plan with timeline, cuts, captions, music, B-roll,
        assets, quality checks, and export settings.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "video edit")
        platform = _safe_str(task.get("platform") or task.get("channel"), "youtube_shorts")
        duration = self._safe_int(task.get("duration_seconds"), self.config.default_video_duration_seconds, 5, 1800)
        style = _safe_str(task.get("style"), "clean, fast-paced, premium")
        brand = self._brand_style_from_task(task)

        timeline = self._build_editing_timeline(topic, platform, duration, style)
        export_settings = self._export_settings(platform)
        checklist = self._editing_quality_checklist(platform, brand)

        editing_plan = {
            "topic": topic,
            "platform": platform,
            "duration_seconds": duration,
            "style": style,
            "brand": brand.to_dict(),
            "timeline": timeline,
            "b_roll_plan": self._b_roll_plan(topic, duration),
            "caption_plan": self._caption_plan(platform),
            "music_sfx_direction": {
                "music": "Use subtle, license-safe background music that supports the emotional pace.",
                "sound_effects": "Use light whooshes, soft impacts, and transition accents only where they improve clarity.",
                "volume_rules": "Keep voiceover clear; duck music under speech.",
            },
            "graphics_plan": {
                "lower_thirds": "Use clean lower-thirds for key names, offers, or statistics.",
                "logo": "Add logo only at intro/outro or subtle corner placement where appropriate.",
                "brand_colors": brand.colors,
                "text_style": "High contrast, large readable captions, no clutter.",
            },
            "export_settings": export_settings,
            "quality_checklist": checklist,
            "handoff_notes": [
                "This is a preparation plan only; no real media was edited.",
                "Send to Video Editor module when available for asset-level execution.",
                "Run final media through Verification Agent before publishing.",
            ],
        }

        return self._safe_result(
            success=True,
            message="Editing plan prepared successfully.",
            data={"editing_plan": editing_plan},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.EDITING_PLAN.value),
        )

    def generate_captions(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Generate social captions, hooks, hashtags, CTA variants, and platform notes.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "content update")
        platform = _safe_str(task.get("platform") or task.get("channel"), "instagram_reels")
        goal = _safe_str(task.get("goal"), "engagement")
        variants = self._safe_int(task.get("variants"), self.config.default_caption_variants, 1, self.config.max_caption_variants)
        brand = self._brand_style_from_task(task)
        cta = _safe_str(task.get("cta") or brand.cta, "Message us to learn more.")

        captions = []
        for index in range(variants):
            angle = self._caption_angle(index, goal)
            captions.append(
                {
                    "variant": index + 1,
                    "angle": angle,
                    "caption": self._build_caption_text(topic, platform, goal, brand, cta, angle),
                    "cta": cta,
                    "hashtags": self._generate_hashtags(topic, platform, brand),
                    "best_for": self._caption_best_for(angle),
                }
            )

        result = {
            "topic": topic,
            "platform": platform,
            "goal": goal,
            "brand": brand.to_dict(),
            "captions": captions,
            "posting_notes": self._posting_notes(platform),
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Captions prepared successfully.",
            data={"caption_pack": result},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.CAPTIONS.value),
        )

    def create_thumbnail_brief(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a thumbnail design brief with layout, headline options, emotion,
        visual hierarchy, and designer handoff notes.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "video topic")
        platform = _safe_str(task.get("platform") or task.get("channel"), "youtube")
        brand = self._brand_style_from_task(task)

        headlines = self._thumbnail_headlines(topic)
        brief = {
            "topic": topic,
            "platform": platform,
            "brand": brand.to_dict(),
            "thumbnail_goal": "Earn attention quickly while staying truthful to the content.",
            "headline_options": headlines,
            "recommended_headline": headlines[0],
            "layout": {
                "primary_subject": "Large face/product/result visual on one side.",
                "text_area": "Short bold headline on the opposite side.",
                "contrast": "Use strong foreground/background separation.",
                "safe_space": "Keep text away from edges and platform overlays.",
            },
            "visual_direction": {
                "emotion": "Clear curiosity, urgency, or premium confidence.",
                "background": "Simple high-contrast background with minimal clutter.",
                "brand_colors": brand.colors,
                "style": "Clean, modern, high-retention YouTube/social style.",
            },
            "designer_notes": [
                "Use no more than 3-5 words of thumbnail text.",
                "Avoid fake claims, fake before/after proof, or misleading imagery.",
                "Make mobile readability the first priority.",
                "Export at recommended platform resolution.",
            ],
            "alt_text": f"Thumbnail for content about {topic}.",
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Thumbnail brief prepared successfully.",
            data={"thumbnail_brief": brief},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.THUMBNAIL_BRIEF.value),
        )

    def create_content_calendar(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a content calendar with daily/weekly content ideas, channels,
        formats, goals, CTAs, and production notes.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        niche = _safe_str(task.get("niche") or task.get("topic") or task.get("brief"), "business growth")
        days = self._safe_int(task.get("days"), self.config.default_calendar_days, 1, self.config.max_calendar_days)
        platforms = self._normalize_platforms(task.get("platforms") or task.get("channels") or ["instagram_reels", "youtube_shorts", "linkedin"])
        posts_per_week = self._safe_int(task.get("posts_per_week"), 5, 1, 21)
        brand = self._brand_style_from_task(task)
        goals = _safe_list(task.get("goals")) or ["awareness", "lead_generation", "authority"]

        calendar_items = self._generate_calendar_items(
            niche=niche,
            days=days,
            platforms=platforms,
            posts_per_week=posts_per_week,
            brand=brand,
            goals=[_safe_str(g) for g in goals],
        )

        calendar = {
            "niche": niche,
            "days": days,
            "platforms": platforms,
            "posts_per_week": posts_per_week,
            "brand": brand.to_dict(),
            "strategy": {
                "content_pillars": self._content_pillars(niche),
                "funnel_mix": {
                    "top_of_funnel": "Educational, problem-aware, relatable content.",
                    "middle_of_funnel": "Case-study, comparison, objection-handling content.",
                    "bottom_of_funnel": "Offer, demo, testimonial, consultation CTA content.",
                },
                "reuse_strategy": "Turn every strong video into captions, carousel points, email snippets, and shorts.",
            },
            "calendar": calendar_items,
            "weekly_review_checklist": [
                "Check watch time and hook retention.",
                "Identify top 3 topics by engagement.",
                "Repurpose the best post into 2 additional formats.",
                "Update next week based on comments and lead quality.",
            ],
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Content calendar prepared successfully.",
            data={"content_calendar": calendar},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.CONTENT_CALENDAR.value),
        )

    def create_creative_brief(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a creative brief that can be handed off to script, video editor,
        designer, voiceover, caption, or content planner modules.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "creative campaign")
        brand = self._brand_style_from_task(task)
        platform = _safe_str(task.get("platform") or task.get("channel"), "multi_platform")
        goal = _safe_str(task.get("goal"), "lead_generation")
        audience = _safe_str(task.get("audience"), brand.audience)

        brief = {
            "brief_id": str(uuid.uuid4()),
            "topic": topic,
            "brand": brand.to_dict(),
            "platform": platform,
            "goal": goal,
            "audience": audience,
            "core_message": self._core_message(topic, audience, goal),
            "offer": _safe_str(task.get("offer") or brand.primary_offer, ""),
            "cta": _safe_str(task.get("cta") or brand.cta, "Contact us to learn more."),
            "deliverables": self._requested_deliverables(task),
            "creative_angles": self._creative_angles(topic, audience, goal),
            "must_include": _safe_list(task.get("must_include")),
            "must_avoid": _dedupe_preserve_order(
                [_safe_str(x) for x in _safe_list(task.get("must_avoid")) + brand.forbidden_terms]
            ),
            "production_requirements": {
                "format": _safe_str(task.get("format"), "video/social content"),
                "duration_seconds": self._safe_int(
                    task.get("duration_seconds"),
                    self.config.default_video_duration_seconds,
                    5,
                    1800,
                ),
                "aspect_ratio": _safe_str(task.get("aspect_ratio"), self._default_aspect_ratio(platform)),
            },
            "handoff_targets": [
                "script_writer.py",
                "video_editor.py",
                "caption_generator.py",
                "thumbnail_designer.py",
                "content_planner.py",
                "veo_prompt_builder.py",
            ],
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Creative brief prepared successfully.",
            data={"creative_brief": brief},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.CREATIVE_BRIEF.value),
        )

    def create_production_plan(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create an end-to-end content/video production plan from idea to review.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "production")
        platform = _safe_str(task.get("platform") or task.get("channel"), "multi_platform")
        brand = self._brand_style_from_task(task)

        plan = {
            "topic": topic,
            "platform": platform,
            "brand": brand.to_dict(),
            "phases": [
                {
                    "phase": "Creative Strategy",
                    "tasks": [
                        "Confirm audience and offer.",
                        "Choose content angle.",
                        "Prepare hook and core message.",
                    ],
                    "owner_agent": "CreatorAgent",
                },
                {
                    "phase": "Script",
                    "tasks": [
                        "Write hook, scenes, voiceover, CTA.",
                        "Check claims and brand tone.",
                    ],
                    "owner_agent": "script_writer.py",
                },
                {
                    "phase": "Assets",
                    "tasks": [
                        "Collect logo, product shots, B-roll, screenshots, brand colors.",
                        "Check usage rights before editing.",
                    ],
                    "owner_agent": "asset_manager.py",
                },
                {
                    "phase": "Video Prompt / Shoot Plan",
                    "tasks": [
                        "Prepare VEO/video generation prompt or shot list.",
                        "Define camera, lighting, style, and safe zones.",
                    ],
                    "owner_agent": "veo_prompt_builder.py",
                },
                {
                    "phase": "Edit",
                    "tasks": [
                        "Build timeline.",
                        "Add captions, music, SFX, B-roll, graphics.",
                        "Export platform-specific versions.",
                    ],
                    "owner_agent": "video_editor.py",
                },
                {
                    "phase": "Packaging",
                    "tasks": [
                        "Create caption variants.",
                        "Prepare thumbnail brief.",
                        "Prepare posting metadata.",
                    ],
                    "owner_agent": "caption_generator.py / thumbnail_designer.py",
                },
                {
                    "phase": "Verification",
                    "tasks": [
                        "Check claims, spelling, visuals, brand safety, and platform fit.",
                        "Prepare final approval payload.",
                    ],
                    "owner_agent": "VerificationAgent",
                },
            ],
            "risk_controls": [
                "Do not publish automatically.",
                "Do not use copyrighted media without permission.",
                "Do not generate fake testimonials or misleading before/after claims.",
                "Route sensitive claims to Security Agent.",
            ],
            "final_review_checklist": self._final_content_review_checklist(),
        }

        return self._safe_result(
            success=True,
            message="Production plan prepared successfully.",
            data={"production_plan": plan},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.PRODUCTION_PLAN.value),
        )

    def create_short_form_plan(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a short-form video plan optimized for Reels, Shorts, TikTok,
        and similar vertical platforms.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        topic = _safe_str(task.get("topic") or task.get("brief") or task.get("prompt"), "short-form video")
        platform = _safe_str(task.get("platform") or task.get("channel"), "instagram_reels")
        brand = self._brand_style_from_task(task)
        duration = self._safe_int(task.get("duration_seconds"), 30, 6, 90)

        plan = {
            "topic": topic,
            "platform": platform,
            "duration_seconds": duration,
            "aspect_ratio": "9:16",
            "brand": brand.to_dict(),
            "structure": [
                {"time": "0-2s", "purpose": "Hook", "instruction": self._generate_hooks(topic, brand.audience, "engagement", brand.tone)[0]},
                {"time": "2-7s", "purpose": "Problem", "instruction": f"Show the pain or missed opportunity around {topic}."},
                {"time": "7-18s", "purpose": "Value", "instruction": "Give the viewer one clear idea, step, example, or transformation."},
                {"time": "18-25s", "purpose": "Proof/Reason", "instruction": "Add a simple reason, mini-case, or credibility cue."},
                {"time": "25-30s", "purpose": "CTA", "instruction": brand.cta or "Message us to learn more."},
            ],
            "retention_rules": [
                "Change visual every 1-3 seconds.",
                "Use captions from the first second.",
                "Avoid long intros.",
                "Keep one idea per video.",
            ],
            "caption_overlay": self._caption_plan(platform),
            "editing_style": "Fast, clean, high-contrast, mobile-first.",
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Short-form content plan prepared successfully.",
            data={"short_form_plan": plan},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.SHORT_FORM_PLAN.value),
        )

    def repurpose_content(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Turn source content into multiple platform-ready content ideas.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        source_content = _safe_str(task.get("source_content") or task.get("content") or task.get("brief"), "")
        topic = _safe_str(task.get("topic") or self._infer_topic_from_text(source_content), "repurposed content")
        platforms = self._normalize_platforms(task.get("platforms") or task.get("channels") or ["youtube_shorts", "instagram_reels", "linkedin"])
        brand = self._brand_style_from_task(task)

        ideas = []
        for platform in platforms:
            ideas.append(
                {
                    "platform": platform,
                    "format": self._platform_format(platform),
                    "title": self._generate_title(topic, platform),
                    "angle": self._creative_angles(topic, brand.audience, "engagement")[0],
                    "hook": self._generate_hooks(topic, brand.audience, "engagement", brand.tone)[0],
                    "cta": brand.cta or "Contact us to learn more.",
                    "notes": self._posting_notes(platform),
                }
            )

        repurpose_pack = {
            "source_summary": _truncate(source_content, 1200) if source_content else "No source content provided; built from topic.",
            "topic": topic,
            "brand": brand.to_dict(),
            "platforms": platforms,
            "repurposed_ideas": ideas,
            "extra_formats": [
                "Turn strongest point into a carousel.",
                "Turn objections into FAQ posts.",
                "Turn statistics into short LinkedIn posts.",
                "Turn comments into next-week video hooks.",
            ],
            "safety_notes": self._creative_compliance_notes(task, brand),
        }

        return self._safe_result(
            success=True,
            message="Content repurposing pack prepared successfully.",
            data={"repurpose_pack": repurpose_pack},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.REPURPOSE_CONTENT.value),
        )

    def create_brand_content_pack(
        self,
        task: Mapping[str, Any],
        context: Optional[CreatorContext] = None,
    ) -> Dict[str, Any]:
        """
        Create a complete brand content pack combining brief, script, captions,
        thumbnail brief, VEO prompt, and editing plan.
        """
        context = context or self._context_from_task_or_raise(task)
        started_at = _utc_now_iso()

        base_task = dict(task)
        topic = _safe_str(base_task.get("topic") or base_task.get("brief") or base_task.get("prompt"), "brand content")
        base_task["topic"] = topic

        creative_brief = self.create_creative_brief(base_task, context).get("data", {}).get("creative_brief", {})
        script = self.create_script(base_task, context).get("data", {}).get("script", {})
        captions = self.generate_captions(base_task, context).get("data", {}).get("caption_pack", {})
        thumbnail = self.create_thumbnail_brief(base_task, context).get("data", {}).get("thumbnail_brief", {})
        veo_prompt = self.build_veo_prompt(base_task, context).get("data", {}).get("veo_prompt", {})
        editing_plan = self.create_editing_plan(base_task, context).get("data", {}).get("editing_plan", {})

        pack = {
            "topic": topic,
            "creative_brief": creative_brief,
            "script": script,
            "caption_pack": captions,
            "thumbnail_brief": thumbnail,
            "veo_prompt": veo_prompt,
            "editing_plan": editing_plan,
            "handoff_order": [
                "Review creative_brief",
                "Approve script",
                "Generate/shoot video assets",
                "Follow editing_plan",
                "Design thumbnail",
                "Use caption_pack",
                "Send final output to Verification Agent",
            ],
        }

        return self._safe_result(
            success=True,
            message="Brand content pack prepared successfully.",
            data={"brand_content_pack": pack},
            metadata=self._base_metadata(context, started_at, task_type=CreatorTaskType.BRAND_CONTENT_PACK.value),
        )

    # -------------------------------------------------------------------------
    # Compatibility hooks required by William/Jarvis architecture
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate user_id and workspace_id for SaaS isolation.

        Every user-specific creative request must include both user_id and workspace_id.
        """
        started_at = _utc_now_iso()

        user_id = _safe_str(task.get("user_id"))
        workspace_id = _safe_str(task.get("workspace_id"))

        if self.config.strict_context_validation:
            if not user_id:
                return self._error_result(
                    message="Missing required user_id for Creator Agent task.",
                    error="missing_user_id",
                    metadata={"started_at": started_at, "agent": AGENT_SLUG},
                )
            if not workspace_id:
                return self._error_result(
                    message="Missing required workspace_id for Creator Agent task.",
                    error="missing_workspace_id",
                    metadata={"started_at": started_at, "agent": AGENT_SLUG},
                )

        context = CreatorContext(
            user_id=user_id or "anonymous_user",
            workspace_id=workspace_id or "default_workspace",
            request_id=_safe_str(task.get("request_id"), str(uuid.uuid4())),
            role=_safe_str(task.get("role")) or None,
            permissions=[_safe_str(p) for p in _safe_list(task.get("permissions"))],
            locale=_safe_str(task.get("locale"), "en-US"),
            timezone=_safe_str(task.get("timezone"), "UTC"),
            source=_safe_str(task.get("source"), "api"),
            correlation_id=_safe_str(task.get("correlation_id")) or None,
        )

        return self._safe_result(
            success=True,
            message="Creator task context validated.",
            data={"context": context},
            metadata={"agent": AGENT_SLUG, "started_at": started_at},
        )

    def _requires_security_check(self, task: Mapping[str, Any]) -> SecurityDecision:
        """
        Decide whether a task requires Security Agent approval.

        Security is required for:
            - publish/send/upload-like actions
            - high-risk claims
            - deepfake/impersonation/celebrity/political content
            - financial/legal/medical claims
            - fake testimonials/reviews
        """
        text = _extract_task_text(task).lower()
        matched: List[str] = []

        for pattern in SENSITIVE_CREATIVE_PATTERNS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                matched.append(pattern)

        blocked_actions = []
        requested_action = _slugify(_safe_str(task.get("action") or task.get("requested_action")))
        if requested_action in PROHIBITED_DIRECT_ACTIONS:
            blocked_actions.append(requested_action)

        for action in PROHIBITED_DIRECT_ACTIONS:
            if re.search(rf"\b{re.escape(action.replace('_', ' '))}\b", text, flags=re.IGNORECASE):
                blocked_actions.append(action)

        blocked_actions = _dedupe_preserve_order(blocked_actions)

        if blocked_actions:
            return SecurityDecision(
                required=True,
                reason="Task includes direct external/destructive/publish-like action that Creator Agent must not execute directly.",
                risk_level="high",
                matched_patterns=matched,
                blocked_direct_actions=blocked_actions,
            )

        if matched and not self.config.allow_sensitive_without_security:
            return SecurityDecision(
                required=True,
                reason="Task contains sensitive creative, compliance, impersonation, political, regulated, or high-risk claim indicators.",
                risk_level="medium",
                matched_patterns=matched,
                blocked_direct_actions=[],
            )

        return SecurityDecision(
            required=False,
            reason="No security handoff required for safe creative preparation.",
            risk_level="low",
            matched_patterns=matched,
            blocked_direct_actions=[],
        )

    def _request_security_approval(
        self,
        task: Mapping[str, Any],
        context: CreatorContext,
        decision: SecurityDecision,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a real security_client is attached, this method attempts to call it.
        Without a client, it returns a safe blocked result instead of guessing approval.
        """
        payload = {
            "approval_id": str(uuid.uuid4()),
            "agent": AGENT_SLUG,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "risk_level": decision.risk_level,
            "reason": decision.reason,
            "matched_patterns": decision.matched_patterns,
            "blocked_direct_actions": decision.blocked_direct_actions,
            "task_hash": _hash_payload(task),
            "created_at": _utc_now_iso(),
        }

        self._emit_agent_event(
            event_type="creator_security_approval_requested",
            context=context,
            payload=payload,
        )

        if self.security_client is None:
            return self._safe_result(
                success=False,
                message="Security approval is required, but no Security Agent client is attached.",
                data={"approval_payload": payload},
                error="security_client_unavailable",
                metadata={"agent": AGENT_SLUG, "request_id": context.request_id},
            )

        try:
            if hasattr(self.security_client, "approve"):
                response = self.security_client.approve(payload)
            elif hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(payload)
            elif callable(self.security_client):
                response = self.security_client(payload)
            else:
                return self._error_result(
                    message="Attached Security Agent client has no supported approval method.",
                    error="invalid_security_client",
                    metadata={"agent": AGENT_SLUG, "request_id": context.request_id},
                )

            if isinstance(response, Mapping):
                approved = bool(response.get("approved") or response.get("success"))
                return self._safe_result(
                    success=approved,
                    message="Security Agent approved task." if approved else "Security Agent did not approve task.",
                    data={"approval_payload": payload, "security_response": dict(response)},
                    error=None if approved else "security_not_approved",
                    metadata={"agent": AGENT_SLUG, "request_id": context.request_id},
                )

            return self._error_result(
                message="Security Agent returned an unsupported response.",
                error="invalid_security_response",
                metadata={"agent": AGENT_SLUG, "request_id": context.request_id},
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=str(exc),
                metadata={"agent": AGENT_SLUG, "request_id": context.request_id},
            )

    def _prepare_verification_payload(
        self,
        task: Mapping[str, Any],
        context: CreatorContext,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        This payload is intentionally structured and safe for later dashboard/API use.
        """
        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": AGENT_SLUG,
            "agent_version": AGENT_VERSION,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_type": _safe_str(task.get("type") or task.get("task_type") or task.get("intent")),
            "result_success": bool(result.get("success")),
            "result_hash": _hash_payload(result),
            "checks": [
                "brand_consistency",
                "claim_safety",
                "platform_fit",
                "spelling_and_grammar",
                "cta_accuracy",
                "no_auto_publish",
                "rights_and_usage_review",
            ],
            "needs_human_review": self._requires_security_check(task).required,
            "created_at": _utc_now_iso(),
        }

        if self.verification_client is not None:
            try:
                if hasattr(self.verification_client, "prepare"):
                    self.verification_client.prepare(payload)
                elif hasattr(self.verification_client, "queue"):
                    self.verification_client.queue(payload)
                elif callable(self.verification_client):
                    self.verification_client(payload)
            except Exception:
                self.logger.exception("Verification payload dispatch failed.")

        return payload

    def _prepare_memory_payload(
        self,
        task: Mapping[str, Any],
        context: CreatorContext,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Only safe, reusable preferences are proposed for memory.
        This method does not store sensitive personal attributes or raw private content.
        """
        brand = self._brand_style_from_task(task)
        safe_preferences = {
            "brand_name": brand.brand_name,
            "tone": brand.tone,
            "audience": brand.audience,
            "preferred_terms": brand.preferred_terms,
            "forbidden_terms": brand.forbidden_terms,
            "colors": brand.colors,
            "default_cta": brand.cta,
        }

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent": AGENT_SLUG,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "memory_type": "creative_preferences",
            "safe_to_store": self.config.memory_enabled,
            "preferences": safe_preferences,
            "result_hash": _hash_payload(result),
            "created_at": _utc_now_iso(),
        }

        if self.memory_client is not None and self.config.memory_enabled:
            try:
                if hasattr(self.memory_client, "prepare"):
                    self.memory_client.prepare(payload)
                elif hasattr(self.memory_client, "store"):
                    self.memory_client.store(payload)
                elif callable(self.memory_client):
                    self.memory_client(payload)
            except Exception:
                self.logger.exception("Memory payload dispatch failed.")

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        context: CreatorContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API event without breaking agent flow.

        Event failures are logged but never crash creative task handling.
        """
        if not self.config.emit_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": AGENT_SLUG,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "correlation_id": context.correlation_id,
            "payload": dict(payload or {}),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Creator event: %s", event)
        except Exception:
            self.logger.exception("Failed to emit Creator Agent event.")

    def _log_audit_event(
        self,
        action: str,
        context: CreatorContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event for SaaS workspace history.

        This does not store raw long content by default; it stores hashes and metadata.
        """
        if not self.config.audit_enabled:
            return

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "agent": AGENT_SLUG,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "role": context.role,
            "payload": dict(payload or {}),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Creator audit event: %s", audit_event)
        except Exception:
            self.logger.exception("Failed to log Creator Agent audit event.")

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured result.
        """
        return {
            "success": bool(success),
            "message": _safe_str(message),
            "data": dict(data or {}),
            "error": error,
            "metadata": {
                "agent": AGENT_SLUG,
                "agent_name": AGENT_NAME,
                "agent_version": AGENT_VERSION,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error result.
        """
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or "creator_agent_error",
            metadata=metadata or {},
        )

    # -------------------------------------------------------------------------
    # Internal configuration/context helpers
    # -------------------------------------------------------------------------

    def _build_config(self, config: Optional[Union[CreatorConfig, Mapping[str, Any]]]) -> CreatorConfig:
        """Build CreatorConfig from dataclass or mapping."""
        if config is None:
            return CreatorConfig()
        if isinstance(config, CreatorConfig):
            return config
        if isinstance(config, Mapping):
            default = CreatorConfig()
            data = default.to_dict()
            for key, value in config.items():
                if key == "default_brand_style" and isinstance(value, Mapping):
                    data[key] = BrandStyle(**{**BrandStyle().to_dict(), **dict(value)})
                elif key in data:
                    data[key] = value
            if isinstance(data["default_brand_style"], dict):
                data["default_brand_style"] = BrandStyle(**data["default_brand_style"])
            return CreatorConfig(**data)
        return CreatorConfig()

    def _context_from_task_or_raise(self, task: Mapping[str, Any]) -> CreatorContext:
        """Return CreatorContext or raise ValueError for internal direct method usage."""
        result = self._validate_task_context(task)
        if not result.get("success"):
            raise ValueError(result.get("error") or result.get("message"))
        return result["data"]["context"]

    def _base_metadata(
        self,
        context: CreatorContext,
        started_at: str,
        task_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Common metadata for results."""
        return {
            "agent": AGENT_SLUG,
            "agent_name": AGENT_NAME,
            "agent_version": AGENT_VERSION,
            "task_type": task_type,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "correlation_id": context.correlation_id,
            "started_at": started_at,
            "completed_at": _utc_now_iso(),
        }

    def _brand_style_from_task(self, task: Mapping[str, Any]) -> BrandStyle:
        """Build brand style from task data and safe defaults."""
        default = copy.deepcopy(self.config.default_brand_style)
        raw_brand = task.get("brand") or task.get("brand_style") or {}

        if isinstance(raw_brand, Mapping):
            brand_data = {
                **default.to_dict(),
                **{k: v for k, v in dict(raw_brand).items() if k in default.to_dict()},
            }
        else:
            brand_data = default.to_dict()

        simple_fields = {
            "brand_name": task.get("brand_name"),
            "tone": task.get("tone"),
            "audience": task.get("audience"),
            "primary_offer": task.get("offer") or task.get("primary_offer"),
            "unique_value": task.get("unique_value"),
            "cta": task.get("cta"),
        }

        for key, value in simple_fields.items():
            if value is not None and _safe_str(value):
                brand_data[key] = _safe_str(value)

        for list_key in ("forbidden_terms", "preferred_terms", "colors", "compliance_notes"):
            if task.get(list_key) is not None:
                brand_data[list_key] = [_safe_str(x) for x in _safe_list(task.get(list_key)) if _safe_str(x)]

        return BrandStyle(**brand_data)

    def _safe_int(self, value: Any, default: int, minimum: int, maximum: int) -> int:
        """Safely parse integer and clamp to range."""
        try:
            parsed = int(value)
        except Exception:
            parsed = default
        return max(minimum, min(maximum, parsed))

    def _infer_task_type(self, task: Mapping[str, Any]) -> str:
        """Infer task type from broad text."""
        text = _extract_task_text(task).lower()

        if any(word in text for word in ["veo", "video generation prompt", "generate video prompt", "cinematic prompt"]):
            return CreatorTaskType.VEO_PROMPT.value
        if any(word in text for word in ["caption", "hashtags", "social copy"]):
            return CreatorTaskType.CAPTIONS.value
        if any(word in text for word in ["thumbnail", "cover image"]):
            return CreatorTaskType.THUMBNAIL_BRIEF.value
        if any(word in text for word in ["calendar", "30 days", "content plan", "posting schedule"]):
            return CreatorTaskType.CONTENT_CALENDAR.value
        if any(word in text for word in ["edit", "timeline", "b-roll", "export settings"]):
            return CreatorTaskType.EDITING_PLAN.value
        if any(word in text for word in ["short form", "reel", "shorts", "tiktok"]):
            return CreatorTaskType.SHORT_FORM_PLAN.value
        if any(word in text for word in ["repurpose", "turn this into", "reuse content"]):
            return CreatorTaskType.REPURPOSE_CONTENT.value
        if any(word in text for word in ["script", "voiceover", "scene"]):
            return CreatorTaskType.SCRIPT.value
        if any(word in text for word in ["pack", "full content package", "complete content"]):
            return CreatorTaskType.BRAND_CONTENT_PACK.value

        return CreatorTaskType.CREATIVE_BRIEF.value

    # -------------------------------------------------------------------------
    # Content generation helpers
    # -------------------------------------------------------------------------

    def _generate_title(self, topic: str, platform: str) -> str:
        """Generate a practical content title."""
        cleaned = topic.strip().rstrip(".")
        if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"}:
            return f"{cleaned}: Quick Value Video"
        if platform == "linkedin":
            return f"What business owners should know about {cleaned}"
        return f"{cleaned}: Content Asset"

    def _generate_hooks(self, topic: str, audience: str, goal: str, tone: str) -> List[str]:
        """Generate hook options."""
        hooks = [
            f"Most {audience} miss this one thing about {topic}.",
            f"If you care about {topic}, watch this before making your next move.",
            f"Here is a simple way to think about {topic}.",
            f"The fastest way to improve {topic} starts with this.",
            f"Stop guessing about {topic}; focus on this instead.",
            f"Want better results from {topic}? Start here.",
            f"This is why {topic} feels harder than it should.",
            f"Before you spend more on {topic}, check this.",
            f"One small change can make {topic} much clearer.",
            f"Here is the practical truth about {topic}.",
        ]
        if goal == "conversion":
            hooks.insert(0, f"Before you buy anything for {topic}, ask this question.")
        if tone == "premium":
            hooks.insert(0, f"Premium brands approach {topic} differently.")
        return hooks[: self.config.max_hooks]

    def _generate_script_scenes(
        self,
        topic: str,
        platform: str,
        goal: str,
        duration: int,
        audience: str,
        brand: BrandStyle,
        offer: str,
        cta: str,
        scene_count: int,
    ) -> List[Dict[str, Any]]:
        """Generate scene-by-scene script."""
        seconds_per_scene = max(1, duration // max(1, scene_count))
        scenes = []

        scene_templates = [
            ("Hook", f"Open with a sharp problem or curiosity gap about {topic}."),
            ("Problem", f"Show why {audience} struggle with {topic}."),
            ("Insight", f"Explain the key idea that makes {topic} easier to understand."),
            ("Solution", f"Connect the insight to {offer}."),
            ("Proof", "Add a credibility cue, example, process step, or practical benefit."),
            ("CTA", cta),
        ]

        while len(scene_templates) < scene_count:
            scene_templates.insert(-1, ("Value Point", f"Add one practical tip about {topic}."))

        for idx in range(scene_count):
            label, instruction = scene_templates[min(idx, len(scene_templates) - 1)]
            start = idx * seconds_per_scene
            end = duration if idx == scene_count - 1 else min(duration, (idx + 1) * seconds_per_scene)
            scenes.append(
                {
                    "scene_number": idx + 1,
                    "time_range": f"{start:02d}s-{end:02d}s",
                    "purpose": label,
                    "visual_direction": self._scene_visual_direction(label, topic, platform),
                    "voiceover": self._scene_voiceover(label, instruction, brand),
                    "on_screen_text": self._scene_on_screen_text(label, topic, cta),
                    "editing_notes": self._scene_editing_notes(label),
                }
            )

        return scenes

    def _scene_visual_direction(self, label: str, topic: str, platform: str) -> str:
        """Visual direction for a scene."""
        if label == "Hook":
            return f"Start with a bold visual related to {topic}; use fast movement or clear contrast."
        if label == "Problem":
            return "Show the pain point, confusion, wasted time, or missed opportunity."
        if label == "Insight":
            return "Use clean graphics, screen recording, or simple visual metaphor."
        if label == "Solution":
            return "Show the service/product/process in a polished, trustworthy way."
        if label == "Proof":
            return "Show checklist, result snapshot, workflow, testimonial-style text, or process evidence."
        if label == "CTA":
            return "End with branded screen, clear next step, and minimal distractions."
        return "Use B-roll that supports the spoken point and keeps retention high."

    def _scene_voiceover(self, label: str, instruction: str, brand: BrandStyle) -> str:
        """Voiceover sentence for a scene."""
        if label == "CTA":
            return instruction
        return f"{instruction} Keep it {brand.tone}, clear, and easy to understand."

    def _scene_on_screen_text(self, label: str, topic: str, cta: str) -> str:
        """On-screen text for a scene."""
        mapping = {
            "Hook": f"Stop ignoring {topic}",
            "Problem": "The real problem",
            "Insight": "What actually matters",
            "Solution": "Here is the smarter way",
            "Proof": "Why it works",
            "CTA": cta,
        }
        return mapping.get(label, "Key point")

    def _scene_editing_notes(self, label: str) -> str:
        """Editing notes per scene."""
        if label == "Hook":
            return "Use quick cut, punch-in, or pattern interrupt in first second."
        if label == "CTA":
            return "Slow slightly, keep CTA readable, add brand mark."
        return "Use clean jump cuts, captions, and relevant B-roll."

    def _compose_voiceover(self, scenes: Sequence[Mapping[str, Any]]) -> str:
        """Compose voiceover script from scene list."""
        return "\n".join(f"{scene.get('scene_number')}. {scene.get('voiceover')}" for scene in scenes)

    def _build_shot_list(self, scenes: Sequence[Mapping[str, Any]], platform: str) -> List[Dict[str, Any]]:
        """Build shot list from scenes."""
        return [
            {
                "shot": scene.get("scene_number"),
                "time_range": scene.get("time_range"),
                "type": "vertical" if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"} else "standard",
                "visual": scene.get("visual_direction"),
                "text": scene.get("on_screen_text"),
            }
            for scene in scenes
        ]

    def _build_production_notes(self, platform: str, tone: str, duration: int) -> List[str]:
        """General production notes."""
        notes = [
            f"Keep total runtime close to {duration} seconds.",
            f"Maintain a {tone} tone throughout.",
            "Use captions for all spoken content.",
            "Keep claims truthful and verifiable.",
            "Do not use copyrighted assets without permission.",
        ]
        if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"}:
            notes.append("Use 9:16 framing and keep important elements in center safe zone.")
        return notes

    def _suggest_scene_count(self, duration: int) -> int:
        """Suggest number of scenes based on duration."""
        if duration <= 15:
            return 4
        if duration <= 45:
            return 6
        if duration <= 90:
            return 8
        return 10

    def _generate_veo_shot_sequence(self, topic: str, duration: int) -> List[Dict[str, str]]:
        """Generate VEO shot sequence."""
        if duration <= 15:
            return [
                {"time": "0-3s", "shot": f"Bold opening visual introducing {topic}."},
                {"time": "3-9s", "shot": "Main action, transformation, product, or service moment."},
                {"time": "9-15s", "shot": "Clean final branded composition with space for CTA."},
            ]
        return [
            {"time": "0-3s", "shot": f"Attention-grabbing cinematic opener for {topic}."},
            {"time": "3-8s", "shot": "Context shot showing the environment or problem."},
            {"time": "8-18s", "shot": "Primary subject action with smooth camera movement."},
            {"time": "18-26s", "shot": "Detail shots, proof points, process, or product close-ups."},
            {"time": "26s-end", "shot": "Final clean hero frame with room for captions and CTA."},
        ]

    def _caption_safe_zones(self, platform: str) -> Dict[str, str]:
        """Return caption safe zone notes."""
        if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"}:
            return {
                "top": "Avoid top 15% for profile/UI overlays.",
                "center": "Keep main subject and captions in central 60%.",
                "bottom": "Avoid bottom 20% for captions/buttons/UI.",
            }
        return {
            "top": "Keep title-safe margin.",
            "center": "Primary content area.",
            "bottom": "Leave room for subtitles/lower-thirds.",
        }

    def _default_aspect_ratio(self, platform: str) -> str:
        """Default aspect ratio by platform."""
        if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"}:
            return "9:16"
        if platform in {"youtube_long", "youtube", "website"}:
            return "16:9"
        if platform in {"instagram_feed", "facebook_feed"}:
            return "1:1"
        return "9:16"

    def _build_editing_timeline(self, topic: str, platform: str, duration: int, style: str) -> List[Dict[str, str]]:
        """Build editing timeline."""
        return [
            {
                "time": "0-2s",
                "section": "Hook",
                "instructions": f"Open with strongest visual and direct text about {topic}.",
            },
            {
                "time": "2-8s",
                "section": "Context",
                "instructions": "Show the problem or promise. Keep cuts tight.",
            },
            {
                "time": f"8-{max(12, duration - 8)}s",
                "section": "Main Value",
                "instructions": f"Deliver the main point in a {style} style with B-roll and captions.",
            },
            {
                "time": f"{max(12, duration - 8)}-{duration}s",
                "section": "CTA",
                "instructions": "End with clear next step, logo, and readable CTA.",
            },
        ]

    def _export_settings(self, platform: str) -> Dict[str, Any]:
        """Platform export settings."""
        aspect = self._default_aspect_ratio(platform)
        resolution = "1080x1920" if aspect == "9:16" else "1920x1080" if aspect == "16:9" else "1080x1080"
        return {
            "aspect_ratio": aspect,
            "resolution": resolution,
            "format": "mp4",
            "codec": "h264",
            "audio": "aac",
            "fps": 30,
            "notes": "Use high bitrate export suitable for platform upload; verify file size limits separately.",
        }

    def _editing_quality_checklist(self, platform: str, brand: BrandStyle) -> List[str]:
        """Editing review checklist."""
        return [
            "Hook is clear in first 1-2 seconds.",
            "Captions are readable on mobile.",
            "No misspelled brand/service names.",
            f"Tone matches {brand.tone}.",
            "CTA is accurate and not misleading.",
            "No copyrighted music/assets without license.",
            "No unsupported claims.",
            f"Export matches {platform} format requirements.",
        ]

    def _b_roll_plan(self, topic: str, duration: int) -> List[str]:
        """Generate B-roll ideas."""
        return [
            f"Primary visual showing {topic}.",
            "Close-up detail shot.",
            "Screen recording or process visual.",
            "Customer/business context shot.",
            "Before/problem visual without misleading claims.",
            "After/solution visual framed as expected outcome, not guarantee.",
        ][: 3 if duration < 20 else 6]

    def _caption_plan(self, platform: str) -> Dict[str, Any]:
        """Caption overlay plan."""
        return {
            "style": "Large, high-contrast, mobile-readable captions.",
            "placement": "Center-lower safe zone" if self._default_aspect_ratio(platform) == "9:16" else "Bottom title-safe area",
            "rules": [
                "Break lines every 3-6 words.",
                "Highlight key words sparingly.",
                "Avoid covering faces, products, or UI.",
                "Proofread before export.",
            ],
        }

    def _caption_angle(self, index: int, goal: str) -> str:
        """Caption angle by index."""
        angles = {
            "lead_generation": ["problem-aware", "offer-focused", "authority", "objection-handling", "soft CTA"],
            "conversion": ["offer-focused", "urgency", "proof", "objection-handling", "direct CTA"],
            "engagement": ["question", "relatable", "educational", "myth-busting", "conversation starter"],
            "awareness": ["educational", "problem-aware", "story", "myth-busting", "trend response"],
        }
        selected = angles.get(goal, angles["engagement"])
        return selected[index % len(selected)]

    def _build_caption_text(self, topic: str, platform: str, goal: str, brand: BrandStyle, cta: str, angle: str) -> str:
        """Build caption text."""
        openers = {
            "problem-aware": f"Struggling with {topic}? You are not alone.",
            "offer-focused": f"If {topic} matters to your business, the right execution makes a big difference.",
            "authority": f"Most brands overcomplicate {topic}. Here is the cleaner way to think about it.",
            "objection-handling": f"Think {topic} is too complicated or expensive? It does not have to be.",
            "soft CTA": f"Here is a simple reminder about {topic}.",
            "question": f"What is the biggest challenge you face with {topic}?",
            "relatable": f"We see this all the time with {topic}.",
            "educational": f"Here is one practical lesson about {topic}.",
            "myth-busting": f"Myth: {topic} has to be confusing.",
            "conversation starter": f"Let’s talk about {topic}.",
            "urgency": f"Waiting too long on {topic} can cost more than fixing it.",
            "proof": f"Good {topic} is built on clear strategy, not guesswork.",
            "direct CTA": cta,
            "story": f"The best results with {topic} usually start with one clear decision.",
            "trend response": f"Everyone is talking about {topic}, but the basics still matter most.",
        }
        body = openers.get(angle, f"Here is something useful about {topic}.")
        return f"{body}\n\nKeep the message clear, the offer simple, and the next step easy.\n\n{cta}"

    def _generate_hashtags(self, topic: str, platform: str, brand: BrandStyle) -> List[str]:
        """Generate simple hashtag set."""
        words = re.findall(r"[A-Za-z0-9]+", topic.lower())
        topic_tags = [f"#{w}" for w in words[:4] if len(w) > 2]
        base = ["#contentmarketing", "#digitalmarketing", "#businessgrowth"]
        if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"}:
            base.extend(["#shortformvideo", "#reels"])
        if brand.brand_name:
            base.append("#" + re.sub(r"[^A-Za-z0-9]", "", brand.brand_name))
        return _dedupe_preserve_order(topic_tags + base)[:10]

    def _caption_best_for(self, angle: str) -> str:
        """Explain best use for caption angle."""
        mapping = {
            "problem-aware": "Cold audience that needs pain-point clarity.",
            "offer-focused": "Warm audience considering a solution.",
            "authority": "Building trust and expert positioning.",
            "objection-handling": "Leads who hesitate or compare options.",
            "question": "Engagement and comment generation.",
            "educational": "Saving/sharing and authority building.",
            "direct CTA": "Bottom-funnel conversion posts.",
        }
        return mapping.get(angle, "General social engagement.")

    def _posting_notes(self, platform: str) -> List[str]:
        """Platform posting notes."""
        notes = [
            "Review final creative before posting.",
            "Keep CTA aligned with campaign goal.",
            "Track saves, shares, comments, clicks, and qualified leads.",
        ]
        if platform in {"instagram_reels", "tiktok", "youtube_shorts", "facebook_reels"}:
            notes.append("Use strong first-frame visual and captions from the first second.")
        if platform == "linkedin":
            notes.append("Lead with business insight; keep hashtags minimal.")
        return notes

    def _thumbnail_headlines(self, topic: str) -> List[str]:
        """Thumbnail headline options."""
        key = topic.strip().title()
        return [
            f"Fix {key}",
            "Stop This Mistake",
            "Do This First",
            "Before You Spend",
            "The Smart Way",
            "What Works Now",
        ]

    def _content_pillars(self, niche: str) -> List[Dict[str, str]]:
        """Generate content pillars."""
        return [
            {"pillar": "Education", "description": f"Teach useful concepts about {niche}."},
            {"pillar": "Authority", "description": "Show expertise, process, examples, and frameworks."},
            {"pillar": "Trust", "description": "Share proof, FAQs, objections, and behind-the-scenes content."},
            {"pillar": "Conversion", "description": "Present offers, demos, consultations, and clear CTAs."},
        ]

    def _generate_calendar_items(
        self,
        niche: str,
        days: int,
        platforms: Sequence[str],
        posts_per_week: int,
        brand: BrandStyle,
        goals: Sequence[str],
    ) -> List[Dict[str, Any]]:
        """Generate content calendar items."""
        total_posts = max(1, min(days * 3, round((days / 7) * posts_per_week)))
        pillars = self._content_pillars(niche)
        formats = ["short_video", "carousel", "single_post", "story", "long_post", "live_topic"]

        items = []
        for index in range(total_posts):
            day = 1 + int((index * days) / total_posts)
            platform = platforms[index % len(platforms)]
            pillar = pillars[index % len(pillars)]["pillar"]
            goal = goals[index % len(goals)] if goals else "awareness"
            content_format = formats[index % len(formats)]
            topic = f"{pillar} angle for {niche}"

            items.append(
                {
                    "day": day,
                    "platform": platform,
                    "format": content_format,
                    "pillar": pillar,
                    "goal": goal,
                    "title": self._generate_title(topic, platform),
                    "hook": self._generate_hooks(topic, brand.audience, goal, brand.tone)[0],
                    "cta": brand.cta or "Contact us to learn more.",
                    "production_note": self._production_note_for_format(content_format),
                }
            )

        return items

    def _production_note_for_format(self, content_format: str) -> str:
        """Production note for format."""
        mapping = {
            "short_video": "Record vertical video with captions and fast first-frame hook.",
            "carousel": "Use 5-7 slides with one idea per slide.",
            "single_post": "Use one clear visual and concise caption.",
            "story": "Use poll/question/CTA sticker where platform supports it.",
            "long_post": "Lead with a strong first sentence and practical insight.",
            "live_topic": "Prepare 3 talking points and one offer CTA.",
        }
        return mapping.get(content_format, "Keep creative simple and audience-focused.")

    def _core_message(self, topic: str, audience: str, goal: str) -> str:
        """Core message for creative brief."""
        return f"For {audience}, {topic} becomes easier when the message is clear, the value is specific, and the next step matches the goal of {goal}."

    def _requested_deliverables(self, task: Mapping[str, Any]) -> List[str]:
        """Normalize requested deliverables."""
        deliverables = [_safe_str(x) for x in _safe_list(task.get("deliverables")) if _safe_str(x)]
        if deliverables:
            return deliverables
        return ["script", "caption", "thumbnail_brief", "editing_plan"]

    def _creative_angles(self, topic: str, audience: str, goal: str) -> List[str]:
        """Generate creative angles."""
        return [
            f"Problem/Solution: What {audience} get wrong about {topic}.",
            f"Education: A simple framework for understanding {topic}.",
            f"Authority: Why expert execution matters for {topic}.",
            f"Objection: Why {topic} does not need to be complicated.",
            f"CTA: How to take the next step toward better {topic}.",
        ]

    def _final_content_review_checklist(self) -> List[str]:
        """Final content review checklist."""
        return [
            "User/workspace context is correct.",
            "Brand name, CTA, offer, and contact details are accurate.",
            "No unsupported guarantees or misleading claims.",
            "No copyrighted or unlicensed assets are included.",
            "No sensitive content requires unresolved Security Agent approval.",
            "Captions and thumbnails are readable on mobile.",
            "Export format matches target platform.",
            "Verification Agent payload is attached.",
        ]

    def _platform_format(self, platform: str) -> str:
        """Return common format by platform."""
        if platform in {"youtube_shorts", "instagram_reels", "tiktok", "facebook_reels"}:
            return "vertical_short_video"
        if platform in {"youtube", "youtube_long"}:
            return "long_form_video"
        if platform == "linkedin":
            return "professional_post"
        if platform == "blog":
            return "article"
        return "social_post"

    def _normalize_platforms(self, platforms: Any) -> List[str]:
        """Normalize platform list."""
        raw = [_slugify(_safe_str(p)) for p in _safe_list(platforms)]
        valid = [p for p in raw if p]
        return valid or ["instagram_reels", "youtube_shorts"]

    def _infer_topic_from_text(self, text: str) -> str:
        """Infer rough topic from source content."""
        clean = re.sub(r"\s+", " ", text).strip()
        if not clean:
            return "repurposed content"
        words = clean.split()
        return " ".join(words[:8]).rstrip(".,:;")

    def _creative_compliance_notes(self, task: Mapping[str, Any], brand: BrandStyle) -> List[str]:
        """Return safety/compliance notes for creative output."""
        notes = [
            "Prepared content only; no publishing or external action was performed.",
            "Review all claims before public use.",
            "Use only licensed or owned media assets.",
            "Do not present expected outcomes as guaranteed results.",
        ]

        security = self._requires_security_check(task)
        if security.required:
            notes.append(f"Security Agent review recommended: {security.reason}")

        if brand.compliance_notes:
            notes.extend(brand.compliance_notes)

        return _dedupe_preserve_order(notes)

    # -------------------------------------------------------------------------
    # Capability / registry helpers
    # -------------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """Return capabilities for Agent Registry and dashboard."""
        return {
            "agent": AGENT_SLUG,
            "version": AGENT_VERSION,
            "capabilities": copy.deepcopy(AGENT_METADATA["capabilities"]),
            "supported_task_types": sorted(SUPPORTED_TASK_TYPES),
            "safe_actions_only": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """Basic health check for loader/dashboard."""
        return self._safe_result(
            success=True,
            message="Creator Agent is import-safe and ready.",
            data={
                "agent": AGENT_SLUG,
                "version": AGENT_VERSION,
                "config": self.config.to_dict(),
                "metadata": self.metadata,
            },
            metadata={"health": "ok"},
        )

    def to_registry_dict(self) -> Dict[str, Any]:
        """Return registry-ready metadata."""
        return {
            **copy.deepcopy(AGENT_METADATA),
            "health": "ready",
            "loaded_at": _utc_now_iso(),
        }


# ======================================================================================
# Factory function for Agent Loader / Registry
# ======================================================================================

def create_agent(**kwargs: Any) -> CreatorAgent:
    """
    Factory used by Agent Loader or Registry.

    Example:
        agent = create_agent()
        result = agent.run({
            "user_id": "user_123",
            "workspace_id": "workspace_456",
            "type": "create_script",
            "topic": "AI automation for service businesses"
        })
    """
    return CreatorAgent(**kwargs)


# ======================================================================================
# Module exports
# ======================================================================================

__all__ = [
    "AGENT_METADATA",
    "AGENT_NAME",
    "AGENT_SLUG",
    "AGENT_VERSION",
    "BrandStyle",
    "CreatorAgent",
    "CreatorConfig",
    "CreatorContext",
    "CreatorTaskType",
    "SecurityDecision",
    "create_agent",
]