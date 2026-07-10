"""
agents/super_agents/creator_agent/short_form_editor.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Reels/Shorts/TikTok pacing, retention, cuts, pattern breaks.

This module provides a production-ready, import-safe ShortFormEditor class for
the Creator Agent. It generates structured short-form video edit plans for:

    - Instagram Reels
    - YouTube Shorts
    - TikTok
    - Facebook Reels
    - LinkedIn short-form clips
    - Generic vertical video

Core responsibilities:
    - Analyze script/transcript for short-form pacing.
    - Build second-by-second edit timelines.
    - Recommend jump cuts, zooms, captions, B-roll, sound beats, overlays.
    - Add retention-focused pattern breaks.
    - Score hooks, pacing, clarity, CTA strength, and retention risk.
    - Generate platform-specific editing instructions.
    - Prepare payloads for Memory Agent and Verification Agent.
    - Emit structured events for dashboard/API/registry workflows.

Safety and architecture:
    - Requires user_id and workspace_id for all user/workspace operations.
    - Never mixes content, logs, memory, or analytics between tenants.
    - Does not execute real file edits, video rendering, uploads, browser actions,
      financial actions, calls, or destructive actions directly.
    - Sensitive actions are protected by Security Agent approval hooks.
    - Public results always follow:
        {
            "success": bool,
            "message": str,
            "data": Any,
            "error": Optional[str],
            "metadata": dict
        }

This file is safe to import even if the full William/Jarvis codebase is not
created yet because it includes optional BaseAgent fallback support.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis BaseAgent may include routing, observability,
        permissions, and lifecycle hooks. This fallback keeps this file usable
        during early development and isolated testing.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.config = kwargs.get("config", {}) or {}

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run.",
                "data": None,
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {
                    "agent": self.agent_name,
                    "agent_id": self.agent_id,
                },
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "CreatorShortFormEditor"
DEFAULT_AGENT_ID = "creator_agent.short_form_editor"
DEFAULT_VERSION = "1.0.0"

DEFAULT_ASPECT_RATIO = "9:16"
DEFAULT_LANGUAGE = "en"
DEFAULT_TARGET_DURATION_SECONDS = 30

SENSITIVE_ACTIONS = {
    "render_video",
    "export_video",
    "upload_video",
    "publish_video",
    "delete_project",
    "overwrite_file",
    "send_to_client",
}

SUPPORTED_PLATFORMS = {
    "tiktok",
    "youtube_shorts",
    "instagram_reels",
    "facebook_reels",
    "linkedin",
    "generic_vertical",
}

WORD_RE = re.compile(r"\b[\w'-]+\b", re.UNICODE)
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
WHITESPACE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value: Any) -> Optional[str]:
    """Normalize string-like values safely."""
    if value is None:
        return None
    text = str(value).strip()
    text = WHITESPACE_RE.sub(" ", text)
    return text or None


def safe_json_dumps(value: Any) -> str:
    """Safely serialize any object for logs, hashes, or metadata."""
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def ensure_list(value: Any) -> List[Any]:
    """Convert flexible values into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def clamp_number(value: Any, minimum: float, maximum: float, default: float) -> float:
    """Safely convert and clamp numeric values."""
    try:
        number = float(value)
    except Exception:
        number = default
    return max(minimum, min(maximum, number))


def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    """Safely convert and clamp integer values."""
    return int(clamp_number(value, minimum, maximum, default))


def count_words(text: str) -> int:
    """Count words in text."""
    return len(WORD_RE.findall(text or ""))


def split_sentences(text: str) -> List[str]:
    """Best-effort sentence splitter without external dependencies."""
    clean = normalize_text(text) or ""
    if not clean:
        return []
    parts = SENTENCE_SPLIT_RE.split(clean)
    sentences = [normalize_text(part) for part in parts]
    return [sentence for sentence in sentences if sentence]


def estimate_speech_duration_seconds(text: str, words_per_minute: int = 150) -> float:
    """Estimate spoken duration from word count."""
    words = count_words(text)
    if words <= 0:
        return 0.0
    return round((words / max(1, words_per_minute)) * 60, 2)


def generate_id(prefix: str) -> str:
    """Generate stable-style unique ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def hash_payload(payload: Dict[str, Any]) -> str:
    """Create SHA256 hash for payload identity/audit references."""
    raw = safe_json_dumps(payload)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def deep_copy_dict(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Safely deep copy dict values."""
    if not value:
        return {}
    try:
        return copy.deepcopy(value)
    except Exception:
        return dict(value)


def seconds_to_timecode(seconds: Union[int, float]) -> str:
    """Convert seconds to MM:SS.mmm style timecode."""
    seconds_float = max(0.0, float(seconds))
    minutes = int(seconds_float // 60)
    secs = seconds_float % 60
    return f"{minutes:02d}:{secs:06.3f}"


def normalize_platform(value: Any) -> str:
    """Normalize platform name into supported platform key."""
    text = (normalize_text(value) or "generic_vertical").lower()
    text = text.replace("-", "_").replace(" ", "_")
    aliases = {
        "shorts": "youtube_shorts",
        "youtube": "youtube_shorts",
        "yt_shorts": "youtube_shorts",
        "reels": "instagram_reels",
        "instagram": "instagram_reels",
        "ig_reels": "instagram_reels",
        "fb_reels": "facebook_reels",
        "facebook": "facebook_reels",
        "tik_tok": "tiktok",
        "vertical": "generic_vertical",
        "generic": "generic_vertical",
    }
    text = aliases.get(text, text)
    return text if text in SUPPORTED_PLATFORMS else "generic_vertical"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ShortFormPlatform(str, Enum):
    TIKTOK = "tiktok"
    YOUTUBE_SHORTS = "youtube_shorts"
    INSTAGRAM_REELS = "instagram_reels"
    FACEBOOK_REELS = "facebook_reels"
    LINKEDIN = "linkedin"
    GENERIC_VERTICAL = "generic_vertical"


class EditIntent(str, Enum):
    EDUCATIONAL = "educational"
    SALES = "sales"
    STORY = "story"
    ENTERTAINMENT = "entertainment"
    AUTHORITY = "authority"
    PRODUCT_DEMO = "product_demo"
    TESTIMONIAL = "testimonial"
    NEWS = "news"
    GENERAL = "general"


class CutType(str, Enum):
    JUMP_CUT = "jump_cut"
    PUNCH_IN = "punch_in"
    PUNCH_OUT = "punch_out"
    B_ROLL = "b_roll"
    TEXT_POP = "text_pop"
    CAPTION_EMPHASIS = "caption_emphasis"
    SOUND_HIT = "sound_hit"
    SPEED_RAMP = "speed_ramp"
    FREEZE_FRAME = "freeze_frame"
    SPLIT_SCREEN = "split_screen"
    SCREEN_RECORDING = "screen_recording"
    TRANSITION = "transition"
    CTA_CARD = "cta_card"


class RetentionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CaptionStyle(str, Enum):
    CLEAN = "clean"
    BOLD_KEYWORDS = "bold_keywords"
    KARAOKE = "karaoke"
    MINIMAL = "minimal"
    HIGH_ENERGY = "high_energy"


class PacingStyle(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    CALM = "calm"
    AGGRESSIVE = "aggressive"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PlatformPreset:
    """Platform-specific editing constraints and recommendations."""

    platform: str
    aspect_ratio: str = DEFAULT_ASPECT_RATIO
    recommended_duration_min: int = 15
    recommended_duration_max: int = 45
    max_duration: int = 60
    opening_hook_window: float = 1.5
    pattern_break_interval: float = 3.0
    caption_safe_area_top_percent: int = 12
    caption_safe_area_bottom_percent: int = 18
    preferred_caption_style: str = CaptionStyle.BOLD_KEYWORDS.value
    preferred_pacing: str = PacingStyle.BALANCED.value
    notes: List[str] = field(default_factory=list)


@dataclass
class ScriptSegment:
    """Script/transcript segment mapped to a time range."""

    segment_id: str
    start: float
    end: float
    text: str
    word_count: int
    estimated_wpm: int
    purpose: str = "body"
    retention_risk: str = RetentionRisk.LOW.value
    recommended_action: Optional[str] = None


@dataclass
class EditBeat:
    """One editing beat/cut/pattern break in the timeline."""

    beat_id: str
    start: float
    end: float
    cut_type: str
    instruction: str
    reason: str
    priority: str = "medium"
    assets_needed: List[str] = field(default_factory=list)
    overlay_text: Optional[str] = None
    caption_emphasis: List[str] = field(default_factory=list)
    sound_direction: Optional[str] = None


@dataclass
class RetentionScore:
    """Scoring summary for short-form performance risk."""

    hook_score: int
    pacing_score: int
    clarity_score: int
    pattern_break_score: int
    cta_score: int
    overall_score: int
    risk: str
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ShortFormEditPlan:
    """Canonical short-form edit plan."""

    plan_id: str
    user_id: str
    workspace_id: str
    project_id: Optional[str]
    platform: str
    intent: str
    target_duration_seconds: int
    estimated_duration_seconds: float
    aspect_ratio: str
    language: str

    title: Optional[str] = None
    hook: Optional[str] = None
    script: Optional[str] = None
    cta: Optional[str] = None

    segments: List[ScriptSegment] = field(default_factory=list)
    edit_beats: List[EditBeat] = field(default_factory=list)
    caption_plan: List[Dict[str, Any]] = field(default_factory=list)
    b_roll_plan: List[Dict[str, Any]] = field(default_factory=list)
    sound_plan: List[Dict[str, Any]] = field(default_factory=list)
    retention_score: Optional[RetentionScore] = None

    style_notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checklist: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ShortFormEditor(BaseAgent):
    """
    Creator Agent helper for Reels/Shorts/TikTok edit planning.

    This class does not render files. It produces edit-ready structured plans
    that can later be used by Video Editor Agent, Dashboard/API, or human editors.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", DEFAULT_AGENT_NAME),
            agent_id=kwargs.get("agent_id", DEFAULT_AGENT_ID),
            config=config or kwargs.get("config", {}) or {},
        )

        self.agent_name = kwargs.get("agent_name", DEFAULT_AGENT_NAME)
        self.agent_id = kwargs.get("agent_id", DEFAULT_AGENT_ID)
        self.version = kwargs.get("version", DEFAULT_VERSION)
        self.config = config or kwargs.get("config", {}) or {}

        self.security_callback = security_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self.default_language = self.config.get("default_language", DEFAULT_LANGUAGE)
        self.default_target_duration = clamp_int(
            self.config.get("default_target_duration_seconds", DEFAULT_TARGET_DURATION_SECONDS),
            5,
            180,
            DEFAULT_TARGET_DURATION_SECONDS,
        )
        self.default_words_per_minute = clamp_int(
            self.config.get("default_words_per_minute", 155),
            90,
            240,
            155,
        )
        self.default_pattern_break_interval = clamp_number(
            self.config.get("default_pattern_break_interval", 3.0),
            1.0,
            10.0,
            3.0,
        )

    # ------------------------------------------------------------------
    # Master Agent / Router entrypoint
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async task entrypoint compatible with Master Agent routing.

        Supported actions:
            - create_edit_plan
            - analyze_script
            - generate_cut_timeline
            - generate_retention_plan
            - optimize_hook
            - create_caption_plan
            - create_broll_plan
            - score_retention
        """
        try:
            context = self._validate_task_context(task)
            if not context["success"]:
                return context

            action = normalize_text(task.get("action")) or "create_edit_plan"
            payload = task.get("payload") or {}
            user_id = task["user_id"]
            workspace_id = task["workspace_id"]
            actor_id = task.get("actor_id")

            if self._requires_security_check(action, payload):
                approval = self._request_security_approval(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    payload=payload,
                    actor_id=actor_id,
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval denied or unavailable.",
                        error="SECURITY_APPROVAL_REQUIRED",
                        metadata={
                            "action": action,
                            "approval": approval,
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                        },
                    )

            if action in {"create_edit_plan", "create_short_form_plan", "plan_short"}:
                return self.create_edit_plan(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "analyze_script":
                return self.analyze_script(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "generate_cut_timeline":
                return self.generate_cut_timeline(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "generate_retention_plan":
                return self.generate_retention_plan(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "optimize_hook":
                return self.optimize_hook(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "create_caption_plan":
                return self.create_caption_plan(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "create_broll_plan":
                return self.create_broll_plan(user_id, workspace_id, payload, actor_id=actor_id)

            if action == "score_retention":
                return self.score_retention(user_id, workspace_id, payload, actor_id=actor_id)

            return self._error_result(
                message=f"Unsupported ShortFormEditor action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"action": action},
            )

        except Exception as exc:
            LOGGER.exception("ShortFormEditor run failed.")
            return self._error_result(
                message="ShortFormEditor task failed.",
                error=str(exc),
                metadata={"agent": self.agent_id},
            )

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def create_edit_plan(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a full short-form editing plan.

        Input payload may include:
            {
                "project_id": str,
                "platform": "tiktok" | "youtube_shorts" | "instagram_reels",
                "intent": "educational" | "sales" | ...,
                "title": str,
                "script": str,
                "transcript": str,
                "hook": str,
                "cta": str,
                "target_duration_seconds": int,
                "language": str,
                "brand_style": dict,
                "assets": list,
                "notes": list
            }
        """
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        try:
            payload = deep_copy_dict(payload)
            script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
            if not script:
                return self._error_result(
                    message="script, transcript, or voiceover text is required.",
                    error="MISSING_SCRIPT",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            platform = normalize_platform(payload.get("platform"))
            preset = self.get_platform_preset(platform)
            intent = self._normalize_intent(payload.get("intent"))
            target_duration = clamp_int(
                payload.get("target_duration_seconds", self.default_target_duration),
                5,
                preset.max_duration,
                self.default_target_duration,
            )
            language = normalize_text(payload.get("language")) or self.default_language
            estimated_duration = estimate_speech_duration_seconds(script, self.default_words_per_minute)

            segments = self._segment_script(
                script=script,
                target_duration_seconds=target_duration,
                words_per_minute=self.default_words_per_minute,
            )

            hook = normalize_text(payload.get("hook")) or self._extract_hook(script)
            cta = normalize_text(payload.get("cta")) or self._extract_cta(script)

            edit_beats = self._build_edit_beats(
                segments=segments,
                platform=platform,
                preset=preset,
                intent=intent,
                hook=hook,
                cta=cta,
                payload=payload,
            )
            caption_plan = self._build_caption_plan(
                segments=segments,
                preset=preset,
                style=payload.get("caption_style"),
            )
            b_roll_plan = self._build_broll_plan(
                segments=segments,
                intent=intent,
                assets=ensure_list(payload.get("assets")),
            )
            sound_plan = self._build_sound_plan(
                segments=segments,
                edit_beats=edit_beats,
                platform=platform,
                intent=intent,
            )
            retention_score = self._calculate_retention_score(
                script=script,
                hook=hook,
                cta=cta,
                segments=segments,
                edit_beats=edit_beats,
                target_duration_seconds=target_duration,
                estimated_duration_seconds=estimated_duration,
            )

            warnings = self._build_warnings(
                preset=preset,
                target_duration_seconds=target_duration,
                estimated_duration_seconds=estimated_duration,
                retention_score=retention_score,
                segments=segments,
            )

            plan = ShortFormEditPlan(
                plan_id=generate_id("short_plan"),
                user_id=user_id,
                workspace_id=workspace_id,
                project_id=normalize_text(payload.get("project_id")),
                platform=platform,
                intent=intent,
                target_duration_seconds=target_duration,
                estimated_duration_seconds=estimated_duration,
                aspect_ratio=normalize_text(payload.get("aspect_ratio")) or preset.aspect_ratio,
                language=language,
                title=normalize_text(payload.get("title")),
                hook=hook,
                script=script,
                cta=cta,
                segments=segments,
                edit_beats=edit_beats,
                caption_plan=caption_plan,
                b_roll_plan=b_roll_plan,
                sound_plan=sound_plan,
                retention_score=retention_score,
                style_notes=self._build_style_notes(platform, intent, payload),
                warnings=warnings,
                checklist=self._build_editor_checklist(platform, intent),
                metadata={
                    "payload_hash": hash_payload(payload),
                    "actor_id": actor_id,
                    "platform_preset": asdict(preset),
                    "source": payload.get("source", "manual"),
                },
            )

            data = {"edit_plan": self._serialize_plan(plan)}

            self._emit_agent_event("short_form.edit_plan_created", user_id, workspace_id, data)
            self._log_audit_event("short_form_edit_plan_created", user_id, workspace_id, actor_id, data)
            self._send_memory_payload("short_form_edit_plan_created", plan)
            self._send_verification_payload("short_form_edit_plan_created", plan, data)

            return self._safe_result(
                success=True,
                message="Short-form edit plan created successfully.",
                data=data,
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "plan_id": plan.plan_id,
                    "platform": platform,
                    "overall_score": retention_score.overall_score,
                },
            )

        except Exception as exc:
            LOGGER.exception("Failed to create short-form edit plan.")
            return self._error_result(
                message="Failed to create short-form edit plan.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def analyze_script(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze short-form script for pacing, duration, hook, and CTA."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
        if not script:
            return self._error_result("script, transcript, or voiceover text is required.", "MISSING_SCRIPT")

        words = count_words(script)
        estimated_duration = estimate_speech_duration_seconds(script, self.default_words_per_minute)
        target_duration = clamp_int(payload.get("target_duration_seconds", self.default_target_duration), 5, 180, self.default_target_duration)
        segments = self._segment_script(script, target_duration, self.default_words_per_minute)
        hook = normalize_text(payload.get("hook")) or self._extract_hook(script)
        cta = normalize_text(payload.get("cta")) or self._extract_cta(script)

        analysis = {
            "word_count": words,
            "estimated_duration_seconds": estimated_duration,
            "target_duration_seconds": target_duration,
            "estimated_words_per_minute": self.default_words_per_minute,
            "hook": hook,
            "cta": cta,
            "segment_count": len(segments),
            "segments": [asdict(segment) for segment in segments],
            "recommendations": self._script_recommendations(script, hook, cta, estimated_duration, target_duration),
        }

        self._emit_agent_event("short_form.script_analyzed", user_id, workspace_id, analysis)

        return self._safe_result(
            success=True,
            message="Script analyzed successfully.",
            data={"analysis": analysis},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "actor_id": actor_id},
        )

    def generate_cut_timeline(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate timeline cuts/pattern breaks from script or segments."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
        if not script:
            return self._error_result("script, transcript, or voiceover text is required.", "MISSING_SCRIPT")

        platform = normalize_platform(payload.get("platform"))
        preset = self.get_platform_preset(platform)
        target_duration = clamp_int(payload.get("target_duration_seconds", self.default_target_duration), 5, preset.max_duration, self.default_target_duration)
        intent = self._normalize_intent(payload.get("intent"))
        segments = self._segment_script(script, target_duration, self.default_words_per_minute)

        edit_beats = self._build_edit_beats(
            segments=segments,
            platform=platform,
            preset=preset,
            intent=intent,
            hook=normalize_text(payload.get("hook")) or self._extract_hook(script),
            cta=normalize_text(payload.get("cta")) or self._extract_cta(script),
            payload=payload,
        )

        data = {
            "timeline": [asdict(beat) for beat in edit_beats],
            "platform": platform,
            "target_duration_seconds": target_duration,
            "timeline_summary": self._timeline_summary(edit_beats),
        }

        self._emit_agent_event("short_form.cut_timeline_generated", user_id, workspace_id, data)

        return self._safe_result(
            success=True,
            message="Cut timeline generated successfully.",
            data=data,
            metadata={"user_id": user_id, "workspace_id": workspace_id, "actor_id": actor_id},
        )

    def generate_retention_plan(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate retention-specific improvement plan."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
        if not script:
            return self._error_result("script, transcript, or voiceover text is required.", "MISSING_SCRIPT")

        platform = normalize_platform(payload.get("platform"))
        preset = self.get_platform_preset(platform)
        target_duration = clamp_int(payload.get("target_duration_seconds", self.default_target_duration), 5, preset.max_duration, self.default_target_duration)
        segments = self._segment_script(script, target_duration, self.default_words_per_minute)
        hook = normalize_text(payload.get("hook")) or self._extract_hook(script)
        cta = normalize_text(payload.get("cta")) or self._extract_cta(script)

        edit_beats = self._build_edit_beats(
            segments=segments,
            platform=platform,
            preset=preset,
            intent=self._normalize_intent(payload.get("intent")),
            hook=hook,
            cta=cta,
            payload=payload,
        )

        score = self._calculate_retention_score(
            script=script,
            hook=hook,
            cta=cta,
            segments=segments,
            edit_beats=edit_beats,
            target_duration_seconds=target_duration,
            estimated_duration_seconds=estimate_speech_duration_seconds(script, self.default_words_per_minute),
        )

        plan = {
            "score": asdict(score),
            "retention_actions": self._retention_actions(score, segments, edit_beats),
            "first_3_seconds": self._first_three_second_plan(hook, platform),
            "pattern_breaks": [asdict(beat) for beat in edit_beats if beat.cut_type in {
                CutType.PUNCH_IN.value,
                CutType.TEXT_POP.value,
                CutType.SOUND_HIT.value,
                CutType.B_ROLL.value,
                CutType.FREEZE_FRAME.value,
            }],
        }

        self._emit_agent_event("short_form.retention_plan_generated", user_id, workspace_id, plan)

        return self._safe_result(
            success=True,
            message="Retention plan generated successfully.",
            data={"retention_plan": plan},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "actor_id": actor_id},
        )

    def optimize_hook(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate stronger hook options for the first 1-3 seconds."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("topic") or payload.get("hook"))
        if not script:
            return self._error_result("script, topic, or hook is required.", "MISSING_HOOK_INPUT")

        intent = self._normalize_intent(payload.get("intent"))
        platform = normalize_platform(payload.get("platform"))
        current_hook = normalize_text(payload.get("hook")) or self._extract_hook(script)
        options = self._generate_hook_options(script, intent, platform)

        data = {
            "current_hook": current_hook,
            "platform": platform,
            "intent": intent,
            "recommended_hooks": options,
            "hook_rules": [
                "Open with tension, contrast, pain, curiosity, or a clear promise.",
                "Avoid slow intros, greetings, and brand names in the first second.",
                "Make the first caption line readable in under one second.",
                "Use a visual change before the viewer has time to scroll.",
            ],
        }

        return self._safe_result(
            success=True,
            message="Hook options generated successfully.",
            data=data,
            metadata={"user_id": user_id, "workspace_id": workspace_id, "actor_id": actor_id},
        )

    def create_caption_plan(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create timed caption plan for short-form edit."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
        if not script:
            return self._error_result("script, transcript, or voiceover text is required.", "MISSING_SCRIPT")

        platform = normalize_platform(payload.get("platform"))
        preset = self.get_platform_preset(platform)
        target_duration = clamp_int(payload.get("target_duration_seconds", self.default_target_duration), 5, preset.max_duration, self.default_target_duration)
        segments = self._segment_script(script, target_duration, self.default_words_per_minute)
        caption_plan = self._build_caption_plan(segments, preset, payload.get("caption_style"))

        return self._safe_result(
            success=True,
            message="Caption plan created successfully.",
            data={
                "caption_plan": caption_plan,
                "caption_safe_area": {
                    "top_percent": preset.caption_safe_area_top_percent,
                    "bottom_percent": preset.caption_safe_area_bottom_percent,
                },
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id, "platform": platform, "actor_id": actor_id},
        )

    def create_broll_plan(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create B-roll plan for short-form pacing and clarity."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
        if not script:
            return self._error_result("script, transcript, or voiceover text is required.", "MISSING_SCRIPT")

        target_duration = clamp_int(payload.get("target_duration_seconds", self.default_target_duration), 5, 180, self.default_target_duration)
        intent = self._normalize_intent(payload.get("intent"))
        segments = self._segment_script(script, target_duration, self.default_words_per_minute)
        b_roll_plan = self._build_broll_plan(segments, intent, ensure_list(payload.get("assets")))

        return self._safe_result(
            success=True,
            message="B-roll plan created successfully.",
            data={"b_roll_plan": b_roll_plan},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "actor_id": actor_id},
        )

    def score_retention(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Score a short-form script/edit for retention risk."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        script = normalize_text(payload.get("script") or payload.get("transcript") or payload.get("voiceover"))
        if not script:
            return self._error_result("script, transcript, or voiceover text is required.", "MISSING_SCRIPT")

        target_duration = clamp_int(payload.get("target_duration_seconds", self.default_target_duration), 5, 180, self.default_target_duration)
        platform = normalize_platform(payload.get("platform"))
        preset = self.get_platform_preset(platform)
        segments = self._segment_script(script, target_duration, self.default_words_per_minute)
        edit_beats = self._build_edit_beats(
            segments=segments,
            platform=platform,
            preset=preset,
            intent=self._normalize_intent(payload.get("intent")),
            hook=normalize_text(payload.get("hook")) or self._extract_hook(script),
            cta=normalize_text(payload.get("cta")) or self._extract_cta(script),
            payload=payload,
        )
        score = self._calculate_retention_score(
            script=script,
            hook=normalize_text(payload.get("hook")) or self._extract_hook(script),
            cta=normalize_text(payload.get("cta")) or self._extract_cta(script),
            segments=segments,
            edit_beats=edit_beats,
            target_duration_seconds=target_duration,
            estimated_duration_seconds=estimate_speech_duration_seconds(script, self.default_words_per_minute),
        )

        return self._safe_result(
            success=True,
            message="Retention score generated successfully.",
            data={"retention_score": asdict(score)},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "actor_id": actor_id},
        )

    # ------------------------------------------------------------------
    # Platform presets
    # ------------------------------------------------------------------

    def get_platform_preset(self, platform: Any) -> PlatformPreset:
        """Return platform editing preset."""
        platform_key = normalize_platform(platform)

        if platform_key == ShortFormPlatform.TIKTOK.value:
            return PlatformPreset(
                platform=platform_key,
                recommended_duration_min=12,
                recommended_duration_max=35,
                max_duration=180,
                opening_hook_window=1.0,
                pattern_break_interval=2.5,
                preferred_caption_style=CaptionStyle.HIGH_ENERGY.value,
                preferred_pacing=PacingStyle.FAST.value,
                notes=[
                    "Prioritize fast visual change in the first second.",
                    "Use native-feeling captions and quick proof moments.",
                    "Avoid long logo intros.",
                ],
            )

        if platform_key == ShortFormPlatform.YOUTUBE_SHORTS.value:
            return PlatformPreset(
                platform=platform_key,
                recommended_duration_min=20,
                recommended_duration_max=55,
                max_duration=60,
                opening_hook_window=1.5,
                pattern_break_interval=3.0,
                preferred_caption_style=CaptionStyle.BOLD_KEYWORDS.value,
                preferred_pacing=PacingStyle.BALANCED.value,
                notes=[
                    "Make the topic clear immediately.",
                    "Use payoff structure to improve completion rate.",
                    "Keep CTA quick and natural.",
                ],
            )

        if platform_key == ShortFormPlatform.INSTAGRAM_REELS.value:
            return PlatformPreset(
                platform=platform_key,
                recommended_duration_min=10,
                recommended_duration_max=45,
                max_duration=90,
                opening_hook_window=1.5,
                pattern_break_interval=3.0,
                preferred_caption_style=CaptionStyle.KARAOKE.value,
                preferred_pacing=PacingStyle.FAST.value,
                notes=[
                    "Use clean visuals and strong on-screen text.",
                    "Add pattern breaks every 2-4 seconds.",
                    "Keep captions inside safe zone.",
                ],
            )

        if platform_key == ShortFormPlatform.FACEBOOK_REELS.value:
            return PlatformPreset(
                platform=platform_key,
                recommended_duration_min=15,
                recommended_duration_max=45,
                max_duration=90,
                opening_hook_window=2.0,
                pattern_break_interval=3.5,
                preferred_caption_style=CaptionStyle.CLEAN.value,
                preferred_pacing=PacingStyle.BALANCED.value,
                notes=[
                    "Use clear captions for sound-off viewing.",
                    "Make the benefit obvious early.",
                    "Avoid overly dense text overlays.",
                ],
            )

        if platform_key == ShortFormPlatform.LINKEDIN.value:
            return PlatformPreset(
                platform=platform_key,
                recommended_duration_min=20,
                recommended_duration_max=60,
                max_duration=120,
                opening_hook_window=2.0,
                pattern_break_interval=4.0,
                preferred_caption_style=CaptionStyle.CLEAN.value,
                preferred_pacing=PacingStyle.CALM.value,
                notes=[
                    "Keep pacing professional and clear.",
                    "Use proof, numbers, and business outcomes.",
                    "Avoid gimmicky transitions.",
                ],
            )

        return PlatformPreset(
            platform=ShortFormPlatform.GENERIC_VERTICAL.value,
            recommended_duration_min=15,
            recommended_duration_max=45,
            max_duration=90,
            opening_hook_window=1.5,
            pattern_break_interval=3.0,
            preferred_caption_style=CaptionStyle.BOLD_KEYWORDS.value,
            preferred_pacing=PacingStyle.BALANCED.value,
            notes=[
                "Use vertical 9:16 framing.",
                "Add clear captions.",
                "Break visual pattern every 3 seconds.",
            ],
        )

    # ------------------------------------------------------------------
    # Internal generation methods
    # ------------------------------------------------------------------

    def _segment_script(
        self,
        script: str,
        target_duration_seconds: int,
        words_per_minute: int,
    ) -> List[ScriptSegment]:
        """Convert script into approximate timed segments."""
        sentences = split_sentences(script)
        if not sentences:
            return []

        total_words = max(1, count_words(script))
        total_duration = estimate_speech_duration_seconds(script, words_per_minute)
        if total_duration <= 0:
            total_duration = float(target_duration_seconds)

        segments: List[ScriptSegment] = []
        current_start = 0.0

        for index, sentence in enumerate(sentences):
            words = count_words(sentence)
            segment_duration = max(0.8, (words / total_words) * total_duration)
            current_end = current_start + segment_duration

            purpose = "body"
            if index == 0:
                purpose = "hook"
            elif index == len(sentences) - 1:
                purpose = "cta_or_close"

            estimated_wpm = int((words / max(0.1, segment_duration)) * 60)
            retention_risk = self._segment_retention_risk(sentence, segment_duration, estimated_wpm, index)

            segments.append(
                ScriptSegment(
                    segment_id=f"seg_{index + 1:03d}",
                    start=round(current_start, 2),
                    end=round(current_end, 2),
                    text=sentence,
                    word_count=words,
                    estimated_wpm=estimated_wpm,
                    purpose=purpose,
                    retention_risk=retention_risk,
                    recommended_action=self._segment_action(retention_risk, purpose),
                )
            )
            current_start = current_end

        return segments

    def _build_edit_beats(
        self,
        segments: List[ScriptSegment],
        platform: str,
        preset: PlatformPreset,
        intent: str,
        hook: Optional[str],
        cta: Optional[str],
        payload: Dict[str, Any],
    ) -> List[EditBeat]:
        """Build edit beat timeline with retention-focused pattern breaks."""
        beats: List[EditBeat] = []

        if not segments:
            return beats

        first = segments[0]
        beats.append(
            EditBeat(
                beat_id=generate_id("beat"),
                start=0.0,
                end=min(first.end, preset.opening_hook_window),
                cut_type=CutType.TEXT_POP.value,
                instruction="Open with large on-screen hook text and immediate visual movement.",
                reason="The first second must stop the scroll and communicate value fast.",
                priority="high",
                overlay_text=self._short_overlay(hook or first.text, max_words=8),
                caption_emphasis=self._extract_keywords(hook or first.text, limit=3),
                sound_direction="Add subtle impact hit or beat drop on first frame.",
            )
        )

        beats.append(
            EditBeat(
                beat_id=generate_id("beat"),
                start=round(min(0.8, first.end), 2),
                end=round(min(1.6, first.end + 0.4), 2),
                cut_type=CutType.PUNCH_IN.value,
                instruction="Punch in 8-15% after the hook line.",
                reason="Early camera movement prevents a static opening.",
                priority="high",
            )
        )

        interval = preset.pattern_break_interval
        current_time = interval
        total_end = max(segment.end for segment in segments)

        pattern_cycle = [
            CutType.PUNCH_IN.value,
            CutType.B_ROLL.value,
            CutType.CAPTION_EMPHASIS.value,
            CutType.SOUND_HIT.value,
            CutType.PUNCH_OUT.value,
            CutType.TEXT_POP.value,
        ]

        cycle_index = 0
        while current_time < total_end:
            segment = self._segment_at_time(segments, current_time)
            cut_type = pattern_cycle[cycle_index % len(pattern_cycle)]
            instruction, reason = self._pattern_break_instruction(cut_type, segment, intent, platform)

            beats.append(
                EditBeat(
                    beat_id=generate_id("beat"),
                    start=round(current_time, 2),
                    end=round(min(current_time + 0.7, total_end), 2),
                    cut_type=cut_type,
                    instruction=instruction,
                    reason=reason,
                    priority="high" if segment and segment.retention_risk == RetentionRisk.HIGH.value else "medium",
                    assets_needed=self._assets_for_cut(cut_type, segment, intent),
                    overlay_text=self._overlay_for_cut(cut_type, segment),
                    caption_emphasis=self._extract_keywords(segment.text if segment else "", limit=3),
                    sound_direction=self._sound_for_cut(cut_type),
                )
            )
            current_time += interval
            cycle_index += 1

        for segment in segments:
            if segment.retention_risk == RetentionRisk.HIGH.value:
                beats.append(
                    EditBeat(
                        beat_id=generate_id("beat"),
                        start=segment.start,
                        end=min(segment.end, segment.start + 1.2),
                        cut_type=CutType.B_ROLL.value,
                        instruction="Cover this slower/high-risk section with relevant B-roll or screen recording.",
                        reason="This segment may feel too dense or slow for short-form retention.",
                        priority="high",
                        assets_needed=self._assets_for_cut(CutType.B_ROLL.value, segment, intent),
                        overlay_text=self._short_overlay(segment.text, max_words=6),
                        caption_emphasis=self._extract_keywords(segment.text, limit=4),
                    )
                )

        if cta:
            final_start = max(0.0, total_end - 3.0)
            beats.append(
                EditBeat(
                    beat_id=generate_id("beat"),
                    start=round(final_start, 2),
                    end=round(total_end, 2),
                    cut_type=CutType.CTA_CARD.value,
                    instruction="Show quick CTA card with clear next step. Keep it under 3 seconds.",
                    reason="Short-form CTA should be fast, visual, and easy to act on.",
                    priority="high",
                    overlay_text=self._short_overlay(cta, max_words=8),
                    caption_emphasis=self._extract_keywords(cta, limit=3),
                    sound_direction="Lower music slightly so CTA is clear.",
                )
            )

        beats.sort(key=lambda beat: (beat.start, beat.end, beat.cut_type))
        return self._dedupe_close_beats(beats)

    def _build_caption_plan(
        self,
        segments: List[ScriptSegment],
        preset: PlatformPreset,
        style: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Build timed captions with keyword emphasis."""
        caption_style = self._normalize_caption_style(style or preset.preferred_caption_style)
        caption_plan: List[Dict[str, Any]] = []

        for segment in segments:
            chunks = self._caption_chunks(segment.text, max_words=7 if caption_style != CaptionStyle.MINIMAL.value else 5)
            duration = max(0.1, segment.end - segment.start)
            chunk_duration = duration / max(1, len(chunks))

            for index, chunk in enumerate(chunks):
                start = segment.start + (index * chunk_duration)
                end = min(segment.end, start + chunk_duration)
                caption_plan.append({
                    "caption_id": generate_id("cap"),
                    "start": round(start, 2),
                    "end": round(end, 2),
                    "timecode_start": seconds_to_timecode(start),
                    "timecode_end": seconds_to_timecode(end),
                    "text": chunk,
                    "style": caption_style,
                    "emphasis_words": self._extract_keywords(chunk, limit=2),
                    "safe_area": {
                        "top_percent": preset.caption_safe_area_top_percent,
                        "bottom_percent": preset.caption_safe_area_bottom_percent,
                    },
                    "instruction": self._caption_instruction(caption_style),
                })

        return caption_plan

    def _build_broll_plan(
        self,
        segments: List[ScriptSegment],
        intent: str,
        assets: Sequence[Any],
    ) -> List[Dict[str, Any]]:
        """Build B-roll and visual support plan."""
        asset_labels = [normalize_text(asset) for asset in assets]
        asset_labels = [asset for asset in asset_labels if asset]

        broll: List[Dict[str, Any]] = []
        for segment in segments:
            needs_broll = (
                segment.retention_risk in {RetentionRisk.MEDIUM.value, RetentionRisk.HIGH.value}
                or segment.purpose == "hook"
                or self._contains_abstract_claim(segment.text)
            )
            if not needs_broll:
                continue

            visual_type = self._visual_type_for_segment(segment, intent)
            broll.append({
                "broll_id": generate_id("broll"),
                "start": segment.start,
                "end": segment.end,
                "timecode_start": seconds_to_timecode(segment.start),
                "timecode_end": seconds_to_timecode(segment.end),
                "segment_id": segment.segment_id,
                "visual_type": visual_type,
                "suggestion": self._broll_suggestion(segment, intent, asset_labels),
                "assets_needed": self._assets_for_visual_type(visual_type, segment, intent),
                "reason": "Supports clarity and prevents static talking-head fatigue.",
            })

        return broll

    def _build_sound_plan(
        self,
        segments: List[ScriptSegment],
        edit_beats: List[EditBeat],
        platform: str,
        intent: str,
    ) -> List[Dict[str, Any]]:
        """Build sound and music direction plan."""
        total_end = max((segment.end for segment in segments), default=0.0)
        sound_plan: List[Dict[str, Any]] = [
            {
                "sound_id": generate_id("sound"),
                "start": 0.0,
                "end": round(total_end, 2),
                "type": "music_bed",
                "instruction": self._music_bed_instruction(platform, intent),
                "volume_guidance": "Keep music below voice. Duck music during key proof or CTA lines.",
            }
        ]

        for beat in edit_beats:
            if beat.sound_direction:
                sound_plan.append({
                    "sound_id": generate_id("sound"),
                    "start": beat.start,
                    "end": beat.end,
                    "type": "sound_effect",
                    "linked_beat_id": beat.beat_id,
                    "instruction": beat.sound_direction,
                    "volume_guidance": "Use lightly. Do not overpower voice.",
                })

        return sound_plan

    def _calculate_retention_score(
        self,
        script: str,
        hook: Optional[str],
        cta: Optional[str],
        segments: List[ScriptSegment],
        edit_beats: List[EditBeat],
        target_duration_seconds: int,
        estimated_duration_seconds: float,
    ) -> RetentionScore:
        """Score retention strength."""
        hook_text = hook or ""
        hook_words = count_words(hook_text)
        hook_score = 50
        if hook_words <= 12 and hook_words >= 3:
            hook_score += 20
        if self._has_curiosity_or_tension(hook_text):
            hook_score += 20
        if hook_text.lower().startswith(("hi ", "hello", "welcome", "today i")):
            hook_score -= 25
        hook_score = clamp_int(hook_score, 0, 100, 50)

        duration_gap = abs(estimated_duration_seconds - target_duration_seconds)
        pacing_score = 90 - int(duration_gap * 2)
        if estimated_duration_seconds > target_duration_seconds * 1.25:
            pacing_score -= 15
        pacing_score = clamp_int(pacing_score, 0, 100, 70)

        avg_sentence_words = count_words(script) / max(1, len(split_sentences(script)))
        clarity_score = 90
        if avg_sentence_words > 22:
            clarity_score -= 25
        if avg_sentence_words > 30:
            clarity_score -= 20
        if self._jargon_density(script) > 0.08:
            clarity_score -= 15
        clarity_score = clamp_int(clarity_score, 0, 100, 75)

        total_duration = max(1.0, max((segment.end for segment in segments), default=estimated_duration_seconds or 1))
        pattern_break_count = len(edit_beats)
        ideal_breaks = max(1, int(total_duration / self.default_pattern_break_interval))
        pattern_break_score = int(100 - abs(pattern_break_count - ideal_breaks) * 8)
        pattern_break_score = clamp_int(pattern_break_score, 0, 100, 70)

        cta_score = 50
        if cta:
            cta_words = count_words(cta)
            cta_score += 25 if cta_words <= 12 else 10
            if any(word in cta.lower() for word in ["comment", "follow", "message", "click", "book", "save", "share", "dm"]):
                cta_score += 15
        cta_score = clamp_int(cta_score, 0, 100, 50)

        overall = int(round(
            hook_score * 0.25
            + pacing_score * 0.20
            + clarity_score * 0.20
            + pattern_break_score * 0.25
            + cta_score * 0.10
        ))

        risk = RetentionRisk.LOW.value
        if overall < 55:
            risk = RetentionRisk.HIGH.value
        elif overall < 75:
            risk = RetentionRisk.MEDIUM.value

        recommendations = []
        if hook_score < 75:
            recommendations.append("Rewrite the first line with more curiosity, tension, or a direct benefit.")
        if pacing_score < 75:
            recommendations.append("Trim or speed up the script so it fits the target duration.")
        if clarity_score < 75:
            recommendations.append("Simplify long sentences and replace jargon with visual examples.")
        if pattern_break_score < 75:
            recommendations.append("Add pattern breaks every 2-4 seconds using zooms, B-roll, captions, or sound hits.")
        if cta_score < 70:
            recommendations.append("Add one clear CTA in the final 2-3 seconds.")

        return RetentionScore(
            hook_score=hook_score,
            pacing_score=pacing_score,
            clarity_score=clarity_score,
            pattern_break_score=pattern_break_score,
            cta_score=cta_score,
            overall_score=overall,
            risk=risk,
            recommendations=recommendations,
        )

    # ------------------------------------------------------------------
    # Hook, CTA, recommendations
    # ------------------------------------------------------------------

    def _extract_hook(self, script: str) -> Optional[str]:
        """Use first sentence or first 12 words as hook."""
        sentences = split_sentences(script)
        if sentences:
            return self._short_overlay(sentences[0], max_words=14)
        words = WORD_RE.findall(script)
        return " ".join(words[:12]) if words else None

    def _extract_cta(self, script: str) -> Optional[str]:
        """Best-effort CTA detection from final sentence."""
        sentences = split_sentences(script)
        if not sentences:
            return None
        final = sentences[-1]
        cta_terms = ["follow", "comment", "share", "save", "book", "message", "dm", "click", "subscribe", "call"]
        if any(term in final.lower() for term in cta_terms):
            return final
        return None

    def _generate_hook_options(self, script_or_topic: str, intent: str, platform: str) -> List[Dict[str, Any]]:
        """Generate practical short-form hook options."""
        topic = self._topic_from_text(script_or_topic)
        pain = "you are losing attention"
        outcome = "get better results"

        if intent == EditIntent.SALES.value:
            options = [
                f"Most businesses lose leads because of this one mistake.",
                f"If your ads are getting clicks but no sales, watch this.",
                f"Stop wasting money before you fix this.",
                f"Here is why customers are not buying from you.",
                f"Do this before you run your next campaign.",
            ]
        elif intent == EditIntent.EDUCATIONAL.value:
            options = [
                f"Here is the simple way to understand {topic}.",
                f"Most people explain {topic} wrong.",
                f"Learn this before you try {topic}.",
                f"This is the fastest way to improve {topic}.",
                f"If {topic} feels confusing, start here.",
            ]
        elif intent == EditIntent.PRODUCT_DEMO.value:
            options = [
                f"Watch how this solves the problem in seconds.",
                f"This is what happens when you use it the right way.",
                f"Here is the feature most people miss.",
                f"Before and after using this is completely different.",
                f"Let me show you the quickest demo.",
            ]
        elif intent == EditIntent.STORY.value:
            options = [
                f"I did not expect this to happen.",
                f"This started as a small problem.",
                f"Here is the moment everything changed.",
                f"I almost ignored this, and that was the mistake.",
                f"The result surprised me.",
            ]
        else:
            options = [
                f"Stop scrolling if you care about {topic}.",
                f"This one change can help you {outcome}.",
                f"Nobody tells you this about {topic}.",
                f"If you are doing {topic}, avoid this mistake.",
                f"Here is the shortcut I would use first.",
            ]

        return [
            {
                "hook_id": generate_id("hook"),
                "text": option,
                "first_frame_text": self._short_overlay(option, max_words=7),
                "visual_direction": self._hook_visual_direction(platform),
                "why_it_works": "Creates curiosity and gives the viewer a reason to keep watching.",
            }
            for option in options
        ]

    def _script_recommendations(
        self,
        script: str,
        hook: Optional[str],
        cta: Optional[str],
        estimated_duration: float,
        target_duration: int,
    ) -> List[str]:
        """Generate script-level edit recommendations."""
        recommendations: List[str] = []

        if not hook or count_words(hook) > 14:
            recommendations.append("Shorten the opening hook to one sharp line under 12-14 words.")

        if estimated_duration > target_duration * 1.2:
            recommendations.append("Trim the script or increase pacing because estimated duration exceeds target length.")

        if not cta:
            recommendations.append("Add a clear CTA in the final 2-3 seconds.")

        if self._jargon_density(script) > 0.08:
            recommendations.append("Reduce jargon and replace abstract claims with simple examples or visuals.")

        if len(split_sentences(script)) < 3:
            recommendations.append("Add clearer structure: hook, proof/value, payoff, CTA.")

        if not recommendations:
            recommendations.append("Script structure is usable. Focus on strong captions and pattern breaks.")

        return recommendations

    # ------------------------------------------------------------------
    # Retention helpers
    # ------------------------------------------------------------------

    def _segment_retention_risk(
        self,
        sentence: str,
        duration: float,
        estimated_wpm: int,
        index: int,
    ) -> str:
        """Estimate retention risk for one segment."""
        words = count_words(sentence)
        risk_points = 0

        if words > 24:
            risk_points += 2
        elif words > 16:
            risk_points += 1

        if duration > 5:
            risk_points += 2
        elif duration > 3.5:
            risk_points += 1

        if estimated_wpm < 115:
            risk_points += 1

        if self._contains_abstract_claim(sentence):
            risk_points += 1

        if index == 0 and not self._has_curiosity_or_tension(sentence):
            risk_points += 1

        if risk_points >= 4:
            return RetentionRisk.HIGH.value
        if risk_points >= 2:
            return RetentionRisk.MEDIUM.value
        return RetentionRisk.LOW.value

    def _segment_action(self, risk: str, purpose: str) -> Optional[str]:
        """Recommend action based on segment risk."""
        if purpose == "hook":
            return "Use bold hook text, punch-in, and immediate visual proof."
        if risk == RetentionRisk.HIGH.value:
            return "Trim, split sentence, add B-roll, or add text emphasis."
        if risk == RetentionRisk.MEDIUM.value:
            return "Add caption emphasis or subtle zoom."
        return "Keep clean pacing."

    def _retention_actions(
        self,
        score: RetentionScore,
        segments: List[ScriptSegment],
        edit_beats: List[EditBeat],
    ) -> List[Dict[str, Any]]:
        """Build actionable retention tasks."""
        actions: List[Dict[str, Any]] = []

        for rec in score.recommendations:
            actions.append({
                "action_id": generate_id("retention_action"),
                "priority": "high" if score.risk == RetentionRisk.HIGH.value else "medium",
                "task": rec,
            })

        high_risk_segments = [segment for segment in segments if segment.retention_risk == RetentionRisk.HIGH.value]
        for segment in high_risk_segments:
            actions.append({
                "action_id": generate_id("retention_action"),
                "priority": "high",
                "segment_id": segment.segment_id,
                "timecode_start": seconds_to_timecode(segment.start),
                "timecode_end": seconds_to_timecode(segment.end),
                "task": "Split this segment with B-roll, proof visual, or caption emphasis.",
                "text": segment.text,
            })

        if len(edit_beats) < max(1, int(max((s.end for s in segments), default=0) / 4)):
            actions.append({
                "action_id": generate_id("retention_action"),
                "priority": "medium",
                "task": "Add more visual pattern breaks to avoid static sections.",
            })

        return actions

    def _first_three_second_plan(self, hook: Optional[str], platform: str) -> Dict[str, Any]:
        """First 3-second opening plan."""
        hook_text = hook or "Start with the strongest promise or problem."
        return {
            "0.0-0.5": "Show motion immediately. No logo intro.",
            "0.5-1.5": f"Display hook text: {self._short_overlay(hook_text, max_words=7)}",
            "1.5-3.0": "Punch in or switch visual while continuing the first value line.",
            "platform_note": self._hook_visual_direction(platform),
        }

    # ------------------------------------------------------------------
    # Visual, caption, sound helpers
    # ------------------------------------------------------------------

    def _pattern_break_instruction(
        self,
        cut_type: str,
        segment: Optional[ScriptSegment],
        intent: str,
        platform: str,
    ) -> Tuple[str, str]:
        """Return instruction/reason for a pattern break."""
        text = segment.text if segment else ""

        if cut_type == CutType.PUNCH_IN.value:
            return "Punch in 8-12% on the key phrase.", "Subtle motion refreshes attention without distracting."
        if cut_type == CutType.PUNCH_OUT.value:
            return "Punch back out or reset framing.", "Resets visual rhythm after close-up."
        if cut_type == CutType.B_ROLL.value:
            return self._broll_suggestion(segment, intent, []), "B-roll supports the spoken point and reduces talking-head fatigue."
        if cut_type == CutType.CAPTION_EMPHASIS.value:
            return "Highlight 1-3 important words in the caption.", "Keyword emphasis improves comprehension and visual rhythm."
        if cut_type == CutType.SOUND_HIT.value:
            return "Add a light whoosh, click, or impact hit on the transition.", "Sound cues make the cut feel intentional."
        if cut_type == CutType.TEXT_POP.value:
            return f"Pop up short text: {self._short_overlay(text, max_words=5)}", "Short text reinforces the message visually."
        return "Add a clean visual change.", "Prevents a static section."

    def _assets_for_cut(
        self,
        cut_type: str,
        segment: Optional[ScriptSegment],
        intent: str,
    ) -> List[str]:
        """Suggest assets needed for a cut."""
        if cut_type == CutType.B_ROLL.value:
            return self._assets_for_visual_type(self._visual_type_for_segment(segment, intent), segment, intent)
        if cut_type == CutType.SCREEN_RECORDING.value:
            return ["screen recording", "cursor highlight"]
        if cut_type == CutType.CTA_CARD.value:
            return ["brand CTA card", "logo optional", "URL or handle optional"]
        if cut_type == CutType.SPLIT_SCREEN.value:
            return ["secondary visual", "comparison asset"]
        return []

    def _overlay_for_cut(self, cut_type: str, segment: Optional[ScriptSegment]) -> Optional[str]:
        """Generate overlay text for a cut."""
        if not segment:
            return None
        if cut_type in {CutType.TEXT_POP.value, CutType.CAPTION_EMPHASIS.value, CutType.B_ROLL.value}:
            return self._short_overlay(segment.text, max_words=6)
        return None

    def _sound_for_cut(self, cut_type: str) -> Optional[str]:
        """Suggest sound cue for cut type."""
        if cut_type == CutType.SOUND_HIT.value:
            return "Add soft impact sound synced to the cut."
        if cut_type == CutType.TEXT_POP.value:
            return "Add subtle pop/click sound only if it matches brand style."
        if cut_type == CutType.SPEED_RAMP.value:
            return "Add rising whoosh during speed ramp."
        return None

    def _visual_type_for_segment(self, segment: Optional[ScriptSegment], intent: str) -> str:
        """Choose B-roll visual type."""
        text = (segment.text if segment else "").lower()

        if intent == EditIntent.PRODUCT_DEMO.value:
            return "product_demo"
        if intent == EditIntent.TESTIMONIAL.value:
            return "proof_or_testimonial"
        if any(term in text for term in ["website", "dashboard", "software", "app", "tool", "screen"]):
            return "screen_recording"
        if any(term in text for term in ["before", "after", "compare", "difference"]):
            return "before_after"
        if any(term in text for term in ["results", "growth", "sales", "leads", "revenue"]):
            return "proof_visual"
        return "contextual_broll"

    def _assets_for_visual_type(
        self,
        visual_type: str,
        segment: Optional[ScriptSegment],
        intent: str,
    ) -> List[str]:
        """Return asset suggestions for visual type."""
        mapping = {
            "product_demo": ["product screen recording", "feature close-up", "cursor highlight"],
            "proof_or_testimonial": ["testimonial clip", "review screenshot", "result highlight"],
            "screen_recording": ["screen recording", "zoomed UI crop", "cursor highlight"],
            "before_after": ["before visual", "after visual", "split-screen layout"],
            "proof_visual": ["analytics screenshot", "chart/graph", "result number overlay"],
            "contextual_broll": ["relevant stock clip", "workspace shot", "process visual"],
        }
        return mapping.get(visual_type, ["relevant B-roll"])

    def _broll_suggestion(
        self,
        segment: Optional[ScriptSegment],
        intent: str,
        available_assets: Sequence[str],
    ) -> str:
        """Generate B-roll instruction."""
        text = segment.text if segment else ""
        visual_type = self._visual_type_for_segment(segment, intent)

        if available_assets:
            return f"Use available asset related to this line: {self._short_overlay(text, max_words=8)}."

        if visual_type == "screen_recording":
            return "Show screen recording or dashboard close-up matching the spoken point."
        if visual_type == "proof_visual":
            return "Show result proof, analytics screenshot, chart, or number overlay."
        if visual_type == "before_after":
            return "Use split-screen before/after visual for contrast."
        if visual_type == "product_demo":
            return "Show the product or feature in action with quick cursor movement."
        if visual_type == "proof_or_testimonial":
            return "Show review, testimonial, or client result visual."
        return "Use contextual B-roll that visually explains the spoken line."

    def _caption_chunks(self, text: str, max_words: int = 7) -> List[str]:
        """Split segment text into caption-friendly chunks."""
        words = WORD_RE.findall(text or "")
        if not words:
            return []
        chunks = []
        for index in range(0, len(words), max_words):
            chunks.append(" ".join(words[index:index + max_words]))
        return chunks

    def _caption_instruction(self, style: str) -> str:
        """Caption style instruction."""
        if style == CaptionStyle.KARAOKE.value:
            return "Animate captions word-by-word or phrase-by-phrase with clear contrast."
        if style == CaptionStyle.BOLD_KEYWORDS.value:
            return "Keep captions clean and emphasize key words in bold or brighter weight."
        if style == CaptionStyle.HIGH_ENERGY.value:
            return "Use fast captions with dynamic keyword pops and tight timing."
        if style == CaptionStyle.MINIMAL.value:
            return "Use minimal captions only for key phrases."
        return "Use clean readable captions inside safe area."

    def _music_bed_instruction(self, platform: str, intent: str) -> str:
        """Music bed recommendation."""
        if platform == ShortFormPlatform.LINKEDIN.value:
            return "Use subtle modern background music or no music for professional tone."
        if intent in {EditIntent.SALES.value, EditIntent.PRODUCT_DEMO.value}:
            return "Use confident upbeat music with low volume under voice."
        if intent == EditIntent.STORY.value:
            return "Use light emotional or cinematic bed that supports story pacing."
        return "Use platform-native upbeat music with gentle volume under the voice."

    def _build_style_notes(self, platform: str, intent: str, payload: Dict[str, Any]) -> List[str]:
        """Build editor style notes."""
        notes = [
            "Use 9:16 vertical composition unless a different aspect ratio is explicitly required.",
            "Keep face/subject centered with captions away from platform UI safe zones.",
            "Remove pauses, filler words, and dead air.",
            "Use pattern breaks every 2-4 seconds.",
        ]

        brand_style = payload.get("brand_style")
        if isinstance(brand_style, dict):
            if brand_style.get("colors"):
                notes.append(f"Use brand colors for text highlights where suitable: {brand_style.get('colors')}.")
            if brand_style.get("tone"):
                notes.append(f"Match brand tone: {brand_style.get('tone')}.")

        if intent == EditIntent.SALES.value:
            notes.append("Prioritize proof, problem, transformation, and CTA clarity.")
        elif intent == EditIntent.EDUCATIONAL.value:
            notes.append("Use visual examples to simplify each teaching point.")

        if platform == ShortFormPlatform.TIKTOK.value:
            notes.append("Make edits feel native, fast, and less corporate.")
        elif platform == ShortFormPlatform.LINKEDIN.value:
            notes.append("Keep transitions professional and avoid excessive effects.")

        return notes

    def _build_editor_checklist(self, platform: str, intent: str) -> List[str]:
        """Return final editor checklist."""
        return [
            "Hook appears in the first 1 second.",
            "No slow intro or unnecessary greeting.",
            "Captions are readable on mobile.",
            "Pattern break every 2-4 seconds.",
            "Important words are visually emphasized.",
            "B-roll supports abstract or dense sections.",
            "Audio is clear and music does not overpower voice.",
            "CTA is short and visible near the end.",
            "Export in vertical 9:16 format.",
            f"Check platform fit for {platform}.",
        ]

    def _build_warnings(
        self,
        preset: PlatformPreset,
        target_duration_seconds: int,
        estimated_duration_seconds: float,
        retention_score: RetentionScore,
        segments: List[ScriptSegment],
    ) -> List[str]:
        """Build warnings for editor/dashboard."""
        warnings: List[str] = []

        if target_duration_seconds > preset.max_duration:
            warnings.append(f"Target duration exceeds {preset.platform} max duration preset.")

        if estimated_duration_seconds > target_duration_seconds * 1.25:
            warnings.append("Estimated speech duration is much longer than target. Trim script or increase pacing.")

        if estimated_duration_seconds < max(5, target_duration_seconds * 0.45):
            warnings.append("Script may be too short for the selected target duration.")

        if retention_score.risk == RetentionRisk.HIGH.value:
            warnings.append("Retention risk is high. Improve hook, pacing, and pattern breaks before publishing.")

        high_risk_count = len([segment for segment in segments if segment.retention_risk == RetentionRisk.HIGH.value])
        if high_risk_count:
            warnings.append(f"{high_risk_count} segment(s) may need trimming, B-roll, or caption emphasis.")

        return warnings

    # ------------------------------------------------------------------
    # Text heuristics
    # ------------------------------------------------------------------

    def _normalize_intent(self, value: Any) -> str:
        """Normalize edit intent."""
        text = (normalize_text(value) or EditIntent.GENERAL.value).lower().replace("-", "_").replace(" ", "_")
        allowed = {item.value for item in EditIntent}
        return text if text in allowed else EditIntent.GENERAL.value

    def _normalize_caption_style(self, value: Any) -> str:
        """Normalize caption style."""
        text = (normalize_text(value) or CaptionStyle.BOLD_KEYWORDS.value).lower().replace("-", "_").replace(" ", "_")
        allowed = {item.value for item in CaptionStyle}
        return text if text in allowed else CaptionStyle.BOLD_KEYWORDS.value

    def _short_overlay(self, text: str, max_words: int = 8) -> str:
        """Create short overlay text."""
        words = WORD_RE.findall(text or "")
        if not words:
            return ""
        overlay = " ".join(words[:max_words])
        if len(words) > max_words:
            overlay += "..."
        return overlay

    def _extract_keywords(self, text: str, limit: int = 3) -> List[str]:
        """Extract simple keyword emphasis candidates."""
        stopwords = {
            "the", "and", "for", "you", "your", "this", "that", "with", "from",
            "are", "was", "were", "have", "has", "but", "not", "can", "will",
            "our", "their", "they", "them", "then", "than", "into", "about",
            "what", "when", "where", "why", "how", "a", "an", "to", "of", "in",
            "on", "is", "it", "as", "by", "or", "be", "we", "i",
        }
        words = [word.lower() for word in WORD_RE.findall(text or "")]
        candidates = []
        for word in words:
            if len(word) < 4 or word in stopwords:
                continue
            if word not in candidates:
                candidates.append(word)
        return candidates[:limit]

    def _contains_abstract_claim(self, text: str) -> bool:
        """Detect abstract phrases that usually need visual support."""
        abstract_terms = {
            "strategy", "growth", "success", "results", "system", "process",
            "automation", "performance", "optimize", "improve", "scale",
            "conversion", "engagement", "traffic", "branding", "trust",
        }
        lower = (text or "").lower()
        return any(term in lower for term in abstract_terms)

    def _has_curiosity_or_tension(self, text: str) -> bool:
        """Detect hook curiosity/tension markers."""
        lower = (text or "").lower()
        markers = [
            "mistake", "secret", "nobody", "stop", "before", "after",
            "why", "how", "watch", "avoid", "wrong", "truth", "problem",
            "losing", "wasting", "fix", "fastest", "simple", "hidden",
        ]
        return any(marker in lower for marker in markers) or "?" in lower

    def _jargon_density(self, text: str) -> float:
        """Estimate jargon/abstract density."""
        words = [word.lower() for word in WORD_RE.findall(text or "")]
        if not words:
            return 0.0
        jargon = {
            "synergy", "leverage", "scalable", "framework", "omnichannel",
            "ecosystem", "paradigm", "optimization", "conversion", "funnel",
            "automation", "segmentation", "attribution", "analytics",
            "infrastructure", "workflow", "pipeline", "implementation",
        }
        count = sum(1 for word in words if word in jargon)
        return count / len(words)

    def _topic_from_text(self, text: str) -> str:
        """Extract simple topic phrase from script/topic."""
        words = self._extract_keywords(text, limit=4)
        return " ".join(words) if words else "this"

    def _hook_visual_direction(self, platform: str) -> str:
        """Visual direction for hook."""
        if platform == ShortFormPlatform.TIKTOK.value:
            return "Start with motion, facial expression, or proof visual immediately."
        if platform == ShortFormPlatform.LINKEDIN.value:
            return "Start with clean face-to-camera or professional proof visual."
        if platform == ShortFormPlatform.YOUTUBE_SHORTS.value:
            return "Start with visual payoff preview or bold claim text."
        return "Start with a quick visual change and large readable hook text."

    def _segment_at_time(self, segments: List[ScriptSegment], time_seconds: float) -> Optional[ScriptSegment]:
        """Find segment containing a timestamp."""
        for segment in segments:
            if segment.start <= time_seconds <= segment.end:
                return segment
        return segments[-1] if segments else None

    def _dedupe_close_beats(self, beats: List[EditBeat]) -> List[EditBeat]:
        """Avoid too many identical beats at nearly same timestamp."""
        cleaned: List[EditBeat] = []
        seen: set = set()

        for beat in beats:
            key = (round(beat.start, 1), beat.cut_type)
            if key in seen and beat.priority != "high":
                continue
            seen.add(key)
            cleaned.append(beat)

        return cleaned

    def _timeline_summary(self, beats: List[EditBeat]) -> Dict[str, Any]:
        """Summarize timeline beats."""
        by_type: Dict[str, int] = {}
        high_priority = 0
        for beat in beats:
            by_type[beat.cut_type] = by_type.get(beat.cut_type, 0) + 1
            if beat.priority == "high":
                high_priority += 1
        return {
            "total_beats": len(beats),
            "high_priority_beats": high_priority,
            "by_cut_type": by_type,
        }

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Validate MasterAgent task context."""
        if not isinstance(task, dict):
            return self._error_result("Task must be a dictionary.", "INVALID_TASK")
        return self._validate_ids(task.get("user_id"), task.get("workspace_id"))

    def _validate_ids(self, user_id: Any, workspace_id: Any) -> Dict[str, Any]:
        """Validate required SaaS isolation fields."""
        uid = normalize_text(user_id)
        wid = normalize_text(workspace_id)

        if not uid:
            return self._error_result("user_id is required.", "MISSING_USER_ID")
        if not wid:
            return self._error_result("workspace_id is required.", "MISSING_WORKSPACE_ID")

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"user_id": uid, "workspace_id": wid},
            metadata={"user_id": uid, "workspace_id": wid},
        )

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Determine whether Security Agent approval is required.

        Planning and analysis are safe. Rendering, exporting, uploading,
        publishing, deleting, or overwriting must be security-gated.
        """
        normalized_action = (normalize_text(action) or "").lower()
        if normalized_action in SENSITIVE_ACTIONS:
            return True

        payload = payload or {}
        if payload.get("publish") is True:
            return True
        if payload.get("overwrite") is True:
            return True
        if payload.get("external_delivery") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If security_callback is not configured:
            - strict mode denies sensitive actions
            - development mode allows local fallback approval
        """
        request = {
            "agent": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "payload_summary": self._redact_sensitive(payload or {}),
            "requested_at": utc_now_iso(),
        }

        if self.security_callback:
            try:
                response = self.security_callback(request)
                if isinstance(response, dict):
                    return response
            except Exception as exc:
                LOGGER.exception("Security callback failed.")
                return {
                    "approved": False,
                    "reason": f"Security callback failed: {exc}",
                    "request": request,
                }

        security_mode = str(self.config.get("security_mode", "development")).lower()
        if security_mode == "strict" and action in SENSITIVE_ACTIONS:
            return {
                "approved": False,
                "reason": "Strict security mode requires Security Agent approval.",
                "request": request,
            }

        return {
            "approved": True,
            "reason": "Local approval fallback. Replace with Security Agent in production.",
            "request": request,
        }

    def _prepare_verification_payload(
        self,
        action: str,
        plan: Optional[ShortFormEditPlan],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""
        return {
            "type": "creator_short_form_verification",
            "agent": self.agent_id,
            "action": action,
            "user_id": plan.user_id if plan else None,
            "workspace_id": plan.workspace_id if plan else None,
            "project_id": plan.project_id if plan else None,
            "plan_id": plan.plan_id if plan else None,
            "platform": plan.platform if plan else None,
            "target_duration_seconds": plan.target_duration_seconds if plan else None,
            "overall_retention_score": plan.retention_score.overall_score if plan and plan.retention_score else None,
            "data": data or {},
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        plan: ShortFormEditPlan,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Stores useful creative context only, scoped to user/workspace.
        """
        return {
            "type": "creator_short_form_memory",
            "agent": self.agent_id,
            "action": action,
            "user_id": plan.user_id,
            "workspace_id": plan.workspace_id,
            "project_id": plan.project_id,
            "plan_id": plan.plan_id,
            "memory_scope": "workspace",
            "summary": (
                f"Short-form edit plan for {plan.platform}, intent {plan.intent}, "
                f"target {plan.target_duration_seconds}s, score "
                f"{plan.retention_score.overall_score if plan.retention_score else 'n/a'}."
            ),
            "entities": {
                "platform": plan.platform,
                "intent": plan.intent,
                "title": plan.title,
                "hook": plan.hook,
                "cta": plan.cta,
            },
            "metadata": {
                "target_duration_seconds": plan.target_duration_seconds,
                "estimated_duration_seconds": plan.estimated_duration_seconds,
                "aspect_ratio": plan.aspect_ratio,
                "language": plan.language,
                "warnings": plan.warnings,
                "created_at": plan.created_at,
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit event for dashboard/API/registry/event bus."""
        event = {
            "event_type": event_type,
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": data or {},
            "timestamp": utc_now_iso(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                LOGGER.exception("Event callback failed.")

        LOGGER.debug("ShortFormEditor event: %s", safe_json_dumps(event))

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit audit event for system audit logging."""
        audit = {
            "agent": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "data": self._redact_sensitive(data or {}),
            "timestamp": utc_now_iso(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit)
                return
            except Exception:
                LOGGER.exception("Audit callback failed.")

        LOGGER.info("ShortFormEditor audit: %s", safe_json_dumps(audit))

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis result dict."""
        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": {
                "agent": self.agent_id,
                "agent_name": self.agent_name,
                "version": self.version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error dict."""
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error=error,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Serialization and callback dispatch
    # ------------------------------------------------------------------

    def _serialize_plan(self, plan: ShortFormEditPlan) -> Dict[str, Any]:
        """Serialize ShortFormEditPlan to dict."""
        return {
            "plan_id": plan.plan_id,
            "user_id": plan.user_id,
            "workspace_id": plan.workspace_id,
            "project_id": plan.project_id,
            "platform": plan.platform,
            "intent": plan.intent,
            "target_duration_seconds": plan.target_duration_seconds,
            "estimated_duration_seconds": plan.estimated_duration_seconds,
            "aspect_ratio": plan.aspect_ratio,
            "language": plan.language,
            "title": plan.title,
            "hook": plan.hook,
            "script": plan.script,
            "cta": plan.cta,
            "segments": [asdict(segment) for segment in plan.segments],
            "edit_beats": [asdict(beat) for beat in plan.edit_beats],
            "caption_plan": copy.deepcopy(plan.caption_plan),
            "b_roll_plan": copy.deepcopy(plan.b_roll_plan),
            "sound_plan": copy.deepcopy(plan.sound_plan),
            "retention_score": asdict(plan.retention_score) if plan.retention_score else None,
            "style_notes": list(plan.style_notes),
            "warnings": list(plan.warnings),
            "checklist": list(plan.checklist),
            "metadata": deep_copy_dict(plan.metadata),
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
        }

    def _send_memory_payload(self, action: str, plan: ShortFormEditPlan) -> None:
        """Send prepared memory payload if callback exists."""
        payload = self._prepare_memory_payload(action, plan)

        if self.memory_callback:
            try:
                self.memory_callback(payload)
                return
            except Exception:
                LOGGER.exception("Memory callback failed.")

        LOGGER.debug("Memory payload prepared: %s", safe_json_dumps(payload))

    def _send_verification_payload(
        self,
        action: str,
        plan: Optional[ShortFormEditPlan],
        data: Dict[str, Any],
    ) -> None:
        """Send prepared verification payload if callback exists."""
        payload = self._prepare_verification_payload(action, plan, data)

        if self.verification_callback:
            try:
                self.verification_callback(payload)
                return
            except Exception:
                LOGGER.exception("Verification callback failed.")

        LOGGER.debug("Verification payload prepared: %s", safe_json_dumps(payload))

    def _redact_sensitive(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact secret-like fields before logs/security summaries."""
        sensitive_terms = {
            "password",
            "secret",
            "token",
            "api_key",
            "authorization",
            "cookie",
            "credential",
            "private_key",
        }

        redacted: Dict[str, Any] = {}
        for key, value in (data or {}).items():
            lower_key = str(key).lower()

            if any(term in lower_key for term in sensitive_terms):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact_sensitive(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_sensitive(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value

        return redacted


# ---------------------------------------------------------------------------
# Registry / loader metadata
# ---------------------------------------------------------------------------

AGENT_MODULE_INFO: Dict[str, Any] = {
    "agent_module": "Creator Agent",
    "file": "short_form_editor.py",
    "class_name": "ShortFormEditor",
    "agent_id": DEFAULT_AGENT_ID,
    "agent_name": DEFAULT_AGENT_NAME,
    "version": DEFAULT_VERSION,
    "purpose": "Reels/Shorts/TikTok pacing, retention, cuts, pattern breaks.",
    "supports_user_workspace_isolation": True,
    "requires_security_for_sensitive_actions": True,
    "compatible_with": [
        "BaseAgent",
        "MasterAgent",
        "AgentRegistry",
        "AgentLoader",
        "AgentRouter",
        "SecurityAgent",
        "MemoryAgent",
        "VerificationAgent",
        "DashboardAPI",
        "CreatorAgent",
        "VideoEditor",
        "CaptionGenerator",
        "AssetManager",
    ],
    "public_methods": [
        "run",
        "create_edit_plan",
        "analyze_script",
        "generate_cut_timeline",
        "generate_retention_plan",
        "optimize_hook",
        "create_caption_plan",
        "create_broll_plan",
        "score_retention",
        "get_platform_preset",
    ],
    "supported_platforms": sorted(SUPPORTED_PLATFORMS),
}


def get_agent_module_info() -> Dict[str, Any]:
    """Return module metadata for Agent Registry / Agent Loader."""
    return copy.deepcopy(AGENT_MODULE_INFO)


def create_agent(**kwargs: Any) -> ShortFormEditor:
    """
    Factory hook for dynamic Agent Loader.

    Example:
        editor = create_agent(config={"security_mode": "strict"})
    """
    return ShortFormEditor(**kwargs)


__all__ = [
    "ShortFormEditor",
    "ShortFormEditPlan",
    "ScriptSegment",
    "EditBeat",
    "RetentionScore",
    "PlatformPreset",
    "ShortFormPlatform",
    "EditIntent",
    "CutType",
    "RetentionRisk",
    "CaptionStyle",
    "PacingStyle",
    "AGENT_MODULE_INFO",
    "get_agent_module_info",
    "create_agent",
]


# ---------------------------------------------------------------------------
# Lightweight manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    editor = ShortFormEditor(config={"security_mode": "development"})

    sample = editor.create_edit_plan(
        user_id="demo_user",
        workspace_id="demo_workspace",
        payload={
            "project_id": "demo_project",
            "platform": "instagram_reels",
            "intent": "sales",
            "title": "Why Your Ads Are Not Converting",
            "script": (
                "Most businesses waste money on ads because their landing page does not match the promise. "
                "The ad gets attention, but the page creates confusion. "
                "Fix the headline, show proof, and make the next step obvious. "
                "If you want better leads, message us today."
            ),
            "target_duration_seconds": 30,
            "brand_style": {
                "colors": ["#6400B3", "#101010", "#FFFFFF"],
                "tone": "confident and direct",
            },
            "assets": ["landing page screenshot", "ad dashboard screenshot"],
        },
        actor_id="demo_actor",
    )

    print(json.dumps(sample, indent=2, default=str))