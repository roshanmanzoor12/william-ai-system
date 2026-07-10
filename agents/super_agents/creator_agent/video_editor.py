"""
agents/super_agents/creator_agent/video_editor.py

Creator Agent - Video Editor helper for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Builds safe, structured video editing plans including cuts, timing, b-roll,
    pacing, retention pattern breaks, captions notes, hook placement, timeline
    segments, and review-ready payloads.

Architecture Compatibility:
    - Import-safe even when other William/Jarvis modules are not available yet.
    - Compatible with BaseAgent-style execution.
    - Supports user_id and workspace_id isolation.
    - Produces structured dict/JSON results:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[str],
            "metadata": dict
        }
    - Prepares payloads for:
        - Security Agent
        - Verification Agent
        - Memory Agent
        - Dashboard/API
        - Agent Registry
        - Master Agent routing

Important Safety Notes:
    This file only creates video editing plans and metadata.
    It does NOT:
        - Edit files directly.
        - Delete files.
        - Upload/download assets.
        - Publish content.
        - Send messages.
        - Execute shell/system actions.
        - Access browser/call/financial systems.
"""

from __future__ import annotations

import copy
import json
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
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This fallback keeps this file importable before the full William/Jarvis
        framework is present. In production, the real BaseAgent should be used.
        """

        agent_name: str = "base_agent"
        agent_type: str = "fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.config = kwargs.get("config", {})
            self.logger = logging.getLogger(self.__class__.__name__)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement async run.",
                "data": {},
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {},
            }


try:
    from agents.agent_registry import register_agent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    def register_agent(*args: Any, **kwargs: Any):  # type: ignore
        """
        No-op register_agent fallback.

        In production, Agent Registry can import this module and register
        VideoEditor using its own registry mechanism.
        """
        def decorator(cls: Any) -> Any:
            return cls

        if args and isinstance(args[0], type):
            return args[0]
        return decorator


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

MODULE_NAME = "creator_agent.video_editor"
AGENT_NAME = "VideoEditor"
AGENT_TYPE = "creator_helper"
DEFAULT_VERSION = "1.0.0"

SAFE_MAX_DURATION_SECONDS = 6 * 60 * 60
DEFAULT_SHORT_FORM_DURATION = 60
DEFAULT_LONG_FORM_DURATION = 600
DEFAULT_RETENTION_BREAK_INTERVAL = 8
DEFAULT_SCENE_MIN_SECONDS = 2
DEFAULT_SCENE_MAX_SECONDS = 18

SUPPORTED_PLATFORMS = {
    "youtube",
    "youtube_shorts",
    "tiktok",
    "instagram_reels",
    "instagram_feed",
    "facebook_reels",
    "facebook_video",
    "linkedin",
    "x",
    "twitter",
    "website",
    "course",
    "webinar",
    "podcast_video",
    "custom",
}

SUPPORTED_VIDEO_STYLES = {
    "educational",
    "sales",
    "vlog",
    "podcast",
    "documentary",
    "cinematic",
    "ugc",
    "ad",
    "tutorial",
    "case_study",
    "testimonial",
    "explainer",
    "short_form",
    "long_form",
    "custom",
}

SUPPORTED_GOALS = {
    "retention",
    "awareness",
    "lead_generation",
    "sales",
    "education",
    "authority",
    "engagement",
    "conversion",
    "community",
    "watch_time",
    "custom",
}


class EditIntensity(str, Enum):
    """Controls the density of cuts, overlays, b-roll, and pattern breaks."""

    LIGHT = "light"
    STANDARD = "standard"
    HIGH_RETENTION = "high_retention"
    AGGRESSIVE_SHORT_FORM = "aggressive_short_form"
    CINEMATIC = "cinematic"


class SegmentType(str, Enum):
    """Timeline segment classification."""

    HOOK = "hook"
    CONTEXT = "context"
    MAIN_POINT = "main_point"
    DEMO = "demo"
    PROOF = "proof"
    PATTERN_BREAK = "pattern_break"
    B_ROLL = "b_roll"
    CTA = "cta"
    RECAP = "recap"
    TRANSITION = "transition"
    OUTRO = "outro"


class CutType(str, Enum):
    """Recommended editing cut style."""

    JUMP_CUT = "jump_cut"
    HARD_CUT = "hard_cut"
    MATCH_CUT = "match_cut"
    L_CUT = "l_cut"
    J_CUT = "j_cut"
    CUTAWAY = "cutaway"
    SPEED_RAMP = "speed_ramp"
    PUNCH_IN = "punch_in"
    PUNCH_OUT = "punch_out"
    TEXT_INTERRUPT = "text_interrupt"
    B_ROLL_COVER = "b_roll_cover"
    PAUSE_REMOVAL = "pause_removal"


class PatternBreakType(str, Enum):
    """Retention pattern break ideas."""

    ZOOM_IN = "zoom_in"
    ZOOM_OUT = "zoom_out"
    B_ROLL_INSERT = "b_roll_insert"
    ON_SCREEN_TEXT = "on_screen_text"
    SOUND_EFFECT = "sound_effect"
    CAMERA_ANGLE_CHANGE = "camera_angle_change"
    GRAPHIC_OVERLAY = "graphic_overlay"
    QUESTION_PROMPT = "question_prompt"
    SPEED_CHANGE = "speed_change"
    SILENCE_BEAT = "silence_beat"
    SCREEN_RECORDING = "screen_recording"
    VISUAL_METAPHOR = "visual_metaphor"


class SecurityRiskLevel(str, Enum):
    """Risk level used for Security Agent handoff."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VideoEditorConfig:
    """
    Configuration for the VideoEditor.

    This file keeps local defaults so it can work even before creator_agent/config.py
    exists. Future config.py can pass settings into the constructor.
    """

    agent_name: str = AGENT_NAME
    module_name: str = MODULE_NAME
    version: str = DEFAULT_VERSION
    default_platform: str = "youtube"
    default_style: str = "educational"
    default_goal: str = "retention"
    default_intensity: str = EditIntensity.STANDARD.value
    default_retention_break_interval_seconds: int = DEFAULT_RETENTION_BREAK_INTERVAL
    default_scene_min_seconds: int = DEFAULT_SCENE_MIN_SECONDS
    default_scene_max_seconds: int = DEFAULT_SCENE_MAX_SECONDS
    max_duration_seconds: int = SAFE_MAX_DURATION_SECONDS
    allow_security_auto_approve_low_risk: bool = True
    enable_audit_events: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True


@dataclass
class TimelineSegment:
    """A planned video timeline segment."""

    index: int
    start_seconds: float
    end_seconds: float
    duration_seconds: float
    segment_type: str
    objective: str
    spoken_content_summary: str = ""
    visual_direction: str = ""
    edit_notes: List[str] = field(default_factory=list)
    b_roll_ideas: List[str] = field(default_factory=list)
    overlay_text: Optional[str] = None
    retention_reason: Optional[str] = None


@dataclass
class CutRecommendation:
    """A recommended cut or edit action."""

    index: int
    timestamp_seconds: float
    cut_type: str
    reason: str
    instruction: str
    priority: str = "medium"
    estimated_impact: str = "retention"


@dataclass
class BrollRecommendation:
    """A b-roll suggestion attached to a timeline window."""

    index: int
    start_seconds: float
    end_seconds: float
    concept: str
    visual_description: str
    source_preference: str = "brand_or_stock_safe"
    usage_reason: str = "support spoken point"
    overlay_text: Optional[str] = None


@dataclass
class PatternBreakRecommendation:
    """A retention pattern break suggestion."""

    index: int
    timestamp_seconds: float
    break_type: str
    instruction: str
    reason: str
    intensity: str = "standard"


@dataclass
class VideoEditingPlan:
    """Complete video editing plan."""

    plan_id: str
    user_id: str
    workspace_id: str
    title: str
    platform: str
    video_style: str
    goal: str
    intensity: str
    target_duration_seconds: int
    created_at: str
    summary: str
    timeline: List[TimelineSegment] = field(default_factory=list)
    cuts: List[CutRecommendation] = field(default_factory=list)
    b_roll: List[BrollRecommendation] = field(default_factory=list)
    pattern_breaks: List[PatternBreakRecommendation] = field(default_factory=list)
    retention_strategy: Dict[str, Any] = field(default_factory=dict)
    caption_notes: Dict[str, Any] = field(default_factory=dict)
    audio_notes: Dict[str, Any] = field(default_factory=dict)
    export_notes: Dict[str, Any] = field(default_factory=dict)
    safety_notes: List[str] = field(default_factory=list)
    verification_payload: Dict[str, Any] = field(default_factory=dict)
    memory_payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    try:
        if value is None:
            return default
        converted = float(value)
        if converted != converted:
            return default
        return converted
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def _clamp(value: Union[int, float], min_value: Union[int, float], max_value: Union[int, float]) -> Union[int, float]:
    """Clamp number into a safe range."""
    return max(min_value, min(value, max_value))


def _normalize_string(value: Any, default: str = "") -> str:
    """Normalize user-provided strings."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _slugify(value: str) -> str:
    """Simple slug for metadata and IDs."""
    text = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower())
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "untitled"


def _split_script_into_sentences(script: str) -> List[str]:
    """
    Split a script/transcript into simple sentence-like chunks.

    This avoids external NLP dependencies and remains import-safe.
    """
    script = _normalize_string(script)
    if not script:
        return []
    chunks = re.split(r"(?<=[.!?])\s+|\n+", script)
    return [chunk.strip() for chunk in chunks if chunk and chunk.strip()]


def _seconds_to_timecode(seconds: Union[int, float]) -> str:
    """Convert seconds to HH:MM:SS.mmm style timecode."""
    total_ms = int(max(0, float(seconds)) * 1000)
    ms = total_ms % 1000
    total_seconds = total_ms // 1000
    s = total_seconds % 60
    m = (total_seconds // 60) % 60
    h = total_seconds // 3600
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


def _asdict_list(items: Sequence[Any]) -> List[Dict[str, Any]]:
    """Convert dataclass list to serializable dict list."""
    output: List[Dict[str, Any]] = []
    for item in items:
        if hasattr(item, "__dataclass_fields__"):
            output.append(asdict(item))
        elif isinstance(item, Mapping):
            output.append(dict(item))
        else:
            output.append({"value": item})
    return output


def _estimate_read_time_seconds(text: str, words_per_minute: int = 145) -> int:
    """Estimate spoken duration for script text."""
    cleaned = re.sub(r"\s+", " ", _normalize_string(text))
    if not cleaned:
        return DEFAULT_SHORT_FORM_DURATION
    words = cleaned.split(" ")
    seconds = int((len(words) / max(1, words_per_minute)) * 60)
    return max(5, seconds)


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """Deduplicate strings while preserving order."""
    seen = set()
    output: List[str] = []
    for item in items:
        normalized = _normalize_string(item)
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            output.append(normalized)
    return output


# ---------------------------------------------------------------------------
# VideoEditor
# ---------------------------------------------------------------------------

@register_agent
class VideoEditor(BaseAgent):
    """
    Creator Agent helper responsible for video editing plans.

    Master Agent:
        Can route creator/video-editing tasks here using the public `run()` or
        `create_edit_plan()` methods.

    Security Agent:
        `_requires_security_check()` and `_request_security_approval()` are
        provided so the Master Agent/Security Agent can enforce permission gates.
        This helper only creates plans and does not execute destructive actions.

    Memory Agent:
        `_prepare_memory_payload()` extracts safe reusable preferences such as
        preferred platform, style, target duration, and editing intensity.

    Verification Agent:
        `_prepare_verification_payload()` prepares a review payload so a
        Verification Agent can validate the output before dashboard display or
        user delivery.

    Dashboard/API:
        All public methods return structured dicts with success/message/data/error.
    """

    agent_name = AGENT_NAME
    agent_type = AGENT_TYPE
    module_name = MODULE_NAME
    version = DEFAULT_VERSION

    def __init__(
        self,
        config: Optional[Union[VideoEditorConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the VideoEditor.

        Args:
            config: Optional config dataclass or mapping.
            security_agent: Optional Security Agent adapter.
            memory_agent: Optional Memory Agent adapter.
            verification_agent: Optional Verification Agent adapter.
            event_bus: Optional event bus adapter.
            audit_logger: Optional audit logger adapter.
            **kwargs: Forward-compatible extra options.
        """
        try:
            super().__init__(config=config, **kwargs)
        except Exception:
            BaseAgent.__init__(self, config=config, **kwargs)

        self.config_obj = self._build_config(config)
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(f"{MODULE_NAME}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entrypoint.

        Supported actions:
            - create_edit_plan
            - plan_cuts
            - suggest_broll
            - build_retention_map
            - revise_plan
            - validate_plan

        Args:
            task: Structured task from Master Agent/Agent Router.

        Returns:
            Structured result dict.
        """
        action = _normalize_string(task.get("action"), "create_edit_plan")
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        if self._requires_security_check(task):
            approval = await self._request_security_approval(task)
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied or unavailable.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    metadata={
                        "agent": self.agent_name,
                        "action": action,
                        "approval": approval,
                    },
                )

        if action in {"create_edit_plan", "create_plan", "video_edit_plan"}:
            return self.create_edit_plan(task)

        if action in {"plan_cuts", "cuts"}:
            return self.plan_cuts(task)

        if action in {"suggest_broll", "broll", "b_roll"}:
            return self.suggest_broll(task)

        if action in {"build_retention_map", "retention_map", "pattern_breaks"}:
            return self.build_retention_map(task)

        if action in {"revise_plan", "update_plan"}:
            return self.revise_plan(task)

        if action in {"validate_plan", "validate"}:
            return self.validate_plan(task)

        return self._error_result(
            message=f"Unsupported VideoEditor action: {action}",
            error="UNSUPPORTED_ACTION",
            metadata={
                "agent": self.agent_name,
                "supported_actions": [
                    "create_edit_plan",
                    "plan_cuts",
                    "suggest_broll",
                    "build_retention_map",
                    "revise_plan",
                    "validate_plan",
                ],
            },
        )

    def create_edit_plan(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Create a full video editing plan.

        Args:
            task: Mapping with fields such as:
                user_id, workspace_id, title, script, transcript, platform,
                video_style, goal, intensity, target_duration_seconds,
                source_notes, brand_notes, cta, audience, assets.

        Returns:
            Structured result containing a full editing plan.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        try:
            normalized = self._normalize_task(task)
            plan_id = self._generate_plan_id(normalized)
            timeline = self._build_timeline(normalized)
            cuts = self._build_cut_recommendations(normalized, timeline)
            b_roll = self._build_broll_recommendations(normalized, timeline)
            pattern_breaks = self._build_pattern_breaks(normalized, timeline)
            retention_strategy = self._build_retention_strategy(normalized, timeline, pattern_breaks)
            caption_notes = self._build_caption_notes(normalized)
            audio_notes = self._build_audio_notes(normalized)
            export_notes = self._build_export_notes(normalized)
            safety_notes = self._build_safety_notes(normalized)

            plan = VideoEditingPlan(
                plan_id=plan_id,
                user_id=normalized["user_id"],
                workspace_id=normalized["workspace_id"],
                title=normalized["title"],
                platform=normalized["platform"],
                video_style=normalized["video_style"],
                goal=normalized["goal"],
                intensity=normalized["intensity"],
                target_duration_seconds=normalized["target_duration_seconds"],
                created_at=_utc_now_iso(),
                summary=self._build_plan_summary(normalized, timeline, cuts, b_roll, pattern_breaks),
                timeline=timeline,
                cuts=cuts,
                b_roll=b_roll,
                pattern_breaks=pattern_breaks,
                retention_strategy=retention_strategy,
                caption_notes=caption_notes,
                audio_notes=audio_notes,
                export_notes=export_notes,
                safety_notes=safety_notes,
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                    "version": self.version,
                    "source": "video_editor",
                    "compatible_with": [
                        "MasterAgent",
                        "CreatorAgent",
                        "SecurityAgent",
                        "VerificationAgent",
                        "MemoryAgent",
                        "DashboardAPI",
                        "AgentRegistry",
                    ],
                    "input_digest": self._safe_input_digest(normalized),
                },
            )

            plan.verification_payload = self._prepare_verification_payload(
                task=normalized,
                result_data=self._serialize_plan(plan, include_aux_payloads=False),
            )
            plan.memory_payload = self._prepare_memory_payload(
                task=normalized,
                result_data=self._serialize_plan(plan, include_aux_payloads=False),
            )

            data = self._serialize_plan(plan, include_aux_payloads=True)

            self._emit_agent_event(
                event_name="creator.video_editor.plan_created",
                payload={
                    "plan_id": plan.plan_id,
                    "user_id": plan.user_id,
                    "workspace_id": plan.workspace_id,
                    "platform": plan.platform,
                    "target_duration_seconds": plan.target_duration_seconds,
                },
            )
            self._log_audit_event(
                action="create_edit_plan",
                user_id=plan.user_id,
                workspace_id=plan.workspace_id,
                details={
                    "plan_id": plan.plan_id,
                    "title": plan.title,
                    "platform": plan.platform,
                    "style": plan.video_style,
                    "goal": plan.goal,
                },
            )

            return self._safe_result(
                message="Video editing plan created successfully.",
                data=data,
                metadata={
                    "agent": self.agent_name,
                    "plan_id": plan.plan_id,
                    "timeline_segments": len(timeline),
                    "cuts": len(cuts),
                    "b_roll_items": len(b_roll),
                    "pattern_breaks": len(pattern_breaks),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to create video editing plan.")
            return self._error_result(
                message="Failed to create video editing plan.",
                error=str(exc),
                metadata={"agent": self.agent_name, "action": "create_edit_plan"},
            )

    def plan_cuts(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate cut recommendations only.

        Useful for a dashboard/API route that already has transcript/timeline
        data and only needs cut timing.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        try:
            normalized = self._normalize_task(task)
            timeline = self._build_timeline(normalized)
            cuts = self._build_cut_recommendations(normalized, timeline)
            cut_data = _asdict_list(cuts)

            return self._safe_result(
                message="Cut recommendations created successfully.",
                data={
                    "user_id": normalized["user_id"],
                    "workspace_id": normalized["workspace_id"],
                    "cuts": cut_data,
                    "timecoded_cuts": [
                        {
                            **cut,
                            "timecode": _seconds_to_timecode(cut["timestamp_seconds"]),
                        }
                        for cut in cut_data
                    ],
                },
                metadata={
                    "agent": self.agent_name,
                    "action": "plan_cuts",
                    "count": len(cuts),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to plan cuts.")
            return self._error_result(
                message="Failed to plan cuts.",
                error=str(exc),
                metadata={"agent": self.agent_name, "action": "plan_cuts"},
            )

    def suggest_broll(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate b-roll recommendations only.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        try:
            normalized = self._normalize_task(task)
            timeline = self._build_timeline(normalized)
            b_roll = self._build_broll_recommendations(normalized, timeline)
            broll_data = _asdict_list(b_roll)

            return self._safe_result(
                message="B-roll recommendations created successfully.",
                data={
                    "user_id": normalized["user_id"],
                    "workspace_id": normalized["workspace_id"],
                    "b_roll": broll_data,
                    "timecoded_b_roll": [
                        {
                            **item,
                            "start_timecode": _seconds_to_timecode(item["start_seconds"]),
                            "end_timecode": _seconds_to_timecode(item["end_seconds"]),
                        }
                        for item in broll_data
                    ],
                },
                metadata={
                    "agent": self.agent_name,
                    "action": "suggest_broll",
                    "count": len(b_roll),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to suggest b-roll.")
            return self._error_result(
                message="Failed to suggest b-roll.",
                error=str(exc),
                metadata={"agent": self.agent_name, "action": "suggest_broll"},
            )

    def build_retention_map(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate a retention map with pattern breaks and pacing notes.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        try:
            normalized = self._normalize_task(task)
            timeline = self._build_timeline(normalized)
            pattern_breaks = self._build_pattern_breaks(normalized, timeline)
            retention_strategy = self._build_retention_strategy(normalized, timeline, pattern_breaks)

            return self._safe_result(
                message="Retention map created successfully.",
                data={
                    "user_id": normalized["user_id"],
                    "workspace_id": normalized["workspace_id"],
                    "retention_strategy": retention_strategy,
                    "pattern_breaks": _asdict_list(pattern_breaks),
                    "timeline_attention_points": self._build_attention_points(timeline, pattern_breaks),
                },
                metadata={
                    "agent": self.agent_name,
                    "action": "build_retention_map",
                    "pattern_break_count": len(pattern_breaks),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to build retention map.")
            return self._error_result(
                message="Failed to build retention map.",
                error=str(exc),
                metadata={"agent": self.agent_name, "action": "build_retention_map"},
            )

    def revise_plan(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Revise an existing plan with user instructions.

        This method is intentionally non-destructive. It returns a revised copy
        and does not mutate stored state or external files.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        try:
            existing_plan = task.get("existing_plan") or task.get("plan") or {}
            revision_notes = _normalize_string(task.get("revision_notes") or task.get("instructions"))

            if not isinstance(existing_plan, Mapping):
                return self._error_result(
                    message="existing_plan must be a dictionary.",
                    error="INVALID_EXISTING_PLAN",
                    metadata={"agent": self.agent_name, "action": "revise_plan"},
                )

            if not revision_notes:
                return self._error_result(
                    message="revision_notes are required to revise a plan.",
                    error="MISSING_REVISION_NOTES",
                    metadata={"agent": self.agent_name, "action": "revise_plan"},
                )

            revised = copy.deepcopy(dict(existing_plan))
            revised.setdefault("metadata", {})
            revised["metadata"]["revised_at"] = _utc_now_iso()
            revised["metadata"]["revision_source"] = self.agent_name
            revised["metadata"]["revision_notes"] = revision_notes
            revised["revision_summary"] = self._interpret_revision_notes(revision_notes)

            user_id = _normalize_string(task.get("user_id") or revised.get("user_id"))
            workspace_id = _normalize_string(task.get("workspace_id") or revised.get("workspace_id"))

            self._log_audit_event(
                action="revise_plan",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "plan_id": revised.get("plan_id"),
                    "revision_notes": revision_notes[:500],
                },
            )

            return self._safe_result(
                message="Video editing plan revised successfully.",
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "revised_plan": revised,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": "revise_plan",
                    "plan_id": revised.get("plan_id"),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to revise plan.")
            return self._error_result(
                message="Failed to revise video editing plan.",
                error=str(exc),
                metadata={"agent": self.agent_name, "action": "revise_plan"},
            )

    def validate_plan(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate a video editing plan structure.

        Returns issues/warnings instead of throwing where possible.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        plan = task.get("plan") or task.get("editing_plan") or {}
        if not isinstance(plan, Mapping):
            return self._error_result(
                message="plan must be a dictionary.",
                error="INVALID_PLAN",
                metadata={"agent": self.agent_name, "action": "validate_plan"},
            )

        issues: List[str] = []
        warnings: List[str] = []

        required_fields = [
            "plan_id",
            "user_id",
            "workspace_id",
            "title",
            "platform",
            "target_duration_seconds",
            "timeline",
            "cuts",
            "b_roll",
            "pattern_breaks",
        ]

        for field_name in required_fields:
            if field_name not in plan:
                issues.append(f"Missing required field: {field_name}")

        if plan.get("user_id") != task.get("user_id"):
            warnings.append("Plan user_id does not match task user_id.")

        if plan.get("workspace_id") != task.get("workspace_id"):
            warnings.append("Plan workspace_id does not match task workspace_id.")

        duration = _safe_int(plan.get("target_duration_seconds"), 0)
        if duration <= 0:
            issues.append("target_duration_seconds must be greater than 0.")

        if duration > self.config_obj.max_duration_seconds:
            issues.append("target_duration_seconds exceeds configured maximum.")

        timeline = plan.get("timeline", [])
        if not isinstance(timeline, list):
            issues.append("timeline must be a list.")
        elif not timeline:
            warnings.append("timeline is empty.")

        return self._safe_result(
            message="Video editing plan validation completed.",
            data={
                "valid": not issues,
                "issues": issues,
                "warnings": warnings,
                "plan_id": plan.get("plan_id"),
            },
            metadata={
                "agent": self.agent_name,
                "action": "validate_plan",
                "issue_count": len(issues),
                "warning_count": len(warnings),
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return registry-friendly metadata for Agent Registry/Agent Loader.
        """
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module_name": self.module_name,
            "version": self.version,
            "class_name": self.__class__.__name__,
            "public_methods": [
                "run",
                "create_edit_plan",
                "plan_cuts",
                "suggest_broll",
                "build_retention_map",
                "revise_plan",
                "validate_plan",
                "get_registry_metadata",
            ],
            "capabilities": [
                "video_editing_plan",
                "cut_planning",
                "timeline_design",
                "b_roll_suggestions",
                "retention_pattern_breaks",
                "caption_notes",
                "audio_edit_notes",
                "export_notes",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "executes_external_actions": False,
            "safe_to_import": True,
        }

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation fields.

        Every user-specific task must include user_id and workspace_id.
        """
        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a dictionary-like mapping.",
                error="INVALID_TASK_TYPE",
                metadata={"agent": self.agent_name},
            )

        user_id = _normalize_string(task.get("user_id"))
        workspace_id = _normalize_string(task.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="user_id is required for Creator Agent video editing tasks.",
                error="MISSING_USER_ID",
                metadata={"agent": self.agent_name},
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for Creator Agent video editing tasks.",
                error="MISSING_WORKSPACE_ID",
                metadata={"agent": self.agent_name},
            )

        if self._contains_unsafe_identifier(user_id) or self._contains_unsafe_identifier(workspace_id):
            return self._error_result(
                message="Invalid user_id or workspace_id format.",
                error="INVALID_CONTEXT_IDENTIFIER",
                metadata={"agent": self.agent_name},
            )

        return self._safe_result(
            message="Task context is valid.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"agent": self.agent_name, "validated": True},
        )

    def _requires_security_check(self, task: Mapping[str, Any]) -> bool:
        """
        Decide if this task should pass through Security Agent.

        Planning-only tasks are generally low risk. A security check is required
        when the task requests publishing, external file changes, asset deletion,
        real account access, or other external actions.
        """
        action_text = json.dumps(task, default=str).lower()

        risky_terms = [
            "publish",
            "upload",
            "delete",
            "remove file",
            "overwrite",
            "send",
            "email",
            "post now",
            "schedule post",
            "download from",
            "browser",
            "execute",
            "shell",
            "system command",
            "payment",
            "financial",
            "call",
            "sms",
            "whatsapp",
            "oauth",
            "api key",
            "secret",
            "token",
        ]

        return any(term in action_text for term in risky_terms)

    async def _request_security_approval(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Request approval from Security Agent when available.

        If no Security Agent is available, low-risk planning actions can be
        allowed by config. Higher-risk requests are denied by default.
        """
        risk_level = self._estimate_security_risk(task)

        approval_request = {
            "request_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.module_name,
            "risk_level": risk_level.value,
            "action": task.get("action", "create_edit_plan"),
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "summary": "VideoEditor task security approval request.",
            "external_actions_requested": self._requires_security_check(task),
            "created_at": _utc_now_iso(),
        }

        if self.security_agent is not None:
            try:
                if hasattr(self.security_agent, "approve"):
                    response = self.security_agent.approve(approval_request)
                    if hasattr(response, "__await__"):
                        response = await response
                    if isinstance(response, Mapping):
                        return dict(response)

                if hasattr(self.security_agent, "request_approval"):
                    response = self.security_agent.request_approval(approval_request)
                    if hasattr(response, "__await__"):
                        response = await response
                    if isinstance(response, Mapping):
                        return dict(response)
            except Exception as exc:
                self.logger.exception("Security Agent approval request failed.")
                return {
                    "approved": False,
                    "reason": "Security Agent approval request failed.",
                    "error": str(exc),
                    "request": approval_request,
                }

        if (
            risk_level == SecurityRiskLevel.LOW
            and self.config_obj.allow_security_auto_approve_low_risk
        ):
            return {
                "approved": True,
                "reason": "Auto-approved low-risk planning-only task.",
                "request": approval_request,
            }

        return {
            "approved": False,
            "reason": "Security Agent unavailable for non-low-risk request.",
            "request": approval_request,
        }

    def _prepare_verification_payload(
        self,
        task: Mapping[str, Any],
        result_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can check:
            - user/workspace isolation
            - timeline consistency
            - safety notes
            - missing fields
            - retention/cut/b-roll completeness
        """
        return {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.module_name,
            "created_at": _utc_now_iso(),
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "verification_type": "video_editing_plan_review",
            "checks_requested": [
                "validate_user_workspace_isolation",
                "validate_timeline_order",
                "validate_cut_timestamps",
                "validate_b_roll_windows",
                "validate_pattern_break_spacing",
                "validate_no_external_execution",
                "validate_output_schema",
            ],
            "result_summary": {
                "plan_id": (result_data or {}).get("plan_id"),
                "title": (result_data or {}).get("title"),
                "platform": (result_data or {}).get("platform"),
                "target_duration_seconds": (result_data or {}).get("target_duration_seconds"),
            },
            "safe_to_display": True,
            "external_actions_executed": False,
        }

    def _prepare_memory_payload(
        self,
        task: Mapping[str, Any],
        result_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        Stores only safe preferences and recurring creative settings.
        It does not store raw private scripts by default.
        """
        if not self.config_obj.enable_memory_payloads:
            return {}

        normalized = self._normalize_task(task)
        return {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.module_name,
            "created_at": _utc_now_iso(),
            "user_id": normalized["user_id"],
            "workspace_id": normalized["workspace_id"],
            "memory_type": "creator_video_editing_preferences",
            "safe_to_store": True,
            "contains_raw_script": False,
            "preferences": {
                "platform": normalized["platform"],
                "video_style": normalized["video_style"],
                "goal": normalized["goal"],
                "intensity": normalized["intensity"],
                "target_duration_seconds": normalized["target_duration_seconds"],
                "brand_notes_summary": self._summarize_text(normalized.get("brand_notes", ""), 180),
                "audience_summary": self._summarize_text(normalized.get("audience", ""), 180),
            },
            "source_plan_id": (result_data or {}).get("plan_id"),
        }

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit agent event for Dashboard/API/Event Bus.

        This is best-effort and never breaks the main task.
        """
        if not event_name:
            return

        event_payload = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "module": self.module_name,
            "created_at": _utc_now_iso(),
            "payload": dict(payload),
        }

        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit"):
                    self.event_bus.emit(event_name, event_payload)
                elif hasattr(self.event_bus, "publish"):
                    self.event_bus.publish(event_name, event_payload)
            else:
                self.logger.debug("Agent event emitted: %s", event_payload)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Audit logging is best-effort and must not break user workflow.
        """
        if not self.config_obj.enable_audit_events:
            return

        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "details": dict(details or {}),
            "created_at": _utc_now_iso(),
            "external_actions_executed": False,
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit_payload)
                elif hasattr(self.audit_logger, "write"):
                    self.audit_logger.write(audit_payload)
            else:
                self.logger.info("Audit event: %s", audit_payload)
        except Exception:
            self.logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard success response."""
        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard error response."""
        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error or message,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_config(
        self,
        config: Optional[Union[VideoEditorConfig, Mapping[str, Any]]],
    ) -> VideoEditorConfig:
        """Build VideoEditorConfig from dataclass or mapping."""
        if isinstance(config, VideoEditorConfig):
            return config

        if isinstance(config, Mapping):
            defaults = asdict(VideoEditorConfig())
            for key, value in config.items():
                if key in defaults:
                    defaults[key] = value
            return VideoEditorConfig(**defaults)

        return VideoEditorConfig()

    def _normalize_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize task fields with safe defaults."""
        user_id = _normalize_string(task.get("user_id"))
        workspace_id = _normalize_string(task.get("workspace_id"))

        script = _normalize_string(task.get("script") or task.get("transcript") or task.get("content"))
        source_notes = _normalize_string(task.get("source_notes") or task.get("notes"))
        title = _normalize_string(task.get("title"), "Untitled Video")

        platform = _normalize_string(task.get("platform"), self.config_obj.default_platform).lower()
        if platform not in SUPPORTED_PLATFORMS:
            platform = "custom"

        video_style = _normalize_string(task.get("video_style") or task.get("style"), self.config_obj.default_style).lower()
        if video_style not in SUPPORTED_VIDEO_STYLES:
            video_style = "custom"

        goal = _normalize_string(task.get("goal"), self.config_obj.default_goal).lower()
        if goal not in SUPPORTED_GOALS:
            goal = "custom"

        intensity = _normalize_string(task.get("intensity"), self.config_obj.default_intensity).lower()
        valid_intensities = {item.value for item in EditIntensity}
        if intensity not in valid_intensities:
            intensity = self.config_obj.default_intensity

        requested_duration = _safe_int(task.get("target_duration_seconds"), 0)
        if requested_duration <= 0:
            requested_duration = self._infer_target_duration(platform, script)

        requested_duration = int(
            _clamp(
                requested_duration,
                5,
                self.config_obj.max_duration_seconds,
            )
        )

        assets = task.get("assets") or []
        if not isinstance(assets, list):
            assets = [assets]

        existing_timeline = task.get("timeline")
        if not isinstance(existing_timeline, list):
            existing_timeline = []

        cta = _normalize_string(task.get("cta"), "Invite the viewer to take the next step.")
        audience = _normalize_string(task.get("audience"), "Target audience not specified.")
        brand_notes = _normalize_string(task.get("brand_notes") or task.get("brand_style"), "")

        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "title": title,
            "script": script,
            "source_notes": source_notes,
            "platform": platform,
            "video_style": video_style,
            "goal": goal,
            "intensity": intensity,
            "target_duration_seconds": requested_duration,
            "assets": assets,
            "existing_timeline": existing_timeline,
            "cta": cta,
            "audience": audience,
            "brand_notes": brand_notes,
            "raw_task": dict(task),
        }

    def _infer_target_duration(self, platform: str, script: str) -> int:
        """Infer target duration from platform and script length."""
        estimated = _estimate_read_time_seconds(script)

        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return int(_clamp(estimated, 15, 90))

        if platform in {"linkedin", "instagram_feed", "facebook_video", "x", "twitter"}:
            return int(_clamp(estimated, 30, 180))

        if platform in {"course", "webinar", "podcast_video"}:
            return int(_clamp(estimated, 300, 3600))

        if estimated < 120:
            return max(DEFAULT_SHORT_FORM_DURATION, estimated)

        return int(_clamp(estimated, 120, DEFAULT_LONG_FORM_DURATION))

    def _generate_plan_id(self, normalized: Mapping[str, Any]) -> str:
        """Generate stable-ish plan ID with slug and UUID."""
        title_slug = _slugify(str(normalized.get("title", "video")))
        return f"vep_{title_slug}_{uuid.uuid4().hex[:12]}"

    def _build_timeline(self, normalized: Mapping[str, Any]) -> List[TimelineSegment]:
        """Build structured timeline from script/source notes."""
        existing = normalized.get("existing_timeline") or []
        if existing:
            converted = self._convert_existing_timeline(existing)
            if converted:
                return converted

        script = str(normalized.get("script", ""))
        source_notes = str(normalized.get("source_notes", ""))
        duration = int(normalized["target_duration_seconds"])
        platform = str(normalized["platform"])
        intensity = str(normalized["intensity"])

        sentences = _split_script_into_sentences(script)
        if not sentences:
            sentences = self._fallback_content_chunks(normalized)

        desired_segments = self._desired_segment_count(duration, platform, intensity, len(sentences))
        grouped_chunks = self._group_sentences(sentences, desired_segments)

        timeline: List[TimelineSegment] = []
        current = 0.0

        hook_duration = self._hook_duration(platform, duration)
        cta_duration = self._cta_duration(platform, duration)

        for index, chunk in enumerate(grouped_chunks):
            remaining_segments = max(1, len(grouped_chunks) - index)
            remaining_time = max(0.0, duration - current)

            if index == 0:
                segment_type = SegmentType.HOOK.value
                seg_duration = min(hook_duration, remaining_time)
            elif index == len(grouped_chunks) - 1:
                segment_type = SegmentType.CTA.value
                seg_duration = min(max(cta_duration, remaining_time / remaining_segments), remaining_time)
            else:
                segment_type = self._infer_segment_type(index, len(grouped_chunks), chunk)
                seg_duration = remaining_time / remaining_segments

            seg_duration = float(
                _clamp(
                    seg_duration,
                    min(self.config_obj.default_scene_min_seconds, max(1, duration)),
                    max(self.config_obj.default_scene_max_seconds, duration),
                )
            )

            if index == len(grouped_chunks) - 1:
                seg_duration = max(1.0, duration - current)

            end = min(float(duration), current + seg_duration)
            if end <= current:
                end = min(float(duration), current + 1.0)

            timeline.append(
                TimelineSegment(
                    index=index + 1,
                    start_seconds=round(current, 3),
                    end_seconds=round(end, 3),
                    duration_seconds=round(end - current, 3),
                    segment_type=segment_type,
                    objective=self._segment_objective(segment_type, normalized),
                    spoken_content_summary=self._summarize_text(chunk, 220),
                    visual_direction=self._visual_direction(segment_type, normalized, chunk),
                    edit_notes=self._segment_edit_notes(segment_type, normalized),
                    b_roll_ideas=self._segment_broll_ideas(segment_type, normalized, chunk),
                    overlay_text=self._overlay_text_for_segment(segment_type, chunk, normalized),
                    retention_reason=self._retention_reason(segment_type, normalized),
                )
            )

            current = end
            if current >= duration:
                break

        if timeline and timeline[-1].end_seconds < duration:
            last = timeline[-1]
            last.end_seconds = float(duration)
            last.duration_seconds = round(last.end_seconds - last.start_seconds, 3)

        return timeline

    def _convert_existing_timeline(self, existing: Sequence[Any]) -> List[TimelineSegment]:
        """Convert existing timeline dictionaries to TimelineSegment dataclasses."""
        converted: List[TimelineSegment] = []

        for idx, item in enumerate(existing):
            if not isinstance(item, Mapping):
                continue

            start = _safe_float(item.get("start_seconds") or item.get("start") or item.get("start_time"), 0.0)
            end = _safe_float(item.get("end_seconds") or item.get("end") or item.get("end_time"), start + 5.0)
            if end <= start:
                end = start + 1.0

            segment_type = _normalize_string(item.get("segment_type") or item.get("type"), SegmentType.MAIN_POINT.value)
            converted.append(
                TimelineSegment(
                    index=_safe_int(item.get("index"), idx + 1),
                    start_seconds=round(start, 3),
                    end_seconds=round(end, 3),
                    duration_seconds=round(end - start, 3),
                    segment_type=segment_type,
                    objective=_normalize_string(item.get("objective"), "Support the video narrative."),
                    spoken_content_summary=_normalize_string(
                        item.get("spoken_content_summary") or item.get("summary"),
                        "",
                    ),
                    visual_direction=_normalize_string(item.get("visual_direction"), ""),
                    edit_notes=list(item.get("edit_notes", [])) if isinstance(item.get("edit_notes", []), list) else [],
                    b_roll_ideas=list(item.get("b_roll_ideas", [])) if isinstance(item.get("b_roll_ideas", []), list) else [],
                    overlay_text=item.get("overlay_text"),
                    retention_reason=item.get("retention_reason"),
                )
            )

        converted.sort(key=lambda segment: segment.start_seconds)
        for idx, segment in enumerate(converted, start=1):
            segment.index = idx

        return converted

    def _fallback_content_chunks(self, normalized: Mapping[str, Any]) -> List[str]:
        """Create fallback chunks when no script exists."""
        title = str(normalized.get("title", "video"))
        audience = str(normalized.get("audience", "target audience"))
        cta = str(normalized.get("cta", "take action"))

        return [
            f"Open with a strong hook for {title}.",
            f"Set context for {audience}.",
            "Explain the main idea clearly with visual proof.",
            "Add a pattern break to reset attention.",
            f"Close with CTA: {cta}",
        ]

    def _desired_segment_count(
        self,
        duration: int,
        platform: str,
        intensity: str,
        sentence_count: int,
    ) -> int:
        """Determine number of timeline segments."""
        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            base = max(5, duration // 7)
        elif duration <= 180:
            base = max(6, duration // 15)
        else:
            base = max(8, duration // 30)

        if intensity in {EditIntensity.HIGH_RETENTION.value, EditIntensity.AGGRESSIVE_SHORT_FORM.value}:
            base = int(base * 1.35)
        elif intensity == EditIntensity.LIGHT.value:
            base = int(base * 0.75)
        elif intensity == EditIntensity.CINEMATIC.value:
            base = int(base * 0.9)

        if sentence_count:
            base = min(max(3, base), max(3, sentence_count))

        return int(_clamp(base, 3, 80))

    def _group_sentences(self, sentences: Sequence[str], desired_groups: int) -> List[str]:
        """Group sentences into desired number of chunks."""
        if not sentences:
            return []

        desired_groups = int(_clamp(desired_groups, 1, len(sentences)))
        groups: List[List[str]] = [[] for _ in range(desired_groups)]

        for idx, sentence in enumerate(sentences):
            group_idx = min(desired_groups - 1, int(idx * desired_groups / len(sentences)))
            groups[group_idx].append(sentence)

        return [" ".join(group).strip() for group in groups if group]

    def _hook_duration(self, platform: str, duration: int) -> int:
        """Recommended hook duration."""
        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return int(_clamp(duration * 0.12, 2, 5))
        return int(_clamp(duration * 0.06, 4, 15))

    def _cta_duration(self, platform: str, duration: int) -> int:
        """Recommended CTA duration."""
        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return int(_clamp(duration * 0.10, 2, 6))
        return int(_clamp(duration * 0.08, 5, 20))

    def _infer_segment_type(self, index: int, total: int, chunk: str) -> str:
        """Infer segment type from position/content."""
        chunk_lower = chunk.lower()

        if index == 0:
            return SegmentType.HOOK.value

        if index >= total - 1:
            return SegmentType.CTA.value

        if any(word in chunk_lower for word in ["proof", "result", "case study", "testimonial", "example"]):
            return SegmentType.PROOF.value

        if any(word in chunk_lower for word in ["demo", "show", "screen", "step", "tutorial", "how to"]):
            return SegmentType.DEMO.value

        if index == 1:
            return SegmentType.CONTEXT.value

        if index % 4 == 0:
            return SegmentType.PATTERN_BREAK.value

        return SegmentType.MAIN_POINT.value

    def _segment_objective(self, segment_type: str, normalized: Mapping[str, Any]) -> str:
        """Objective per segment."""
        goal = str(normalized.get("goal", "retention"))

        mapping = {
            SegmentType.HOOK.value: "Stop the scroll and create immediate curiosity.",
            SegmentType.CONTEXT.value: "Clarify why the viewer should care.",
            SegmentType.MAIN_POINT.value: f"Deliver the core message while supporting the {goal} goal.",
            SegmentType.DEMO.value: "Show the process visually so the viewer understands faster.",
            SegmentType.PROOF.value: "Increase trust with evidence, examples, or results.",
            SegmentType.PATTERN_BREAK.value: "Reset attention before retention drops.",
            SegmentType.CTA.value: "Move the viewer toward the next step without feeling abrupt.",
            SegmentType.RECAP.value: "Summarize the key takeaway clearly.",
            SegmentType.OUTRO.value: "End cleanly with brand-safe closure.",
        }

        return mapping.get(segment_type, "Support the video narrative and viewer retention.")

    def _visual_direction(self, segment_type: str, normalized: Mapping[str, Any], chunk: str) -> str:
        """Visual direction for a segment."""
        style = str(normalized.get("video_style", "educational"))
        platform = str(normalized.get("platform", "youtube"))

        if segment_type == SegmentType.HOOK.value:
            return "Open with a punch-in, bold headline text, and the strongest visual proof first."

        if segment_type == SegmentType.CONTEXT.value:
            return "Use clean talking-head framing with light motion graphics to define the problem."

        if segment_type == SegmentType.DEMO.value:
            return "Use screen recording, product shots, or step-by-step close-ups with highlighted cursor/areas."

        if segment_type == SegmentType.PROOF.value:
            return "Show screenshots, metrics, before/after visuals, testimonial snippets, or credible examples."

        if segment_type == SegmentType.PATTERN_BREAK.value:
            return "Switch angle, insert b-roll, add large text interruption, or briefly change pacing."

        if segment_type == SegmentType.CTA.value:
            return "Use clean end-frame, concise CTA text, and reduce visual clutter."

        if style == "cinematic":
            return "Use slow push-in, natural b-roll, soft transitions, and purposeful pacing."

        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return "Use vertical framing, fast visual changes, centered captions, and high-contrast overlays."

        return "Use talking-head base with relevant b-roll, captions, and simple motion overlays."

    def _segment_edit_notes(self, segment_type: str, normalized: Mapping[str, Any]) -> List[str]:
        """Edit notes by segment type."""
        intensity = str(normalized.get("intensity", EditIntensity.STANDARD.value))
        notes: List[str] = []

        if segment_type == SegmentType.HOOK.value:
            notes.extend(
                [
                    "Remove all dead air before the first word.",
                    "Start on the strongest phrase or visual.",
                    "Add punch-in within the first 1-2 seconds.",
                ]
            )

        elif segment_type == SegmentType.CONTEXT.value:
            notes.extend(
                [
                    "Keep context tight and avoid long setup.",
                    "Use one supporting visual to make the problem obvious.",
                ]
            )

        elif segment_type == SegmentType.MAIN_POINT.value:
            notes.extend(
                [
                    "Cut filler words and long pauses.",
                    "Use b-roll to cover jump cuts where needed.",
                ]
            )

        elif segment_type == SegmentType.DEMO.value:
            notes.extend(
                [
                    "Zoom into important interface or object details.",
                    "Add arrows, highlights, or labels only where useful.",
                ]
            )

        elif segment_type == SegmentType.PROOF.value:
            notes.extend(
                [
                    "Hold proof visuals long enough to be readable.",
                    "Add a short text label explaining why the proof matters.",
                ]
            )

        elif segment_type == SegmentType.PATTERN_BREAK.value:
            notes.extend(
                [
                    "Change visual rhythm immediately.",
                    "Use a quick graphic, sound cue, angle change, or b-roll insert.",
                ]
            )

        elif segment_type == SegmentType.CTA.value:
            notes.extend(
                [
                    "Keep CTA short and direct.",
                    "Avoid adding too many competing instructions.",
                ]
            )

        if intensity in {EditIntensity.HIGH_RETENTION.value, EditIntensity.AGGRESSIVE_SHORT_FORM.value}:
            notes.append("Add visual change every 2-4 seconds if the platform is short-form.")

        if intensity == EditIntensity.CINEMATIC.value:
            notes.append("Favor intentional cuts over excessive jump cuts.")

        return _dedupe_preserve_order(notes)

    def _segment_broll_ideas(
        self,
        segment_type: str,
        normalized: Mapping[str, Any],
        chunk: str,
    ) -> List[str]:
        """Generate b-roll ideas for a segment."""
        title = str(normalized.get("title", "video"))
        style = str(normalized.get("video_style", "educational"))
        audience = str(normalized.get("audience", "target audience"))

        ideas: List[str] = []

        if segment_type == SegmentType.HOOK.value:
            ideas.extend(
                [
                    f"Fast visual preview of the final outcome for {title}",
                    "Problem visual shown in the first 2 seconds",
                ]
            )

        elif segment_type == SegmentType.CONTEXT.value:
            ideas.extend(
                [
                    f"Audience-relevant situation showing {audience}",
                    "Simple problem/solution comparison graphic",
                ]
            )

        elif segment_type == SegmentType.DEMO.value:
            ideas.extend(
                [
                    "Screen recording or hands-on demonstration",
                    "Close-up of the key step being performed",
                ]
            )

        elif segment_type == SegmentType.PROOF.value:
            ideas.extend(
                [
                    "Before-and-after comparison",
                    "Results screenshot, chart, dashboard, or testimonial snippet",
                ]
            )

        elif segment_type == SegmentType.PATTERN_BREAK.value:
            ideas.extend(
                [
                    "Quick visual metaphor related to the point",
                    "Unexpected zoom, meme-style image, or animated icon",
                ]
            )

        elif segment_type == SegmentType.CTA.value:
            ideas.extend(
                [
                    "Clean branded end card",
                    "CTA button animation or website/contact visual",
                ]
            )

        else:
            ideas.extend(
                [
                    "Relevant stock or brand-safe supporting clip",
                    "Simple kinetic text emphasizing the key phrase",
                ]
            )

        if style == "cinematic":
            ideas.append("Natural environment shot with slow camera movement")

        chunk_keywords = self._extract_keywords(chunk, limit=3)
        for keyword in chunk_keywords:
            ideas.append(f"Visual example representing '{keyword}'")

        return _dedupe_preserve_order(ideas)[:6]

    def _overlay_text_for_segment(
        self,
        segment_type: str,
        chunk: str,
        normalized: Mapping[str, Any],
    ) -> Optional[str]:
        """Suggest overlay text for a segment."""
        if segment_type == SegmentType.HOOK.value:
            return self._short_overlay_from_text(chunk, fallback="Wait—this changes everything")

        if segment_type == SegmentType.CONTEXT.value:
            return self._short_overlay_from_text(chunk, fallback="Here is the real problem")

        if segment_type == SegmentType.PROOF.value:
            return "Proof / Result"

        if segment_type == SegmentType.DEMO.value:
            return "Step-by-step"

        if segment_type == SegmentType.PATTERN_BREAK.value:
            return self._short_overlay_from_text(chunk, fallback="Important")

        if segment_type == SegmentType.CTA.value:
            cta = str(normalized.get("cta", "Take the next step"))
            return self._short_overlay_from_text(cta, fallback="Take the next step")

        return None

    def _retention_reason(self, segment_type: str, normalized: Mapping[str, Any]) -> str:
        """Explain retention role for each segment."""
        mapping = {
            SegmentType.HOOK.value: "The opening must create curiosity before the viewer scrolls away.",
            SegmentType.CONTEXT.value: "Clear stakes help the viewer understand why the next section matters.",
            SegmentType.MAIN_POINT.value: "Core value delivery must stay concise to protect watch time.",
            SegmentType.DEMO.value: "Visual demonstration reduces cognitive load and increases clarity.",
            SegmentType.PROOF.value: "Proof increases trust and gives viewers a reason to keep watching.",
            SegmentType.PATTERN_BREAK.value: "Pattern break resets attention during potential drop-off points.",
            SegmentType.CTA.value: "A clean CTA captures intent without dragging the ending.",
        }
        return mapping.get(segment_type, "Supports pacing and viewer comprehension.")

    def _build_cut_recommendations(
        self,
        normalized: Mapping[str, Any],
        timeline: Sequence[TimelineSegment],
    ) -> List[CutRecommendation]:
        """Build cut recommendations from timeline."""
        intensity = str(normalized.get("intensity", EditIntensity.STANDARD.value))
        platform = str(normalized.get("platform", "youtube"))

        cuts: List[CutRecommendation] = []
        index = 1

        for segment in timeline:
            if segment.segment_type == SegmentType.HOOK.value:
                cuts.append(
                    CutRecommendation(
                        index=index,
                        timestamp_seconds=segment.start_seconds,
                        cut_type=CutType.HARD_CUT.value,
                        reason="Begin immediately without intro delay.",
                        instruction="Cut directly into the strongest hook moment.",
                        priority="high",
                        estimated_impact="scroll_stop",
                    )
                )
                index += 1

                if segment.duration_seconds >= 3:
                    cuts.append(
                        CutRecommendation(
                            index=index,
                            timestamp_seconds=round(segment.start_seconds + min(2.0, segment.duration_seconds / 2), 3),
                            cut_type=CutType.PUNCH_IN.value,
                            reason="Create early visual movement during the hook.",
                            instruction="Add a subtle punch-in or reframing on the key hook phrase.",
                            priority="high",
                            estimated_impact="retention",
                        )
                    )
                    index += 1

            elif segment.segment_type == SegmentType.PATTERN_BREAK.value:
                cuts.append(
                    CutRecommendation(
                        index=index,
                        timestamp_seconds=segment.start_seconds,
                        cut_type=CutType.TEXT_INTERRUPT.value,
                        reason="Reset viewer attention at a likely drop-off point.",
                        instruction="Interrupt with large on-screen text, sound cue, or quick b-roll.",
                        priority="high",
                        estimated_impact="retention_reset",
                    )
                )
                index += 1

            elif segment.segment_type == SegmentType.DEMO.value:
                cuts.append(
                    CutRecommendation(
                        index=index,
                        timestamp_seconds=segment.start_seconds,
                        cut_type=CutType.CUTAWAY.value,
                        reason="Shift from explanation to visual demonstration.",
                        instruction="Cut to screen recording, product view, or close-up demonstration.",
                        priority="high",
                        estimated_impact="clarity",
                    )
                )
                index += 1

            elif segment.segment_type == SegmentType.PROOF.value:
                cuts.append(
                    CutRecommendation(
                        index=index,
                        timestamp_seconds=segment.start_seconds,
                        cut_type=CutType.B_ROLL_COVER.value,
                        reason="Proof should be visible, not only spoken.",
                        instruction="Cover this section with proof visual and readable label.",
                        priority="high",
                        estimated_impact="trust",
                    )
                )
                index += 1

            else:
                cuts.append(
                    CutRecommendation(
                        index=index,
                        timestamp_seconds=segment.start_seconds,
                        cut_type=CutType.JUMP_CUT.value,
                        reason="Maintain pace between ideas.",
                        instruction="Remove filler, silence, and repeated words at this transition.",
                        priority="medium",
                        estimated_impact="pacing",
                    )
                )
                index += 1

            if self._should_add_mid_segment_cut(segment, intensity, platform):
                mid = round(segment.start_seconds + segment.duration_seconds / 2, 3)
                cuts.append(
                    CutRecommendation(
                        index=index,
                        timestamp_seconds=mid,
                        cut_type=self._mid_segment_cut_type(intensity, platform),
                        reason="Prevent static visuals from lasting too long.",
                        instruction="Add a small visual change, angle shift, punch-in, or b-roll cover.",
                        priority="medium",
                        estimated_impact="retention",
                    )
                )
                index += 1

        return self._dedupe_cuts(cuts)

    def _should_add_mid_segment_cut(
        self,
        segment: TimelineSegment,
        intensity: str,
        platform: str,
    ) -> bool:
        """Decide whether a segment needs a mid-point cut."""
        if segment.duration_seconds < 5:
            return False

        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return segment.duration_seconds >= 4

        if intensity in {EditIntensity.HIGH_RETENTION.value, EditIntensity.AGGRESSIVE_SHORT_FORM.value}:
            return segment.duration_seconds >= 6

        if intensity == EditIntensity.LIGHT.value:
            return segment.duration_seconds >= 18

        return segment.duration_seconds >= 10

    def _mid_segment_cut_type(self, intensity: str, platform: str) -> str:
        """Choose mid-segment cut style."""
        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return CutType.PUNCH_IN.value

        if intensity == EditIntensity.CINEMATIC.value:
            return CutType.L_CUT.value

        if intensity in {EditIntensity.HIGH_RETENTION.value, EditIntensity.AGGRESSIVE_SHORT_FORM.value}:
            return CutType.TEXT_INTERRUPT.value

        return CutType.B_ROLL_COVER.value

    def _dedupe_cuts(self, cuts: Sequence[CutRecommendation]) -> List[CutRecommendation]:
        """Dedupe cut recommendations by timestamp/cut_type."""
        seen = set()
        output: List[CutRecommendation] = []

        for cut in cuts:
            key = (round(cut.timestamp_seconds, 1), cut.cut_type)
            if key not in seen:
                seen.add(key)
                output.append(cut)

        for idx, cut in enumerate(output, start=1):
            cut.index = idx

        return output

    def _build_broll_recommendations(
        self,
        normalized: Mapping[str, Any],
        timeline: Sequence[TimelineSegment],
    ) -> List[BrollRecommendation]:
        """Build b-roll recommendations."""
        b_roll: List[BrollRecommendation] = []
        index = 1

        for segment in timeline:
            should_broll = segment.segment_type in {
                SegmentType.HOOK.value,
                SegmentType.DEMO.value,
                SegmentType.PROOF.value,
                SegmentType.PATTERN_BREAK.value,
            }

            if not should_broll and segment.duration_seconds >= 8:
                should_broll = True

            if not should_broll:
                continue

            ideas = segment.b_roll_ideas or self._segment_broll_ideas(
                segment.segment_type,
                normalized,
                segment.spoken_content_summary,
            )

            concept = ideas[0] if ideas else "Relevant supporting visual"
            end = min(segment.end_seconds, segment.start_seconds + max(2.0, min(6.0, segment.duration_seconds)))

            b_roll.append(
                BrollRecommendation(
                    index=index,
                    start_seconds=segment.start_seconds,
                    end_seconds=round(end, 3),
                    concept=concept,
                    visual_description=self._broll_visual_description(segment, concept, normalized),
                    source_preference=self._source_preference(normalized),
                    usage_reason=self._broll_usage_reason(segment.segment_type),
                    overlay_text=segment.overlay_text,
                )
            )
            index += 1

            if segment.duration_seconds >= 14 and len(ideas) > 1:
                second_start = round(segment.start_seconds + segment.duration_seconds * 0.55, 3)
                second_end = min(segment.end_seconds, second_start + 5.0)
                b_roll.append(
                    BrollRecommendation(
                        index=index,
                        start_seconds=second_start,
                        end_seconds=round(second_end, 3),
                        concept=ideas[1],
                        visual_description=self._broll_visual_description(segment, ideas[1], normalized),
                        source_preference=self._source_preference(normalized),
                        usage_reason="Add second visual beat in longer segment.",
                        overlay_text=None,
                    )
                )
                index += 1

        return b_roll

    def _broll_visual_description(
        self,
        segment: TimelineSegment,
        concept: str,
        normalized: Mapping[str, Any],
    ) -> str:
        """Describe b-roll visual."""
        platform = str(normalized.get("platform", "youtube"))
        style = str(normalized.get("video_style", "educational"))

        frame = "vertical 9:16" if platform in {
            "youtube_shorts",
            "tiktok",
            "instagram_reels",
            "facebook_reels",
        } else "platform-appropriate framing"

        if style == "cinematic":
            return f"Cinematic {frame} b-roll: {concept}. Use smooth movement and natural lighting."

        if segment.segment_type == SegmentType.DEMO.value:
            return f"{frame} demo visual: {concept}. Add highlight boxes or arrows for clarity."

        if segment.segment_type == SegmentType.PROOF.value:
            return f"{frame} proof visual: {concept}. Keep text readable and avoid clutter."

        return f"{frame} supporting visual: {concept}. Match brand style and spoken point."

    def _source_preference(self, normalized: Mapping[str, Any]) -> str:
        """Recommend b-roll source preference."""
        assets = normalized.get("assets") or []
        if assets:
            return "provided_assets_first"
        return "brand_or_stock_safe"

    def _broll_usage_reason(self, segment_type: str) -> str:
        """Reason for b-roll usage."""
        mapping = {
            SegmentType.HOOK.value: "Increase scroll-stopping power in the opening.",
            SegmentType.DEMO.value: "Make the explanation easier to understand visually.",
            SegmentType.PROOF.value: "Support trust with visible evidence.",
            SegmentType.PATTERN_BREAK.value: "Reset attention with a visual change.",
        }
        return mapping.get(segment_type, "Support the spoken point and maintain visual rhythm.")

    def _build_pattern_breaks(
        self,
        normalized: Mapping[str, Any],
        timeline: Sequence[TimelineSegment],
    ) -> List[PatternBreakRecommendation]:
        """Build retention pattern break recommendations."""
        duration = int(normalized.get("target_duration_seconds", DEFAULT_SHORT_FORM_DURATION))
        intensity = str(normalized.get("intensity", EditIntensity.STANDARD.value))
        platform = str(normalized.get("platform", "youtube"))

        interval = self._pattern_break_interval(duration, platform, intensity)
        break_types = self._pattern_break_sequence(platform, intensity)

        recommendations: List[PatternBreakRecommendation] = []
        timestamp = float(interval)
        index = 1

        while timestamp < max(2, duration - 2):
            segment = self._find_segment_at(timeline, timestamp)
            break_type = break_types[(index - 1) % len(break_types)]

            recommendations.append(
                PatternBreakRecommendation(
                    index=index,
                    timestamp_seconds=round(timestamp, 3),
                    break_type=break_type,
                    instruction=self._pattern_break_instruction(break_type, segment, normalized),
                    reason=self._pattern_break_reason(timestamp, duration, segment),
                    intensity=intensity,
                )
            )

            index += 1
            timestamp += interval

        for segment in timeline:
            if segment.segment_type == SegmentType.PATTERN_BREAK.value:
                if not any(abs(pb.timestamp_seconds - segment.start_seconds) <= 1.0 for pb in recommendations):
                    recommendations.append(
                        PatternBreakRecommendation(
                            index=len(recommendations) + 1,
                            timestamp_seconds=segment.start_seconds,
                            break_type=PatternBreakType.B_ROLL_INSERT.value,
                            instruction="Insert a dedicated visual reset at this section boundary.",
                            reason="Timeline marks this as a planned attention reset.",
                            intensity=intensity,
                        )
                    )

        recommendations.sort(key=lambda item: item.timestamp_seconds)
        for idx, item in enumerate(recommendations, start=1):
            item.index = idx

        return recommendations

    def _pattern_break_interval(self, duration: int, platform: str, intensity: str) -> int:
        """Determine pattern break interval."""
        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            base = 4
        elif duration <= 180:
            base = 8
        else:
            base = 15

        if intensity == EditIntensity.LIGHT.value:
            base = int(base * 1.75)
        elif intensity == EditIntensity.STANDARD.value:
            base = base
        elif intensity == EditIntensity.HIGH_RETENTION.value:
            base = max(3, int(base * 0.75))
        elif intensity == EditIntensity.AGGRESSIVE_SHORT_FORM.value:
            base = 3
        elif intensity == EditIntensity.CINEMATIC.value:
            base = int(base * 1.4)

        return int(_clamp(base, 3, 30))

    def _pattern_break_sequence(self, platform: str, intensity: str) -> List[str]:
        """Pattern break sequence for editing rhythm."""
        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            return [
                PatternBreakType.ZOOM_IN.value,
                PatternBreakType.ON_SCREEN_TEXT.value,
                PatternBreakType.B_ROLL_INSERT.value,
                PatternBreakType.SOUND_EFFECT.value,
                PatternBreakType.SPEED_CHANGE.value,
            ]

        if intensity == EditIntensity.CINEMATIC.value:
            return [
                PatternBreakType.CAMERA_ANGLE_CHANGE.value,
                PatternBreakType.B_ROLL_INSERT.value,
                PatternBreakType.SILENCE_BEAT.value,
                PatternBreakType.VISUAL_METAPHOR.value,
            ]

        return [
            PatternBreakType.B_ROLL_INSERT.value,
            PatternBreakType.ON_SCREEN_TEXT.value,
            PatternBreakType.ZOOM_IN.value,
            PatternBreakType.GRAPHIC_OVERLAY.value,
            PatternBreakType.QUESTION_PROMPT.value,
        ]

    def _find_segment_at(
        self,
        timeline: Sequence[TimelineSegment],
        timestamp: float,
    ) -> Optional[TimelineSegment]:
        """Find segment containing timestamp."""
        for segment in timeline:
            if segment.start_seconds <= timestamp <= segment.end_seconds:
                return segment
        return None

    def _pattern_break_instruction(
        self,
        break_type: str,
        segment: Optional[TimelineSegment],
        normalized: Mapping[str, Any],
    ) -> str:
        """Instruction for a pattern break."""
        segment_summary = segment.spoken_content_summary if segment else "current point"
        short_summary = self._summarize_text(segment_summary, 80)

        mapping = {
            PatternBreakType.ZOOM_IN.value: f"Add a quick punch-in on the phrase around: {short_summary}",
            PatternBreakType.ZOOM_OUT.value: f"Pull back slightly to reset framing around: {short_summary}",
            PatternBreakType.B_ROLL_INSERT.value: f"Insert 1-3 seconds of relevant b-roll supporting: {short_summary}",
            PatternBreakType.ON_SCREEN_TEXT.value: f"Flash concise text emphasizing the key idea: {short_summary}",
            PatternBreakType.SOUND_EFFECT.value: "Add a subtle sound cue only if it fits the brand tone.",
            PatternBreakType.CAMERA_ANGLE_CHANGE.value: "Switch to alternate angle or crop to create visual freshness.",
            PatternBreakType.GRAPHIC_OVERLAY.value: "Add a simple icon, arrow, label, or micro-animation.",
            PatternBreakType.QUESTION_PROMPT.value: "Add a short question overlay that makes the viewer think.",
            PatternBreakType.SPEED_CHANGE.value: "Briefly speed-ramp a transition or b-roll moment.",
            PatternBreakType.SILENCE_BEAT.value: "Use a very short intentional pause before the next important line.",
            PatternBreakType.SCREEN_RECORDING.value: "Cut to a screen recording or interface view for clarity.",
            PatternBreakType.VISUAL_METAPHOR.value: "Use a visual metaphor that makes the idea easier to remember.",
        }

        return mapping.get(break_type, "Add a quick visual reset to protect retention.")

    def _pattern_break_reason(
        self,
        timestamp: float,
        duration: int,
        segment: Optional[TimelineSegment],
    ) -> str:
        """Reason for pattern break placement."""
        percentage = (timestamp / max(1, duration)) * 100
        if percentage < 20:
            return "Early retention protection after the hook."
        if percentage < 60:
            return "Mid-video attention reset before viewer fatigue increases."
        return "Late-video pacing reset to carry the viewer into the CTA."

    def _build_retention_strategy(
        self,
        normalized: Mapping[str, Any],
        timeline: Sequence[TimelineSegment],
        pattern_breaks: Sequence[PatternBreakRecommendation],
    ) -> Dict[str, Any]:
        """Build high-level retention strategy."""
        platform = str(normalized.get("platform", "youtube"))
        intensity = str(normalized.get("intensity", EditIntensity.STANDARD.value))
        duration = int(normalized.get("target_duration_seconds", DEFAULT_SHORT_FORM_DURATION))

        opening_rules = [
            "Start with the strongest promise, problem, or outcome.",
            "Remove logos, greetings, and slow setup before the hook.",
            "Show proof or final result early when possible.",
        ]

        pacing_rules = [
            "Remove filler words, repeated phrases, and long pauses.",
            "Use visual changes before attention drops.",
            "Keep each segment focused on one viewer-facing idea.",
        ]

        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            pacing_rules.extend(
                [
                    "Use centered captions throughout.",
                    "Change visual rhythm every 2-4 seconds.",
                    "Keep CTA extremely short.",
                ]
            )
        else:
            pacing_rules.extend(
                [
                    "Use chapters or section labels for longer videos.",
                    "Let proof/demo moments breathe long enough to be understood.",
                ]
            )

        if intensity == EditIntensity.CINEMATIC.value:
            pacing_rules.append("Use fewer but more intentional pattern breaks.")
        elif intensity in {EditIntensity.HIGH_RETENTION.value, EditIntensity.AGGRESSIVE_SHORT_FORM.value}:
            pacing_rules.append("Prioritize fast cuts, punch-ins, and text interrupts.")

        return {
            "platform": platform,
            "intensity": intensity,
            "target_duration_seconds": duration,
            "opening_rules": opening_rules,
            "pacing_rules": _dedupe_preserve_order(pacing_rules),
            "pattern_break_count": len(pattern_breaks),
            "recommended_pattern_break_interval_seconds": self._pattern_break_interval(duration, platform, intensity),
            "timeline_segment_count": len(timeline),
            "drop_off_protection": [
                {
                    "window": "0-3 seconds",
                    "strategy": "Hook immediately, remove dead air, show value first.",
                },
                {
                    "window": "first 20%",
                    "strategy": "Clarify stakes and preview the benefit.",
                },
                {
                    "window": "middle",
                    "strategy": "Add proof, b-roll, demonstration, and pattern breaks.",
                },
                {
                    "window": "final 20%",
                    "strategy": "Tighten pacing and transition cleanly into CTA.",
                },
            ],
        }

    def _build_caption_notes(self, normalized: Mapping[str, Any]) -> Dict[str, Any]:
        """Build caption editing notes."""
        platform = str(normalized.get("platform", "youtube"))
        style = str(normalized.get("video_style", "educational"))

        notes = {
            "use_captions": True,
            "caption_style": "clear_readable",
            "max_words_per_caption": 7,
            "placement": "lower_center_safe_area",
            "highlight_keywords": True,
            "notes": [
                "Keep captions readable and synchronized with speech.",
                "Avoid covering faces, product UI, or CTA buttons.",
                "Highlight only important words to avoid visual noise.",
            ],
        }

        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            notes.update(
                {
                    "max_words_per_caption": 5,
                    "placement": "center_lower_third_vertical_safe_area",
                    "caption_style": "bold_short_form",
                }
            )
            notes["notes"].append("Use high-contrast captions suitable for mobile viewing.")

        if style == "cinematic":
            notes["caption_style"] = "minimal_cinematic"
            notes["notes"].append("Use captions more selectively if cinematic mood is more important.")

        return notes

    def _build_audio_notes(self, normalized: Mapping[str, Any]) -> Dict[str, Any]:
        """Build audio editing notes."""
        intensity = str(normalized.get("intensity", EditIntensity.STANDARD.value))
        style = str(normalized.get("video_style", "educational"))

        notes = {
            "dialogue_cleanup": [
                "Normalize spoken audio levels.",
                "Reduce background noise where possible.",
                "Remove harsh clicks, long breaths, and distracting mouth sounds.",
            ],
            "music": {
                "recommended": style in {"vlog", "cinematic", "ad", "short_form", "sales"},
                "guidance": "Keep music under voice and aligned with brand tone.",
            },
            "sound_effects": {
                "recommended": intensity in {
                    EditIntensity.HIGH_RETENTION.value,
                    EditIntensity.AGGRESSIVE_SHORT_FORM.value,
                },
                "guidance": "Use subtle sound cues for pattern breaks; avoid overuse.",
            },
        }

        if style == "cinematic":
            notes["music"]["guidance"] = "Use cinematic bed music with emotional pacing and clean transitions."

        return notes

    def _build_export_notes(self, normalized: Mapping[str, Any]) -> Dict[str, Any]:
        """Build export/platform notes."""
        platform = str(normalized.get("platform", "youtube"))

        base = {
            "platform": platform,
            "format": "mp4_h264_or_h265",
            "audio": "aac_48khz",
            "safe_area": "Keep captions and CTA inside platform-safe margins.",
            "quality_check": [
                "Check first 3 seconds for immediate hook.",
                "Check captions are readable on mobile.",
                "Check audio does not peak or distort.",
                "Check CTA is visible and not too long.",
            ],
        }

        if platform in {"youtube_shorts", "tiktok", "instagram_reels", "facebook_reels"}:
            base.update(
                {
                    "aspect_ratio": "9:16",
                    "resolution": "1080x1920",
                    "recommended_duration": "15-60 seconds where possible",
                }
            )
        elif platform in {"instagram_feed"}:
            base.update(
                {
                    "aspect_ratio": "4:5 or 1:1",
                    "resolution": "1080x1350 or 1080x1080",
                }
            )
        else:
            base.update(
                {
                    "aspect_ratio": "16:9",
                    "resolution": "1920x1080 or higher",
                }
            )

        return base

    def _build_safety_notes(self, normalized: Mapping[str, Any]) -> List[str]:
        """Build safety notes for plan."""
        notes = [
            "This plan does not execute file edits, uploads, posts, or destructive actions.",
            "Use only licensed, owned, or platform-safe assets for b-roll, music, fonts, and graphics.",
            "Do not expose private user/workspace assets across tenants.",
            "Any publishing, uploading, deletion, or external account action must go through Security Agent approval.",
        ]

        assets = normalized.get("assets") or []
        if assets:
            notes.append("Provided assets should be checked for ownership, permissions, and workspace isolation.")

        return notes

    def _build_plan_summary(
        self,
        normalized: Mapping[str, Any],
        timeline: Sequence[TimelineSegment],
        cuts: Sequence[CutRecommendation],
        b_roll: Sequence[BrollRecommendation],
        pattern_breaks: Sequence[PatternBreakRecommendation],
    ) -> str:
        """Create summary string for the plan."""
        return (
            f"Editing plan for '{normalized['title']}' targeting {normalized['platform']} "
            f"with {normalized['video_style']} style and {normalized['goal']} goal. "
            f"Includes {len(timeline)} timeline segments, {len(cuts)} cut recommendations, "
            f"{len(b_roll)} b-roll placements, and {len(pattern_breaks)} retention pattern breaks."
        )

    def _build_attention_points(
        self,
        timeline: Sequence[TimelineSegment],
        pattern_breaks: Sequence[PatternBreakRecommendation],
    ) -> List[Dict[str, Any]]:
        """Create timecoded attention points."""
        points: List[Dict[str, Any]] = []

        for segment in timeline:
            if segment.segment_type in {
                SegmentType.HOOK.value,
                SegmentType.PATTERN_BREAK.value,
                SegmentType.PROOF.value,
                SegmentType.CTA.value,
            }:
                points.append(
                    {
                        "timestamp_seconds": segment.start_seconds,
                        "timecode": _seconds_to_timecode(segment.start_seconds),
                        "type": segment.segment_type,
                        "reason": segment.retention_reason,
                        "instruction": segment.visual_direction,
                    }
                )

        for break_item in pattern_breaks:
            points.append(
                {
                    "timestamp_seconds": break_item.timestamp_seconds,
                    "timecode": _seconds_to_timecode(break_item.timestamp_seconds),
                    "type": "pattern_break",
                    "reason": break_item.reason,
                    "instruction": break_item.instruction,
                }
            )

        points.sort(key=lambda item: item["timestamp_seconds"])
        return points

    # ------------------------------------------------------------------
    # Text helpers
    # ------------------------------------------------------------------

    def _summarize_text(self, text: str, max_chars: int = 200) -> str:
        """Simple safe text summary."""
        normalized = re.sub(r"\s+", " ", _normalize_string(text)).strip()
        if len(normalized) <= max_chars:
            return normalized
        return normalized[: max(0, max_chars - 3)].rstrip() + "..."

    def _short_overlay_from_text(self, text: str, fallback: str) -> str:
        """Create short overlay text from a sentence."""
        cleaned = re.sub(r"\s+", " ", _normalize_string(text)).strip()
        if not cleaned:
            return fallback

        cleaned = re.sub(r"^[\"'“”]+|[\"'“”]+$", "", cleaned)
        words = cleaned.split()
        overlay = " ".join(words[:8]).strip()
        overlay = overlay.rstrip(".!?,")

        if len(overlay) < 3:
            return fallback

        return overlay

    def _extract_keywords(self, text: str, limit: int = 5) -> List[str]:
        """Extract simple keywords without external dependencies."""
        stopwords = {
            "the",
            "and",
            "for",
            "with",
            "that",
            "this",
            "your",
            "you",
            "are",
            "was",
            "were",
            "from",
            "into",
            "about",
            "will",
            "can",
            "how",
            "why",
            "what",
            "when",
            "where",
            "then",
            "than",
            "they",
            "them",
            "our",
            "their",
            "have",
            "has",
            "had",
            "not",
            "but",
            "all",
            "one",
            "two",
            "get",
            "got",
        }

        words = re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text.lower())
        scored: Dict[str, int] = {}
        for word in words:
            if word in stopwords:
                continue
            scored[word] = scored.get(word, 0) + 1

        sorted_words = sorted(scored.items(), key=lambda item: (-item[1], item[0]))
        return [word for word, _count in sorted_words[:limit]]

    def _interpret_revision_notes(self, revision_notes: str) -> Dict[str, Any]:
        """Interpret revision notes into structured guidance."""
        text = revision_notes.lower()
        requested_changes: List[str] = []

        checks = {
            "faster_pacing": ["faster", "quick", "speed", "shorter", "tight"],
            "slower_pacing": ["slower", "cinematic", "breathe", "calm"],
            "more_broll": ["more b-roll", "more broll", "more visuals", "stock footage"],
            "less_broll": ["less b-roll", "less broll", "fewer visuals"],
            "stronger_hook": ["stronger hook", "better hook", "opening"],
            "more_captions": ["caption", "subtitle", "text"],
            "stronger_cta": ["cta", "call to action", "conversion"],
        }

        for change, keywords in checks.items():
            if any(keyword in text for keyword in keywords):
                requested_changes.append(change)

        return {
            "revision_notes": revision_notes,
            "detected_requested_changes": requested_changes,
            "recommended_next_step": (
                "Regenerate the affected sections using create_edit_plan with updated instructions."
                if requested_changes
                else "Review notes manually and apply targeted edits to timeline/cuts."
            ),
        }

    # ------------------------------------------------------------------
    # Security and metadata helpers
    # ------------------------------------------------------------------

    def _estimate_security_risk(self, task: Mapping[str, Any]) -> SecurityRiskLevel:
        """Estimate task risk."""
        text = json.dumps(task, default=str).lower()

        high_risk = [
            "delete",
            "overwrite",
            "publish",
            "post now",
            "payment",
            "api key",
            "secret",
            "token",
            "password",
            "system command",
            "shell",
        ]
        medium_risk = [
            "upload",
            "download",
            "send",
            "schedule",
            "external",
            "browser",
            "email",
            "whatsapp",
            "sms",
        ]

        if any(term in text for term in high_risk):
            return SecurityRiskLevel.HIGH

        if any(term in text for term in medium_risk):
            return SecurityRiskLevel.MEDIUM

        return SecurityRiskLevel.LOW

    def _contains_unsafe_identifier(self, value: str) -> bool:
        """Check user/workspace identifiers for unsafe path-like content."""
        if not value:
            return True

        unsafe_patterns = [
            "..",
            "/",
            "\\",
            "\x00",
            "$(",
            "`",
            ";",
            "|",
            "&&",
            "||",
        ]

        return any(pattern in value for pattern in unsafe_patterns)

    def _safe_input_digest(self, normalized: Mapping[str, Any]) -> Dict[str, Any]:
        """Create safe input digest without raw script leakage."""
        script = str(normalized.get("script", ""))

        return {
            "title": normalized.get("title"),
            "platform": normalized.get("platform"),
            "video_style": normalized.get("video_style"),
            "goal": normalized.get("goal"),
            "intensity": normalized.get("intensity"),
            "target_duration_seconds": normalized.get("target_duration_seconds"),
            "script_char_count": len(script),
            "asset_count": len(normalized.get("assets") or []),
            "has_brand_notes": bool(normalized.get("brand_notes")),
            "has_source_notes": bool(normalized.get("source_notes")),
        }

    def _serialize_plan(
        self,
        plan: VideoEditingPlan,
        include_aux_payloads: bool = True,
    ) -> Dict[str, Any]:
        """Serialize plan dataclass to dict."""
        data = {
            "plan_id": plan.plan_id,
            "user_id": plan.user_id,
            "workspace_id": plan.workspace_id,
            "title": plan.title,
            "platform": plan.platform,
            "video_style": plan.video_style,
            "goal": plan.goal,
            "intensity": plan.intensity,
            "target_duration_seconds": plan.target_duration_seconds,
            "created_at": plan.created_at,
            "summary": plan.summary,
            "timeline": _asdict_list(plan.timeline),
            "timeline_timecoded": [
                {
                    **asdict(segment),
                    "start_timecode": _seconds_to_timecode(segment.start_seconds),
                    "end_timecode": _seconds_to_timecode(segment.end_seconds),
                }
                for segment in plan.timeline
            ],
            "cuts": _asdict_list(plan.cuts),
            "cuts_timecoded": [
                {
                    **asdict(cut),
                    "timecode": _seconds_to_timecode(cut.timestamp_seconds),
                }
                for cut in plan.cuts
            ],
            "b_roll": _asdict_list(plan.b_roll),
            "b_roll_timecoded": [
                {
                    **asdict(item),
                    "start_timecode": _seconds_to_timecode(item.start_seconds),
                    "end_timecode": _seconds_to_timecode(item.end_seconds),
                }
                for item in plan.b_roll
            ],
            "pattern_breaks": _asdict_list(plan.pattern_breaks),
            "pattern_breaks_timecoded": [
                {
                    **asdict(item),
                    "timecode": _seconds_to_timecode(item.timestamp_seconds),
                }
                for item in plan.pattern_breaks
            ],
            "retention_strategy": plan.retention_strategy,
            "caption_notes": plan.caption_notes,
            "audio_notes": plan.audio_notes,
            "export_notes": plan.export_notes,
            "safety_notes": plan.safety_notes,
            "metadata": plan.metadata,
        }

        if include_aux_payloads:
            data["verification_payload"] = plan.verification_payload
            data["memory_payload"] = plan.memory_payload

        return data


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------

def create_video_editor(
    config: Optional[Union[VideoEditorConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> VideoEditor:
    """
    Factory helper for Agent Loader / dependency injection.

    Args:
        config: Optional VideoEditorConfig or mapping.
        **kwargs: Optional adapters such as security_agent, memory_agent,
            verification_agent, event_bus, audit_logger.

    Returns:
        VideoEditor instance.
    """
    return VideoEditor(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Module-level registry metadata.

    Allows Agent Registry to inspect capabilities without instantiating through
    the full dependency injection system.
    """
    return {
        "agent_name": AGENT_NAME,
        "agent_type": AGENT_TYPE,
        "module_name": MODULE_NAME,
        "version": DEFAULT_VERSION,
        "class_name": "VideoEditor",
        "factory": "create_video_editor",
        "safe_to_import": True,
        "requires_user_id": True,
        "requires_workspace_id": True,
        "executes_external_actions": False,
        "capabilities": [
            "video_editing_plans",
            "cuts",
            "timing",
            "b_roll",
            "retention_pattern_breaks",
            "caption_notes",
            "audio_notes",
            "export_notes",
        ],
    }


__all__ = [
    "VideoEditor",
    "VideoEditorConfig",
    "VideoEditingPlan",
    "TimelineSegment",
    "CutRecommendation",
    "BrollRecommendation",
    "PatternBreakRecommendation",
    "EditIntensity",
    "SegmentType",
    "CutType",
    "PatternBreakType",
    "create_video_editor",
    "get_agent_metadata",
]


# ---------------------------------------------------------------------------
# Lightweight manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    editor = VideoEditor()
    sample_task = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "action": "create_edit_plan",
        "title": "How AI Automation Helps Small Teams",
        "platform": "youtube_shorts",
        "video_style": "educational",
        "goal": "lead_generation",
        "intensity": "high_retention",
        "script": (
            "Most small teams waste hours on repetitive tasks. "
            "AI automation can answer leads, summarize messages, and prepare reports. "
            "The key is not replacing people, it is removing boring work. "
            "Start with one workflow, measure the result, then automate the next one. "
            "Book a call if you want a simple automation plan."
        ),
        "cta": "Book a free automation strategy call.",
        "audience": "Small business owners and agency teams",
        "brand_notes": "Professional, modern, purple brand style.",
    }

    result = editor.create_edit_plan(sample_task)
    print(json.dumps(result, indent=2))