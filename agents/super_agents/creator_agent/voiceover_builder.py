"""
agents/super_agents/creator_agent/voiceover_builder.py

VoiceoverBuilder for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Voiceover timing, tone, line splits, and scene narration.

This file is production-oriented and import-safe:
    - Uses safe optional imports with fallback stubs.
    - Requires user_id and workspace_id for SaaS tenant isolation.
    - Does not generate real audio, call external TTS APIs, upload files, or perform destructive actions.
    - Prepares structured outputs for Creator Agent, Master Agent, Dashboard/API, Memory Agent,
      Verification Agent, Security Agent, Registry, and Router.
    - Can be tested standalone before the rest of the William/Jarvis files exist.

Expected path:
    agents/super_agents/creator_agent/voiceover_builder.py
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import logging
import math
import re
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Safe optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from core.base_agent import BaseAgent  # type: ignore
    except Exception:
        class BaseAgent:  # type: ignore
            """
            Fallback BaseAgent stub.

            The real William/Jarvis BaseAgent should replace this when available.
            This fallback keeps the file import-safe during early scaffolding.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
                self.logger = logging.getLogger(self.agent_name)

            async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
                raise NotImplementedError("Fallback BaseAgent.run is not implemented.")


try:
    from agents.super_agents.creator_agent.config import CreatorAgentConfig  # type: ignore
except Exception:
    @dataclasses.dataclass
    class CreatorAgentConfig:
        """
        Fallback Creator Agent config until creator_agent/config.py is generated.
        """

        agent_name: str = "VoiceoverBuilder"
        agent_id: str = "voiceover_builder"
        version: str = "1.0.0"
        default_language: str = "en"
        default_voice_style: str = "professional"
        default_tone: str = "confident"
        default_words_per_minute: int = 150
        min_words_per_minute: int = 90
        max_words_per_minute: int = 220
        default_pause_short_seconds: float = 0.25
        default_pause_medium_seconds: float = 0.45
        default_pause_long_seconds: float = 0.75
        max_line_words: int = 12
        max_segment_seconds: float = 8.0
        max_page_size: int = 100
        default_page_size: int = 25
        audit_enabled: bool = True
        memory_enabled: bool = True
        verification_enabled: bool = True
        dashboard_events_enabled: bool = True
        require_security_for_exports: bool = True
        require_security_for_external_generation: bool = True


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger("VoiceoverBuilder")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Enums and constants
# ======================================================================================

class VoiceoverAction(str, enum.Enum):
    """
    Supported VoiceoverBuilder actions.

    These strings are router-friendly for Master Agent, Creator Agent,
    Agent Registry, Dashboard/API, and future FastAPI endpoints.
    """

    HEALTH_CHECK = "health_check"

    BUILD_VOICEOVER = "build_voiceover"
    BUILD_FROM_SCRIPT = "build_from_script"
    BUILD_FROM_SCENES = "build_from_scenes"
    SPLIT_LINES = "split_lines"
    ESTIMATE_TIMING = "estimate_timing"
    BUILD_SCENE_NARRATION = "build_scene_narration"
    BUILD_TONE_GUIDE = "build_tone_guide"
    BUILD_SSML_PLAN = "build_ssml_plan"
    ADJUST_PACING = "adjust_pacing"
    EXPORT_VOICEOVER_PLAN = "export_voiceover_plan"

    ROUTE_VOICEOVER_TASK = "route_voiceover_task"


class VoiceTone(str, enum.Enum):
    PROFESSIONAL = "professional"
    CONFIDENT = "confident"
    FRIENDLY = "friendly"
    ENERGETIC = "energetic"
    CALM = "calm"
    LUXURY = "luxury"
    CINEMATIC = "cinematic"
    EMOTIONAL = "emotional"
    AUTHORITATIVE = "authoritative"
    CONVERSATIONAL = "conversational"
    URGENT = "urgent"
    INSPIRATIONAL = "inspirational"


class VoicePace(str, enum.Enum):
    SLOW = "slow"
    NATURAL = "natural"
    MEDIUM = "medium"
    FAST = "fast"
    AD_READ = "ad_read"
    STORY = "story"


SENSITIVE_ACTIONS = {
    VoiceoverAction.EXPORT_VOICEOVER_PLAN,
}

EXTERNAL_OR_MEDIA_ACTIONS = {
    VoiceoverAction.EXPORT_VOICEOVER_PLAN,
}


TONE_PRESETS: Dict[str, Dict[str, Any]] = {
    "professional": {
        "description": "Clear, polished, business-ready delivery.",
        "energy": "medium",
        "pitch": "neutral",
        "emotion": "controlled",
        "best_for": ["corporate videos", "service explainers", "B2B ads"],
    },
    "confident": {
        "description": "Strong, assured, persuasive delivery.",
        "energy": "medium-high",
        "pitch": "neutral-low",
        "emotion": "assured",
        "best_for": ["sales videos", "offer intros", "authority content"],
    },
    "friendly": {
        "description": "Warm, approachable, helpful delivery.",
        "energy": "medium",
        "pitch": "neutral",
        "emotion": "welcoming",
        "best_for": ["tutorials", "social content", "customer education"],
    },
    "energetic": {
        "description": "Fast, upbeat, high-retention delivery.",
        "energy": "high",
        "pitch": "slightly bright",
        "emotion": "excited",
        "best_for": ["short-form ads", "launch videos", "promos"],
    },
    "calm": {
        "description": "Relaxed, steady, reassuring delivery.",
        "energy": "low-medium",
        "pitch": "soft",
        "emotion": "reassuring",
        "best_for": ["wellness", "premium service", "instructional narration"],
    },
    "luxury": {
        "description": "Premium, slow, elegant, composed delivery.",
        "energy": "low-medium",
        "pitch": "smooth",
        "emotion": "exclusive",
        "best_for": ["luxury brands", "real estate", "premium offers"],
    },
    "cinematic": {
        "description": "Dramatic, visual, trailer-style delivery.",
        "energy": "medium-high",
        "pitch": "deep",
        "emotion": "dramatic",
        "best_for": ["trailers", "brand films", "story videos"],
    },
    "emotional": {
        "description": "Human, sincere, feeling-driven delivery.",
        "energy": "medium",
        "pitch": "soft-dynamic",
        "emotion": "heartfelt",
        "best_for": ["brand story", "nonprofit", "testimonial videos"],
    },
    "authoritative": {
        "description": "Expert, direct, command-style delivery.",
        "energy": "medium",
        "pitch": "neutral-low",
        "emotion": "credible",
        "best_for": ["expert content", "finance", "legal-style explainers"],
    },
    "conversational": {
        "description": "Natural, human, casual delivery.",
        "energy": "medium",
        "pitch": "natural",
        "emotion": "relatable",
        "best_for": ["YouTube", "UGC-style ads", "podcast intros"],
    },
    "urgent": {
        "description": "Direct, fast, action-driven delivery.",
        "energy": "high",
        "pitch": "firm",
        "emotion": "immediate",
        "best_for": ["limited offers", "alerts", "performance ads"],
    },
    "inspirational": {
        "description": "Uplifting, motivational, hopeful delivery.",
        "energy": "medium-high",
        "pitch": "open",
        "emotion": "optimistic",
        "best_for": ["personal growth", "brand mission", "campaign films"],
    },
}


PACE_WPM: Dict[str, int] = {
    "slow": 115,
    "story": 130,
    "natural": 145,
    "medium": 155,
    "ad_read": 170,
    "fast": 185,
}


# ======================================================================================
# Data structures
# ======================================================================================

@dataclasses.dataclass
class VoiceoverContext:
    """
    SaaS-safe execution context.

    Every user/workspace scoped task must include user_id and workspace_id.
    This prevents mixing scripts, assets, reports, memory, logs, or analytics
    between users/workspaces.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    source: str = "voiceover_builder"
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class VoiceoverLine:
    """
    One voiceover line with timing and performance direction.
    """

    line_id: str
    text: str
    start_time: float
    end_time: float
    duration: float
    word_count: int
    tone: str
    pace: str
    emphasis_words: List[str]
    pause_after: float
    delivery_note: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class VoiceoverScene:
    """
    Scene-level narration container.
    """

    scene_id: str
    scene_number: int
    visual_description: str
    narration: str
    start_time: float
    end_time: float
    duration: float
    tone: str
    pace: str
    lines: List[VoiceoverLine]
    on_screen_text: Optional[str] = None
    music_note: Optional[str] = None
    sfx_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["lines"] = [line.to_dict() for line in self.lines]
        return data


@dataclasses.dataclass
class VoiceoverPlan:
    """
    Complete voiceover plan.
    """

    plan_id: str
    title: str
    language: str
    voice_style: str
    tone: str
    pace: str
    target_duration: Optional[float]
    estimated_duration: float
    words_per_minute: int
    total_words: int
    scenes: List[VoiceoverScene]
    lines: List[VoiceoverLine]
    tone_guide: Dict[str, Any]
    ssml_plan: Dict[str, Any]
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["scenes"] = [scene.to_dict() for scene in self.scenes]
        data["lines"] = [line.to_dict() for line in self.lines]
        return data


# ======================================================================================
# Utility helpers
# ======================================================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_mapping(value: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return dict(default or {})


def safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def clamp_float(value: Any, minimum: float, maximum: float, default: float) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def normalize_action(action: Union[str, VoiceoverAction, None]) -> Optional[VoiceoverAction]:
    if isinstance(action, VoiceoverAction):
        return action
    if not action:
        return None
    raw = str(action).strip().lower()
    for item in VoiceoverAction:
        if item.value == raw:
            return item
    return None


def normalize_tone(tone: Optional[str], default: str = "professional") -> str:
    raw = safe_str(tone, default).lower().replace(" ", "_").replace("-", "_")
    if raw in TONE_PRESETS:
        return raw
    for item in VoiceTone:
        if item.value == raw:
            return item.value
    return default


def normalize_pace(pace: Optional[str], default: str = "natural") -> str:
    raw = safe_str(pace, default).lower().replace(" ", "_").replace("-", "_")
    if raw in PACE_WPM:
        return raw
    for item in VoicePace:
        if item.value == raw:
            return item.value
    return default


async def maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    if asyncio.iscoroutine(value) or isinstance(value, Awaitable):
        return await value
    return value


def word_count(text: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", text or ""))


def clean_text(text: str) -> str:
    text = safe_str(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def split_sentences(text: str) -> List[str]:
    text = clean_text(text)
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+", text)
    cleaned = [clean_text(part) for part in parts if clean_text(part)]
    if cleaned:
        return cleaned
    return [text]


def seconds_to_timestamp(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    minutes = int(seconds // 60)
    remaining = seconds - (minutes * 60)
    return f"{minutes:02d}:{remaining:05.2f}"


# ======================================================================================
# VoiceoverBuilder
# ======================================================================================

class VoiceoverBuilder(BaseAgent):
    """
    Creator Agent helper for voiceover timing, tone, line splits, and scene narration.

    Main responsibilities:
        - Build voiceover plans from scripts.
        - Build voiceover plans from scene descriptions.
        - Split narration into voice-friendly lines.
        - Estimate timing based on WPM, punctuation pauses, tone, and pace.
        - Produce scene-level narration.
        - Produce tone and delivery guide.
        - Produce SSML-style planning metadata without calling external TTS.
        - Prepare safe export payloads without writing files or sending media.

    System connections:
        - Master Agent:
            Can route creator/voiceover tasks to this file using run() or handle_task().
        - Creator Agent:
            Can call public methods directly for video, script, and content workflows.
        - Security Agent:
            Export or external generation actions require approval.
        - Memory Agent:
            Useful voiceover preferences and safe summaries are prepared as memory payloads.
        - Verification Agent:
            Every completed result gets verification payload metadata.
        - Dashboard/API:
            Structured results are dashboard-ready.
        - Registry/Loader:
            registry_metadata() exposes capabilities.
    """

    def __init__(
        self,
        config: Optional[CreatorAgentConfig] = None,
        *,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        self.config = config or CreatorAgentConfig()

        try:
            super().__init__(
                agent_name=getattr(self.config, "agent_name", "VoiceoverBuilder"),
                agent_id=getattr(self.config, "agent_id", "voiceover_builder"),
                **kwargs,
            )
        except TypeError:
            try:
                super().__init__(**kwargs)
            except TypeError:
                super().__init__()

        self.agent_name = getattr(self.config, "agent_name", "VoiceoverBuilder")
        self.agent_id = getattr(self.config, "agent_id", "voiceover_builder")
        self.version = getattr(self.config, "version", "1.0.0")
        self.logger = logging.getLogger(self.agent_name)

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self._action_handlers: Dict[VoiceoverAction, Callable[..., Awaitable[Dict[str, Any]]]] = {
            VoiceoverAction.HEALTH_CHECK: self.health_check,
            VoiceoverAction.BUILD_VOICEOVER: self.build_voiceover,
            VoiceoverAction.BUILD_FROM_SCRIPT: self.build_from_script,
            VoiceoverAction.BUILD_FROM_SCENES: self.build_from_scenes,
            VoiceoverAction.SPLIT_LINES: self.split_lines,
            VoiceoverAction.ESTIMATE_TIMING: self.estimate_timing,
            VoiceoverAction.BUILD_SCENE_NARRATION: self.build_scene_narration,
            VoiceoverAction.BUILD_TONE_GUIDE: self.build_tone_guide,
            VoiceoverAction.BUILD_SSML_PLAN: self.build_ssml_plan,
            VoiceoverAction.ADJUST_PACING: self.adjust_pacing,
            VoiceoverAction.EXPORT_VOICEOVER_PLAN: self.export_voiceover_plan,
            VoiceoverAction.ROUTE_VOICEOVER_TASK: self.route_voiceover_task,
        }

    # ==================================================================================
    # Registry and routing compatibility
    # ==================================================================================

    @classmethod
    def registry_metadata(cls) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader discovery metadata.
        """
        return {
            "agent_name": "VoiceoverBuilder",
            "agent_id": "voiceover_builder",
            "module": "agents.super_agents.creator_agent.voiceover_builder",
            "class_name": "VoiceoverBuilder",
            "category": "creator_agent_helper",
            "version": "1.0.0",
            "description": "Voiceover timing, tone, line splits, and scene narration.",
            "capabilities": [
                "voiceover_planning",
                "script_timing",
                "scene_narration",
                "line_splitting",
                "tone_guidance",
                "pacing_adjustment",
                "ssml_planning",
                "dashboard_ready_payloads",
                "memory_payloads",
                "verification_payloads",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "safe_to_import": True,
            "does_not_generate_real_audio": True,
            "sensitive_actions": [item.value for item in SENSITIVE_ACTIONS],
            "public_methods": [
                "run",
                "handle_task",
                "build_voiceover",
                "build_from_script",
                "build_from_scenes",
                "split_lines",
                "estimate_timing",
                "build_scene_narration",
                "build_tone_guide",
                "build_ssml_plan",
                "adjust_pacing",
                "export_voiceover_plan",
            ],
        }

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible entry point.
        """
        return await self.handle_task(task)

    async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Creator Agent / Router-compatible task handler.

        Expected shape:
            {
                "action": "build_voiceover",
                "user_id": "...",
                "workspace_id": "...",
                "payload": {
                    "script": "...",
                    "tone": "confident",
                    "pace": "ad_read"
                }
            }
        """
        started_at = time.time()
        raw_task = ensure_mapping(task)
        action = normalize_action(raw_task.get("action") or raw_task.get("type"))

        if not action:
            return self._error_result(
                message="Unsupported or missing voiceover action.",
                error_code="INVALID_ACTION",
                details={"received_action": raw_task.get("action") or raw_task.get("type")},
            )

        context_result = self._validate_task_context(raw_task)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        payload = ensure_mapping(raw_task.get("payload"), default=raw_task)

        await self._emit_agent_event(
            "voiceover_task_received",
            context=context,
            data={"action": action.value},
        )

        try:
            if self._requires_security_check(action=action, payload=payload, context=context):
                approval = await self._request_security_approval(
                    action=action,
                    payload=payload,
                    context=context,
                )
                if not approval.get("success"):
                    return self._error_result(
                        message="Security approval denied or unavailable.",
                        error_code="SECURITY_APPROVAL_REQUIRED",
                        details={"action": action.value, "approval": approval},
                        context=context,
                    )

            handler = self._action_handlers.get(action)
            if not handler:
                return self._error_result(
                    message="Voiceover action exists but has no handler.",
                    error_code="HANDLER_NOT_FOUND",
                    details={"action": action.value},
                    context=context,
                )

            result = await handler(context=context, payload=payload)

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                result=result,
                started_at=started_at,
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                context=context,
                result=result,
                payload=payload,
            )

            await self._log_audit_event(
                action=action.value,
                context=context,
                success=bool(result.get("success")),
                data={
                    "message": result.get("message"),
                    "verification": verification_payload,
                },
            )

            if getattr(self.config, "memory_enabled", True):
                await self._send_to_memory_agent(memory_payload)

            if getattr(self.config, "verification_enabled", True):
                await self._send_to_verification_agent(verification_payload)

            await self._emit_agent_event(
                "voiceover_task_completed",
                context=context,
                data={
                    "action": action.value,
                    "success": bool(result.get("success")),
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                },
            )

            metadata = ensure_mapping(result.get("metadata"))
            metadata.update(
                {
                    "agent": self.agent_name,
                    "agent_id": self.agent_id,
                    "version": self.version,
                    "action": action.value,
                    "request_id": context.request_id,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                    "verification_payload": verification_payload,
                    "memory_payload_prepared": bool(memory_payload),
                }
            )
            result["metadata"] = metadata
            return result

        except Exception as exc:
            self.logger.exception("VoiceoverBuilder task failed: %s", exc)
            await self._log_audit_event(
                action=action.value,
                context=context,
                success=False,
                data={"exception": str(exc)},
            )
            return self._error_result(
                message="Voiceover task failed unexpectedly.",
                error_code="VOICEOVER_BUILDER_EXCEPTION",
                details={
                    "action": action.value,
                    "exception": str(exc),
                    "traceback": traceback.format_exc(),
                },
                context=context,
            )

    # ==================================================================================
    # Health
    # ==================================================================================

    async def health_check(
        self,
        *,
        context: VoiceoverContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            message="VoiceoverBuilder is healthy and import-safe.",
            data={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.version,
                "supported_actions": [action.value for action in VoiceoverAction],
                "tones": list(TONE_PRESETS.keys()),
                "paces": list(PACE_WPM.keys()),
                "external_audio_generation": False,
                "security_agent_connected": self.security_agent is not None,
                "verification_agent_connected": self.verification_agent is not None,
                "memory_agent_connected": self.memory_agent is not None,
            },
            context=context,
        )

    # ==================================================================================
    # Public voiceover methods
    # ==================================================================================

    async def build_voiceover(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds a complete voiceover plan from either:
            - script text
            - scene list
            - narration list

        This does not generate real audio. It prepares timing, line splits,
        tone guidance, and SSML-style planning metadata.
        """
        scenes = payload.get("scenes")
        script = safe_str(payload.get("script") or payload.get("text") or payload.get("narration"))

        if isinstance(scenes, Sequence) and not isinstance(scenes, (str, bytes, bytearray)) and scenes:
            return await self.build_from_scenes(context=context, payload=payload)

        if script:
            return await self.build_from_script(context=context, payload=payload)

        return self._error_result(
            message="script/text/narration or scenes are required to build a voiceover plan.",
            error_code="VALIDATION_ERROR",
            context=context,
        )

    async def build_from_script(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds a voiceover plan from a single script.
        """
        script = clean_text(safe_str(payload.get("script") or payload.get("text") or payload.get("narration")))
        if not script:
            return self._error_result("Script text is required.", "VALIDATION_ERROR", context=context)

        title = safe_str(payload.get("title"), "Voiceover Plan")
        language = safe_str(payload.get("language"), getattr(self.config, "default_language", "en"))
        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        pace = normalize_pace(payload.get("pace"), "natural")
        voice_style = safe_str(payload.get("voice_style"), getattr(self.config, "default_voice_style", "professional"))
        target_duration = self._optional_float(payload.get("target_duration") or payload.get("target_duration_seconds"))
        wpm = self._resolve_wpm(payload=payload, pace=pace)

        line_result = self._split_text_into_lines(
            text=script,
            tone=tone,
            pace=pace,
            wpm=wpm,
            start_time=0.0,
            target_duration=target_duration,
        )
        lines = line_result["lines"]

        estimated_duration = lines[-1].end_time if lines else 0.0
        tone_guide = self._build_tone_guide_data(tone=tone, pace=pace, voice_style=voice_style, language=language)
        ssml_plan = self._build_ssml_plan_data(lines=lines, tone=tone, pace=pace, language=language)

        scene = VoiceoverScene(
            scene_id=str(uuid.uuid4()),
            scene_number=1,
            visual_description=safe_str(payload.get("visual_description"), "Single-script voiceover narration."),
            narration=script,
            start_time=0.0,
            end_time=estimated_duration,
            duration=estimated_duration,
            tone=tone,
            pace=pace,
            lines=lines,
            on_screen_text=safe_str(payload.get("on_screen_text")) or None,
            music_note=safe_str(payload.get("music_note")) or None,
            sfx_note=safe_str(payload.get("sfx_note")) or None,
        )

        plan = VoiceoverPlan(
            plan_id=str(uuid.uuid4()),
            title=title,
            language=language,
            voice_style=voice_style,
            tone=tone,
            pace=pace,
            target_duration=target_duration,
            estimated_duration=round(estimated_duration, 2),
            words_per_minute=wpm,
            total_words=word_count(script),
            scenes=[scene],
            lines=lines,
            tone_guide=tone_guide,
            ssml_plan=ssml_plan,
            created_at=utc_now_iso(),
        )

        return self._safe_result(
            message="Voiceover plan built from script.",
            data={
                "voiceover_plan": plan.to_dict(),
                "timing_summary": self._timing_summary(plan),
                "copy_ready_script": self._copy_ready_script(lines),
            },
            context=context,
        )

    async def build_from_scenes(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds a voiceover plan from scene descriptions.

        Scene input examples:
            [
                {
                    "visual_description": "Business owner checking ads dashboard",
                    "narration": "Your ads should bring real leads, not wasted clicks.",
                    "duration": 4
                }
            ]
        """
        raw_scenes = payload.get("scenes")
        if not isinstance(raw_scenes, Sequence) or isinstance(raw_scenes, (str, bytes, bytearray)) or not raw_scenes:
            return self._error_result("A non-empty scenes list is required.", "VALIDATION_ERROR", context=context)

        title = safe_str(payload.get("title"), "Scene Voiceover Plan")
        language = safe_str(payload.get("language"), getattr(self.config, "default_language", "en"))
        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        pace = normalize_pace(payload.get("pace"), "natural")
        voice_style = safe_str(payload.get("voice_style"), getattr(self.config, "default_voice_style", "professional"))
        target_duration = self._optional_float(payload.get("target_duration") or payload.get("target_duration_seconds"))
        wpm = self._resolve_wpm(payload=payload, pace=pace)

        scenes: List[VoiceoverScene] = []
        all_lines: List[VoiceoverLine] = []
        current_start = 0.0

        for index, raw_scene in enumerate(raw_scenes, start=1):
            scene_data = ensure_mapping(raw_scene)
            visual_description = safe_str(scene_data.get("visual_description") or scene_data.get("visual") or scene_data.get("description"))
            narration = clean_text(
                safe_str(
                    scene_data.get("narration")
                    or scene_data.get("voiceover")
                    or scene_data.get("script")
                    or scene_data.get("text")
                )
            )

            if not narration:
                narration = self._generate_scene_narration(
                    visual_description=visual_description,
                    scene_number=index,
                    tone=tone,
                    objective=safe_str(payload.get("objective") or payload.get("goal")),
                )

            scene_tone = normalize_tone(scene_data.get("tone"), tone)
            scene_pace = normalize_pace(scene_data.get("pace"), pace)
            scene_wpm = self._resolve_wpm(payload=scene_data, pace=scene_pace, fallback=wpm)

            requested_scene_duration = self._optional_float(scene_data.get("duration") or scene_data.get("duration_seconds"))

            line_result = self._split_text_into_lines(
                text=narration,
                tone=scene_tone,
                pace=scene_pace,
                wpm=scene_wpm,
                start_time=current_start,
                target_duration=requested_scene_duration,
            )
            scene_lines = line_result["lines"]
            scene_end = scene_lines[-1].end_time if scene_lines else current_start
            scene_duration = max(0.0, scene_end - current_start)

            scene = VoiceoverScene(
                scene_id=safe_str(scene_data.get("scene_id")) or str(uuid.uuid4()),
                scene_number=index,
                visual_description=visual_description or f"Scene {index}",
                narration=narration,
                start_time=round(current_start, 2),
                end_time=round(scene_end, 2),
                duration=round(scene_duration, 2),
                tone=scene_tone,
                pace=scene_pace,
                lines=scene_lines,
                on_screen_text=safe_str(scene_data.get("on_screen_text")) or None,
                music_note=safe_str(scene_data.get("music_note")) or None,
                sfx_note=safe_str(scene_data.get("sfx_note")) or None,
            )

            scenes.append(scene)
            all_lines.extend(scene_lines)
            current_start = scene_end + self._pause_seconds("medium")

        if all_lines:
            estimated_duration = all_lines[-1].end_time
        else:
            estimated_duration = 0.0

        tone_guide = self._build_tone_guide_data(tone=tone, pace=pace, voice_style=voice_style, language=language)
        ssml_plan = self._build_ssml_plan_data(lines=all_lines, tone=tone, pace=pace, language=language)

        plan = VoiceoverPlan(
            plan_id=str(uuid.uuid4()),
            title=title,
            language=language,
            voice_style=voice_style,
            tone=tone,
            pace=pace,
            target_duration=target_duration,
            estimated_duration=round(estimated_duration, 2),
            words_per_minute=wpm,
            total_words=sum(line.word_count for line in all_lines),
            scenes=scenes,
            lines=all_lines,
            tone_guide=tone_guide,
            ssml_plan=ssml_plan,
            created_at=utc_now_iso(),
        )

        return self._safe_result(
            message="Voiceover plan built from scenes.",
            data={
                "voiceover_plan": plan.to_dict(),
                "timing_summary": self._timing_summary(plan),
                "copy_ready_script": self._copy_ready_script(all_lines),
            },
            context=context,
        )

    async def split_lines(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Splits script text into voice-friendly lines with timing.
        """
        text = clean_text(safe_str(payload.get("text") or payload.get("script") or payload.get("narration")))
        if not text:
            return self._error_result("text/script/narration is required.", "VALIDATION_ERROR", context=context)

        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        pace = normalize_pace(payload.get("pace"), "natural")
        wpm = self._resolve_wpm(payload=payload, pace=pace)
        start_time = clamp_float(payload.get("start_time"), 0.0, 100000.0, 0.0)
        target_duration = self._optional_float(payload.get("target_duration") or payload.get("target_duration_seconds"))

        line_result = self._split_text_into_lines(
            text=text,
            tone=tone,
            pace=pace,
            wpm=wpm,
            start_time=start_time,
            target_duration=target_duration,
        )

        return self._safe_result(
            message="Voiceover lines split successfully.",
            data={
                "lines": [line.to_dict() for line in line_result["lines"]],
                "line_count": len(line_result["lines"]),
                "estimated_duration": line_result["estimated_duration"],
                "words_per_minute": wpm,
                "copy_ready_script": self._copy_ready_script(line_result["lines"]),
            },
            context=context,
        )

    async def estimate_timing(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Estimates reading duration for script text.
        """
        text = clean_text(safe_str(payload.get("text") or payload.get("script") or payload.get("narration")))
        if not text:
            return self._error_result("text/script/narration is required.", "VALIDATION_ERROR", context=context)

        pace = normalize_pace(payload.get("pace"), "natural")
        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        wpm = self._resolve_wpm(payload=payload, pace=pace)
        count = word_count(text)

        base_seconds = self._words_to_seconds(count, wpm)
        punctuation_pause = self._punctuation_pause_total(text)
        tone_modifier = self._tone_duration_modifier(tone)
        estimated = (base_seconds + punctuation_pause) * tone_modifier

        return self._safe_result(
            message="Voiceover timing estimated.",
            data={
                "text": text,
                "word_count": count,
                "words_per_minute": wpm,
                "pace": pace,
                "tone": tone,
                "base_seconds": round(base_seconds, 2),
                "punctuation_pause_seconds": round(punctuation_pause, 2),
                "estimated_duration_seconds": round(estimated, 2),
                "estimated_duration_timestamp": seconds_to_timestamp(estimated),
                "recommended_line_count": max(1, math.ceil(count / getattr(self.config, "max_line_words", 12))),
            },
            context=context,
        )

    async def build_scene_narration(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds concise narration text from scene descriptions.

        This is deterministic and local. It does not call any external LLM.
        Creator Agent or Script Writer can later replace/enhance this with
        deeper creative generation.
        """
        scenes = payload.get("scenes")
        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        objective = safe_str(payload.get("objective") or payload.get("goal"))
        brand = safe_str(payload.get("brand") or payload.get("brand_name"))

        if isinstance(scenes, Sequence) and not isinstance(scenes, (str, bytes, bytearray)) and scenes:
            generated: List[Dict[str, Any]] = []
            for index, raw_scene in enumerate(scenes, start=1):
                scene_data = ensure_mapping(raw_scene)
                visual = safe_str(scene_data.get("visual_description") or scene_data.get("visual") or scene_data.get("description"))
                narration = self._generate_scene_narration(
                    visual_description=visual,
                    scene_number=index,
                    tone=tone,
                    objective=objective,
                    brand=brand,
                )
                generated.append(
                    {
                        "scene_number": index,
                        "visual_description": visual,
                        "narration": narration,
                        "word_count": word_count(narration),
                    }
                )

            return self._safe_result(
                message="Scene narration generated.",
                data={"scenes": generated},
                context=context,
            )

        visual_description = safe_str(payload.get("visual_description") or payload.get("visual") or payload.get("description"))
        if not visual_description:
            return self._error_result("visual_description or scenes are required.", "VALIDATION_ERROR", context=context)

        narration = self._generate_scene_narration(
            visual_description=visual_description,
            scene_number=1,
            tone=tone,
            objective=objective,
            brand=brand,
        )

        return self._safe_result(
            message="Scene narration generated.",
            data={
                "visual_description": visual_description,
                "narration": narration,
                "word_count": word_count(narration),
            },
            context=context,
        )

    async def build_tone_guide(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds a performance direction guide for voice actors or TTS settings.
        """
        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        pace = normalize_pace(payload.get("pace"), "natural")
        voice_style = safe_str(payload.get("voice_style"), getattr(self.config, "default_voice_style", "professional"))
        language = safe_str(payload.get("language"), getattr(self.config, "default_language", "en"))

        guide = self._build_tone_guide_data(
            tone=tone,
            pace=pace,
            voice_style=voice_style,
            language=language,
        )

        return self._safe_result(
            message="Voiceover tone guide built.",
            data={"tone_guide": guide},
            context=context,
        )

    async def build_ssml_plan(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds SSML-style planning metadata.

        This does not send content to a TTS provider. It only prepares structured
        break/emphasis/speech-rate guidance that a future Voice Agent can use.
        """
        text = clean_text(safe_str(payload.get("text") or payload.get("script") or payload.get("narration")))
        lines_payload = payload.get("lines")
        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        pace = normalize_pace(payload.get("pace"), "natural")
        language = safe_str(payload.get("language"), getattr(self.config, "default_language", "en"))
        wpm = self._resolve_wpm(payload=payload, pace=pace)

        lines: List[VoiceoverLine] = []

        if isinstance(lines_payload, Sequence) and not isinstance(lines_payload, (str, bytes, bytearray)):
            current = 0.0
            for raw in lines_payload:
                if isinstance(raw, Mapping):
                    line_text = clean_text(safe_str(raw.get("text")))
                else:
                    line_text = clean_text(safe_str(raw))
                if not line_text:
                    continue
                duration = self._estimate_line_duration(line_text, wpm, tone)
                pause_after = self._pause_for_text(line_text)
                line = VoiceoverLine(
                    line_id=str(uuid.uuid4()),
                    text=line_text,
                    start_time=round(current, 2),
                    end_time=round(current + duration, 2),
                    duration=round(duration, 2),
                    word_count=word_count(line_text),
                    tone=tone,
                    pace=pace,
                    emphasis_words=self._detect_emphasis_words(line_text),
                    pause_after=pause_after,
                    delivery_note=self._delivery_note_for_line(line_text, tone, pace),
                )
                lines.append(line)
                current += duration + pause_after

        elif text:
            split_result = self._split_text_into_lines(
                text=text,
                tone=tone,
                pace=pace,
                wpm=wpm,
                start_time=0.0,
            )
            lines = split_result["lines"]
        else:
            return self._error_result("text/script/narration or lines are required.", "VALIDATION_ERROR", context=context)

        ssml_plan = self._build_ssml_plan_data(lines=lines, tone=tone, pace=pace, language=language)

        return self._safe_result(
            message="SSML-style voiceover plan built.",
            data={"ssml_plan": ssml_plan},
            context=context,
        )

    async def adjust_pacing(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Adjusts voiceover pacing to better match a target duration.
        """
        text = clean_text(safe_str(payload.get("text") or payload.get("script") or payload.get("narration")))
        if not text:
            return self._error_result("text/script/narration is required.", "VALIDATION_ERROR", context=context)

        target_duration = self._optional_float(payload.get("target_duration") or payload.get("target_duration_seconds"))
        if not target_duration or target_duration <= 0:
            return self._error_result("A valid target_duration is required.", "VALIDATION_ERROR", context=context)

        tone = normalize_tone(payload.get("tone"), getattr(self.config, "default_tone", "confident"))
        current_pace = normalize_pace(payload.get("pace"), "natural")
        current_wpm = self._resolve_wpm(payload=payload, pace=current_pace)
        count = word_count(text)

        required_wpm = int(round((count / target_duration) * 60))
        min_wpm = getattr(self.config, "min_words_per_minute", 90)
        max_wpm = getattr(self.config, "max_words_per_minute", 220)
        safe_required_wpm = max(min_wpm, min(max_wpm, required_wpm))

        recommendation = self._pacing_recommendation(required_wpm, min_wpm, max_wpm)

        split_result = self._split_text_into_lines(
            text=text,
            tone=tone,
            pace=current_pace,
            wpm=safe_required_wpm,
            start_time=0.0,
            target_duration=target_duration,
        )

        return self._safe_result(
            message="Voiceover pacing adjusted.",
            data={
                "target_duration_seconds": round(target_duration, 2),
                "word_count": count,
                "original_wpm": current_wpm,
                "required_wpm": required_wpm,
                "safe_required_wpm": safe_required_wpm,
                "recommendation": recommendation,
                "lines": [line.to_dict() for line in split_result["lines"]],
                "estimated_duration_seconds": split_result["estimated_duration"],
            },
            context=context,
        )

    async def export_voiceover_plan(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepares voiceover plan export metadata.

        This does not write files, upload assets, send messages, or call TTS APIs.
        Any real export should be handled by a dedicated file/storage/export service
        after Security Agent approval.
        """
        export_format = safe_str(payload.get("format"), "json").lower()
        if export_format not in {"json", "txt", "csv", "srt", "vtt", "ssml"}:
            return self._error_result(
                message="Unsupported voiceover export format.",
                error_code="VALIDATION_ERROR",
                details={"allowed_formats": ["json", "txt", "csv", "srt", "vtt", "ssml"]},
                context=context,
            )

        plan = ensure_mapping(payload.get("voiceover_plan") or payload.get("plan"))
        if not plan:
            build_result = await self.build_voiceover(context=context, payload=payload)
            if not build_result.get("success"):
                return build_result
            plan = ensure_mapping(build_result.get("data", {}).get("voiceover_plan"))

        export_payload = {
            "export_id": str(uuid.uuid4()),
            "plan_id": plan.get("plan_id"),
            "format": export_format,
            "status": "prepared",
            "requires_downstream_export_service": True,
            "does_not_write_file": True,
            "does_not_generate_audio": True,
            "prepared_at": utc_now_iso(),
            "suggested_filename": self._suggested_filename(plan, export_format),
        }

        if export_format == "srt":
            export_payload["preview"] = self._render_srt_preview(plan)
        elif export_format == "vtt":
            export_payload["preview"] = self._render_vtt_preview(plan)
        elif export_format == "txt":
            export_payload["preview"] = self._render_text_preview(plan)
        elif export_format == "ssml":
            export_payload["preview"] = self._render_ssml_preview(plan)

        return self._safe_result(
            message="Voiceover export prepared after security approval.",
            data={
                "export": export_payload,
                "voiceover_plan": plan,
            },
            context=context,
        )

    async def route_voiceover_task(
        self,
        *,
        context: VoiceoverContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Lightweight routing for vague creator voiceover requests.
        """
        intent = safe_str(payload.get("intent") or payload.get("goal") or payload.get("query")).lower()

        if "ssml" in intent:
            target = VoiceoverAction.BUILD_SSML_PLAN
        elif "scene" in intent and ("narration" in intent or "voice" in intent):
            target = VoiceoverAction.BUILD_SCENE_NARRATION
        elif "split" in intent or "line" in intent:
            target = VoiceoverAction.SPLIT_LINES
        elif "timing" in intent or "duration" in intent or "estimate" in intent:
            target = VoiceoverAction.ESTIMATE_TIMING
        elif "tone" in intent:
            target = VoiceoverAction.BUILD_TONE_GUIDE
        elif "pace" in intent or "pacing" in intent:
            target = VoiceoverAction.ADJUST_PACING
        elif "export" in intent:
            target = VoiceoverAction.EXPORT_VOICEOVER_PLAN
        else:
            target = VoiceoverAction.BUILD_VOICEOVER

        handler = self._action_handlers[target]
        result = await handler(context=context, payload=payload)
        metadata = ensure_mapping(result.get("metadata"))
        metadata["routed_from"] = VoiceoverAction.ROUTE_VOICEOVER_TASK.value
        metadata["routed_to"] = target.value
        result["metadata"] = metadata
        return result

    # ==================================================================================
    # Required compatibility hooks
    # ==================================================================================

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validates user/workspace context for SaaS isolation.
        """
        user_id = safe_str(task.get("user_id") or task.get("userId"))
        workspace_id = safe_str(task.get("workspace_id") or task.get("workspaceId"))

        payload = ensure_mapping(task.get("payload"))
        if not user_id:
            user_id = safe_str(payload.get("user_id") or payload.get("userId"))
        if not workspace_id:
            workspace_id = safe_str(payload.get("workspace_id") or payload.get("workspaceId"))

        if not user_id or not workspace_id:
            return self._error_result(
                message="user_id and workspace_id are required for VoiceoverBuilder tasks.",
                error_code="MISSING_TENANT_CONTEXT",
                details={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        context = VoiceoverContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=safe_str(task.get("role") or payload.get("role")) or None,
            subscription_plan=safe_str(task.get("subscription_plan") or payload.get("subscription_plan")) or None,
            request_id=safe_str(task.get("request_id") or payload.get("request_id")) or str(uuid.uuid4()),
            session_id=safe_str(task.get("session_id") or payload.get("session_id")) or None,
            source=safe_str(task.get("source"), "voiceover_builder"),
            metadata=ensure_mapping(task.get("metadata")),
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
        )

    def _requires_security_check(
        self,
        *,
        action: Union[VoiceoverAction, str],
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[VoiceoverContext] = None,
    ) -> bool:
        """
        Determines if Security Agent approval is required.

        This builder does not call external TTS or write files. However, export or
        future external-generation payloads should pass security first.
        """
        normalized = normalize_action(action)
        payload = ensure_mapping(payload)

        if not normalized:
            return True

        if normalized in SENSITIVE_ACTIONS:
            return True

        if payload.get("external_tts") is True and getattr(self.config, "require_security_for_external_generation", True):
            return True

        if payload.get("export") is True and getattr(self.config, "require_security_for_exports", True):
            return True

        if payload.get("contains_sensitive_data") is True:
            return True

        return False

    async def _request_security_approval(
        self,
        *,
        action: Union[VoiceoverAction, str],
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[VoiceoverContext] = None,
    ) -> Dict[str, Any]:
        """
        Requests Security Agent approval for sensitive/export actions.
        """
        normalized = normalize_action(action)
        payload_dict = ensure_mapping(payload)

        security_payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": normalized.value if normalized else str(action),
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "payload_summary": self._summarize_payload(payload_dict),
            "requested_at": utc_now_iso(),
            "does_not_generate_real_audio": True,
        }

        if self.security_agent is not None:
            for method_name in ("approve_action", "check_permission", "authorize", "request_approval"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = await maybe_await(method(security_payload))
                        if isinstance(response, Mapping):
                            approved = bool(response.get("success", response.get("approved", False)))
                            return {
                                "success": approved,
                                "message": response.get("message") or ("Approved." if approved else "Denied."),
                                "data": dict(response),
                                "error": None if approved else response.get("error", "SECURITY_DENIED"),
                                "metadata": {"security_method": method_name},
                            }
                    except Exception as exc:
                        return self._error_result(
                            message="Security Agent approval failed.",
                            error_code="SECURITY_AGENT_ERROR",
                            details={"exception": str(exc)},
                            context=context,
                        )

        if payload_dict.get("security_approved") is True and payload_dict.get("test_mode") is True:
            return self._safe_result(
                message="Security approval accepted from explicit test-mode override.",
                data={"approval": security_payload},
                context=context,
            )

        if normalized and normalized not in SENSITIVE_ACTIONS:
            return self._safe_result(
                message="Security approval not required for this non-sensitive voiceover action.",
                data={"approval": security_payload},
                context=context,
            )

        return self._error_result(
            message="Security Agent is not connected for sensitive voiceover action.",
            error_code="SECURITY_AGENT_UNAVAILABLE",
            details={"approval_request": security_payload},
            context=context,
        )

    def _prepare_verification_payload(
        self,
        *,
        action: Union[VoiceoverAction, str],
        context: VoiceoverContext,
        result: Mapping[str, Any],
        started_at: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Verification Agent payload after every completed action.
        """
        normalized = normalize_action(action)
        duration_ms = round((time.time() - started_at) * 1000, 2) if started_at else None
        data = ensure_mapping(result.get("data"))

        return {
            "verification_type": "creator_voiceover_result",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": normalized.value if normalized else str(action),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "result_keys": list(data.keys()),
            "duration_ms": duration_ms,
            "created_at": utc_now_iso(),
            "checks": {
                "tenant_context_present": bool(context.user_id and context.workspace_id),
                "structured_result": all(key in result for key in ("success", "message", "data", "error", "metadata")),
                "no_real_audio_generated": True,
                "no_external_tts_called": True,
                "no_cross_workspace_data_claimed": True,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        action: Union[VoiceoverAction, str],
        context: VoiceoverContext,
        result: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares safe memory payload for Memory Agent.

        Does not store raw long scripts by default. Stores summary-level voiceover
        preferences such as tone, pace, style, language, and successful workflow.
        """
        normalized = normalize_action(action)
        payload = ensure_mapping(payload)
        data = ensure_mapping(result.get("data"))

        safe_context = {
            "tone": payload.get("tone"),
            "pace": payload.get("pace"),
            "voice_style": payload.get("voice_style"),
            "language": payload.get("language"),
            "target_duration": payload.get("target_duration") or payload.get("target_duration_seconds"),
            "result_success": bool(result.get("success")),
            "data_keys": list(data.keys()),
        }

        plan = ensure_mapping(data.get("voiceover_plan"))
        if plan:
            safe_context.update(
                {
                    "estimated_duration": plan.get("estimated_duration"),
                    "total_words": plan.get("total_words"),
                    "words_per_minute": plan.get("words_per_minute"),
                    "scene_count": len(plan.get("scenes", []) or []),
                }
            )

        return {
            "memory_type": "creator_voiceover_context",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": normalized.value if normalized else str(action),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "summary": result.get("message"),
            "safe_context": safe_context,
            "importance": "medium" if normalized in {VoiceoverAction.BUILD_VOICEOVER, VoiceoverAction.BUILD_FROM_SCRIPT, VoiceoverAction.BUILD_FROM_SCENES} else "low",
            "retention_hint": "workspace_creator_preferences",
            "created_at": utc_now_iso(),
        }

    async def _emit_agent_event(
        self,
        event_name: str,
        *,
        context: Optional[VoiceoverContext] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emits dashboard/API compatible events.
        """
        if not getattr(self.config, "dashboard_events_enabled", True):
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "data": dict(data or {}),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in ("emit", "publish", "send", "dispatch"):
                    method = getattr(self.event_bus, method_name, None)
                    if callable(method):
                        await maybe_await(method(event_name, event))
                        return
            self.logger.debug("VoiceoverBuilder event: %s", event)
        except Exception as exc:
            self.logger.warning("Failed to emit VoiceoverBuilder event %s: %s", event_name, exc)

    async def _log_audit_event(
        self,
        action: str,
        *,
        context: Optional[VoiceoverContext] = None,
        success: bool,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Logs audit events with tenant-safe metadata.
        """
        if not getattr(self.config, "audit_enabled", True):
            return

        event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "success": success,
            "data": dict(data or {}),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in ("log", "write", "record", "audit"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        await maybe_await(method(event))
                        return
            self.logger.info("VoiceoverBuilder audit event: %s", event)
        except Exception as exc:
            self.logger.warning("Failed to write VoiceoverBuilder audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        *,
        context: Optional[VoiceoverContext] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured success result.
        """
        result_metadata = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "version": self.version,
            "timestamp": utc_now_iso(),
        }

        if context:
            result_metadata.update(
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                }
            )

        result_metadata.update(dict(metadata or {}))

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": result_metadata,
        }

    def _error_result(
        self,
        message: str,
        error_code: str,
        details: Optional[Mapping[str, Any]] = None,
        *,
        context: Optional[VoiceoverContext] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result.
        """
        result_metadata = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "version": self.version,
            "timestamp": utc_now_iso(),
        }

        if context:
            result_metadata.update(
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                }
            )

        result_metadata.update(dict(metadata or {}))

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": error_code,
                "message": message,
                "details": dict(details or {}),
            },
            "metadata": result_metadata,
        }

    # ==================================================================================
    # Internal voiceover logic
    # ==================================================================================

    def _split_text_into_lines(
        self,
        *,
        text: str,
        tone: str,
        pace: str,
        wpm: int,
        start_time: float = 0.0,
        target_duration: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Splits text into voice-friendly lines and assigns estimated timings.
        """
        max_line_words = getattr(self.config, "max_line_words", 12)
        sentences = split_sentences(text)
        raw_lines: List[str] = []

        for sentence in sentences:
            words = sentence.split()
            if len(words) <= max_line_words:
                raw_lines.append(sentence)
                continue

            chunk: List[str] = []
            for word in words:
                chunk.append(word)
                should_break = len(chunk) >= max_line_words or self._word_has_soft_break(word)
                if should_break:
                    raw_lines.append(clean_text(" ".join(chunk)))
                    chunk = []
            if chunk:
                raw_lines.append(clean_text(" ".join(chunk)))

        raw_lines = [line for line in raw_lines if line]

        if target_duration and word_count(text) > 0:
            required_wpm = int(round((word_count(text) / target_duration) * 60))
            min_wpm = getattr(self.config, "min_words_per_minute", 90)
            max_wpm = getattr(self.config, "max_words_per_minute", 220)
            wpm = max(min_wpm, min(max_wpm, required_wpm))

        lines: List[VoiceoverLine] = []
        cursor = float(start_time)

        for raw_line in raw_lines:
            duration = self._estimate_line_duration(raw_line, wpm, tone)
            pause_after = self._pause_for_text(raw_line)
            line = VoiceoverLine(
                line_id=str(uuid.uuid4()),
                text=raw_line,
                start_time=round(cursor, 2),
                end_time=round(cursor + duration, 2),
                duration=round(duration, 2),
                word_count=word_count(raw_line),
                tone=tone,
                pace=pace,
                emphasis_words=self._detect_emphasis_words(raw_line),
                pause_after=round(pause_after, 2),
                delivery_note=self._delivery_note_for_line(raw_line, tone, pace),
            )
            lines.append(line)
            cursor += duration + pause_after

        estimated_duration = round(lines[-1].end_time - start_time, 2) if lines else 0.0

        return {
            "lines": lines,
            "estimated_duration": estimated_duration,
            "words_per_minute": wpm,
        }

    def _estimate_line_duration(self, line: str, wpm: int, tone: str) -> float:
        count = word_count(line)
        base = self._words_to_seconds(count, wpm)
        punctuation = self._punctuation_pause_total(line)
        modifier = self._tone_duration_modifier(tone)
        return max(0.45, (base + punctuation) * modifier)

    @staticmethod
    def _words_to_seconds(count: int, wpm: int) -> float:
        if wpm <= 0:
            wpm = 150
        return (count / float(wpm)) * 60.0

    def _punctuation_pause_total(self, text: str) -> float:
        short_pause = getattr(self.config, "default_pause_short_seconds", 0.25)
        medium_pause = getattr(self.config, "default_pause_medium_seconds", 0.45)
        long_pause = getattr(self.config, "default_pause_long_seconds", 0.75)

        total = 0.0
        total += text.count(",") * short_pause
        total += text.count(";") * medium_pause
        total += text.count(":") * medium_pause
        total += text.count(".") * medium_pause
        total += text.count("?") * long_pause
        total += text.count("!") * long_pause
        total += text.count("—") * medium_pause
        total += text.count("-") * 0.08
        return total

    def _pause_for_text(self, text: str) -> float:
        text = text.strip()
        if not text:
            return 0.0
        if text.endswith(("?", "!")):
            return self._pause_seconds("long")
        if text.endswith((".", ":")):
            return self._pause_seconds("medium")
        if text.endswith((",", ";", "—")):
            return self._pause_seconds("short")
        return self._pause_seconds("short")

    def _pause_seconds(self, size: str) -> float:
        if size == "long":
            return float(getattr(self.config, "default_pause_long_seconds", 0.75))
        if size == "medium":
            return float(getattr(self.config, "default_pause_medium_seconds", 0.45))
        return float(getattr(self.config, "default_pause_short_seconds", 0.25))

    @staticmethod
    def _tone_duration_modifier(tone: str) -> float:
        if tone in {"luxury", "calm", "cinematic", "emotional"}:
            return 1.12
        if tone in {"urgent", "energetic"}:
            return 0.92
        if tone in {"authoritative", "professional"}:
            return 1.03
        return 1.0

    @staticmethod
    def _word_has_soft_break(word: str) -> bool:
        return word.endswith((",", ";", ":", "—"))

    def _resolve_wpm(
        self,
        *,
        payload: Mapping[str, Any],
        pace: str,
        fallback: Optional[int] = None,
    ) -> int:
        if payload.get("words_per_minute") is not None:
            return clamp_int(
                payload.get("words_per_minute"),
                getattr(self.config, "min_words_per_minute", 90),
                getattr(self.config, "max_words_per_minute", 220),
                getattr(self.config, "default_words_per_minute", 150),
            )

        pace_wpm = PACE_WPM.get(pace)
        if pace_wpm:
            return pace_wpm

        return fallback or getattr(self.config, "default_words_per_minute", 150)

    @staticmethod
    def _optional_float(value: Any) -> Optional[float]:
        if value is None or value == "":
            return None
        try:
            parsed = float(value)
            if parsed <= 0:
                return None
            return parsed
        except Exception:
            return None

    @staticmethod
    def _detect_emphasis_words(text: str) -> List[str]:
        """
        Detects words that may need stronger vocal emphasis.
        """
        candidates: List[str] = []

        quoted = re.findall(r'"([^"]+)"|' r"'([^']+)'", text)
        for pair in quoted:
            for item in pair:
                if item:
                    candidates.extend(item.split())

        uppercase = re.findall(r"\b[A-Z]{2,}\b", text)
        candidates.extend(uppercase)

        power_terms = {
            "now",
            "today",
            "free",
            "save",
            "growth",
            "results",
            "leads",
            "sales",
            "premium",
            "limited",
            "guaranteed",
            "fast",
            "trusted",
            "proven",
            "exclusive",
            "discover",
            "transform",
            "success",
        }

        for word in re.findall(r"\b[\w'-]+\b", text.lower()):
            if word in power_terms:
                candidates.append(word)

        cleaned: List[str] = []
        seen = set()
        for item in candidates:
            clean = re.sub(r"[^\w'-]", "", item).strip()
            if clean and clean.lower() not in seen:
                seen.add(clean.lower())
                cleaned.append(clean)

        return cleaned[:6]

    @staticmethod
    def _delivery_note_for_line(text: str, tone: str, pace: str) -> str:
        if text.endswith("?"):
            return "Lift slightly at the end; make it sound curious and human."
        if text.endswith("!"):
            return "Add controlled energy; avoid shouting."
        if tone == "luxury":
            return "Slow down slightly and leave a premium pause after the line."
        if tone == "urgent":
            return "Deliver with direct momentum and a clear call-to-action feel."
        if tone == "cinematic":
            return "Use dramatic weight and let key words breathe."
        if pace in {"fast", "ad_read"}:
            return "Keep it tight, clear, and high-retention."
        return "Deliver naturally with clear articulation."

    def _build_tone_guide_data(
        self,
        *,
        tone: str,
        pace: str,
        voice_style: str,
        language: str,
    ) -> Dict[str, Any]:
        preset = TONE_PRESETS.get(tone, TONE_PRESETS["professional"])
        wpm = PACE_WPM.get(pace, getattr(self.config, "default_words_per_minute", 150))

        return {
            "tone": tone,
            "pace": pace,
            "voice_style": voice_style,
            "language": language,
            "description": preset["description"],
            "energy": preset["energy"],
            "pitch": preset["pitch"],
            "emotion": preset["emotion"],
            "recommended_words_per_minute": wpm,
            "best_for": preset["best_for"],
            "performance_notes": [
                "Keep pronunciation clear and consistent.",
                "Use pauses after major claims or emotional lines.",
                "Emphasize benefit-driven words without sounding robotic.",
                "Avoid rushing brand names, prices, URLs, phone numbers, and CTAs.",
            ],
            "tts_planning_notes": {
                "speech_rate": self._speech_rate_for_pace(pace),
                "pitch_hint": preset["pitch"],
                "style_hint": tone,
                "pause_strategy": "Use short pauses after commas, medium pauses after periods, and longer pauses after questions or CTAs.",
            },
        }

    def _build_ssml_plan_data(
        self,
        *,
        lines: Sequence[VoiceoverLine],
        tone: str,
        pace: str,
        language: str,
    ) -> Dict[str, Any]:
        """
        Builds SSML-style data without creating provider-specific final SSML.
        """
        return {
            "language": language,
            "tone": tone,
            "pace": pace,
            "speech_rate": self._speech_rate_for_pace(pace),
            "line_count": len(lines),
            "segments": [
                {
                    "line_id": line.line_id,
                    "text": line.text,
                    "start_time": line.start_time,
                    "end_time": line.end_time,
                    "duration": line.duration,
                    "break_after_ms": int(line.pause_after * 1000),
                    "emphasis_words": line.emphasis_words,
                    "delivery_note": line.delivery_note,
                    "ssml_hint": self._line_ssml_hint(line),
                }
                for line in lines
            ],
            "provider_neutral": True,
            "does_not_call_tts": True,
        }

    @staticmethod
    def _speech_rate_for_pace(pace: str) -> str:
        if pace == "slow":
            return "slow"
        if pace in {"fast", "ad_read"}:
            return "fast"
        return "medium"

    @staticmethod
    def _line_ssml_hint(line: VoiceoverLine) -> Dict[str, Any]:
        return {
            "speak": line.text,
            "break_after": f"{int(line.pause_after * 1000)}ms",
            "emphasis": line.emphasis_words,
        }

    def _generate_scene_narration(
        self,
        *,
        visual_description: str,
        scene_number: int,
        tone: str,
        objective: str = "",
        brand: str = "",
    ) -> str:
        """
        Local deterministic narration generator for scene descriptions.
        """
        visual = clean_text(visual_description)
        objective = clean_text(objective)
        brand = clean_text(brand)

        if not visual:
            visual = f"Scene {scene_number}"

        prefix_by_tone = {
            "luxury": "Experience a smoother, more refined way forward.",
            "urgent": "Now is the moment to act.",
            "energetic": "Here is where attention turns into action.",
            "cinematic": "Every moment builds toward something bigger.",
            "emotional": "It starts with a real need and a better way to solve it.",
            "friendly": "Here is a simple way to make things easier.",
            "professional": "This is where clarity meets execution.",
            "confident": "This is how better results begin.",
            "conversational": "Here is what is really happening.",
            "authoritative": "The right strategy changes the outcome.",
            "calm": "A better experience starts with a clear, steady approach.",
            "inspirational": "Progress begins when the next step becomes clear.",
        }

        prefix = prefix_by_tone.get(tone, prefix_by_tone["professional"])

        if brand and objective:
            return f"{prefix} With {brand}, {objective.lower()} becomes easier to achieve."
        if brand:
            return f"{prefix} {brand} helps turn this moment into measurable progress."
        if objective:
            return f"{prefix} The goal is simple: {objective.lower()}."
        return f"{prefix} {visual} shows the next step clearly."

    def _timing_summary(self, plan: VoiceoverPlan) -> Dict[str, Any]:
        target = plan.target_duration
        delta = None
        fit_status = "no_target_duration"

        if target:
            delta = round(plan.estimated_duration - target, 2)
            if abs(delta) <= 1.0:
                fit_status = "fits_target"
            elif delta > 1:
                fit_status = "too_long"
            else:
                fit_status = "too_short"

        return {
            "estimated_duration_seconds": plan.estimated_duration,
            "estimated_duration_timestamp": seconds_to_timestamp(plan.estimated_duration),
            "target_duration_seconds": target,
            "difference_seconds": delta,
            "fit_status": fit_status,
            "total_words": plan.total_words,
            "line_count": len(plan.lines),
            "scene_count": len(plan.scenes),
            "words_per_minute": plan.words_per_minute,
        }

    @staticmethod
    def _copy_ready_script(lines: Sequence[VoiceoverLine]) -> str:
        return "\n".join(line.text for line in lines)

    def _pacing_recommendation(self, required_wpm: int, min_wpm: int, max_wpm: int) -> str:
        if required_wpm < min_wpm:
            return "Script is short for the target duration. Add more narration or use longer pauses."
        if required_wpm > max_wpm:
            return "Script is too long for the target duration. Shorten copy or increase video duration."
        if required_wpm >= 180:
            return "Fast ad-read pacing needed. Keep articulation sharp and reduce complex phrases."
        if required_wpm <= 120:
            return "Slow pacing works. Use emotional pauses and premium delivery."
        return "Target duration is realistic with natural pacing."

    @staticmethod
    def _suggested_filename(plan: Mapping[str, Any], export_format: str) -> str:
        title = safe_str(plan.get("title"), "voiceover_plan").lower()
        title = re.sub(r"[^a-z0-9]+", "_", title).strip("_") or "voiceover_plan"
        return f"{title}.{export_format}"

    def _render_srt_preview(self, plan: Mapping[str, Any]) -> str:
        lines = self._extract_line_dicts(plan)
        blocks = []
        for index, line in enumerate(lines, start=1):
            start = self._srt_timestamp(float(line.get("start_time", 0)))
            end = self._srt_timestamp(float(line.get("end_time", 0)))
            blocks.append(f"{index}\n{start} --> {end}\n{line.get('text', '')}")
        return "\n\n".join(blocks[:10])

    def _render_vtt_preview(self, plan: Mapping[str, Any]) -> str:
        lines = self._extract_line_dicts(plan)
        blocks = ["WEBVTT"]
        for line in lines[:10]:
            start = self._vtt_timestamp(float(line.get("start_time", 0)))
            end = self._vtt_timestamp(float(line.get("end_time", 0)))
            blocks.append(f"{start} --> {end}\n{line.get('text', '')}")
        return "\n\n".join(blocks)

    def _render_text_preview(self, plan: Mapping[str, Any]) -> str:
        lines = self._extract_line_dicts(plan)
        return "\n".join(str(line.get("text", "")) for line in lines)

    def _render_ssml_preview(self, plan: Mapping[str, Any]) -> str:
        lines = self._extract_line_dicts(plan)
        parts = ["<speak>"]
        for line in lines[:20]:
            text = self._xml_escape(str(line.get("text", "")))
            pause_ms = int(float(line.get("pause_after", 0.25)) * 1000)
            parts.append(f"  <p>{text}</p>")
            parts.append(f'  <break time="{pause_ms}ms"/>')
        parts.append("</speak>")
        return "\n".join(parts)

    @staticmethod
    def _extract_line_dicts(plan: Mapping[str, Any]) -> List[Dict[str, Any]]:
        raw_lines = plan.get("lines") or []
        if isinstance(raw_lines, Sequence) and not isinstance(raw_lines, (str, bytes, bytearray)):
            return [dict(line) for line in raw_lines if isinstance(line, Mapping)]
        return []

    @staticmethod
    def _srt_timestamp(seconds: float) -> str:
        seconds = max(0.0, seconds)
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        millis = int(round((seconds - int(seconds)) * 1000))
        return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"

    @staticmethod
    def _vtt_timestamp(seconds: float) -> str:
        seconds = max(0.0, seconds)
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        millis = int(round((seconds - int(seconds)) * 1000))
        return f"{hours:02d}:{minutes:02d}:{secs:02d}.{millis:03d}"

    @staticmethod
    def _xml_escape(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    async def _send_to_memory_agent(self, memory_payload: Mapping[str, Any]) -> None:
        """
        Sends memory payload to connected Memory Agent if available.
        """
        if not memory_payload or self.memory_agent is None:
            return

        for method_name in ("store", "remember", "save_memory", "add_memory", "handle_memory"):
            method = getattr(self.memory_agent, method_name, None)
            if callable(method):
                try:
                    await maybe_await(method(dict(memory_payload)))
                    return
                except Exception as exc:
                    self.logger.warning("Failed to send voiceover memory payload via %s: %s", method_name, exc)

    async def _send_to_verification_agent(self, verification_payload: Mapping[str, Any]) -> None:
        """
        Sends verification payload to connected Verification Agent if available.
        """
        if not verification_payload or self.verification_agent is None:
            return

        for method_name in ("verify", "submit", "record", "prepare_verification", "handle_verification"):
            method = getattr(self.verification_agent, method_name, None)
            if callable(method):
                try:
                    await maybe_await(method(dict(verification_payload)))
                    return
                except Exception as exc:
                    self.logger.warning("Failed to send voiceover verification payload via %s: %s", method_name, exc)

    @staticmethod
    def _summarize_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Creates safe payload summary for security/audit logs.
        """
        sensitive_keys = {"password", "token", "secret", "api_key", "authorization", "auth"}
        safe_preview: Dict[str, Any] = {}

        for key, value in payload.items():
            lower_key = str(key).lower()
            if any(sensitive in lower_key for sensitive in sensitive_keys):
                safe_preview[key] = "[REDACTED]"
            elif isinstance(value, str):
                safe_preview[key] = value[:160] + ("..." if len(value) > 160 else "")
            elif isinstance(value, (int, float, bool)) or value is None:
                safe_preview[key] = value
            elif isinstance(value, Mapping):
                safe_preview[key] = {"type": "object", "keys": list(value.keys())}
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                safe_preview[key] = {"type": "list", "length": len(value)}
            else:
                safe_preview[key] = {"type": type(value).__name__}

        return {
            "keys": list(payload.keys()),
            "size": len(str(payload)),
            "safe_preview": safe_preview,
        }


# ======================================================================================
# Module-level exports
# ======================================================================================

__all__ = [
    "VoiceoverBuilder",
    "CreatorAgentConfig",
    "VoiceoverAction",
    "VoiceTone",
    "VoicePace",
    "VoiceoverContext",
    "VoiceoverLine",
    "VoiceoverScene",
    "VoiceoverPlan",
]