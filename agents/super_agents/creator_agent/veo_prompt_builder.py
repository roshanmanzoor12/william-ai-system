"""
agents/super_agents/creator_agent/veo_prompt_builder.py

William / Jarvis Multi-Agent AI SaaS System
Creator Agent - VEO Prompt Builder

Purpose:
    Builds VEO 3 cinematic prompts, JSON prompts, character continuity profiles,
    scene specifications, shot lists, visual direction, audio direction, and
    dashboard/API-ready prompt packages.

Architecture compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is unavailable.
    - Master Agent / Agent Router compatible through async run().
    - Agent Registry / Agent Loader compatible through metadata + factory.
    - Security Agent compatible through approval hooks.
    - Memory Agent compatible through safe reusable prompt context payloads.
    - Verification Agent compatible through structured verification payloads.
    - SaaS safe: user_id and workspace_id are required for user/workspace tasks.

Important:
    This module only generates prompt/specification text and structured prompt
    data. It does not call VEO, upload assets, send messages, browse, execute
    system actions, charge users, or perform destructive actions.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe if the full William/Jarvis framework is
        not available yet. The real system should provide agents.base_agent.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "creator")
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": None,
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {"agent": self.agent_name},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

DEFAULT_DURATION_SECONDS = 8
DEFAULT_ASPECT_RATIO = "16:9"
DEFAULT_RESOLUTION = "1080p"
DEFAULT_STYLE = "cinematic realism"
DEFAULT_LANGUAGE = "English"
DEFAULT_BRAND_SAFETY_LEVEL = "standard"

SUPPORTED_ASPECT_RATIOS = {"16:9", "9:16", "1:1", "4:5", "21:9"}
SUPPORTED_RESOLUTIONS = {"720p", "1080p", "2k", "4k"}
SUPPORTED_PROMPT_FORMATS = {"text", "json", "both"}
SUPPORTED_CAMERA_MOVES = {
    "static",
    "slow push-in",
    "slow pull-back",
    "tracking shot",
    "handheld",
    "crane shot",
    "drone shot",
    "dolly",
    "orbit",
    "pan",
    "tilt",
    "whip pan",
    "macro close-up",
}
SUPPORTED_LIGHTING_STYLES = {
    "natural light",
    "soft cinematic light",
    "golden hour",
    "blue hour",
    "neon",
    "high contrast",
    "low key",
    "studio lighting",
    "documentary realism",
    "volumetric light",
}
SUPPORTED_MOODS = {
    "premium",
    "dramatic",
    "emotional",
    "energetic",
    "luxury",
    "warm",
    "trustworthy",
    "futuristic",
    "mysterious",
    "inspiring",
    "clean",
    "bold",
    "calm",
    "urgent",
}
SUPPORTED_PLATFORMS = {
    "youtube",
    "youtube_shorts",
    "tiktok",
    "instagram_reels",
    "instagram_feed",
    "facebook",
    "linkedin",
    "x",
    "website",
    "ads",
    "general",
}

SAFETY_BLOCK_TERMS = {
    "deepfake of real person",
    "non-consensual",
    "explicit sexual",
    "child sexual",
    "terrorist propaganda",
    "how to make a bomb",
    "self harm instructions",
    "graphic gore",
}

SENSITIVE_PROMPT_FLAGS = {
    "real_person_likeness",
    "political_persuasion",
    "medical_claim",
    "financial_claim",
    "legal_claim",
    "regulated_product",
    "minor_present",
    "violence",
    "weapon",
}


class PromptFormat(str, Enum):
    """Supported output prompt formats."""

    TEXT = "text"
    JSON = "json"
    BOTH = "both"


class SceneType(str, Enum):
    """Common scene types for video prompt generation."""

    HOOK = "hook"
    PROBLEM = "problem"
    SOLUTION = "solution"
    DEMO = "demo"
    TESTIMONIAL = "testimonial"
    PRODUCT = "product"
    LIFESTYLE = "lifestyle"
    TRANSFORMATION = "transformation"
    CTA = "cta"
    BRAND = "brand"


class ShotSize(str, Enum):
    """Cinematic shot-size labels."""

    EXTREME_WIDE = "extreme wide shot"
    WIDE = "wide shot"
    MEDIUM = "medium shot"
    MEDIUM_CLOSE = "medium close-up"
    CLOSE_UP = "close-up"
    EXTREME_CLOSE = "extreme close-up"
    OVER_THE_SHOULDER = "over-the-shoulder"
    POV = "point-of-view"


class ContinuityStrength(str, Enum):
    """How strongly character/brand continuity should be preserved."""

    LIGHT = "light"
    MEDIUM = "medium"
    STRICT = "strict"


class VeoPromptQuality(str, Enum):
    """Prompt quality presets."""

    FAST = "fast"
    BALANCED = "balanced"
    CINEMATIC = "cinematic"
    PRODUCTION = "production"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CreatorTaskContext:
    """
    SaaS context for all Creator Agent operations.

    Every user/workspace operation must include user_id and workspace_id to
    avoid mixing prompt data, assets, memory, logs, or analytics.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CharacterProfile:
    """
    Character continuity profile for VEO prompt generation.

    This is designed to be reusable by Memory Agent, Creator Agent, and Visual
    Agent without storing sensitive personal data unless explicitly provided.
    """

    name: str
    role: str = "main character"
    age_range: Optional[str] = None
    gender_presentation: Optional[str] = None
    appearance: str = ""
    wardrobe: str = ""
    personality: str = ""
    voice: str = ""
    mannerisms: str = ""
    continuity_notes: str = ""
    avoid_changes: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BrandStyleProfile:
    """
    Brand style profile for prompt consistency.

    A future brand_style.py can own this deeply. This local structure keeps
    veo_prompt_builder.py import-safe and immediately usable.
    """

    brand_name: str = ""
    tone: str = "premium, clear, trustworthy"
    colors: Sequence[str] = field(default_factory=tuple)
    typography: str = ""
    visual_identity: str = ""
    forbidden_elements: Sequence[str] = field(default_factory=tuple)
    logo_usage: str = "include logo only if provided as an approved asset"
    cta_style: str = "clear and confident"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SceneSpec:
    """
    Structured scene specification.

    Used to generate text prompts, JSON prompts, shot lists, dashboard cards,
    and future VEO/API payloads.
    """

    scene_id: str
    scene_type: str = SceneType.DEMO.value
    duration_seconds: int = DEFAULT_DURATION_SECONDS
    description: str = ""
    location: str = ""
    time_of_day: str = ""
    characters: Sequence[CharacterProfile] = field(default_factory=tuple)
    action: str = ""
    dialogue: str = ""
    voiceover: str = ""
    camera: str = "slow push-in"
    shot_size: str = ShotSize.MEDIUM.value
    lens: str = "35mm cinematic lens"
    lighting: str = "soft cinematic light"
    mood: str = "premium"
    audio: str = "subtle cinematic ambience"
    visual_style: str = DEFAULT_STYLE
    negative_prompt: str = ""
    continuity_notes: str = ""
    props: Sequence[str] = field(default_factory=tuple)
    transitions: str = "clean cinematic cut"
    on_screen_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["characters"] = [
            character.to_dict() if hasattr(character, "to_dict") else character
            for character in self.characters
        ]
        return data


@dataclass
class VeoPromptPackage:
    """
    Final prompt package returned to dashboard/API/Master Agent.

    The package contains both human-copyable cinematic prompt text and a
    structured JSON prompt suitable for programmatic prompt workflows.
    """

    prompt_id: str
    title: str
    format: str
    text_prompt: str
    json_prompt: Dict[str, Any]
    scenes: Sequence[SceneSpec]
    character_continuity: Sequence[CharacterProfile]
    brand_style: BrandStyleProfile
    negative_prompt: str
    platform: str
    aspect_ratio: str
    resolution: str
    total_duration_seconds: int
    safety_flags: Sequence[str] = field(default_factory=tuple)
    recommendations: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt_id": self.prompt_id,
            "title": self.title,
            "format": self.format,
            "text_prompt": self.text_prompt,
            "json_prompt": self.json_prompt,
            "scenes": [scene.to_dict() for scene in self.scenes],
            "character_continuity": [
                character.to_dict() for character in self.character_continuity
            ],
            "brand_style": self.brand_style.to_dict(),
            "negative_prompt": self.negative_prompt,
            "platform": self.platform,
            "aspect_ratio": self.aspect_ratio,
            "resolution": self.resolution,
            "total_duration_seconds": self.total_duration_seconds,
            "safety_flags": list(self.safety_flags),
            "recommendations": list(self.recommendations),
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def _safe_str(value: Any, default: str = "") -> str:
    """Convert any value into a clean string."""

    if value is None:
        return default
    try:
        text = str(value).strip()
        return text if text else default
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    """Safely convert value to int with optional min/max bounds."""

    try:
        number = int(value)
    except Exception:
        number = default

    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def _normalize_key(value: Any, default: str = "") -> str:
    """Normalize a string key."""

    text = _safe_str(value, default).lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or default


def _as_list(value: Any) -> List[Any]:
    """Normalize input into a list."""

    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _join_clean(parts: Iterable[Any], separator: str = ", ") -> str:
    """Join non-empty text parts."""

    clean = [_safe_str(part) for part in parts if _safe_str(part)]
    return separator.join(clean)


def _sentence(text: str) -> str:
    """Return text as a sentence."""

    clean = _safe_str(text)
    if not clean:
        return ""
    if clean.endswith((".", "!", "?")):
        return clean
    return clean + "."


def _truncate(text: str, limit: int = 1200) -> str:
    """Truncate long text safely."""

    clean = _safe_str(text)
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."


def _dedupe_keep_order(items: Iterable[Any]) -> List[Any]:
    """Deduplicate list while preserving order."""

    seen = set()
    output = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, Mapping) else str(item)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _json_safe(data: Any) -> Any:
    """Convert data into JSON-safe structure."""

    if isinstance(data, Mapping):
        return {str(key): _json_safe(value) for key, value in data.items()}
    if isinstance(data, (list, tuple, set)):
        return [_json_safe(item) for item in data]
    if isinstance(data, datetime):
        return data.isoformat()
    if hasattr(data, "to_dict"):
        return _json_safe(data.to_dict())
    if isinstance(data, (str, int, float, bool)) or data is None:
        return data
    return str(data)


def _make_prompt_id(prefix: str = "veo_prompt") -> str:
    """Generate stable unique prompt id."""

    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VeoPromptBuilder(BaseAgent):
    """
    Builds VEO 3 cinematic prompts, JSON prompts, character continuity, and scene specs.

    Public methods are safe for:
        - Master Agent routing.
        - Creator Agent internal composition.
        - Dashboard/FastAPI response generation.
        - Memory Agent prompt context storage.
        - Verification Agent output checks.

    This class does not call external VEO APIs. It only creates prompt payloads.
    """

    agent_name = "VeoPromptBuilder"
    agent_type = "creator"
    version = "1.0.0"

    def __init__(
        self,
        *,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        default_language: str = DEFAULT_LANGUAGE,
        default_aspect_ratio: str = DEFAULT_ASPECT_RATIO,
        default_resolution: str = DEFAULT_RESOLUTION,
        default_style: str = DEFAULT_STYLE,
        **kwargs: Any,
    ) -> None:
        """
        Initialize VEO prompt builder.

        Args:
            security_client:
                Optional Security Agent adapter.
            memory_client:
                Optional Memory Agent adapter.
            verification_client:
                Optional Verification Agent adapter.
            event_emitter:
                Optional event bus callback.
            audit_logger:
                Optional audit logger callback.
            default_language:
                Default prompt/script language.
            default_aspect_ratio:
                Default VEO video aspect ratio.
            default_resolution:
                Default output resolution.
            default_style:
                Default visual style.
            **kwargs:
                Forward-compatible BaseAgent kwargs.
        """

        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.default_language = default_language or DEFAULT_LANGUAGE
        self.default_aspect_ratio = (
            default_aspect_ratio
            if default_aspect_ratio in SUPPORTED_ASPECT_RATIOS
            else DEFAULT_ASPECT_RATIO
        )
        self.default_resolution = (
            default_resolution
            if default_resolution in SUPPORTED_RESOLUTIONS
            else DEFAULT_RESOLUTION
        )
        self.default_style = default_style or DEFAULT_STYLE
        self.logger = logging.getLogger(f"{__name__}.{self.agent_name}")

    # ------------------------------------------------------------------
    # Required William/Jarvis compatibility hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "OK",
        data: Any = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured result."""

        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Exception, Dict[str, Any]],
        data: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured error result."""

        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": data,
            "error": error_payload,
            "metadata": metadata or {},
        }

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate user/workspace context.

        SaaS isolation rule:
            user_id and workspace_id are required for every user-specific
            prompt, memory, audit, and dashboard operation.
        """

        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                error="TASK_CONTEXT_MUST_BE_MAPPING",
            )

        user_id = _safe_str(task_context.get("user_id"))
        workspace_id = _safe_str(task_context.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="Missing required user_id.",
                error="MISSING_USER_ID",
            )

        if not workspace_id:
            return self._error_result(
                message="Missing required workspace_id.",
                error="MISSING_WORKSPACE_ID",
            )

        context = CreatorTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=_safe_str(task_context.get("role"), default="") or None,
            request_id=_safe_str(task_context.get("request_id"), default="") or None,
            session_id=_safe_str(task_context.get("session_id"), default="") or None,
            permissions=tuple(task_context.get("permissions") or ()),
        )

        return self._safe_result(
            message="Creator task context validated.",
            data=context,
            metadata={
                "agent": self.agent_name,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is required.

        Prompt generation is usually safe, but sensitive areas need approval:
            - real person likeness continuity
            - political persuasion
            - medical/legal/financial claims
            - regulated products
            - minors
            - raw asset references with sensitive metadata
        """

        action_key = _normalize_key(action)
        payload = payload or {}

        sensitive_actions = {
            "generate_sensitive_prompt",
            "build_real_person_prompt",
            "export_prompt_package",
            "store_character_continuity",
            "generate_regulated_ad_prompt",
        }

        if action_key in sensitive_actions:
            return True

        flags = set(_as_list(payload.get("safety_flags")))
        if flags.intersection(SENSITIVE_PROMPT_FLAGS):
            return True

        if bool(payload.get("real_person_likeness")):
            return True

        if bool(payload.get("include_raw_asset_metadata")):
            return True

        if bool(payload.get("store_to_memory")) and payload.get("character_continuity"):
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if needed.

        If a sensitive prompt requires approval and no Security Agent is
        attached, the action is denied by default.
        """

        payload = dict(payload or {})
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context: CreatorTaskContext = context_result["data"]
        required = self._requires_security_check(action, payload)

        if not required:
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "required": False},
                metadata=context.to_dict(),
            )

        approval_payload = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "risk": "medium",
            "reason": "Sensitive creator prompt requires Security Agent approval.",
            "context": context.to_dict(),
            "payload_summary": self._summarize_payload(payload),
            "timestamp": _utc_now().isoformat(),
        }

        if self.security_client is None:
            return self._error_result(
                message="Security approval is required but no Security Agent client is configured.",
                error="SECURITY_CLIENT_NOT_CONFIGURED",
                metadata={
                    **context.to_dict(),
                    "security_required": True,
                    "approval_payload": approval_payload,
                },
            )

        try:
            if hasattr(self.security_client, "request_approval"):
                approval = self.security_client.request_approval(approval_payload)
            elif hasattr(self.security_client, "approve"):
                approval = self.security_client.approve(approval_payload)
            else:
                return self._error_result(
                    message="Security client does not expose an approval method.",
                    error="SECURITY_CLIENT_INVALID",
                    metadata=context.to_dict(),
                )

            approved = bool(
                approval.get("approved")
                if isinstance(approval, Mapping)
                else getattr(approval, "approved", False)
            )

            if not approved:
                return self._error_result(
                    message="Security Agent denied this creator prompt action.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={**context.to_dict(), "approval": _json_safe(approval)},
                )

            return self._safe_result(
                message="Security Agent approved creator prompt action.",
                data={"approved": True, "required": True, "approval": _json_safe(approval)},
                metadata=context.to_dict(),
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                metadata=context.to_dict(),
            )

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can confirm:
            - tenant context exists
            - prompt package is structured
            - scene specs are present
            - safety flags were checked
            - no external generation was executed
        """

        context_result = self._validate_task_context(task_context)
        context_payload = (
            context_result["data"].to_dict()
            if context_result.get("success") and hasattr(context_result.get("data"), "to_dict")
            else dict(task_context)
        )

        data = result.get("data") if isinstance(result, Mapping) else {}
        prompt_package = data.get("prompt_package") if isinstance(data, Mapping) else {}

        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "verification_type": "creator_veo_prompt",
            "context": context_payload,
            "result_success": bool(result.get("success")) if isinstance(result, Mapping) else False,
            "checks": {
                "tenant_scope_enforced": True,
                "structured_result": isinstance(result, Mapping),
                "contains_prompt_package": isinstance(prompt_package, Mapping),
                "contains_text_prompt": bool(prompt_package.get("text_prompt")) if isinstance(prompt_package, Mapping) else False,
                "contains_json_prompt": bool(prompt_package.get("json_prompt")) if isinstance(prompt_package, Mapping) else False,
                "contains_scenes": bool(prompt_package.get("scenes")) if isinstance(prompt_package, Mapping) else False,
                "no_external_veo_call_executed": True,
                "no_destructive_action_executed": True,
            },
            "safety_flags": (
                prompt_package.get("safety_flags", [])
                if isinstance(prompt_package, Mapping)
                else []
            ),
            "timestamp": _utc_now().isoformat(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        memory_type: str = "creator_veo_prompt_context",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        By default, this stores compact reusable creative context only. It does
        not include raw asset files or private metadata.
        """

        context_result = self._validate_task_context(task_context)
        context_payload = (
            context_result["data"].to_dict()
            if context_result.get("success") and hasattr(context_result.get("data"), "to_dict")
            else dict(task_context)
        )

        data = result.get("data") if isinstance(result, Mapping) else {}
        package = data.get("prompt_package") if isinstance(data, Mapping) else {}

        compact_summary = {}
        if isinstance(package, Mapping):
            compact_summary = {
                "prompt_id": package.get("prompt_id"),
                "title": package.get("title"),
                "platform": package.get("platform"),
                "aspect_ratio": package.get("aspect_ratio"),
                "resolution": package.get("resolution"),
                "total_duration_seconds": package.get("total_duration_seconds"),
                "brand_style": package.get("brand_style"),
                "character_continuity": package.get("character_continuity"),
                "negative_prompt": package.get("negative_prompt"),
                "safety_flags": package.get("safety_flags", []),
            }

        return {
            "memory_type": memory_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "context": context_payload,
            "summary": compact_summary,
            "raw_assets_included": False,
            "external_generation_executed": False,
            "timestamp": _utc_now().isoformat(),
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        task_context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit Creator Agent event for dashboard/task history/event bus.

        Failure to emit never blocks prompt generation.
        """

        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "context": {
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "request_id": task_context.get("request_id"),
                "session_id": task_context.get("session_id"),
            },
            "payload": _json_safe(payload or {}),
            "timestamp": _utc_now().isoformat(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", event)
        except Exception:
            self.logger.exception("Failed to emit creator event.")

    def _log_audit_event(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        success: bool,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event scoped by user/workspace.

        Prompt generation is read-only, but audit logs are still important for
        SaaS workspaces, dashboard history, and admin visibility.
        """

        event = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "success": bool(success),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "request_id": task_context.get("request_id"),
            "session_id": task_context.get("session_id"),
            "details": _json_safe(details or {}),
            "timestamp": _utc_now().isoformat(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                self.logger.info("Audit event: %s", event)
        except Exception:
            self.logger.exception("Failed to log creator audit event.")

    # ------------------------------------------------------------------
    # Master Agent compatible router
    # ------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router entrypoint.

        Supported actions:
            - build_prompt
            - build_json_prompt
            - build_scene_specs
            - build_character_continuity
            - build_ad_prompt
            - build_multi_scene_prompt
            - validate_prompt_package
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="Creator task must be a mapping.",
                error="INVALID_TASK",
            )

        action = _normalize_key(task.get("action", "build_prompt"))
        context = task.get("context") or {
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "role": task.get("role"),
            "request_id": task.get("request_id"),
            "session_id": task.get("session_id"),
            "permissions": task.get("permissions") or (),
        }

        if action in {"build_prompt", "generate_prompt", "veo_prompt"}:
            return self.build_prompt(
                brief=task.get("brief") or task.get("description") or "",
                task_context=context,
                platform=task.get("platform", "general"),
                prompt_format=task.get("prompt_format", PromptFormat.BOTH.value),
                brand_style=task.get("brand_style"),
                characters=task.get("characters"),
                scenes=task.get("scenes"),
                duration_seconds=task.get("duration_seconds", DEFAULT_DURATION_SECONDS),
                aspect_ratio=task.get("aspect_ratio"),
                resolution=task.get("resolution"),
                language=task.get("language"),
                quality=task.get("quality", VeoPromptQuality.CINEMATIC.value),
                safety_flags=task.get("safety_flags"),
                negative_prompt=task.get("negative_prompt"),
                store_to_memory=bool(task.get("store_to_memory", False)),
            )

        if action in {"build_json_prompt", "json_prompt"}:
            return self.build_json_prompt(
                brief=task.get("brief") or task.get("description") or "",
                task_context=context,
                platform=task.get("platform", "general"),
                brand_style=task.get("brand_style"),
                characters=task.get("characters"),
                scenes=task.get("scenes"),
                duration_seconds=task.get("duration_seconds", DEFAULT_DURATION_SECONDS),
                aspect_ratio=task.get("aspect_ratio"),
                resolution=task.get("resolution"),
                language=task.get("language"),
                quality=task.get("quality", VeoPromptQuality.CINEMATIC.value),
                safety_flags=task.get("safety_flags"),
                negative_prompt=task.get("negative_prompt"),
            )

        if action in {"build_scene_specs", "scene_specs", "scenes"}:
            return self.build_scene_specs(
                brief=task.get("brief") or task.get("description") or "",
                task_context=context,
                scenes=task.get("scenes"),
                characters=task.get("characters"),
                duration_seconds=task.get("duration_seconds", DEFAULT_DURATION_SECONDS),
                platform=task.get("platform", "general"),
                quality=task.get("quality", VeoPromptQuality.CINEMATIC.value),
            )

        if action in {"build_character_continuity", "character_continuity", "continuity"}:
            return self.build_character_continuity(
                task_context=context,
                characters=task.get("characters") or [],
                continuity_strength=task.get("continuity_strength", ContinuityStrength.STRICT.value),
            )

        if action in {"build_ad_prompt", "ad_prompt", "veo_ad"}:
            return self.build_ad_prompt(
                product_or_service=task.get("product_or_service") or task.get("offer") or "",
                task_context=context,
                target_audience=task.get("target_audience", ""),
                offer=task.get("offer", ""),
                cta=task.get("cta", ""),
                platform=task.get("platform", "ads"),
                brand_style=task.get("brand_style"),
                duration_seconds=task.get("duration_seconds", DEFAULT_DURATION_SECONDS),
                aspect_ratio=task.get("aspect_ratio"),
                resolution=task.get("resolution"),
                language=task.get("language"),
                safety_flags=task.get("safety_flags"),
            )

        if action in {"build_multi_scene_prompt", "multi_scene_prompt"}:
            return self.build_multi_scene_prompt(
                title=task.get("title", "VEO cinematic sequence"),
                task_context=context,
                scene_briefs=task.get("scene_briefs") or [],
                platform=task.get("platform", "general"),
                brand_style=task.get("brand_style"),
                characters=task.get("characters"),
                aspect_ratio=task.get("aspect_ratio"),
                resolution=task.get("resolution"),
                language=task.get("language"),
                quality=task.get("quality", VeoPromptQuality.PRODUCTION.value),
                safety_flags=task.get("safety_flags"),
            )

        if action in {"validate_prompt_package", "validate"}:
            return self.validate_prompt_package(
                task_context=context,
                prompt_package=task.get("prompt_package") or task.get("package") or {},
            )

        return self._error_result(
            message=f"Unsupported VEO prompt builder action: {action}",
            error="UNSUPPORTED_CREATOR_ACTION",
            metadata={"agent": self.agent_name, "action": action},
        )

    # ------------------------------------------------------------------
    # Public prompt builder methods
    # ------------------------------------------------------------------

    def build_prompt(
        self,
        *,
        brief: str,
        task_context: Mapping[str, Any],
        platform: str = "general",
        prompt_format: str = PromptFormat.BOTH.value,
        brand_style: Optional[Union[Mapping[str, Any], BrandStyleProfile]] = None,
        characters: Optional[Sequence[Union[Mapping[str, Any], CharacterProfile]]] = None,
        scenes: Optional[Sequence[Union[Mapping[str, Any], SceneSpec]]] = None,
        duration_seconds: Any = DEFAULT_DURATION_SECONDS,
        aspect_ratio: Optional[str] = None,
        resolution: Optional[str] = None,
        language: Optional[str] = None,
        quality: str = VeoPromptQuality.CINEMATIC.value,
        safety_flags: Optional[Sequence[str]] = None,
        negative_prompt: Optional[str] = None,
        store_to_memory: bool = False,
    ) -> Dict[str, Any]:
        """
        Build a complete VEO prompt package.

        Returns:
            structured dict containing text prompt, JSON prompt, scene specs,
            character continuity, memory payload, and verification payload.
        """

        action = "build_prompt"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: CreatorTaskContext = context_result["data"]
            safety_result = self._validate_prompt_safety(
                brief=brief,
                safety_flags=safety_flags,
                payload={
                    "characters": characters or [],
                    "brand_style": brand_style or {},
                    "store_to_memory": store_to_memory,
                },
            )
            if not safety_result["success"]:
                return safety_result

            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                payload={
                    "safety_flags": safety_result.get("data", {}).get("safety_flags", []),
                    "character_continuity": characters or [],
                    "store_to_memory": store_to_memory,
                },
            )
            if not approval["success"]:
                return approval

            normalized_platform = self._normalize_platform(platform)
            normalized_format = self._normalize_prompt_format(prompt_format)
            normalized_brand = self._normalize_brand_style(brand_style)
            normalized_characters = self._normalize_characters(characters or [])
            normalized_scenes = self._normalize_or_generate_scenes(
                brief=brief,
                scenes=scenes,
                characters=normalized_characters,
                duration_seconds=duration_seconds,
                platform=normalized_platform,
                quality=quality,
            )

            final_aspect_ratio = self._resolve_aspect_ratio(aspect_ratio, normalized_platform)
            final_resolution = self._resolve_resolution(resolution)
            final_language = language or self.default_language
            final_negative_prompt = self._build_negative_prompt(negative_prompt, normalized_brand)
            recommendations = self._build_recommendations(
                platform=normalized_platform,
                aspect_ratio=final_aspect_ratio,
                scenes=normalized_scenes,
                quality=quality,
            )

            prompt_package = self._assemble_prompt_package(
                title=self._make_title_from_brief(brief),
                brief=brief,
                prompt_format=normalized_format,
                platform=normalized_platform,
                brand_style=normalized_brand,
                characters=normalized_characters,
                scenes=normalized_scenes,
                aspect_ratio=final_aspect_ratio,
                resolution=final_resolution,
                language=final_language,
                quality=quality,
                safety_flags=safety_result.get("data", {}).get("safety_flags", []),
                negative_prompt=final_negative_prompt,
                recommendations=recommendations,
            )

            result = self._safe_result(
                message="VEO cinematic prompt package built successfully.",
                data={
                    "prompt_package": prompt_package.to_dict(),
                    "copy_paste_prompt": prompt_package.text_prompt,
                    "json_prompt_string": json.dumps(
                        prompt_package.json_prompt,
                        ensure_ascii=False,
                        indent=2,
                    ),
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "prompt_id": prompt_package.prompt_id,
                    "generated_at": _utc_now().isoformat(),
                    "security": approval.get("data"),
                },
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                task_context=task_context,
                result=result,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                task_context=task_context,
                result=result,
            )

            self._emit_agent_event(
                event_name="creator.veo.prompt_built",
                task_context=task_context,
                payload={
                    "prompt_id": prompt_package.prompt_id,
                    "platform": normalized_platform,
                    "scene_count": len(normalized_scenes),
                },
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={
                    "prompt_id": prompt_package.prompt_id,
                    "platform": normalized_platform,
                    "scene_count": len(normalized_scenes),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to build VEO prompt.")
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=False,
                details={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to build VEO cinematic prompt package.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def build_json_prompt(
        self,
        *,
        brief: str,
        task_context: Mapping[str, Any],
        platform: str = "general",
        brand_style: Optional[Union[Mapping[str, Any], BrandStyleProfile]] = None,
        characters: Optional[Sequence[Union[Mapping[str, Any], CharacterProfile]]] = None,
        scenes: Optional[Sequence[Union[Mapping[str, Any], SceneSpec]]] = None,
        duration_seconds: Any = DEFAULT_DURATION_SECONDS,
        aspect_ratio: Optional[str] = None,
        resolution: Optional[str] = None,
        language: Optional[str] = None,
        quality: str = VeoPromptQuality.CINEMATIC.value,
        safety_flags: Optional[Sequence[str]] = None,
        negative_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build only JSON-style VEO prompt output."""

        return self.build_prompt(
            brief=brief,
            task_context=task_context,
            platform=platform,
            prompt_format=PromptFormat.JSON.value,
            brand_style=brand_style,
            characters=characters,
            scenes=scenes,
            duration_seconds=duration_seconds,
            aspect_ratio=aspect_ratio,
            resolution=resolution,
            language=language,
            quality=quality,
            safety_flags=safety_flags,
            negative_prompt=negative_prompt,
            store_to_memory=False,
        )

    def build_scene_specs(
        self,
        *,
        brief: str,
        task_context: Mapping[str, Any],
        scenes: Optional[Sequence[Union[Mapping[str, Any], SceneSpec]]] = None,
        characters: Optional[Sequence[Union[Mapping[str, Any], CharacterProfile]]] = None,
        duration_seconds: Any = DEFAULT_DURATION_SECONDS,
        platform: str = "general",
        quality: str = VeoPromptQuality.CINEMATIC.value,
    ) -> Dict[str, Any]:
        """Build normalized VEO scene specifications."""

        action = "build_scene_specs"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: CreatorTaskContext = context_result["data"]
            normalized_platform = self._normalize_platform(platform)
            normalized_characters = self._normalize_characters(characters or [])
            normalized_scenes = self._normalize_or_generate_scenes(
                brief=brief,
                scenes=scenes,
                characters=normalized_characters,
                duration_seconds=duration_seconds,
                platform=normalized_platform,
                quality=quality,
            )

            result = self._safe_result(
                message="VEO scene specifications built successfully.",
                data={
                    "scenes": [scene.to_dict() for scene in normalized_scenes],
                    "scene_count": len(normalized_scenes),
                    "total_duration_seconds": sum(scene.duration_seconds for scene in normalized_scenes),
                    "platform": normalized_platform,
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._emit_agent_event(
                event_name="creator.veo.scene_specs_built",
                task_context=task_context,
                payload={"scene_count": len(normalized_scenes), "platform": normalized_platform},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"scene_count": len(normalized_scenes)},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to build scene specs.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to build VEO scene specifications.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def build_character_continuity(
        self,
        *,
        task_context: Mapping[str, Any],
        characters: Sequence[Union[Mapping[str, Any], CharacterProfile]],
        continuity_strength: str = ContinuityStrength.STRICT.value,
    ) -> Dict[str, Any]:
        """
        Build character continuity profiles and continuity prompt block.

        This helps keep the same character consistent across VEO scenes.
        """

        action = "build_character_continuity"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        approval = self._request_security_approval(
            action=action,
            task_context=task_context,
            payload={
                "character_continuity": characters,
                "store_to_memory": True,
            },
        )
        if not approval["success"]:
            return approval

        try:
            context: CreatorTaskContext = context_result["data"]
            strength = self._normalize_continuity_strength(continuity_strength)
            normalized_characters = self._normalize_characters(characters)

            continuity_block = self._build_character_continuity_block(
                normalized_characters,
                strength,
            )

            result = self._safe_result(
                message="Character continuity profile built successfully.",
                data={
                    "characters": [character.to_dict() for character in normalized_characters],
                    "continuity_strength": strength,
                    "continuity_prompt_block": continuity_block,
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                    "security": approval.get("data"),
                },
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                task_context=task_context,
                result=result,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                task_context=task_context,
                result=result,
                memory_type="creator_character_continuity",
            )

            self._emit_agent_event(
                event_name="creator.veo.character_continuity_built",
                task_context=task_context,
                payload={"character_count": len(normalized_characters), "strength": strength},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"character_count": len(normalized_characters), "strength": strength},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to build character continuity.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to build character continuity profile.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def build_ad_prompt(
        self,
        *,
        product_or_service: str,
        task_context: Mapping[str, Any],
        target_audience: str = "",
        offer: str = "",
        cta: str = "",
        platform: str = "ads",
        brand_style: Optional[Union[Mapping[str, Any], BrandStyleProfile]] = None,
        duration_seconds: Any = DEFAULT_DURATION_SECONDS,
        aspect_ratio: Optional[str] = None,
        resolution: Optional[str] = None,
        language: Optional[str] = None,
        safety_flags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Build a conversion-focused VEO ad prompt.

        The method creates a hook/problem/solution/CTA structure suitable for
        short video ads while staying ready for dashboard/API integration.
        """

        brief_parts = [
            f"Create a cinematic ad for {product_or_service}",
            f"Target audience: {target_audience}" if target_audience else "",
            f"Offer: {offer}" if offer else "",
            f"Call to action: {cta}" if cta else "",
        ]
        brief = ". ".join(part for part in brief_parts if part).strip()

        total_duration = _safe_int(duration_seconds, DEFAULT_DURATION_SECONDS, minimum=4, maximum=60)
        scene_count = 3 if total_duration <= 12 else 4
        per_scene = max(2, total_duration // scene_count)

        scenes = [
            {
                "scene_type": SceneType.HOOK.value,
                "duration_seconds": per_scene,
                "description": f"Attention-grabbing cinematic opening for {product_or_service}.",
                "action": "Show the audience problem in a visually clear, emotionally relatable way.",
                "camera": "slow push-in",
                "shot_size": ShotSize.MEDIUM_CLOSE.value,
                "mood": "urgent",
                "on_screen_text": self._short_text(offer or product_or_service, 52),
            },
            {
                "scene_type": SceneType.SOLUTION.value,
                "duration_seconds": per_scene,
                "description": f"Reveal {product_or_service} as the clean, premium solution.",
                "action": "Show the solution working clearly with confident visual proof.",
                "camera": "tracking shot",
                "shot_size": ShotSize.MEDIUM.value,
                "mood": "trustworthy",
                "voiceover": f"{product_or_service} helps you move faster with less stress.",
            },
            {
                "scene_type": SceneType.CTA.value,
                "duration_seconds": max(2, total_duration - (per_scene * 2)),
                "description": "Strong final brand moment with clear call to action.",
                "action": "End with a clean branded frame and direct next step.",
                "camera": "static",
                "shot_size": ShotSize.CLOSE_UP.value,
                "mood": "premium",
                "on_screen_text": self._short_text(cta or "Get started today", 48),
                "voiceover": cta or "Get started today.",
            },
        ]

        if scene_count == 4:
            scenes.insert(
                2,
                {
                    "scene_type": SceneType.DEMO.value,
                    "duration_seconds": per_scene,
                    "description": "Show a quick proof/demo moment with realistic detail.",
                    "action": "Show the product or service outcome in action.",
                    "camera": "macro close-up",
                    "shot_size": ShotSize.CLOSE_UP.value,
                    "mood": "inspiring",
                },
            )

        return self.build_prompt(
            brief=brief,
            task_context=task_context,
            platform=platform,
            prompt_format=PromptFormat.BOTH.value,
            brand_style=brand_style,
            characters=[],
            scenes=scenes,
            duration_seconds=total_duration,
            aspect_ratio=aspect_ratio,
            resolution=resolution,
            language=language,
            quality=VeoPromptQuality.PRODUCTION.value,
            safety_flags=safety_flags,
            negative_prompt=None,
            store_to_memory=False,
        )

    def build_multi_scene_prompt(
        self,
        *,
        title: str,
        task_context: Mapping[str, Any],
        scene_briefs: Sequence[Union[str, Mapping[str, Any]]],
        platform: str = "general",
        brand_style: Optional[Union[Mapping[str, Any], BrandStyleProfile]] = None,
        characters: Optional[Sequence[Union[Mapping[str, Any], CharacterProfile]]] = None,
        aspect_ratio: Optional[str] = None,
        resolution: Optional[str] = None,
        language: Optional[str] = None,
        quality: str = VeoPromptQuality.PRODUCTION.value,
        safety_flags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Build a complete prompt package from multiple scene briefs."""

        normalized_scenes: List[Dict[str, Any]] = []
        for index, scene_brief in enumerate(scene_briefs):
            if isinstance(scene_brief, Mapping):
                scene_data = dict(scene_brief)
                scene_data.setdefault("scene_id", f"scene_{index + 1:02d}")
                normalized_scenes.append(scene_data)
            else:
                normalized_scenes.append(
                    {
                        "scene_id": f"scene_{index + 1:02d}",
                        "description": _safe_str(scene_brief),
                        "duration_seconds": DEFAULT_DURATION_SECONDS,
                        "scene_type": SceneType.DEMO.value,
                    }
                )

        full_brief = f"{title}. " + " ".join(
            _safe_str(scene.get("description")) for scene in normalized_scenes
        )

        result = self.build_prompt(
            brief=full_brief,
            task_context=task_context,
            platform=platform,
            prompt_format=PromptFormat.BOTH.value,
            brand_style=brand_style,
            characters=characters,
            scenes=normalized_scenes,
            duration_seconds=sum(
                _safe_int(scene.get("duration_seconds"), DEFAULT_DURATION_SECONDS, minimum=1, maximum=60)
                for scene in normalized_scenes
            ),
            aspect_ratio=aspect_ratio,
            resolution=resolution,
            language=language,
            quality=quality,
            safety_flags=safety_flags,
            negative_prompt=None,
            store_to_memory=False,
        )

        if result["success"] and isinstance(result.get("data"), Mapping):
            result["data"]["prompt_package"]["title"] = title

        return result

    def validate_prompt_package(
        self,
        *,
        task_context: Mapping[str, Any],
        prompt_package: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate a generated prompt package.

        Useful for Verification Agent, FastAPI, dashboard QA, and tests.
        """

        action = "validate_prompt_package"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: CreatorTaskContext = context_result["data"]
            issues: List[str] = []
            warnings: List[str] = []

            if not isinstance(prompt_package, Mapping):
                return self._error_result(
                    message="Prompt package must be a mapping.",
                    error="PROMPT_PACKAGE_MUST_BE_MAPPING",
                    metadata=context.to_dict(),
                )

            if not _safe_str(prompt_package.get("text_prompt")):
                issues.append("Missing text_prompt.")

            if not isinstance(prompt_package.get("json_prompt"), Mapping):
                issues.append("Missing or invalid json_prompt.")

            scenes = prompt_package.get("scenes")
            if not isinstance(scenes, Sequence) or isinstance(scenes, (str, bytes)) or not scenes:
                issues.append("Missing scenes.")
            else:
                for index, scene in enumerate(scenes):
                    if not isinstance(scene, Mapping):
                        issues.append(f"Scene {index + 1} is not a mapping.")
                        continue
                    if not _safe_str(scene.get("description")):
                        warnings.append(f"Scene {index + 1} has no description.")
                    if _safe_int(scene.get("duration_seconds"), 0) <= 0:
                        warnings.append(f"Scene {index + 1} has invalid duration_seconds.")

            aspect_ratio = _safe_str(prompt_package.get("aspect_ratio"))
            if aspect_ratio and aspect_ratio not in SUPPORTED_ASPECT_RATIOS:
                warnings.append(f"Unsupported aspect ratio: {aspect_ratio}")

            resolution = _safe_str(prompt_package.get("resolution"))
            if resolution and resolution not in SUPPORTED_RESOLUTIONS:
                warnings.append(f"Unsupported resolution: {resolution}")

            text_prompt = _safe_str(prompt_package.get("text_prompt"))
            safety_result = self._validate_prompt_safety(
                brief=text_prompt,
                safety_flags=prompt_package.get("safety_flags", []),
                payload=prompt_package,
            )
            if not safety_result["success"]:
                issues.append("Safety validation failed.")

            valid = not issues

            result = self._safe_result(
                success=valid,
                message="Prompt package validation completed." if valid else "Prompt package has validation issues.",
                data={
                    "valid": valid,
                    "issues": issues,
                    "warnings": warnings,
                    "safety": safety_result.get("data"),
                },
                error=None if valid else "PROMPT_PACKAGE_VALIDATION_FAILED",
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=valid,
                details={"issues": issues, "warnings": warnings},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to validate prompt package.")
            return self._error_result(
                message="Failed to validate prompt package.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_platform(self, platform: Any) -> str:
        """Normalize platform."""

        key = _normalize_key(platform, "general")
        return key if key in SUPPORTED_PLATFORMS else "general"

    def _normalize_prompt_format(self, prompt_format: Any) -> str:
        """Normalize prompt format."""

        key = _normalize_key(prompt_format, PromptFormat.BOTH.value)
        return key if key in SUPPORTED_PROMPT_FORMATS else PromptFormat.BOTH.value

    def _normalize_continuity_strength(self, value: Any) -> str:
        """Normalize continuity strength."""

        key = _normalize_key(value, ContinuityStrength.STRICT.value)
        allowed = {item.value for item in ContinuityStrength}
        return key if key in allowed else ContinuityStrength.STRICT.value

    def _resolve_aspect_ratio(self, aspect_ratio: Optional[str], platform: str) -> str:
        """Resolve aspect ratio using platform defaults."""

        if aspect_ratio in SUPPORTED_ASPECT_RATIOS:
            return str(aspect_ratio)

        platform_defaults = {
            "youtube": "16:9",
            "youtube_shorts": "9:16",
            "tiktok": "9:16",
            "instagram_reels": "9:16",
            "instagram_feed": "4:5",
            "facebook": "4:5",
            "linkedin": "16:9",
            "website": "16:9",
            "ads": "9:16",
            "general": self.default_aspect_ratio,
        }
        return platform_defaults.get(platform, self.default_aspect_ratio)

    def _resolve_resolution(self, resolution: Optional[str]) -> str:
        """Resolve supported resolution."""

        if resolution in SUPPORTED_RESOLUTIONS:
            return str(resolution)
        return self.default_resolution

    def _normalize_brand_style(
        self,
        brand_style: Optional[Union[Mapping[str, Any], BrandStyleProfile]],
    ) -> BrandStyleProfile:
        """Normalize brand style input."""

        if isinstance(brand_style, BrandStyleProfile):
            return brand_style

        if not isinstance(brand_style, Mapping):
            return BrandStyleProfile()

        return BrandStyleProfile(
            brand_name=_safe_str(brand_style.get("brand_name") or brand_style.get("name")),
            tone=_safe_str(brand_style.get("tone"), "premium, clear, trustworthy"),
            colors=tuple(_safe_str(color) for color in _as_list(brand_style.get("colors")) if _safe_str(color)),
            typography=_safe_str(brand_style.get("typography")),
            visual_identity=_safe_str(brand_style.get("visual_identity") or brand_style.get("style")),
            forbidden_elements=tuple(
                _safe_str(item)
                for item in _as_list(brand_style.get("forbidden_elements"))
                if _safe_str(item)
            ),
            logo_usage=_safe_str(
                brand_style.get("logo_usage"),
                "include logo only if provided as an approved asset",
            ),
            cta_style=_safe_str(brand_style.get("cta_style"), "clear and confident"),
        )

    def _normalize_characters(
        self,
        characters: Sequence[Union[Mapping[str, Any], CharacterProfile]],
    ) -> List[CharacterProfile]:
        """Normalize character profiles."""

        normalized: List[CharacterProfile] = []

        for index, item in enumerate(characters or []):
            if isinstance(item, CharacterProfile):
                normalized.append(item)
                continue

            if not isinstance(item, Mapping):
                normalized.append(
                    CharacterProfile(
                        name=f"Character {index + 1}",
                        appearance=_safe_str(item),
                    )
                )
                continue

            normalized.append(
                CharacterProfile(
                    name=_safe_str(item.get("name"), f"Character {index + 1}"),
                    role=_safe_str(item.get("role"), "main character"),
                    age_range=_safe_str(item.get("age_range"), "") or None,
                    gender_presentation=_safe_str(item.get("gender_presentation") or item.get("gender"), "") or None,
                    appearance=_safe_str(item.get("appearance") or item.get("look")),
                    wardrobe=_safe_str(item.get("wardrobe") or item.get("clothing")),
                    personality=_safe_str(item.get("personality")),
                    voice=_safe_str(item.get("voice")),
                    mannerisms=_safe_str(item.get("mannerisms")),
                    continuity_notes=_safe_str(item.get("continuity_notes") or item.get("notes")),
                    avoid_changes=tuple(
                        _safe_str(value)
                        for value in _as_list(item.get("avoid_changes"))
                        if _safe_str(value)
                    ),
                )
            )

        return normalized

    def _normalize_or_generate_scenes(
        self,
        *,
        brief: str,
        scenes: Optional[Sequence[Union[Mapping[str, Any], SceneSpec]]],
        characters: Sequence[CharacterProfile],
        duration_seconds: Any,
        platform: str,
        quality: str,
    ) -> List[SceneSpec]:
        """Normalize provided scenes or generate a default scene structure."""

        if scenes:
            return self._normalize_scenes(scenes, characters)

        return self._generate_default_scenes(
            brief=brief,
            characters=characters,
            duration_seconds=duration_seconds,
            platform=platform,
            quality=quality,
        )

    def _normalize_scenes(
        self,
        scenes: Sequence[Union[Mapping[str, Any], SceneSpec]],
        characters: Sequence[CharacterProfile],
    ) -> List[SceneSpec]:
        """Normalize scene specs."""

        normalized: List[SceneSpec] = []

        for index, item in enumerate(scenes):
            if isinstance(item, SceneSpec):
                normalized.append(item)
                continue

            if not isinstance(item, Mapping):
                item = {"description": _safe_str(item)}

            scene_characters = self._resolve_scene_characters(
                scene_character_data=item.get("characters"),
                fallback_characters=characters,
            )

            scene_id = _safe_str(item.get("scene_id") or item.get("id"), f"scene_{index + 1:02d}")
            scene_type = _normalize_key(item.get("scene_type") or item.get("type"), SceneType.DEMO.value)

            normalized.append(
                SceneSpec(
                    scene_id=scene_id,
                    scene_type=scene_type,
                    duration_seconds=_safe_int(
                        item.get("duration_seconds") or item.get("duration"),
                        DEFAULT_DURATION_SECONDS,
                        minimum=1,
                        maximum=120,
                    ),
                    description=_safe_str(item.get("description") or item.get("prompt") or item.get("brief")),
                    location=_safe_str(item.get("location")),
                    time_of_day=_safe_str(item.get("time_of_day")),
                    characters=tuple(scene_characters),
                    action=_safe_str(item.get("action")),
                    dialogue=_safe_str(item.get("dialogue")),
                    voiceover=_safe_str(item.get("voiceover") or item.get("voice_over")),
                    camera=self._normalize_camera(item.get("camera") or item.get("camera_move")),
                    shot_size=self._normalize_shot_size(item.get("shot_size")),
                    lens=_safe_str(item.get("lens"), "35mm cinematic lens"),
                    lighting=self._normalize_lighting(item.get("lighting")),
                    mood=self._normalize_mood(item.get("mood")),
                    audio=_safe_str(item.get("audio") or item.get("sound"), "subtle cinematic ambience"),
                    visual_style=_safe_str(item.get("visual_style") or item.get("style"), self.default_style),
                    negative_prompt=_safe_str(item.get("negative_prompt")),
                    continuity_notes=_safe_str(item.get("continuity_notes")),
                    props=tuple(_safe_str(prop) for prop in _as_list(item.get("props")) if _safe_str(prop)),
                    transitions=_safe_str(item.get("transitions") or item.get("transition"), "clean cinematic cut"),
                    on_screen_text=_safe_str(item.get("on_screen_text") or item.get("text")),
                    metadata=dict(item.get("metadata") or {}),
                )
            )

        return normalized

    def _resolve_scene_characters(
        self,
        *,
        scene_character_data: Any,
        fallback_characters: Sequence[CharacterProfile],
    ) -> List[CharacterProfile]:
        """Resolve characters for a scene."""

        if scene_character_data is None:
            return list(fallback_characters)

        if isinstance(scene_character_data, Sequence) and not isinstance(scene_character_data, (str, bytes)):
            return self._normalize_characters(scene_character_data)

        return self._normalize_characters([scene_character_data])

    def _generate_default_scenes(
        self,
        *,
        brief: str,
        characters: Sequence[CharacterProfile],
        duration_seconds: Any,
        platform: str,
        quality: str,
    ) -> List[SceneSpec]:
        """Generate reasonable default scene specs from a single brief."""

        total_duration = _safe_int(duration_seconds, DEFAULT_DURATION_SECONDS, minimum=3, maximum=120)
        quality_key = _normalize_key(quality, VeoPromptQuality.CINEMATIC.value)

        if total_duration <= 8:
            scene_count = 1
        elif total_duration <= 20:
            scene_count = 3
        else:
            scene_count = 5

        if platform in {"tiktok", "youtube_shorts", "instagram_reels", "ads"} and total_duration <= 15:
            scene_count = min(scene_count, 3)

        per_scene = max(1, total_duration // scene_count)
        remainder = max(0, total_duration - (per_scene * scene_count))

        cinematic_details = self._quality_to_scene_defaults(quality_key)
        brief_clean = _safe_str(brief, "Create a cinematic video scene.")

        if scene_count == 1:
            return [
                SceneSpec(
                    scene_id="scene_01",
                    scene_type=SceneType.DEMO.value,
                    duration_seconds=total_duration,
                    description=brief_clean,
                    characters=tuple(characters),
                    action="Show the main idea clearly with cinematic movement and realistic detail.",
                    camera=cinematic_details["camera"],
                    shot_size=cinematic_details["shot_size"],
                    lens=cinematic_details["lens"],
                    lighting=cinematic_details["lighting"],
                    mood=cinematic_details["mood"],
                    audio=cinematic_details["audio"],
                    visual_style=cinematic_details["visual_style"],
                    transitions="clean cinematic cut",
                )
            ]

        scene_templates = [
            (
                SceneType.HOOK.value,
                "Open with an attention-grabbing visual that instantly communicates the main idea.",
                "slow push-in",
                ShotSize.MEDIUM_CLOSE.value,
                "premium",
            ),
            (
                SceneType.PROBLEM.value,
                "Show the problem, tension, or desire behind the story in a relatable cinematic way.",
                "tracking shot",
                ShotSize.MEDIUM.value,
                "dramatic",
            ),
            (
                SceneType.SOLUTION.value,
                "Reveal the solution or transformation with clean, confident visual proof.",
                "dolly",
                ShotSize.CLOSE_UP.value,
                "trustworthy",
            ),
            (
                SceneType.DEMO.value,
                "Show the most important action, feature, or emotional payoff with realistic detail.",
                "macro close-up",
                ShotSize.CLOSE_UP.value,
                "inspiring",
            ),
            (
                SceneType.CTA.value,
                "End with a memorable branded visual and a clear final message.",
                "static",
                ShotSize.MEDIUM_CLOSE.value,
                "premium",
            ),
        ]

        selected_templates = scene_templates[:scene_count]
        scenes: List[SceneSpec] = []

        for index, template in enumerate(selected_templates):
            scene_type, description, camera, shot_size, mood = template
            duration = per_scene + (1 if index < remainder else 0)

            scenes.append(
                SceneSpec(
                    scene_id=f"scene_{index + 1:02d}",
                    scene_type=scene_type,
                    duration_seconds=duration,
                    description=f"{description} Main brief: {brief_clean}",
                    characters=tuple(characters),
                    action=self._default_action_for_scene(scene_type),
                    camera=camera,
                    shot_size=shot_size,
                    lens=cinematic_details["lens"],
                    lighting=cinematic_details["lighting"],
                    mood=mood,
                    audio=cinematic_details["audio"],
                    visual_style=cinematic_details["visual_style"],
                    transitions="clean cinematic cut" if index < scene_count - 1 else "final brand hold",
                )
            )

        return scenes

    def _normalize_camera(self, value: Any) -> str:
        """Normalize camera movement."""

        clean = _safe_str(value, "slow push-in")
        return clean if clean in SUPPORTED_CAMERA_MOVES else clean

    def _normalize_lighting(self, value: Any) -> str:
        """Normalize lighting style."""

        clean = _safe_str(value, "soft cinematic light")
        return clean if clean in SUPPORTED_LIGHTING_STYLES else clean

    def _normalize_mood(self, value: Any) -> str:
        """Normalize mood."""

        clean = _safe_str(value, "premium")
        return clean if clean in SUPPORTED_MOODS else clean

    def _normalize_shot_size(self, value: Any) -> str:
        """Normalize shot size."""

        clean = _safe_str(value, ShotSize.MEDIUM.value)
        allowed = {item.value for item in ShotSize}
        return clean if clean in allowed else clean

    # ------------------------------------------------------------------
    # Prompt assembly
    # ------------------------------------------------------------------

    def _assemble_prompt_package(
        self,
        *,
        title: str,
        brief: str,
        prompt_format: str,
        platform: str,
        brand_style: BrandStyleProfile,
        characters: Sequence[CharacterProfile],
        scenes: Sequence[SceneSpec],
        aspect_ratio: str,
        resolution: str,
        language: str,
        quality: str,
        safety_flags: Sequence[str],
        negative_prompt: str,
        recommendations: Sequence[str],
    ) -> VeoPromptPackage:
        """Assemble final prompt package."""

        prompt_id = _make_prompt_id()
        total_duration = sum(scene.duration_seconds for scene in scenes)

        json_prompt = self._build_json_prompt_payload(
            prompt_id=prompt_id,
            title=title,
            brief=brief,
            platform=platform,
            brand_style=brand_style,
            characters=characters,
            scenes=scenes,
            aspect_ratio=aspect_ratio,
            resolution=resolution,
            language=language,
            quality=quality,
            negative_prompt=negative_prompt,
            safety_flags=safety_flags,
        )

        text_prompt = self._build_text_prompt(
            title=title,
            brief=brief,
            platform=platform,
            brand_style=brand_style,
            characters=characters,
            scenes=scenes,
            aspect_ratio=aspect_ratio,
            resolution=resolution,
            language=language,
            quality=quality,
            negative_prompt=negative_prompt,
        )

        if prompt_format == PromptFormat.TEXT.value:
            json_prompt_output = {}
        else:
            json_prompt_output = json_prompt

        if prompt_format == PromptFormat.JSON.value:
            text_prompt_output = json.dumps(json_prompt, ensure_ascii=False, indent=2)
        else:
            text_prompt_output = text_prompt

        return VeoPromptPackage(
            prompt_id=prompt_id,
            title=title,
            format=prompt_format,
            text_prompt=text_prompt_output,
            json_prompt=json_prompt_output,
            scenes=list(scenes),
            character_continuity=list(characters),
            brand_style=brand_style,
            negative_prompt=negative_prompt,
            platform=platform,
            aspect_ratio=aspect_ratio,
            resolution=resolution,
            total_duration_seconds=total_duration,
            safety_flags=tuple(safety_flags),
            recommendations=tuple(recommendations),
        )

    def _build_text_prompt(
        self,
        *,
        title: str,
        brief: str,
        platform: str,
        brand_style: BrandStyleProfile,
        characters: Sequence[CharacterProfile],
        scenes: Sequence[SceneSpec],
        aspect_ratio: str,
        resolution: str,
        language: str,
        quality: str,
        negative_prompt: str,
    ) -> str:
        """Build cinematic copy-paste VEO prompt."""

        lines: List[str] = []

        lines.append(f"VEO 3 CINEMATIC PROMPT: {title}")
        lines.append("")
        lines.append("GOAL")
        lines.append(_sentence(brief))
        lines.append("")
        lines.append("OUTPUT SETTINGS")
        lines.append(f"- Platform: {platform}")
        lines.append(f"- Aspect ratio: {aspect_ratio}")
        lines.append(f"- Resolution: {resolution}")
        lines.append(f"- Language: {language}")
        lines.append(f"- Quality style: {quality}")
        lines.append(f"- Visual style: {self.default_style}")
        lines.append("")

        brand_block = self._build_brand_block(brand_style)
        if brand_block:
            lines.append("BRAND STYLE")
            lines.append(brand_block)
            lines.append("")

        continuity_block = self._build_character_continuity_block(
            characters,
            ContinuityStrength.STRICT.value,
        )
        if continuity_block:
            lines.append("CHARACTER CONTINUITY")
            lines.append(continuity_block)
            lines.append("")

        lines.append("GLOBAL CINEMATIC DIRECTION")
        lines.append(
            "Create a polished, realistic, cinematic video with natural motion, "
            "consistent lighting, believable physics, stable composition, clean cuts, "
            "and premium production value. Keep faces, outfits, props, locations, "
            "brand elements, and scene continuity consistent throughout."
        )
        lines.append("")

        lines.append("SCENE SPECS")
        for index, scene in enumerate(scenes, start=1):
            lines.append(f"Scene {index}: {scene.scene_type.upper()} | {scene.duration_seconds}s")
            scene_lines = [
                f"Description: {_sentence(scene.description)}",
                f"Location: {scene.location or 'cinematic location matching the brief'}",
                f"Time of day: {scene.time_of_day or 'natural cinematic timing'}",
                f"Action: {_sentence(scene.action)}",
                f"Camera: {scene.camera}",
                f"Shot size: {scene.shot_size}",
                f"Lens: {scene.lens}",
                f"Lighting: {scene.lighting}",
                f"Mood: {scene.mood}",
                f"Audio: {scene.audio}",
                f"Transition: {scene.transitions}",
            ]

            if scene.dialogue:
                scene_lines.append(f"Dialogue: {scene.dialogue}")
            if scene.voiceover:
                scene_lines.append(f"Voiceover: {scene.voiceover}")
            if scene.on_screen_text:
                scene_lines.append(f"On-screen text: {scene.on_screen_text}")
            if scene.props:
                scene_lines.append(f"Props: {_join_clean(scene.props)}")
            if scene.continuity_notes:
                scene_lines.append(f"Continuity notes: {scene.continuity_notes}")

            lines.extend(f"- {line}" for line in scene_lines if _safe_str(line))
            lines.append("")

        lines.append("NEGATIVE PROMPT")
        lines.append(negative_prompt)
        lines.append("")

        lines.append("FINAL QUALITY RULES")
        lines.append(
            "Avoid flickering, distorted hands, warped faces, inconsistent clothing, "
            "extra fingers, unreadable text, random logos, unstable camera, duplicate "
            "characters, plastic skin, over-sharpening, low-resolution artifacts, "
            "jittery motion, and sudden style changes."
        )

        return "\n".join(lines).strip()

    def _build_json_prompt_payload(
        self,
        *,
        prompt_id: str,
        title: str,
        brief: str,
        platform: str,
        brand_style: BrandStyleProfile,
        characters: Sequence[CharacterProfile],
        scenes: Sequence[SceneSpec],
        aspect_ratio: str,
        resolution: str,
        language: str,
        quality: str,
        negative_prompt: str,
        safety_flags: Sequence[str],
    ) -> Dict[str, Any]:
        """Build structured JSON prompt payload."""

        return {
            "prompt_id": prompt_id,
            "type": "veo_3_cinematic_prompt",
            "title": title,
            "brief": brief,
            "settings": {
                "platform": platform,
                "aspect_ratio": aspect_ratio,
                "resolution": resolution,
                "language": language,
                "quality": quality,
                "duration_seconds": sum(scene.duration_seconds for scene in scenes),
                "external_generation_executed": False,
            },
            "brand_style": brand_style.to_dict(),
            "character_continuity": [
                character.to_dict() for character in characters
            ],
            "global_direction": {
                "visual_style": self.default_style,
                "continuity": "Maintain consistent characters, wardrobe, props, lighting, and brand identity across all scenes.",
                "motion": "Natural cinematic motion with stable camera behavior and believable physics.",
                "production_value": "Premium, polished, realistic, high-detail video generation.",
            },
            "scenes": [scene.to_dict() for scene in scenes],
            "negative_prompt": negative_prompt,
            "safety": {
                "safety_flags": list(safety_flags),
                "blocked_terms_checked": True,
                "requires_human_review": bool(set(safety_flags).intersection(SENSITIVE_PROMPT_FLAGS)),
            },
            "created_at": _utc_now().isoformat(),
        }

    def _build_brand_block(self, brand_style: BrandStyleProfile) -> str:
        """Build human-readable brand style block."""

        parts = []
        if brand_style.brand_name:
            parts.append(f"Brand name: {brand_style.brand_name}")
        if brand_style.tone:
            parts.append(f"Tone: {brand_style.tone}")
        if brand_style.colors:
            parts.append(f"Brand colors: {_join_clean(brand_style.colors)}")
        if brand_style.typography:
            parts.append(f"Typography: {brand_style.typography}")
        if brand_style.visual_identity:
            parts.append(f"Visual identity: {brand_style.visual_identity}")
        if brand_style.logo_usage:
            parts.append(f"Logo usage: {brand_style.logo_usage}")
        if brand_style.cta_style:
            parts.append(f"CTA style: {brand_style.cta_style}")
        if brand_style.forbidden_elements:
            parts.append(f"Avoid brand elements: {_join_clean(brand_style.forbidden_elements)}")

        return "\n".join(f"- {part}" for part in parts)

    def _build_character_continuity_block(
        self,
        characters: Sequence[CharacterProfile],
        strength: str,
    ) -> str:
        """Build character continuity text block."""

        if not characters:
            return ""

        strength_text = {
            ContinuityStrength.LIGHT.value: "Maintain general character style and role.",
            ContinuityStrength.MEDIUM.value: "Maintain recognizable appearance, wardrobe, role, and mannerisms.",
            ContinuityStrength.STRICT.value: "Maintain exact character identity, face structure, wardrobe, colors, voice style, mannerisms, and role across every scene.",
        }.get(strength, "Maintain exact character identity and styling across every scene.")

        lines = [strength_text]

        for character in characters:
            details = [
                f"Name: {character.name}",
                f"Role: {character.role}",
                f"Age range: {character.age_range}" if character.age_range else "",
                f"Gender presentation: {character.gender_presentation}" if character.gender_presentation else "",
                f"Appearance: {character.appearance}" if character.appearance else "",
                f"Wardrobe: {character.wardrobe}" if character.wardrobe else "",
                f"Personality: {character.personality}" if character.personality else "",
                f"Voice: {character.voice}" if character.voice else "",
                f"Mannerisms: {character.mannerisms}" if character.mannerisms else "",
                f"Continuity notes: {character.continuity_notes}" if character.continuity_notes else "",
                f"Do not change: {_join_clean(character.avoid_changes)}" if character.avoid_changes else "",
            ]
            clean_details = [detail for detail in details if detail]
            lines.append("- " + "; ".join(clean_details))

        return "\n".join(lines)

    def _build_negative_prompt(
        self,
        negative_prompt: Optional[str],
        brand_style: BrandStyleProfile,
    ) -> str:
        """Build final negative prompt."""

        defaults = [
            "low quality",
            "blurry",
            "distorted faces",
            "warped hands",
            "extra fingers",
            "missing fingers",
            "unreadable text",
            "random text",
            "wrong logo",
            "fake watermark",
            "jittery motion",
            "flicker",
            "inconsistent wardrobe",
            "inconsistent character face",
            "duplicate characters",
            "plastic skin",
            "overexposed highlights",
            "underexposed shadows",
            "low-resolution artifacts",
            "bad anatomy",
            "sudden style change",
            "unstable camera",
        ]

        if brand_style.forbidden_elements:
            defaults.extend(str(item) for item in brand_style.forbidden_elements)

        if negative_prompt:
            defaults.append(negative_prompt)

        return ", ".join(_dedupe_keep_order(defaults))

    def _build_recommendations(
        self,
        *,
        platform: str,
        aspect_ratio: str,
        scenes: Sequence[SceneSpec],
        quality: str,
    ) -> List[str]:
        """Generate helpful prompt recommendations."""

        recommendations: List[str] = []

        if platform in {"tiktok", "youtube_shorts", "instagram_reels"} and aspect_ratio != "9:16":
            recommendations.append("Use 9:16 for short-form vertical platforms.")

        if platform == "youtube" and aspect_ratio != "16:9":
            recommendations.append("Use 16:9 for standard YouTube videos.")

        if len(scenes) > 5:
            recommendations.append("For stronger VEO consistency, keep each generation under 5 scenes when possible.")

        total_duration = sum(scene.duration_seconds for scene in scenes)
        if total_duration > 30:
            recommendations.append("For long prompts, consider generating in shorter scene batches and stitching later.")

        if _normalize_key(quality) == VeoPromptQuality.FAST.value:
            recommendations.append("Use cinematic or production quality for final client-ready outputs.")

        if not recommendations:
            recommendations.append("Prompt structure is ready for VEO generation or dashboard review.")

        return recommendations

    # ------------------------------------------------------------------
    # Safety and validation
    # ------------------------------------------------------------------

    def _validate_prompt_safety(
        self,
        *,
        brief: str,
        safety_flags: Optional[Sequence[str]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate prompt safety.

        This is a local lightweight safety layer. Security Agent approval is
        still requested for sensitive prompt categories.
        """

        text = " ".join(
            [
                _safe_str(brief),
                json.dumps(_json_safe(payload or {}), ensure_ascii=False),
            ]
        ).lower()

        blocked_matches = [
            term for term in SAFETY_BLOCK_TERMS
            if term in text
        ]

        if blocked_matches:
            return self._error_result(
                message="Prompt brief contains blocked unsafe content.",
                error={
                    "code": "UNSAFE_PROMPT_BLOCKED",
                    "blocked_matches": blocked_matches,
                },
                metadata={"agent": self.agent_name},
            )

        normalized_flags = [
            _normalize_key(flag)
            for flag in _as_list(safety_flags)
            if _safe_str(flag)
        ]

        if "real_person_likeness" not in normalized_flags:
            if any(term in text for term in ["real person likeness", "celebrity likeness", "make him look like", "make her look like"]):
                normalized_flags.append("real_person_likeness")

        if "minor_present" not in normalized_flags:
            if any(term in text for term in ["child actor", "minor", "kid", "teenager"]):
                normalized_flags.append("minor_present")

        if "regulated_product" not in normalized_flags:
            if any(term in text for term in ["crypto investment", "medical treatment", "loan approval", "gambling", "alcohol ad"]):
                normalized_flags.append("regulated_product")

        normalized_flags = _dedupe_keep_order(normalized_flags)

        return self._safe_result(
            message="Prompt safety validation completed.",
            data={
                "safe": True,
                "safety_flags": normalized_flags,
                "requires_human_review": bool(set(normalized_flags).intersection(SENSITIVE_PROMPT_FLAGS)),
            },
            metadata={"agent": self.agent_name},
        )

    # ------------------------------------------------------------------
    # Small creative helpers
    # ------------------------------------------------------------------

    def _quality_to_scene_defaults(self, quality: str) -> Dict[str, str]:
        """Return scene defaults based on quality preset."""

        quality_key = _normalize_key(quality, VeoPromptQuality.CINEMATIC.value)

        if quality_key == VeoPromptQuality.FAST.value:
            return {
                "camera": "static",
                "shot_size": ShotSize.MEDIUM.value,
                "lens": "35mm lens",
                "lighting": "natural light",
                "mood": "clean",
                "audio": "simple ambient sound",
                "visual_style": "clean realistic video",
            }

        if quality_key == VeoPromptQuality.BALANCED.value:
            return {
                "camera": "slow push-in",
                "shot_size": ShotSize.MEDIUM.value,
                "lens": "35mm cinematic lens",
                "lighting": "soft cinematic light",
                "mood": "premium",
                "audio": "subtle cinematic ambience",
                "visual_style": "cinematic realism",
            }

        if quality_key == VeoPromptQuality.PRODUCTION.value:
            return {
                "camera": "tracking shot",
                "shot_size": ShotSize.MEDIUM_CLOSE.value,
                "lens": "anamorphic 35mm cinematic lens",
                "lighting": "soft cinematic light with realistic shadows",
                "mood": "luxury",
                "audio": "premium cinematic sound design with clean ambience",
                "visual_style": "high-end commercial cinematic realism",
            }

        return {
            "camera": "slow push-in",
            "shot_size": ShotSize.MEDIUM_CLOSE.value,
            "lens": "35mm cinematic lens",
            "lighting": "soft cinematic light",
            "mood": "premium",
            "audio": "subtle cinematic ambience",
            "visual_style": "cinematic realism",
        }

    def _default_action_for_scene(self, scene_type: str) -> str:
        """Return default action by scene type."""

        scene_type = _normalize_key(scene_type, SceneType.DEMO.value)

        actions = {
            SceneType.HOOK.value: "Create immediate visual interest with a clear emotional or practical reason to keep watching.",
            SceneType.PROBLEM.value: "Show the pain point or tension in a realistic, relatable way.",
            SceneType.SOLUTION.value: "Reveal the solution with confidence, clarity, and premium visual detail.",
            SceneType.DEMO.value: "Show the main feature, transformation, or proof moment in action.",
            SceneType.CTA.value: "Finish with a clean brand moment and a simple next step.",
            SceneType.BRAND.value: "Show a polished brand identity moment with strong visual consistency.",
            SceneType.PRODUCT.value: "Show the product with realistic texture, lighting, scale, and use context.",
            SceneType.TESTIMONIAL.value: "Show a believable person sharing a concise, natural reaction.",
            SceneType.LIFESTYLE.value: "Show the result in a natural lifestyle environment.",
            SceneType.TRANSFORMATION.value: "Show a clear before-to-after improvement.",
        }

        return actions.get(scene_type, "Show the scene action clearly with cinematic realism.")

    def _make_title_from_brief(self, brief: str) -> str:
        """Create title from brief."""

        clean = _safe_str(brief, "VEO cinematic prompt")
        clean = re.sub(r"\s+", " ", clean)
        clean = clean.strip(". ")
        if len(clean) <= 72:
            return clean
        return clean[:69].rstrip() + "..."

    def _short_text(self, text: str, limit: int = 52) -> str:
        """Shorten on-screen text."""

        return _truncate(_safe_str(text), limit)

    def _summarize_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Summarize payload safely for Security Agent."""

        summary: Dict[str, Any] = {}
        for key, value in payload.items():
            if key in {"assets", "raw_assets", "files", "raw_file_metadata"}:
                if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                    summary[key] = {"type": "sequence", "count": len(value)}
                else:
                    summary[key] = {"type": type(value).__name__}
            elif key in {"characters", "character_continuity"}:
                summary[key] = {
                    "type": "character_profiles",
                    "count": len(_as_list(value)),
                }
            elif isinstance(value, (str, int, float, bool)) or value is None:
                summary[key] = value
            else:
                summary[key] = {"type": type(value).__name__}
        return summary

    # ------------------------------------------------------------------
    # Metadata and dashboard helpers
    # ------------------------------------------------------------------

    def get_supported_options(self) -> Dict[str, Any]:
        """Return supported VEO prompt builder options."""

        return self._safe_result(
            message="Supported VEO prompt builder options loaded.",
            data={
                "prompt_formats": sorted(SUPPORTED_PROMPT_FORMATS),
                "aspect_ratios": sorted(SUPPORTED_ASPECT_RATIOS),
                "resolutions": sorted(SUPPORTED_RESOLUTIONS),
                "platforms": sorted(SUPPORTED_PLATFORMS),
                "camera_moves": sorted(SUPPORTED_CAMERA_MOVES),
                "lighting_styles": sorted(SUPPORTED_LIGHTING_STYLES),
                "moods": sorted(SUPPORTED_MOODS),
                "scene_types": [item.value for item in SceneType],
                "shot_sizes": [item.value for item in ShotSize],
                "quality_presets": [item.value for item in VeoPromptQuality],
                "continuity_strengths": [item.value for item in ContinuityStrength],
            },
            metadata={
                "agent": self.agent_name,
                "version": self.version,
            },
        )


# ---------------------------------------------------------------------------
# Registry / loader helpers
# ---------------------------------------------------------------------------

def create_veo_prompt_builder(**kwargs: Any) -> VeoPromptBuilder:
    """
    Factory for Agent Loader / Agent Registry compatibility.

    Example:
        builder = create_veo_prompt_builder(default_resolution="1080p")
    """

    return VeoPromptBuilder(**kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Return registry-friendly metadata for this helper module.
    """

    return {
        "agent_name": VeoPromptBuilder.agent_name,
        "agent_type": VeoPromptBuilder.agent_type,
        "class_name": "VeoPromptBuilder",
        "version": VeoPromptBuilder.version,
        "module": "agents.super_agents.creator_agent.veo_prompt_builder",
        "file_path": "agents/super_agents/creator_agent/veo_prompt_builder.py",
        "capabilities": [
            "build_prompt",
            "build_json_prompt",
            "build_scene_specs",
            "build_character_continuity",
            "build_ad_prompt",
            "build_multi_scene_prompt",
            "validate_prompt_package",
            "prepare_verification_payload",
            "prepare_memory_payload",
        ],
        "requires_user_context": True,
        "requires_workspace_context": True,
        "side_effects": "prompt_generation_only",
        "external_generation_executed": False,
        "safe_to_import": True,
    }


__all__ = [
    "VeoPromptBuilder",
    "CreatorTaskContext",
    "CharacterProfile",
    "BrandStyleProfile",
    "SceneSpec",
    "VeoPromptPackage",
    "PromptFormat",
    "SceneType",
    "ShotSize",
    "ContinuityStrength",
    "VeoPromptQuality",
    "create_veo_prompt_builder",
    "get_agent_metadata",
]


# ---------------------------------------------------------------------------
# Local smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    builder = VeoPromptBuilder()

    sample_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "role": "owner",
        "request_id": "local_test",
    }

    sample_result = builder.build_ad_prompt(
        product_or_service="AI automation services for agencies",
        target_audience="mature business owners who want more leads and faster operations",
        offer="free strategy call",
        cta="Book your free AI automation strategy call today",
        task_context=sample_context,
        brand_style={
            "brand_name": "Digital Promotix",
            "tone": "premium, confident, trustworthy",
            "colors": ["#6400B3", "#101010", "#FFFFFF"],
            "visual_identity": "modern SaaS agency, clean purple-black-white look",
        },
        platform="instagram_reels",
        duration_seconds=12,
    )

    print(json.dumps(sample_result, ensure_ascii=False, indent=2))