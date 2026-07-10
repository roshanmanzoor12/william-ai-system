"""
agents/voice_agent/voice_profiles.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix

Purpose:
    Stores user voice preferences, language style, speed, volume, and voice persona.

This module belongs to the Voice Agent layer and is designed to connect with:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader
    - Agent Router
    - TTS Engine
    - STT Engine
    - Language Engine
    - Whisper Mode
    - Emotion Detector
    - Memory Agent
    - Security Agent
    - Verification Agent
    - Dashboard/API integration

Core responsibilities:
    - Create default voice profile per user/workspace.
    - Store and update user voice preferences safely.
    - Store language, style, speaking speed, volume, pitch, persona, and tone.
    - Support multiple named profiles per user/workspace.
    - Never mix voice profile data between SaaS users/workspaces.
    - Prepare runtime voice settings for TTS/STT/Voice Agent.
    - Provide structured dict/JSON results.
    - Remain import-safe even if future William modules do not exist yet.

Security model:
    - Normal preference updates are allowed.
    - Sensitive profile changes can request Security Agent approval.
    - Cross-user/workspace access is blocked by storage isolation.
    - No secrets are hardcoded.
    - No real system/call/browser/financial actions are executed here.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union


# ---------------------------------------------------------------------------
# Import-safe BaseAgent fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe while the full William/Jarvis
        architecture is still being created.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("WilliamVoiceProfiles")
if not LOGGER.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_STORAGE_DIR = os.getenv(
    "WILLIAM_VOICE_PROFILE_DIR",
    str(Path.home() / ".william" / "voice_agent" / "voice_profiles"),
)

DEFAULT_PROFILE_ID = "default"

SUPPORTED_LANGUAGE_CODES = {
    "auto",
    "en",
    "en-US",
    "en-GB",
    "en-AU",
    "en-CA",
    "ur",
    "hi",
    "ar",
    "fr",
    "de",
    "es",
    "it",
    "pt",
    "tr",
    "zh",
    "ja",
    "ko",
}

SUPPORTED_PERSONAS = {
    "jarvis",
    "william",
    "professional",
    "friendly",
    "calm",
    "coach",
    "assistant",
    "executive",
    "creative",
    "technical",
    "security",
    "minimal",
    "custom",
}

SUPPORTED_STYLE_PRESETS = {
    "balanced",
    "concise",
    "detailed",
    "warm",
    "formal",
    "casual",
    "executive",
    "technical",
    "sales",
    "storytelling",
    "calm",
    "energetic",
    "custom",
}

SUPPORTED_EMOTIONAL_TONES = {
    "neutral",
    "warm",
    "calm",
    "confident",
    "empathetic",
    "energetic",
    "serious",
    "friendly",
    "professional",
    "custom",
}

SUPPORTED_TTS_PROVIDERS = {
    "auto",
    "system",
    "openai",
    "elevenlabs",
    "azure",
    "google",
    "aws",
    "local",
    "custom",
}

SUPPORTED_STT_PROVIDERS = {
    "auto",
    "whisper",
    "openai",
    "google",
    "azure",
    "local",
    "custom",
}

SENSITIVE_PROFILE_FIELDS = {
    "allow_sensitive_voice_commands",
    "voice_unlock_enabled",
    "trusted_speaker_required",
    "owner_voice_required",
    "security_confirmation_mode",
    "profile_visibility",
    "memory_sync_enabled",
    "voice_biometric_profile_id",
}

SENSITIVE_TASK_TYPES = {
    "voice_profile_security_change",
    "voice_unlock_change",
    "trusted_speaker_change",
    "owner_voice_change",
    "memory_sync_change",
    "profile_delete",
    "profile_export",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def safe_string(value: Any, max_length: int = 255) -> str:
    """Convert input to safe trimmed string."""
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


def sanitize_path_part(value: Any, fallback: str = "unknown") -> str:
    """Sanitize user/workspace/profile IDs for filesystem paths."""
    text = safe_string(value, 120)
    if not text:
        text = fallback

    safe_chars = []
    for char in text:
        if char.isalnum() or char in ("-", "_", "."):
            safe_chars.append(char)
        else:
            safe_chars.append("_")

    cleaned = "".join(safe_chars).strip("._")
    return cleaned or fallback


def clamp_float(value: Any, minimum: float, maximum: float, default: float) -> float:
    """Safely clamp a numeric value."""
    try:
        number = float(value)
    except Exception:
        return default

    if number < minimum:
        return minimum
    if number > maximum:
        return maximum
    return number


def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    """Safely clamp an integer value."""
    try:
        number = int(value)
    except Exception:
        return default

    if number < minimum:
        return minimum
    if number > maximum:
        return maximum
    return number


def normalize_bool(value: Any, default: bool = False) -> bool:
    """Safely normalize bool-like input."""
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on", "enabled"}:
            return True
        if lowered in {"false", "0", "no", "n", "off", "disabled"}:
            return False

    return bool(value)


def normalize_choice(value: Any, allowed: set, default: str) -> str:
    """Normalize an enum-like string choice."""
    text = safe_string(value, 80)
    if text in allowed:
        return text
    return default


def deep_merge(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge dictionaries.

    Used for metadata/runtime options without replacing entire nested objects.
    """
    merged = dict(base)

    for key, value in updates.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class VoiceProfilesConfig:
    """
    Runtime config for VoiceProfiles.
    """

    storage_dir: str = DEFAULT_STORAGE_DIR
    profile_file_version: str = "1.0"
    max_profiles_per_workspace: int = 25
    audit_enabled: bool = True
    events_enabled: bool = True
    memory_payload_enabled: bool = True
    require_security_for_sensitive_fields: bool = True
    default_language_code: str = "auto"
    default_persona: str = "jarvis"
    default_style_preset: str = "balanced"
    default_tts_provider: str = "auto"
    default_stt_provider: str = "auto"


@dataclass
class VoicePersonaSettings:
    """
    Voice persona controls how William/Jarvis sounds and responds.
    """

    persona_name: str = "jarvis"
    custom_persona_prompt: str = ""
    style_preset: str = "balanced"
    emotional_tone: str = "neutral"
    formality_level: float = 0.65
    warmth_level: float = 0.65
    directness_level: float = 0.75
    humor_level: float = 0.15
    empathy_level: float = 0.60
    technical_depth: float = 0.60


@dataclass
class VoiceAudioSettings:
    """
    Audio playback and TTS settings.
    """

    voice_id: str = "default"
    tts_provider: str = "auto"
    stt_provider: str = "auto"
    speed: float = 1.00
    volume: float = 0.85
    pitch: float = 1.00
    stability: float = 0.70
    clarity: float = 0.80
    latency_mode: str = "balanced"
    streaming_enabled: bool = True
    interruption_enabled: bool = True
    whisper_mode_preferred: bool = False
    noise_suppression_enabled: bool = True
    auto_gain_enabled: bool = True


@dataclass
class VoiceLanguageSettings:
    """
    Language preferences for Voice Agent, STT Engine, and Language Engine.
    """

    language_code: str = "auto"
    fallback_language_code: str = "en-US"
    auto_detect_language: bool = True
    allow_multilingual_response: bool = True
    translate_to_preferred_language: bool = False
    roman_urdu_enabled: bool = True
    response_script: str = "auto"
    pronunciation_notes: Dict[str, str] = field(default_factory=dict)


@dataclass
class VoiceSecuritySettings:
    """
    Security-related profile preferences.

    These settings do not directly authorize actions.
    They prepare the policy that Security Agent and SpeakerRecognition can use.
    """

    trusted_speaker_required: bool = True
    owner_voice_required: bool = False
    allow_sensitive_voice_commands: bool = False
    voice_unlock_enabled: bool = False
    security_confirmation_mode: str = "ask_before_sensitive_action"
    profile_visibility: str = "private"
    memory_sync_enabled: bool = True
    voice_biometric_profile_id: str = ""


@dataclass
class VoiceProfile:
    """
    Complete user voice profile.

    Isolated by user_id + workspace_id + profile_id.
    """

    profile_id: str
    user_id: str
    workspace_id: str
    profile_name: str = "Default Voice Profile"
    active: bool = True
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    persona: VoicePersonaSettings = field(default_factory=VoicePersonaSettings)
    audio: VoiceAudioSettings = field(default_factory=VoiceAudioSettings)
    language: VoiceLanguageSettings = field(default_factory=VoiceLanguageSettings)
    security: VoiceSecuritySettings = field(default_factory=VoiceSecuritySettings)

    dashboard_tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    disabled: bool = False


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class VoiceProfiles(BaseAgent):
    """
    Stores and manages voice preferences for William/Jarvis Voice Agent.

    This file is intentionally independent from real TTS/STT execution.
    It prepares clean profile settings that other voice modules can consume.
    """

    def __init__(
        self,
        config: Optional[VoiceProfilesConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", "VoiceProfiles"),
            agent_id=kwargs.pop("agent_id", "voice_agent.voice_profiles"),
            *args,
            **kwargs,
        )

        self.config = config or VoiceProfilesConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.storage_dir = Path(self.config.storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self.logger = logging.getLogger("WilliamVoiceProfiles")

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def create_default_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str = DEFAULT_PROFILE_ID,
        profile_name: str = "Default Voice Profile",
        set_active: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a default voice profile for one user/workspace.

        If the profile already exists, it is returned safely.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="create_default_profile",
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)
        safe_profile_id = self._validate_profile_id(profile_id)

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)

            existing = profiles.get(safe_profile_id)
            if existing is not None:
                return self._safe_result(
                    message="Voice profile already exists.",
                    data={
                        "profile": self._public_profile(existing),
                        "created": False,
                    },
                )

            if len(profiles) >= self.config.max_profiles_per_workspace:
                return self._error_result(
                    message="Maximum voice profiles reached for this workspace.",
                    error_code="PROFILE_LIMIT_REACHED",
                    metadata={"limit": self.config.max_profiles_per_workspace},
                )

            profile = self._build_default_profile(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                profile_id=safe_profile_id,
                profile_name=profile_name,
                metadata=metadata or {},
            )

            if set_active:
                for item in profiles.values():
                    item.active = False
                    item.updated_at = utc_now_iso()
                profile.active = True

            profiles[safe_profile_id] = profile
            self._save_profiles(safe_user_id, safe_workspace_id, profiles)

        self._emit_agent_event(
            "voice.profile.created",
            {
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
            },
        )

        self._log_audit_event(
            {
                "event_type": "voice_profile_created",
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
                "timestamp": utc_now_iso(),
            }
        )

        data = {
            "profile": self._public_profile(profile),
            "created": True,
        }

        return self._safe_result(
            message="Default voice profile created.",
            data=data,
            metadata={
                "verification_payload": self._prepare_verification_payload(
                    action="voice_profile_created",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data=data,
                ),
                "memory_payload": self._prepare_memory_payload(
                    action="voice_profile_created",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data={
                        "profile_id": safe_profile_id,
                        "profile_name": profile.profile_name,
                    },
                ),
            },
        )

    def get_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str = DEFAULT_PROFILE_ID,
        auto_create: bool = True,
    ) -> Dict[str, Any]:
        """
        Get one voice profile.

        If auto_create=True and the profile does not exist, a default profile is created.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="get_profile",
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)
        safe_profile_id = self._validate_profile_id(profile_id)

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)
            profile = profiles.get(safe_profile_id)

        if profile is None:
            if auto_create:
                return self.create_default_profile(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    profile_id=safe_profile_id,
                )

            return self._error_result(
                message="Voice profile not found.",
                error_code="PROFILE_NOT_FOUND",
                metadata={"profile_id": safe_profile_id},
            )

        return self._safe_result(
            message="Voice profile loaded.",
            data={"profile": self._public_profile(profile)},
        )

    def get_active_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        auto_create: bool = True,
    ) -> Dict[str, Any]:
        """
        Get active voice profile for user/workspace.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="get_active_profile",
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)

        active_profiles = [
            profile for profile in profiles.values()
            if profile.active and not profile.disabled
        ]

        if active_profiles:
            active_profiles.sort(key=lambda item: item.updated_at, reverse=True)
            return self._safe_result(
                message="Active voice profile loaded.",
                data={"profile": self._public_profile(active_profiles[0])},
            )

        if auto_create:
            return self.create_default_profile(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                profile_id=DEFAULT_PROFILE_ID,
                set_active=True,
            )

        return self._error_result(
            message="No active voice profile found.",
            error_code="ACTIVE_PROFILE_NOT_FOUND",
        )

    def list_profiles(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_disabled: bool = False,
    ) -> Dict[str, Any]:
        """
        List voice profiles for one user/workspace only.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="list_profiles",
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)

        public_profiles = []
        for profile in profiles.values():
            if profile.disabled and not include_disabled:
                continue
            public_profiles.append(self._public_profile(profile))

        public_profiles.sort(
            key=lambda item: (
                not item.get("active", False),
                item.get("profile_name", "").lower(),
            )
        )

        return self._safe_result(
            message="Voice profiles loaded.",
            data={
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profiles": public_profiles,
                "count": len(public_profiles),
            },
        )

    def set_active_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set one profile as active for runtime voice behavior.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="set_active_profile",
            task_context=task_context,
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)
        safe_profile_id = self._validate_profile_id(profile_id)

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)
            target = profiles.get(safe_profile_id)

            if target is None or target.disabled:
                return self._error_result(
                    message="Voice profile not found or disabled.",
                    error_code="PROFILE_NOT_FOUND",
                    metadata={"profile_id": safe_profile_id},
                )

            for profile in profiles.values():
                profile.active = False
                profile.updated_at = utc_now_iso()

            target.active = True
            target.updated_at = utc_now_iso()
            profiles[safe_profile_id] = target
            self._save_profiles(safe_user_id, safe_workspace_id, profiles)

        data = {"profile": self._public_profile(target)}

        self._emit_agent_event(
            "voice.profile.active_changed",
            {
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
            },
        )

        self._log_audit_event(
            {
                "event_type": "voice_profile_active_changed",
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
                "timestamp": utc_now_iso(),
            }
        )

        return self._safe_result(
            message="Active voice profile changed.",
            data=data,
            metadata={
                "verification_payload": self._prepare_verification_payload(
                    action="voice_profile_active_changed",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data=data,
                ),
            },
        )

    def update_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str = DEFAULT_PROFILE_ID,
        updates: Optional[Dict[str, Any]] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update a voice profile.

        Supported update structure:
            {
                "profile_name": "...",
                "persona": {...},
                "audio": {...},
                "language": {...},
                "security": {...},
                "dashboard_tags": [...],
                "metadata": {...}
            }
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="update_profile",
            task_context=task_context,
        )
        if not context_result["success"]:
            return context_result

        if updates is None:
            updates = {}

        if not isinstance(updates, dict):
            return self._error_result(
                message="updates must be a dictionary.",
                error_code="INVALID_UPDATES",
            )

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)
        safe_profile_id = self._validate_profile_id(profile_id)

        sensitive_fields = self._detect_sensitive_update_fields(updates)
        security_payload: Optional[Dict[str, Any]] = None

        if sensitive_fields and self._requires_security_check(
            task_type="voice_profile_security_change",
            task_context=task_context,
        ):
            security_payload = self._request_security_approval(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                task_type="voice_profile_security_change",
                reason="Sensitive voice profile settings are being changed.",
                sensitive_fields=sensitive_fields,
                task_context=task_context,
            )

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)
            profile = profiles.get(safe_profile_id)

            if profile is None:
                profile = self._build_default_profile(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    profile_id=safe_profile_id,
                    profile_name=safe_string(
                        updates.get("profile_name") or "Default Voice Profile",
                        120,
                    ),
                )

            profile = self._apply_profile_updates(profile, updates)
            profile.updated_at = utc_now_iso()
            profiles[safe_profile_id] = profile
            self._save_profiles(safe_user_id, safe_workspace_id, profiles)

        data = {
            "profile": self._public_profile(profile),
            "updated_fields": sorted(list(updates.keys())),
            "sensitive_fields": sensitive_fields,
            "security_payload": security_payload,
        }

        self._emit_agent_event(
            "voice.profile.updated",
            {
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
                "updated_fields": sorted(list(updates.keys())),
                "sensitive_fields": sensitive_fields,
            },
        )

        self._log_audit_event(
            {
                "event_type": "voice_profile_updated",
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
                "updated_fields": sorted(list(updates.keys())),
                "sensitive_fields": sensitive_fields,
                "timestamp": utc_now_iso(),
            }
        )

        return self._safe_result(
            message="Voice profile updated.",
            data=data,
            metadata={
                "verification_payload": self._prepare_verification_payload(
                    action="voice_profile_updated",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data=data,
                ),
                "memory_payload": self._prepare_memory_payload(
                    action="voice_profile_updated",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data=self._memory_safe_profile_summary(profile),
                ),
            },
        )

    def update_voice_preferences(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str = DEFAULT_PROFILE_ID,
        language_code: Optional[str] = None,
        style_preset: Optional[str] = None,
        speed: Optional[float] = None,
        volume: Optional[float] = None,
        pitch: Optional[float] = None,
        persona_name: Optional[str] = None,
        emotional_tone: Optional[str] = None,
        voice_id: Optional[str] = None,
        tts_provider: Optional[str] = None,
        stt_provider: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for common dashboard/API preference updates.
        """
        updates: Dict[str, Any] = {
            "audio": {},
            "persona": {},
            "language": {},
        }

        if language_code is not None:
            updates["language"]["language_code"] = language_code
        if style_preset is not None:
            updates["persona"]["style_preset"] = style_preset
        if speed is not None:
            updates["audio"]["speed"] = speed
        if volume is not None:
            updates["audio"]["volume"] = volume
        if pitch is not None:
            updates["audio"]["pitch"] = pitch
        if persona_name is not None:
            updates["persona"]["persona_name"] = persona_name
        if emotional_tone is not None:
            updates["persona"]["emotional_tone"] = emotional_tone
        if voice_id is not None:
            updates["audio"]["voice_id"] = voice_id
        if tts_provider is not None:
            updates["audio"]["tts_provider"] = tts_provider
        if stt_provider is not None:
            updates["audio"]["stt_provider"] = stt_provider

        updates = {key: value for key, value in updates.items() if value}

        return self.update_profile(
            user_id=user_id,
            workspace_id=workspace_id,
            profile_id=profile_id,
            updates=updates,
            task_context=task_context,
        )

    def get_runtime_voice_settings(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: Optional[str] = None,
        include_security_policy: bool = True,
    ) -> Dict[str, Any]:
        """
        Return runtime settings for TTS/STT/Voice Agent.

        This is the best method for voice_agent.py, tts_engine.py,
        stt_engine.py, whisper_mode.py, and language_engine.py to call.
        """
        if profile_id:
            profile_result = self.get_profile(
                user_id=user_id,
                workspace_id=workspace_id,
                profile_id=profile_id,
                auto_create=True,
            )
        else:
            profile_result = self.get_active_profile(
                user_id=user_id,
                workspace_id=workspace_id,
                auto_create=True,
            )

        if not profile_result["success"]:
            return profile_result

        profile = profile_result["data"]["profile"]

        runtime = {
            "profile_id": profile["profile_id"],
            "profile_name": profile["profile_name"],
            "voice_id": profile["audio"]["voice_id"],
            "tts_provider": profile["audio"]["tts_provider"],
            "stt_provider": profile["audio"]["stt_provider"],
            "speed": profile["audio"]["speed"],
            "volume": profile["audio"]["volume"],
            "pitch": profile["audio"]["pitch"],
            "stability": profile["audio"]["stability"],
            "clarity": profile["audio"]["clarity"],
            "latency_mode": profile["audio"]["latency_mode"],
            "streaming_enabled": profile["audio"]["streaming_enabled"],
            "interruption_enabled": profile["audio"]["interruption_enabled"],
            "whisper_mode_preferred": profile["audio"]["whisper_mode_preferred"],
            "noise_suppression_enabled": profile["audio"]["noise_suppression_enabled"],
            "auto_gain_enabled": profile["audio"]["auto_gain_enabled"],
            "language_code": profile["language"]["language_code"],
            "fallback_language_code": profile["language"]["fallback_language_code"],
            "auto_detect_language": profile["language"]["auto_detect_language"],
            "allow_multilingual_response": profile["language"]["allow_multilingual_response"],
            "translate_to_preferred_language": profile["language"]["translate_to_preferred_language"],
            "roman_urdu_enabled": profile["language"]["roman_urdu_enabled"],
            "response_script": profile["language"]["response_script"],
            "persona_name": profile["persona"]["persona_name"],
            "custom_persona_prompt": profile["persona"]["custom_persona_prompt"],
            "style_preset": profile["persona"]["style_preset"],
            "emotional_tone": profile["persona"]["emotional_tone"],
            "formality_level": profile["persona"]["formality_level"],
            "warmth_level": profile["persona"]["warmth_level"],
            "directness_level": profile["persona"]["directness_level"],
            "humor_level": profile["persona"]["humor_level"],
            "empathy_level": profile["persona"]["empathy_level"],
            "technical_depth": profile["persona"]["technical_depth"],
            "pronunciation_notes": profile["language"]["pronunciation_notes"],
        }

        if include_security_policy:
            runtime["security_policy"] = {
                "trusted_speaker_required": profile["security"]["trusted_speaker_required"],
                "owner_voice_required": profile["security"]["owner_voice_required"],
                "allow_sensitive_voice_commands": profile["security"]["allow_sensitive_voice_commands"],
                "voice_unlock_enabled": profile["security"]["voice_unlock_enabled"],
                "security_confirmation_mode": profile["security"]["security_confirmation_mode"],
                "profile_visibility": profile["security"]["profile_visibility"],
                "memory_sync_enabled": profile["security"]["memory_sync_enabled"],
                "voice_biometric_profile_id": profile["security"]["voice_biometric_profile_id"],
            }

        return self._safe_result(
            message="Runtime voice settings prepared.",
            data={
                "user_id": safe_string(user_id),
                "workspace_id": safe_string(workspace_id),
                "runtime_settings": runtime,
            },
        )

    def remove_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str,
        hard_delete: bool = False,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remove a voice profile.

        Default behavior is soft-disable. hard_delete=True removes it from storage.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="remove_profile",
            task_context=task_context,
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)
        safe_profile_id = self._validate_profile_id(profile_id)

        security_payload = self._request_security_approval(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            task_type="profile_delete",
            reason="Voice profile removal requested.",
            sensitive_fields=["profile_delete"],
            task_context=task_context,
        )

        with self._lock:
            profiles = self._load_profiles(safe_user_id, safe_workspace_id)
            profile = profiles.get(safe_profile_id)

            if profile is None:
                return self._error_result(
                    message="Voice profile not found.",
                    error_code="PROFILE_NOT_FOUND",
                    metadata={"profile_id": safe_profile_id},
                )

            if hard_delete:
                profiles.pop(safe_profile_id, None)
                action = "hard_deleted"
            else:
                profile.disabled = True
                profile.active = False
                profile.updated_at = utc_now_iso()
                profiles[safe_profile_id] = profile
                action = "disabled"

            remaining_active = [
                item for item in profiles.values()
                if item.active and not item.disabled
            ]

            if not remaining_active and profiles:
                for item in profiles.values():
                    if not item.disabled:
                        item.active = True
                        item.updated_at = utc_now_iso()
                        break

            self._save_profiles(safe_user_id, safe_workspace_id, profiles)

        data = {
            "profile_id": safe_profile_id,
            "action": action,
            "hard_delete": hard_delete,
            "security_payload": security_payload,
        }

        self._log_audit_event(
            {
                "event_type": "voice_profile_removed",
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "profile_id": safe_profile_id,
                "action": action,
                "timestamp": utc_now_iso(),
            }
        )

        return self._safe_result(
            message=f"Voice profile {action}.",
            data=data,
            metadata={
                "verification_payload": self._prepare_verification_payload(
                    action="voice_profile_removed",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data=data,
                ),
            },
        )

    def export_profile(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        profile_id: str = DEFAULT_PROFILE_ID,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export one profile as JSON-safe data.

        This is a sensitive task because profile preferences may contain
        user-specific behavior/persona information.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="export_profile",
            task_context=task_context,
        )
        if not context_result["success"]:
            return context_result

        safe_user_id = safe_string(user_id)
        safe_workspace_id = safe_string(workspace_id)
        safe_profile_id = self._validate_profile_id(profile_id)

        security_payload = self._request_security_approval(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            task_type="profile_export",
            reason="Voice profile export requested.",
            sensitive_fields=["profile_export"],
            task_context=task_context,
        )

        profile_result = self.get_profile(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            profile_id=safe_profile_id,
            auto_create=False,
        )

        if not profile_result["success"]:
            return profile_result

        exported = {
            "export_id": str(uuid.uuid4()),
            "exported_at": utc_now_iso(),
            "source_agent": "voice_agent.voice_profiles",
            "profile": profile_result["data"]["profile"],
            "security_payload": security_payload,
        }

        return self._safe_result(
            message="Voice profile exported.",
            data=exported,
            metadata={
                "verification_payload": self._prepare_verification_payload(
                    action="voice_profile_exported",
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    data={
                        "profile_id": safe_profile_id,
                        "export_id": exported["export_id"],
                    },
                )
            },
        )

    def handle_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router compatible entry point.

        Expected shape:
            {
                "operation": "get_profile|update_profile|...",
                "user_id": "...",
                "workspace_id": "...",
                "data": {...},
                "task_context": {...}
            }
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error_code="INVALID_TASK",
            )

        operation = safe_string(task.get("operation"), 100)
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")
        data = task.get("data") or {}
        task_context = task.get("task_context") or {}

        if not isinstance(data, dict):
            return self._error_result(
                message="Task data must be a dictionary.",
                error_code="INVALID_TASK_DATA",
            )

        try:
            if operation == "create_default_profile":
                return self.create_default_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    **data,
                )

            if operation == "get_profile":
                return self.get_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    **data,
                )

            if operation == "get_active_profile":
                return self.get_active_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    **data,
                )

            if operation == "list_profiles":
                return self.list_profiles(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    **data,
                )

            if operation == "set_active_profile":
                return self.set_active_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_context=task_context,
                    **data,
                )

            if operation == "update_profile":
                return self.update_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_context=task_context,
                    **data,
                )

            if operation == "update_voice_preferences":
                return self.update_voice_preferences(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_context=task_context,
                    **data,
                )

            if operation == "get_runtime_voice_settings":
                return self.get_runtime_voice_settings(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    **data,
                )

            if operation == "remove_profile":
                return self.remove_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_context=task_context,
                    **data,
                )

            if operation == "export_profile":
                return self.export_profile(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_context=task_context,
                    **data,
                )

            return self._error_result(
                message=f"Unsupported voice profile operation: {operation}",
                error_code="UNSUPPORTED_OPERATION",
                metadata={"operation": operation},
            )

        except TypeError as exc:
            return self._error_result(
                message="Invalid arguments for voice profile operation.",
                error=exc,
                error_code="INVALID_ARGUMENTS",
                metadata={"operation": operation},
            )
        except Exception as exc:
            return self._error_result(
                message="Voice profile task failed.",
                error=exc,
                error_code="TASK_FAILED",
                metadata={"operation": operation},
            )

    # -----------------------------------------------------------------------
    # Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        operation: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation fields.

        Every user-specific voice profile operation requires user_id/workspace_id.
        """
        safe_operation = safe_string(operation, 100)

        if user_id is None or safe_string(user_id) == "":
            return self._error_result(
                message="user_id is required for voice profile operations.",
                error_code="MISSING_USER_ID",
                metadata={"operation": safe_operation},
            )

        if workspace_id is None or safe_string(workspace_id) == "":
            return self._error_result(
                message="workspace_id is required for voice profile operations.",
                error_code="MISSING_WORKSPACE_ID",
                metadata={"operation": safe_operation},
            )

        if task_context is not None and not isinstance(task_context, dict):
            return self._error_result(
                message="task_context must be a dictionary when provided.",
                error_code="INVALID_TASK_CONTEXT",
                metadata={"operation": safe_operation},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": safe_string(user_id),
                "workspace_id": safe_string(workspace_id),
                "operation": safe_operation,
            },
        )

    def _requires_security_check(
        self,
        *,
        task_type: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether this voice profile operation needs Security Agent.
        """
        if not self.config.require_security_for_sensitive_fields:
            return False

        safe_task_type = safe_string(task_type, 120)

        if safe_task_type in SENSITIVE_TASK_TYPES:
            return True

        if task_context:
            if normalize_bool(task_context.get("sensitive"), False):
                return True

            risk_level = safe_string(task_context.get("risk_level"), 40).lower()
            if risk_level in {"high", "critical"}:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_type: str,
        reason: str,
        sensitive_fields: Optional[List[str]] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare or request Security Agent approval.

        If injected Security Agent has request_approval(), this method calls it.
        Otherwise, it returns a prepared payload for future integration.
        """
        payload = {
            "approval_id": str(uuid.uuid4()),
            "source_agent": "voice_agent.voice_profiles",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_type": task_type,
            "reason": safe_string(reason, 500),
            "sensitive_fields": sensitive_fields or [],
            "task_context": task_context or {},
            "created_at": utc_now_iso(),
            "status": "prepared",
        }

        if self.security_agent is not None:
            request_approval = getattr(self.security_agent, "request_approval", None)
            if callable(request_approval):
                try:
                    response = request_approval(payload)
                    if isinstance(response, dict):
                        return response
                except Exception as exc:
                    self.logger.warning("Security Agent approval request failed: %s", exc)
                    payload["status"] = "security_agent_error"
                    payload["error"] = str(exc)

        return payload

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """
        return {
            "verification_id": str(uuid.uuid4()),
            "source_agent": "voice_agent.voice_profiles",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": data,
            "created_at": utc_now_iso(),
            "status": "ready_for_verification_agent",
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Keeps the payload preference-focused and safe.
        """
        if not self.config.memory_payload_enabled:
            return {}

        return {
            "memory_id": str(uuid.uuid4()),
            "source_agent": "voice_agent.voice_profiles",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "memory_type": "voice_preference",
            "data": data,
            "created_at": utc_now_iso(),
            "safe_to_store": True,
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit Agent Registry / Dashboard compatible event.
        """
        if not self.config.events_enabled:
            return

        event_payload = dict(payload)
        event_payload.setdefault("event_id", str(uuid.uuid4()))
        event_payload.setdefault("source_agent", "voice_agent.voice_profiles")
        event_payload.setdefault("timestamp", utc_now_iso())

        try:
            if callable(self.event_emitter):
                self.event_emitter(event_name, event_payload)
                return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_name, event_payload)
                return

            self.logger.debug("Agent event: %s | %s", event_name, event_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit event %s: %s", event_name, exc)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """
        Log audit events without mixing users/workspaces.
        """
        if not self.config.audit_enabled:
            return

        audit_payload = dict(payload)
        audit_payload.setdefault("audit_id", str(uuid.uuid4()))
        audit_payload.setdefault("source_agent", "voice_agent.voice_profiles")
        audit_payload.setdefault("timestamp", utc_now_iso())

        try:
            if callable(self.audit_logger):
                self.audit_logger(audit_payload)
            else:
                self.logger.info("AUDIT | %s", json.dumps(audit_payload, default=str))
        except Exception as exc:
            self.logger.warning("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result shape.
        """
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
        error: Optional[BaseException] = None,
        error_code: str = "ERROR",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result shape.
        """
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": str(error) if error else message,
                "type": error.__class__.__name__ if error else None,
            },
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Profile Builders / Validators
    # -----------------------------------------------------------------------

    def _build_default_profile(
        self,
        *,
        user_id: str,
        workspace_id: str,
        profile_id: str,
        profile_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VoiceProfile:
        """
        Build default VoiceProfile using config defaults.
        """
        profile = VoiceProfile(
            profile_id=profile_id,
            user_id=user_id,
            workspace_id=workspace_id,
            profile_name=safe_string(profile_name, 120) or "Default Voice Profile",
            active=True,
            metadata=metadata or {},
        )

        profile.language.language_code = normalize_choice(
            self.config.default_language_code,
            SUPPORTED_LANGUAGE_CODES,
            "auto",
        )
        profile.persona.persona_name = normalize_choice(
            self.config.default_persona,
            SUPPORTED_PERSONAS,
            "jarvis",
        )
        profile.persona.style_preset = normalize_choice(
            self.config.default_style_preset,
            SUPPORTED_STYLE_PRESETS,
            "balanced",
        )
        profile.audio.tts_provider = normalize_choice(
            self.config.default_tts_provider,
            SUPPORTED_TTS_PROVIDERS,
            "auto",
        )
        profile.audio.stt_provider = normalize_choice(
            self.config.default_stt_provider,
            SUPPORTED_STT_PROVIDERS,
            "auto",
        )

        return profile

    def _validate_profile_id(self, profile_id: str) -> str:
        """
        Validate and sanitize profile_id.
        """
        safe_profile_id = sanitize_path_part(profile_id, DEFAULT_PROFILE_ID)

        if not safe_profile_id:
            raise ValueError("profile_id cannot be empty.")

        if len(safe_profile_id) > 120:
            raise ValueError("profile_id is too long. Maximum length is 120.")

        return safe_profile_id

    def _apply_profile_updates(
        self,
        profile: VoiceProfile,
        updates: Dict[str, Any],
    ) -> VoiceProfile:
        """
        Apply validated updates to a profile.
        """
        if "profile_name" in updates:
            profile.profile_name = safe_string(
                updates.get("profile_name"),
                120,
            ) or profile.profile_name

        if "active" in updates:
            profile.active = normalize_bool(updates.get("active"), profile.active)

        if "disabled" in updates:
            profile.disabled = normalize_bool(updates.get("disabled"), profile.disabled)

        if "persona" in updates and isinstance(updates["persona"], dict):
            profile.persona = self._update_persona_settings(
                profile.persona,
                updates["persona"],
            )

        if "audio" in updates and isinstance(updates["audio"], dict):
            profile.audio = self._update_audio_settings(
                profile.audio,
                updates["audio"],
            )

        if "language" in updates and isinstance(updates["language"], dict):
            profile.language = self._update_language_settings(
                profile.language,
                updates["language"],
            )

        if "security" in updates and isinstance(updates["security"], dict):
            profile.security = self._update_security_settings(
                profile.security,
                updates["security"],
            )

        if "dashboard_tags" in updates:
            tags = updates.get("dashboard_tags")
            if isinstance(tags, list):
                profile.dashboard_tags = [
                    safe_string(tag, 60)
                    for tag in tags
                    if safe_string(tag, 60)
                ][:20]

        if "metadata" in updates and isinstance(updates["metadata"], dict):
            cleaned_metadata = self._sanitize_metadata(updates["metadata"])
            profile.metadata = deep_merge(profile.metadata, cleaned_metadata)

        return profile

    def _update_persona_settings(
        self,
        current: VoicePersonaSettings,
        updates: Dict[str, Any],
    ) -> VoicePersonaSettings:
        """
        Update persona settings with validation.
        """
        if "persona_name" in updates:
            current.persona_name = normalize_choice(
                updates.get("persona_name"),
                SUPPORTED_PERSONAS,
                current.persona_name,
            )

        if "custom_persona_prompt" in updates:
            current.custom_persona_prompt = safe_string(
                updates.get("custom_persona_prompt"),
                1500,
            )

        if "style_preset" in updates:
            current.style_preset = normalize_choice(
                updates.get("style_preset"),
                SUPPORTED_STYLE_PRESETS,
                current.style_preset,
            )

        if "emotional_tone" in updates:
            current.emotional_tone = normalize_choice(
                updates.get("emotional_tone"),
                SUPPORTED_EMOTIONAL_TONES,
                current.emotional_tone,
            )

        if "formality_level" in updates:
            current.formality_level = clamp_float(
                updates.get("formality_level"),
                0.0,
                1.0,
                current.formality_level,
            )

        if "warmth_level" in updates:
            current.warmth_level = clamp_float(
                updates.get("warmth_level"),
                0.0,
                1.0,
                current.warmth_level,
            )

        if "directness_level" in updates:
            current.directness_level = clamp_float(
                updates.get("directness_level"),
                0.0,
                1.0,
                current.directness_level,
            )

        if "humor_level" in updates:
            current.humor_level = clamp_float(
                updates.get("humor_level"),
                0.0,
                1.0,
                current.humor_level,
            )

        if "empathy_level" in updates:
            current.empathy_level = clamp_float(
                updates.get("empathy_level"),
                0.0,
                1.0,
                current.empathy_level,
            )

        if "technical_depth" in updates:
            current.technical_depth = clamp_float(
                updates.get("technical_depth"),
                0.0,
                1.0,
                current.technical_depth,
            )

        return current

    def _update_audio_settings(
        self,
        current: VoiceAudioSettings,
        updates: Dict[str, Any],
    ) -> VoiceAudioSettings:
        """
        Update TTS/STT/audio playback settings with validation.
        """
        if "voice_id" in updates:
            current.voice_id = safe_string(updates.get("voice_id"), 160) or current.voice_id

        if "tts_provider" in updates:
            current.tts_provider = normalize_choice(
                updates.get("tts_provider"),
                SUPPORTED_TTS_PROVIDERS,
                current.tts_provider,
            )

        if "stt_provider" in updates:
            current.stt_provider = normalize_choice(
                updates.get("stt_provider"),
                SUPPORTED_STT_PROVIDERS,
                current.stt_provider,
            )

        if "speed" in updates:
            current.speed = clamp_float(updates.get("speed"), 0.50, 2.00, current.speed)

        if "volume" in updates:
            current.volume = clamp_float(updates.get("volume"), 0.00, 1.00, current.volume)

        if "pitch" in updates:
            current.pitch = clamp_float(updates.get("pitch"), 0.50, 2.00, current.pitch)

        if "stability" in updates:
            current.stability = clamp_float(
                updates.get("stability"),
                0.00,
                1.00,
                current.stability,
            )

        if "clarity" in updates:
            current.clarity = clamp_float(
                updates.get("clarity"),
                0.00,
                1.00,
                current.clarity,
            )

        if "latency_mode" in updates:
            latency_mode = safe_string(updates.get("latency_mode"), 40).lower()
            if latency_mode in {"low", "balanced", "quality"}:
                current.latency_mode = latency_mode

        if "streaming_enabled" in updates:
            current.streaming_enabled = normalize_bool(
                updates.get("streaming_enabled"),
                current.streaming_enabled,
            )

        if "interruption_enabled" in updates:
            current.interruption_enabled = normalize_bool(
                updates.get("interruption_enabled"),
                current.interruption_enabled,
            )

        if "whisper_mode_preferred" in updates:
            current.whisper_mode_preferred = normalize_bool(
                updates.get("whisper_mode_preferred"),
                current.whisper_mode_preferred,
            )

        if "noise_suppression_enabled" in updates:
            current.noise_suppression_enabled = normalize_bool(
                updates.get("noise_suppression_enabled"),
                current.noise_suppression_enabled,
            )

        if "auto_gain_enabled" in updates:
            current.auto_gain_enabled = normalize_bool(
                updates.get("auto_gain_enabled"),
                current.auto_gain_enabled,
            )

        return current

    def _update_language_settings(
        self,
        current: VoiceLanguageSettings,
        updates: Dict[str, Any],
    ) -> VoiceLanguageSettings:
        """
        Update language settings with validation.
        """
        if "language_code" in updates:
            current.language_code = normalize_choice(
                updates.get("language_code"),
                SUPPORTED_LANGUAGE_CODES,
                current.language_code,
            )

        if "fallback_language_code" in updates:
            current.fallback_language_code = normalize_choice(
                updates.get("fallback_language_code"),
                SUPPORTED_LANGUAGE_CODES,
                current.fallback_language_code,
            )

        if "auto_detect_language" in updates:
            current.auto_detect_language = normalize_bool(
                updates.get("auto_detect_language"),
                current.auto_detect_language,
            )

        if "allow_multilingual_response" in updates:
            current.allow_multilingual_response = normalize_bool(
                updates.get("allow_multilingual_response"),
                current.allow_multilingual_response,
            )

        if "translate_to_preferred_language" in updates:
            current.translate_to_preferred_language = normalize_bool(
                updates.get("translate_to_preferred_language"),
                current.translate_to_preferred_language,
            )

        if "roman_urdu_enabled" in updates:
            current.roman_urdu_enabled = normalize_bool(
                updates.get("roman_urdu_enabled"),
                current.roman_urdu_enabled,
            )

        if "response_script" in updates:
            response_script = safe_string(updates.get("response_script"), 40).lower()
            if response_script in {"auto", "latin", "arabic", "native"}:
                current.response_script = response_script

        if "pronunciation_notes" in updates and isinstance(
            updates["pronunciation_notes"],
            dict,
        ):
            cleaned_notes: Dict[str, str] = {}
            for key, value in updates["pronunciation_notes"].items():
                cleaned_key = safe_string(key, 80)
                cleaned_value = safe_string(value, 300)
                if cleaned_key and cleaned_value:
                    cleaned_notes[cleaned_key] = cleaned_value
            current.pronunciation_notes = deep_merge(
                current.pronunciation_notes,
                cleaned_notes,
            )

        return current

    def _update_security_settings(
        self,
        current: VoiceSecuritySettings,
        updates: Dict[str, Any],
    ) -> VoiceSecuritySettings:
        """
        Update voice security settings with validation.
        """
        if "trusted_speaker_required" in updates:
            current.trusted_speaker_required = normalize_bool(
                updates.get("trusted_speaker_required"),
                current.trusted_speaker_required,
            )

        if "owner_voice_required" in updates:
            current.owner_voice_required = normalize_bool(
                updates.get("owner_voice_required"),
                current.owner_voice_required,
            )

        if "allow_sensitive_voice_commands" in updates:
            current.allow_sensitive_voice_commands = normalize_bool(
                updates.get("allow_sensitive_voice_commands"),
                current.allow_sensitive_voice_commands,
            )

        if "voice_unlock_enabled" in updates:
            current.voice_unlock_enabled = normalize_bool(
                updates.get("voice_unlock_enabled"),
                current.voice_unlock_enabled,
            )

        if "security_confirmation_mode" in updates:
            mode = safe_string(updates.get("security_confirmation_mode"), 80).lower()
            if mode in {
                "always_ask",
                "ask_before_sensitive_action",
                "speaker_verification_only",
                "disabled",
            }:
                current.security_confirmation_mode = mode

        if "profile_visibility" in updates:
            visibility = safe_string(updates.get("profile_visibility"), 40).lower()
            if visibility in {"private", "workspace", "admin_only"}:
                current.profile_visibility = visibility

        if "memory_sync_enabled" in updates:
            current.memory_sync_enabled = normalize_bool(
                updates.get("memory_sync_enabled"),
                current.memory_sync_enabled,
            )

        if "voice_biometric_profile_id" in updates:
            current.voice_biometric_profile_id = safe_string(
                updates.get("voice_biometric_profile_id"),
                160,
            )

        return current

    def _detect_sensitive_update_fields(self, updates: Dict[str, Any]) -> List[str]:
        """
        Detect sensitive voice profile fields in nested updates.
        """
        found: List[str] = []

        for key in updates.keys():
            if key in SENSITIVE_PROFILE_FIELDS:
                found.append(key)

        security_updates = updates.get("security")
        if isinstance(security_updates, dict):
            for key in security_updates.keys():
                if key in SENSITIVE_PROFILE_FIELDS:
                    found.append(f"security.{key}")

        return sorted(set(found))

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Keep metadata safe and JSON-serializable.
        """
        cleaned: Dict[str, Any] = {}

        for key, value in metadata.items():
            safe_key = safe_string(key, 80)
            if not safe_key:
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                cleaned[safe_key] = value
            elif isinstance(value, list):
                cleaned[safe_key] = [
                    item for item in value
                    if isinstance(item, (str, int, float, bool)) or item is None
                ][:50]
            elif isinstance(value, dict):
                cleaned[safe_key] = self._sanitize_metadata(value)
            else:
                cleaned[safe_key] = safe_string(value, 300)

        return cleaned

    def _public_profile(self, profile: VoiceProfile) -> Dict[str, Any]:
        """
        Return JSON-safe public profile representation.

        This can be returned to dashboard/API.
        """
        return asdict(profile)

    def _memory_safe_profile_summary(self, profile: VoiceProfile) -> Dict[str, Any]:
        """
        Prepare a compact profile summary for Memory Agent.
        """
        return {
            "profile_id": profile.profile_id,
            "profile_name": profile.profile_name,
            "active": profile.active,
            "persona_name": profile.persona.persona_name,
            "style_preset": profile.persona.style_preset,
            "emotional_tone": profile.persona.emotional_tone,
            "language_code": profile.language.language_code,
            "speed": profile.audio.speed,
            "volume": profile.audio.volume,
            "pitch": profile.audio.pitch,
            "tts_provider": profile.audio.tts_provider,
            "stt_provider": profile.audio.stt_provider,
            "whisper_mode_preferred": profile.audio.whisper_mode_preferred,
        }

    # -----------------------------------------------------------------------
    # Storage
    # -----------------------------------------------------------------------

    def _profile_file_path(self, user_id: str, workspace_id: str) -> Path:
        """
        Return isolated storage path for one user/workspace.
        """
        safe_user = sanitize_path_part(user_id, "user")
        safe_workspace = sanitize_path_part(workspace_id, "workspace")

        directory = self.storage_dir / safe_user / safe_workspace
        directory.mkdir(parents=True, exist_ok=True)

        return directory / "voice_profiles.json"

    def _load_profiles(self, user_id: str, workspace_id: str) -> Dict[str, VoiceProfile]:
        """
        Load voice profiles for one user/workspace.
        """
        path = self._profile_file_path(user_id, workspace_id)

        if not path.exists():
            return {}

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            backup_path = path.with_suffix(f".corrupt.{int(time.time())}.json")
            path.rename(backup_path)
            self.logger.warning("Corrupt voice profile file moved to %s", backup_path)
            return {}
        except Exception as exc:
            self.logger.warning("Failed to load voice profiles: %s", exc)
            return {}

        raw_profiles = raw.get("profiles", {})
        if not isinstance(raw_profiles, dict):
            return {}

        profiles: Dict[str, VoiceProfile] = {}

        for profile_id, item in raw_profiles.items():
            if not isinstance(item, dict):
                continue

            try:
                profile = self._profile_from_dict(
                    item,
                    fallback_profile_id=profile_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                )

                if profile.user_id != user_id or profile.workspace_id != workspace_id:
                    self.logger.warning(
                        "Skipped cross-context voice profile: %s",
                        profile.profile_id,
                    )
                    continue

                profiles[profile.profile_id] = profile

            except Exception as exc:
                self.logger.warning(
                    "Skipped invalid voice profile %s: %s",
                    profile_id,
                    exc,
                )

        return profiles

    def _save_profiles(
        self,
        user_id: str,
        workspace_id: str,
        profiles: Dict[str, VoiceProfile],
    ) -> None:
        """
        Save voice profiles for one user/workspace only.
        """
        path = self._profile_file_path(user_id, workspace_id)
        temp_path = path.with_suffix(".tmp")

        payload = {
            "file_version": self.config.profile_file_version,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "updated_at": utc_now_iso(),
            "profiles": {
                profile_id: asdict(profile)
                for profile_id, profile in profiles.items()
                if profile.user_id == user_id and profile.workspace_id == workspace_id
            },
        }

        temp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temp_path.replace(path)

    def _profile_from_dict(
        self,
        item: Dict[str, Any],
        *,
        fallback_profile_id: str,
        user_id: str,
        workspace_id: str,
    ) -> VoiceProfile:
        """
        Rebuild VoiceProfile dataclass from JSON dictionary.
        """
        persona_raw = item.get("persona") if isinstance(item.get("persona"), dict) else {}
        audio_raw = item.get("audio") if isinstance(item.get("audio"), dict) else {}
        language_raw = item.get("language") if isinstance(item.get("language"), dict) else {}
        security_raw = item.get("security") if isinstance(item.get("security"), dict) else {}

        profile = VoiceProfile(
            profile_id=safe_string(item.get("profile_id") or fallback_profile_id, 120),
            user_id=safe_string(item.get("user_id") or user_id),
            workspace_id=safe_string(item.get("workspace_id") or workspace_id),
            profile_name=safe_string(item.get("profile_name") or "Default Voice Profile", 120),
            active=normalize_bool(item.get("active"), False),
            created_at=safe_string(item.get("created_at") or utc_now_iso()),
            updated_at=safe_string(item.get("updated_at") or utc_now_iso()),
            persona=VoicePersonaSettings(),
            audio=VoiceAudioSettings(),
            language=VoiceLanguageSettings(),
            security=VoiceSecuritySettings(),
            dashboard_tags=[
                safe_string(tag, 60)
                for tag in item.get("dashboard_tags", [])
                if safe_string(tag, 60)
            ][:20],
            metadata=self._sanitize_metadata(
                item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            ),
            disabled=normalize_bool(item.get("disabled"), False),
        )

        profile.persona = self._update_persona_settings(profile.persona, persona_raw)
        profile.audio = self._update_audio_settings(profile.audio, audio_raw)
        profile.language = self._update_language_settings(profile.language, language_raw)
        profile.security = self._update_security_settings(profile.security, security_raw)

        return profile

    # -----------------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for dashboard/API integration.
        """
        storage_ok = False
        storage_error = None

        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            test_file = self.storage_dir / ".healthcheck"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            storage_ok = True
        except Exception as exc:
            storage_error = str(exc)

        return self._safe_result(
            message="VoiceProfiles health check completed.",
            data={
                "agent": "voice_agent.voice_profiles",
                "storage_dir": str(self.storage_dir),
                "storage_ok": storage_ok,
                "storage_error": storage_error,
                "max_profiles_per_workspace": self.config.max_profiles_per_workspace,
                "default_language_code": self.config.default_language_code,
                "default_persona": self.config.default_persona,
                "default_style_preset": self.config.default_style_preset,
                "default_tts_provider": self.config.default_tts_provider,
                "default_stt_provider": self.config.default_stt_provider,
                "audit_enabled": self.config.audit_enabled,
                "events_enabled": self.config.events_enabled,
            },
        )


# ---------------------------------------------------------------------------
# Optional manual smoke test
# ---------------------------------------------------------------------------

def _demo_smoke_test() -> Dict[str, Any]:
    """
    Manual smoke test.
    Runs only when this file is executed directly.
    """
    profiles = VoiceProfiles()

    user_id = "demo_user"
    workspace_id = "demo_workspace"

    created = profiles.create_default_profile(
        user_id=user_id,
        workspace_id=workspace_id,
    )

    updated = profiles.update_voice_preferences(
        user_id=user_id,
        workspace_id=workspace_id,
        language_code="en-US",
        style_preset="warm",
        speed=1.05,
        volume=0.90,
        pitch=1.00,
        persona_name="jarvis",
        emotional_tone="confident",
        tts_provider="auto",
        stt_provider="auto",
    )

    runtime = profiles.get_runtime_voice_settings(
        user_id=user_id,
        workspace_id=workspace_id,
    )

    listed = profiles.list_profiles(
        user_id=user_id,
        workspace_id=workspace_id,
    )

    return {
        "created": created,
        "updated": updated,
        "runtime": runtime,
        "listed": listed,
    }


if __name__ == "__main__":
    print(json.dumps(_demo_smoke_test(), indent=2, default=str))