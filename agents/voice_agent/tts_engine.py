"""
agents/voice_agent/tts_engine.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Converts text to natural speech with language voices, streaming,
    styles, volume, and interruption support for the Voice Agent.

This file is designed to be:
    - Import-safe
    - SaaS user/workspace aware
    - Compatible with BaseAgent / Agent Registry / Agent Loader / Agent Router / Master Agent
    - Ready for FastAPI/dashboard integration
    - Ready for future local TTS, cloud TTS, browser TTS, mobile TTS,
      voice profiles, voice cloning, audio routing, interruption handling,
      and real-time streaming playback modules

Important:
    This file does not directly play system audio, call paid APIs,
    clone voices, access microphones, or perform sensitive actions by default.

    It generates structured speech jobs/audio payloads through provider callbacks.
    Real playback should be handled later by:
        - audio_router.py
        - device_stream.py
        - voice_loop.py
        - interruption.py
        - mobile/browser/dashboard client
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import time
import uuid
import wave
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        Keeps tts_engine.py import-safe while the full William architecture
        is still being created.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger("william.voice_agent.tts_engine")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# Enums / Dataclasses
# ---------------------------------------------------------------------

class TTSProvider(str, Enum):
    """Supported TTS provider labels."""

    AUTO = "auto"
    LOCAL = "local"
    CLOUD = "cloud"
    BROWSER = "browser"
    MOBILE = "mobile"
    MOCK = "mock"


class TTSStatus(str, Enum):
    """Runtime status for TTSEngine."""

    IDLE = "idle"
    READY = "ready"
    SYNTHESIZING = "synthesizing"
    STREAMING = "streaming"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    ERROR = "error"
    DISABLED = "disabled"


class TTSOutputFormat(str, Enum):
    """Supported output formats."""

    WAV = "wav"
    MP3 = "mp3"
    OGG = "ogg"
    PCM = "pcm"
    JSON = "json"


class VoiceStyle(str, Enum):
    """Supported speech style labels."""

    DEFAULT = "default"
    NATURAL = "natural"
    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    CALM = "calm"
    ENERGETIC = "energetic"
    WHISPER = "whisper"
    URGENT = "urgent"
    STORYTELLING = "storytelling"
    FORMAL = "formal"
    CASUAL = "casual"


class PlaybackCommand(str, Enum):
    """Playback/interruption command labels."""

    SPEAK = "speak"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    INTERRUPT = "interrupt"
    CANCEL = "cancel"


@dataclass
class TTSEngineConfig:
    """
    Runtime configuration for TTSEngine.

    Database/dashboard friendly and avoids hardcoded secrets.
    """

    default_provider: TTSProvider = TTSProvider.AUTO
    provider_order: List[TTSProvider] = field(
        default_factory=lambda: [
            TTSProvider.LOCAL,
            TTSProvider.BROWSER,
            TTSProvider.MOBILE,
            TTSProvider.MOCK,
        ]
    )

    default_language: str = "en"
    supported_languages: List[str] = field(
        default_factory=lambda: [
            "en",
            "ur",
            "hi",
            "ar",
            "es",
            "fr",
            "de",
            "it",
            "pt",
            "tr",
            "zh",
            "ja",
            "ko",
        ]
    )

    default_voice_id: str = "william_default"
    default_style: VoiceStyle = VoiceStyle.NATURAL
    output_format: TTSOutputFormat = TTSOutputFormat.WAV

    default_volume: float = 0.85
    min_volume: float = 0.0
    max_volume: float = 1.0

    default_rate: float = 1.0
    min_rate: float = 0.5
    max_rate: float = 2.0

    default_pitch: float = 1.0
    min_pitch: float = 0.5
    max_pitch: float = 2.0

    sample_rate: int = 24000
    channels: int = 1
    sample_width: int = 2

    enable_streaming: bool = True
    enable_interruption: bool = True
    enable_styles: bool = True
    enable_voice_profiles: bool = True
    enable_ssml: bool = False
    enable_text_cleanup: bool = True
    enable_audio_hashing: bool = True

    allow_cloud_tts: bool = False
    allow_voice_cloning: bool = False
    store_generated_audio: bool = False

    max_text_chars: int = 12000
    max_stream_text_chars: int = 2000
    stream_chunk_chars: int = 320

    require_user_context: bool = True
    require_workspace_context: bool = True

    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    voice_map: Dict[str, Dict[str, Any]] = field(
        default_factory=lambda: {
            "william_default": {
                "voice_id": "william_default",
                "name": "William Default",
                "language": "en",
                "gender": "neutral",
                "provider": "mock",
                "description": "Safe default William voice profile.",
            },
            "william_urdu": {
                "voice_id": "william_urdu",
                "name": "William Urdu",
                "language": "ur",
                "gender": "neutral",
                "provider": "mock",
                "description": "Safe Urdu/Hindi style William voice profile.",
            },
            "william_professional": {
                "voice_id": "william_professional",
                "name": "William Professional",
                "language": "en",
                "gender": "neutral",
                "provider": "mock",
                "description": "Professional business voice profile.",
            },
        }
    )


@dataclass
class TTSContext:
    """
    SaaS context for safe user/workspace isolation.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TTSRequest:
    """
    Normalized TTS request.
    """

    text: str
    language: str
    voice_id: str
    style: VoiceStyle
    volume: float
    rate: float
    pitch: float
    provider: TTSProvider
    output_format: TTSOutputFormat
    stream: bool = False
    ssml: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TTSResult:
    """
    Internal TTS result before conversion to public structured dict.
    """

    success: bool
    provider: TTSProvider
    text: str
    language: str
    voice_id: str
    style: VoiceStyle
    output_format: TTSOutputFormat
    audio_bytes: Optional[bytes] = None
    audio_base64: Optional[str] = None
    audio_path: Optional[str] = None
    audio_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    sample_rate: Optional[int] = None
    channels: Optional[int] = None
    volume: float = 0.85
    rate: float = 1.0
    pitch: float = 1.0
    is_stream: bool = False
    stream_id: Optional[str] = None
    message: str = ""
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------
# TTSEngine
# ---------------------------------------------------------------------

class TTSEngine(BaseAgent):
    """
    Text-to-speech engine for William Voice Agent.

    Responsibilities:
        - Convert text into natural speech payloads
        - Support language-specific voices
        - Support voice style, volume, pitch, and rate
        - Support streaming text-to-speech interface
        - Support interruption commands: stop, pause, resume, interrupt, cancel
        - Support local/browser/mobile/cloud provider routing through callbacks
        - Return safe structured JSON/dict results
        - Prepare Security, Memory, Verification, Audit, and Dashboard payloads

    How this connects to William/Jarvis architecture:
        - Master Agent:
            Sends final response text to TTSEngine after reasoning/routing.

        - Voice Agent:
            Uses this file for spoken responses.

        - Audio Router:
            Receives audio bytes, audio URLs, stream chunks, or playback commands.

        - Interruption Agent/File:
            Can call interrupt(), stop(), pause(), resume(), or cancel_stream().

        - Security Agent:
            Cloud TTS, voice cloning, or generated audio storage can be blocked
            unless approved.

        - Memory Agent:
            Stores safe speech metadata and optionally the spoken text.

        - Verification Agent:
            Confirms provider, voice, language, output format, and interruption state.

        - Dashboard/API:
            Results are structured for task history, streaming partials, analytics,
            session logs, and audit trails.

        - Agent Registry / Loader:
            Public metadata is exposed through get_agent_manifest().
    """

    def __init__(
        self,
        config: Optional[TTSEngineConfig] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        provider_callbacks: Optional[Dict[str, Callable[..., Dict[str, Any]]]] = None,
        playback_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="TTSEngine", agent_type="voice_agent", **kwargs)

        self.config = config or TTSEngineConfig()
        self.status = TTSStatus.READY

        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.security_callback = security_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback
        self.playback_callback = playback_callback

        self.provider_callbacks = provider_callbacks or {}

        self._active_streams: Dict[str, Dict[str, Any]] = {}
        self._active_jobs: Dict[str, Dict[str, Any]] = {}
        self._interrupted_jobs: Dict[str, Dict[str, Any]] = {}

    # -----------------------------------------------------------------
    # Public metadata
    # -----------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Registry/Loader compatible manifest.
        """

        return self._safe_result(
            message="TTSEngine manifest loaded.",
            data={
                "agent_name": "TTSEngine",
                "agent_type": "voice_agent",
                "module": "agents.voice_agent.tts_engine",
                "class_name": "TTSEngine",
                "version": "1.0.0",
                "status": self.status.value,
                "capabilities": [
                    "text_to_speech",
                    "language_voice_selection",
                    "voice_styles",
                    "volume_control",
                    "rate_control",
                    "pitch_control",
                    "streaming_tts_interface",
                    "interruption_support",
                    "pause_resume_stop_commands",
                    "provider_callback_routing",
                    "saas_context_validation",
                    "audit_event_payloads",
                    "memory_payloads",
                    "verification_payloads",
                    "dashboard_api_ready_results",
                ],
                "public_methods": [
                    "speak",
                    "synthesize",
                    "synthesize_stream",
                    "start_stream",
                    "push_stream_text",
                    "finish_stream",
                    "interrupt",
                    "stop",
                    "pause",
                    "resume",
                    "cancel_stream",
                    "list_voices",
                    "get_voice",
                    "register_voice",
                    "get_config",
                    "update_config",
                    "health_check",
                    "reset_runtime_state",
                ],
                "supported_providers": [provider.value for provider in TTSProvider],
                "supported_languages": self.config.supported_languages,
                "supported_styles": [style.value for style in VoiceStyle],
                "supported_output_formats": [fmt.value for fmt in TTSOutputFormat],
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Returns TTSEngine health for dashboard/API.
        """

        try:
            return self._safe_result(
                message="TTSEngine is healthy.",
                data={
                    "status": self.status.value,
                    "default_provider": self.config.default_provider.value,
                    "default_language": self.config.default_language,
                    "default_voice_id": self.config.default_voice_id,
                    "streaming_enabled": self.config.enable_streaming,
                    "interruption_enabled": self.config.enable_interruption,
                    "styles_enabled": self.config.enable_styles,
                    "cloud_tts_allowed": self.config.allow_cloud_tts,
                    "voice_cloning_allowed": self.config.allow_voice_cloning,
                    "store_generated_audio": self.config.store_generated_audio,
                    "provider_callbacks": sorted(list(self.provider_callbacks.keys())),
                    "active_streams": len(self._active_streams),
                    "active_jobs": len(self._active_jobs),
                    "registered_voices": len(self.config.voice_map),
                },
            )
        except Exception as exc:
            return self._error_result("TTSEngine health check failed.", exc)

    # -----------------------------------------------------------------
    # Config methods
    # -----------------------------------------------------------------

    def get_config(self) -> Dict[str, Any]:
        """
        Returns safe config snapshot.
        """

        config = asdict(self.config)
        config["default_provider"] = self.config.default_provider.value
        config["provider_order"] = [
            provider.value if isinstance(provider, TTSProvider) else str(provider)
            for provider in self.config.provider_order
        ]
        config["default_style"] = self.config.default_style.value
        config["output_format"] = self.config.output_format.value

        return self._safe_result(
            message="TTS config loaded.",
            data=config,
        )

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates config safely.

        Args:
            updates: Dictionary of TTSEngineConfig fields.

        Returns:
            Structured result.
        """

        try:
            if not isinstance(updates, dict):
                return self._error_result(
                    "TTS config update failed.",
                    ValueError("updates must be a dictionary."),
                )

            valid_fields = set(TTSEngineConfig.__dataclass_fields__.keys())
            changed: Dict[str, Any] = {}

            for key, value in updates.items():
                if key not in valid_fields:
                    continue

                if key == "default_provider":
                    value = self._parse_provider(value)

                if key == "provider_order":
                    value = [self._parse_provider(item) for item in value]

                if key == "default_style":
                    value = self._parse_style(value)

                if key == "output_format":
                    value = self._parse_output_format(value)

                setattr(self.config, key, value)

                if isinstance(value, Enum):
                    changed[key] = value.value
                elif isinstance(value, list):
                    changed[key] = [
                        item.value if isinstance(item, Enum) else item
                        for item in value
                    ]
                else:
                    changed[key] = value

            self._emit_agent_event(
                event_type="tts_config_updated",
                payload={
                    "changed_keys": list(changed.keys()),
                },
            )

            return self._safe_result(
                message="TTS config updated.",
                data={
                    "changed": changed,
                    "config": self.get_config().get("data", {}),
                },
            )

        except Exception as exc:
            return self._error_result("TTS config update failed.", exc)

    def reset_runtime_state(self) -> Dict[str, Any]:
        """
        Clears active streams/jobs and resets status.
        """

        try:
            self._active_streams.clear()
            self._active_jobs.clear()
            self._interrupted_jobs.clear()
            self.status = TTSStatus.READY

            return self._safe_result(
                message="TTSEngine runtime state reset.",
                data={
                    "status": self.status.value,
                    "active_streams": 0,
                    "active_jobs": 0,
                    "interrupted_jobs": 0,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to reset TTSEngine runtime state.", exc)

    # -----------------------------------------------------------------
    # Voice profile methods
    # -----------------------------------------------------------------

    def list_voices(
        self,
        language: Optional[str] = None,
        provider: Optional[Union[TTSProvider, str]] = None,
    ) -> Dict[str, Any]:
        """
        Lists available voice profiles.
        """

        try:
            selected_language = self._validate_language(language) if language else None
            selected_provider = self._parse_provider(provider) if provider else None

            voices = []

            for voice_id, voice in self.config.voice_map.items():
                if selected_language and voice.get("language") != selected_language:
                    continue

                if selected_provider and voice.get("provider") != selected_provider.value:
                    continue

                voices.append(
                    {
                        "voice_id": voice_id,
                        **voice,
                    }
                )

            return self._safe_result(
                message="Voice profiles loaded.",
                data={
                    "voices": voices,
                    "count": len(voices),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to list voice profiles.", exc)

    def get_voice(self, voice_id: str) -> Dict[str, Any]:
        """
        Gets one voice profile.
        """

        try:
            voice = self.config.voice_map.get(voice_id)

            if not voice:
                return self._error_result(
                    "Voice profile not found.",
                    KeyError(voice_id),
                )

            return self._safe_result(
                message="Voice profile loaded.",
                data={
                    "voice_id": voice_id,
                    **voice,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get voice profile.", exc)

    def register_voice(
        self,
        voice_id: str,
        voice_data: Dict[str, Any],
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Registers or updates a voice profile.

        This does not clone a voice. It only registers a profile reference.
        """

        try:
            validation = self._validate_task_context(context, allow_missing=True)
            if not validation["success"]:
                return validation

            if not isinstance(voice_id, str) or not voice_id.strip():
                return self._error_result(
                    "Voice registration failed.",
                    ValueError("voice_id must be a non-empty string."),
                )

            if not isinstance(voice_data, dict):
                return self._error_result(
                    "Voice registration failed.",
                    ValueError("voice_data must be a dictionary."),
                )

            normalized_voice_id = self._safe_identifier(voice_id)

            safe_voice_data = {
                "voice_id": normalized_voice_id,
                "name": str(voice_data.get("name", normalized_voice_id)),
                "language": self._validate_language(voice_data.get("language", self.config.default_language)),
                "gender": str(voice_data.get("gender", "neutral")),
                "provider": str(voice_data.get("provider", TTSProvider.MOCK.value)),
                "description": str(voice_data.get("description", "")),
                "style_tags": list(voice_data.get("style_tags", []) or []),
                "metadata": dict(voice_data.get("metadata", {}) or {}),
            }

            self.config.voice_map[normalized_voice_id] = safe_voice_data

            self._log_audit_event(
                action="tts_voice_registered",
                context=context,
                details={
                    "voice_id": normalized_voice_id,
                    "language": safe_voice_data["language"],
                    "provider": safe_voice_data["provider"],
                },
            )

            return self._safe_result(
                message="Voice profile registered.",
                data=safe_voice_data,
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            return self._error_result("Voice registration failed.", exc)

    # -----------------------------------------------------------------
    # Main TTS methods
    # -----------------------------------------------------------------

    def speak(
        self,
        text: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        voice_id: Optional[str] = None,
        style: Optional[Union[VoiceStyle, str]] = None,
        volume: Optional[float] = None,
        rate: Optional[float] = None,
        pitch: Optional[float] = None,
        provider: Optional[Union[TTSProvider, str]] = None,
        output_format: Optional[Union[TTSOutputFormat, str]] = None,
        stream: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        High-level speech method.

        It synthesizes speech and sends a playback-ready command to
        playback_callback if configured.

        Without playback_callback, it still returns generated audio payloads.
        """

        try:
            result = self.synthesize(
                text=text,
                context=context,
                language=language,
                voice_id=voice_id,
                style=style,
                volume=volume,
                rate=rate,
                pitch=pitch,
                provider=provider,
                output_format=output_format,
                stream=stream,
                metadata=metadata,
            )

            if not result.get("success"):
                return result

            playback_payload = {
                "command": PlaybackCommand.SPEAK.value,
                "job_id": result["data"].get("job_id"),
                "audio_base64": result["data"].get("audio_base64"),
                "audio_path": result["data"].get("audio_path"),
                "audio_url": result["data"].get("audio_url"),
                "output_format": result["data"].get("output_format"),
                "volume": result["data"].get("volume"),
                "rate": result["data"].get("rate"),
                "pitch": result["data"].get("pitch"),
                "context": self._context_to_public_dict(context),
                "metadata": metadata or {},
            }

            playback_result = self._send_playback_command(playback_payload)

            result["data"]["playback"] = playback_result.get("data", {})
            result["metadata"]["playback_message"] = playback_result.get("message")

            return result

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result("TTS speak failed.", exc)

    def synthesize(
        self,
        text: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        voice_id: Optional[str] = None,
        style: Optional[Union[VoiceStyle, str]] = None,
        volume: Optional[float] = None,
        rate: Optional[float] = None,
        pitch: Optional[float] = None,
        provider: Optional[Union[TTSProvider, str]] = None,
        output_format: Optional[Union[TTSOutputFormat, str]] = None,
        stream: bool = False,
        ssml: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Converts text to speech payload.

        Returns:
            Structured result with audio bytes encoded as base64 when available.
        """

        try:
            self.status = TTSStatus.SYNTHESIZING

            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = TTSStatus.ERROR
                return validation

            request = self._build_tts_request(
                text=text,
                language=language,
                voice_id=voice_id,
                style=style,
                volume=volume,
                rate=rate,
                pitch=pitch,
                provider=provider,
                output_format=output_format,
                stream=stream,
                ssml=ssml,
                metadata=metadata,
            )

            if self._requires_security_check(request, context=context):
                approval = self._request_security_approval(
                    action="synthesize_speech",
                    context=context,
                    details={
                        "provider": request.provider.value,
                        "language": request.language,
                        "voice_id": request.voice_id,
                        "style": request.style.value,
                        "output_format": request.output_format.value,
                        "text_length": len(request.text),
                        "ssml": request.ssml,
                    },
                )
                if not approval["success"]:
                    self.status = TTSStatus.ERROR
                    return approval

            tts_result = self._run_provider(
                request=request,
                context=context,
            )

            return self._finalize_tts_result(tts_result, context=context)

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result("TTS synthesis failed.", exc)

    def synthesize_stream(
        self,
        text: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        voice_id: Optional[str] = None,
        style: Optional[Union[VoiceStyle, str]] = None,
        volume: Optional[float] = None,
        rate: Optional[float] = None,
        pitch: Optional[float] = None,
        provider: Optional[Union[TTSProvider, str]] = None,
        output_format: Optional[Union[TTSOutputFormat, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a streaming TTS job and returns chunk metadata.

        Provider callback can implement true streaming. Without callback,
        text is split into safe chunks and each chunk can be synthesized later.
        """

        try:
            if not self.config.enable_streaming:
                return self._error_result(
                    "Streaming TTS is disabled.",
                    PermissionError("enable_streaming is False."),
                )

            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            stream = self.start_stream(
                context=context,
                language=language,
                voice_id=voice_id,
                style=style,
                volume=volume,
                rate=rate,
                pitch=pitch,
                provider=provider,
                output_format=output_format,
                metadata=metadata,
            )

            if not stream.get("success"):
                return stream

            stream_id = stream["data"]["stream_id"]

            pushed = self.push_stream_text(
                stream_id=stream_id,
                text=text,
                context=context,
                metadata=metadata,
            )

            if not pushed.get("success"):
                return pushed

            return self.finish_stream(
                stream_id=stream_id,
                context=context,
                metadata=metadata,
            )

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result("Streaming TTS synthesis failed.", exc)

    # -----------------------------------------------------------------
    # Streaming interface
    # -----------------------------------------------------------------

    def start_stream(
        self,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        stream_id: Optional[str] = None,
        language: Optional[str] = None,
        voice_id: Optional[str] = None,
        style: Optional[Union[VoiceStyle, str]] = None,
        volume: Optional[float] = None,
        rate: Optional[float] = None,
        pitch: Optional[float] = None,
        provider: Optional[Union[TTSProvider, str]] = None,
        output_format: Optional[Union[TTSOutputFormat, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Starts a streaming TTS session.

        This does not play audio. It creates a stream state that future text
        chunks can use.
        """

        try:
            if not self.config.enable_streaming:
                return self._error_result(
                    "Streaming TTS is disabled.",
                    PermissionError("enable_streaming is False."),
                )

            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            sid = stream_id or str(uuid.uuid4())

            if sid in self._active_streams:
                return self._error_result(
                    "TTS stream already exists.",
                    ValueError(f"stream_id already active: {sid}"),
                )

            stream_state = {
                "stream_id": sid,
                "language": self._validate_language(language or self.config.default_language),
                "voice_id": self._validate_voice_id(voice_id),
                "style": self._parse_style(style or self.config.default_style).value,
                "volume": self._clamp_float(volume, self.config.default_volume, self.config.min_volume, self.config.max_volume),
                "rate": self._clamp_float(rate, self.config.default_rate, self.config.min_rate, self.config.max_rate),
                "pitch": self._clamp_float(pitch, self.config.default_pitch, self.config.min_pitch, self.config.max_pitch),
                "provider": self._parse_provider(provider or self.config.default_provider).value,
                "output_format": self._parse_output_format(output_format or self.config.output_format).value,
                "text_chunks": [],
                "audio_chunks": [],
                "created_at": time.time(),
                "status": TTSStatus.STREAMING.value,
                "context": self._context_to_public_dict(context),
                "metadata": metadata or {},
            }

            self._active_streams[sid] = stream_state
            self.status = TTSStatus.STREAMING

            self._emit_agent_event(
                event_type="tts_stream_started",
                payload={
                    "stream_id": sid,
                    "language": stream_state["language"],
                    "voice_id": stream_state["voice_id"],
                    "context": self._context_to_public_dict(context),
                },
            )

            return self._safe_result(
                message="TTS stream started.",
                data={
                    "stream_id": sid,
                    "status": self.status.value,
                    "language": stream_state["language"],
                    "voice_id": stream_state["voice_id"],
                    "style": stream_state["style"],
                    "provider": stream_state["provider"],
                    "output_format": stream_state["output_format"],
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result("Failed to start TTS stream.", exc)

    def push_stream_text(
        self,
        stream_id: str,
        text: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Pushes text into an active TTS stream.
        """

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            if stream_id not in self._active_streams:
                return self._error_result(
                    "TTS stream not found.",
                    KeyError(stream_id),
                )

            clean_text = self._prepare_text(text, ssml=False)

            if not clean_text:
                return self._error_result(
                    "Stream text is empty.",
                    ValueError("text cannot be empty."),
                )

            if len(clean_text) > self.config.max_stream_text_chars:
                chunks = self._chunk_text(clean_text, self.config.stream_chunk_chars)
            else:
                chunks = [clean_text]

            self._active_streams[stream_id]["text_chunks"].extend(chunks)

            self._emit_agent_event(
                event_type="tts_stream_text_pushed",
                payload={
                    "stream_id": stream_id,
                    "chunks_added": len(chunks),
                    "text_length": len(clean_text),
                    "context": self._context_to_public_dict(context),
                    **(metadata or {}),
                },
            )

            return self._safe_result(
                message="TTS stream text accepted.",
                data={
                    "stream_id": stream_id,
                    "chunks_added": len(chunks),
                    "total_chunks": len(self._active_streams[stream_id]["text_chunks"]),
                    "text_length": len(clean_text),
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result("Failed to push TTS stream text.", exc)

    def finish_stream(
        self,
        stream_id: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Finishes a TTS stream and synthesizes the accumulated text.
        """

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            if stream_id not in self._active_streams:
                return self._error_result(
                    "TTS stream not found.",
                    KeyError(stream_id),
                )

            stream_state = self._active_streams.pop(stream_id)
            text = " ".join(stream_state.get("text_chunks", [])).strip()

            if not text:
                return self._error_result(
                    "TTS stream has no text.",
                    ValueError("No text chunks were pushed into the stream."),
                )

            result = self.synthesize(
                text=text,
                context=context,
                language=stream_state.get("language"),
                voice_id=stream_state.get("voice_id"),
                style=stream_state.get("style"),
                volume=stream_state.get("volume"),
                rate=stream_state.get("rate"),
                pitch=stream_state.get("pitch"),
                provider=stream_state.get("provider"),
                output_format=stream_state.get("output_format"),
                stream=True,
                metadata={
                    **(metadata or {}),
                    "stream_id": stream_id,
                    "stream_chunks": len(stream_state.get("text_chunks", [])),
                    "stream_age_seconds": round(time.time() - stream_state.get("created_at", time.time()), 4),
                },
            )

            self._emit_agent_event(
                event_type="tts_stream_finished",
                payload={
                    "stream_id": stream_id,
                    "context": self._context_to_public_dict(context),
                },
            )

            return result

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result("Failed to finish TTS stream.", exc)

    def cancel_stream(
        self,
        stream_id: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        reason: str = "cancelled_by_user",
    ) -> Dict[str, Any]:
        """
        Cancels an active TTS stream.
        """

        try:
            validation = self._validate_task_context(context, allow_missing=True)
            if not validation["success"]:
                return validation

            existed = stream_id in self._active_streams
            stream_state = self._active_streams.pop(stream_id, None)

            self._emit_agent_event(
                event_type="tts_stream_cancelled",
                payload={
                    "stream_id": stream_id,
                    "existed": existed,
                    "reason": reason,
                    "context": self._context_to_public_dict(context),
                },
            )

            return self._safe_result(
                message="TTS stream cancelled." if existed else "TTS stream was not active.",
                data={
                    "stream_id": stream_id,
                    "cancelled": existed,
                    "reason": reason,
                    "stream_state": {
                        "created_at": stream_state.get("created_at") if stream_state else None,
                        "chunks": len(stream_state.get("text_chunks", [])) if stream_state else 0,
                    },
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to cancel TTS stream.", exc)

    # -----------------------------------------------------------------
    # Interruption / playback control
    # -----------------------------------------------------------------

    def interrupt(
        self,
        job_id: Optional[str] = None,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        reason: str = "user_interrupted",
    ) -> Dict[str, Any]:
        """
        Interrupts current or selected TTS job.
        """

        return self._handle_playback_command(
            command=PlaybackCommand.INTERRUPT,
            job_id=job_id,
            context=context,
            reason=reason,
        )

    def stop(
        self,
        job_id: Optional[str] = None,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        reason: str = "user_stopped",
    ) -> Dict[str, Any]:
        """
        Stops current or selected TTS job.
        """

        return self._handle_playback_command(
            command=PlaybackCommand.STOP,
            job_id=job_id,
            context=context,
            reason=reason,
        )

    def pause(
        self,
        job_id: Optional[str] = None,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        reason: str = "user_paused",
    ) -> Dict[str, Any]:
        """
        Pauses current or selected TTS job.
        """

        return self._handle_playback_command(
            command=PlaybackCommand.PAUSE,
            job_id=job_id,
            context=context,
            reason=reason,
        )

    def resume(
        self,
        job_id: Optional[str] = None,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        reason: str = "user_resumed",
    ) -> Dict[str, Any]:
        """
        Resumes current or selected TTS job.
        """

        return self._handle_playback_command(
            command=PlaybackCommand.RESUME,
            job_id=job_id,
            context=context,
            reason=reason,
        )

    def _handle_playback_command(
        self,
        command: PlaybackCommand,
        job_id: Optional[str],
        context: Optional[Union[TTSContext, Dict[str, Any]]],
        reason: str,
    ) -> Dict[str, Any]:
        """
        Handles interruption/playback command safely.
        """

        try:
            if not self.config.enable_interruption and command in {
                PlaybackCommand.INTERRUPT,
                PlaybackCommand.STOP,
                PlaybackCommand.PAUSE,
                PlaybackCommand.RESUME,
            }:
                return self._error_result(
                    "TTS interruption support is disabled.",
                    PermissionError("enable_interruption is False."),
                )

            validation = self._validate_task_context(context, allow_missing=True)
            if not validation["success"]:
                return validation

            target_job_id = job_id or self._latest_job_id()

            payload = {
                "command": command.value,
                "job_id": target_job_id,
                "reason": reason,
                "context": self._context_to_public_dict(context),
                "timestamp": time.time(),
            }

            playback_result = self._send_playback_command(payload)

            if command in {PlaybackCommand.INTERRUPT, PlaybackCommand.STOP, PlaybackCommand.CANCEL}:
                self.status = TTSStatus.INTERRUPTED

                if target_job_id:
                    job = self._active_jobs.pop(target_job_id, None)
                    self._interrupted_jobs[target_job_id] = {
                        "job_id": target_job_id,
                        "reason": reason,
                        "interrupted_at": time.time(),
                        "job": job,
                    }

            elif command == PlaybackCommand.PAUSE:
                self.status = TTSStatus.PAUSED

            elif command == PlaybackCommand.RESUME:
                self.status = TTSStatus.READY

            self._emit_agent_event(
                event_type=f"tts_{command.value}",
                payload=payload,
            )

            self._log_audit_event(
                action=f"tts_{command.value}",
                context=context,
                details={
                    "job_id": target_job_id,
                    "reason": reason,
                },
            )

            return self._safe_result(
                message=f"TTS {command.value} command processed.",
                data={
                    "command": command.value,
                    "job_id": target_job_id,
                    "reason": reason,
                    "status": self.status.value,
                    "playback": playback_result.get("data", {}),
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            self.status = TTSStatus.ERROR
            return self._error_result(f"TTS {command.value} command failed.", exc)

    # -----------------------------------------------------------------
    # Provider routing
    # -----------------------------------------------------------------

    def _run_provider(
        self,
        request: TTSRequest,
        context: Optional[Union[TTSContext, Dict[str, Any]]],
    ) -> TTSResult:
        """
        Routes TTS request to selected provider.

        Real TTS providers can be injected through provider_callbacks:
            {
                "local": callable,
                "browser": callable,
                "mobile": callable,
                "cloud": callable,
                "mock": callable
            }

        Callback expected output:
            {
                "success": True,
                "audio_bytes": b"...",
                "audio_base64": "...",
                "audio_path": "/tmp/file.wav",
                "audio_url": "https://...",
                "duration_seconds": 1.25,
                "sample_rate": 24000,
                "channels": 1,
                "message": "Generated"
            }
        """

        if request.provider == TTSProvider.AUTO:
            provider_order = list(self.config.provider_order)

            if self.config.allow_cloud_tts and TTSProvider.CLOUD not in provider_order:
                provider_order.append(TTSProvider.CLOUD)

            if TTSProvider.MOCK not in provider_order:
                provider_order.append(TTSProvider.MOCK)
        else:
            provider_order = [request.provider]

        last_error: Optional[str] = None

        for selected in provider_order:
            if selected == TTSProvider.CLOUD and not self.config.allow_cloud_tts:
                last_error = "Cloud TTS is disabled."
                continue

            callback = self.provider_callbacks.get(selected.value)

            if callback:
                try:
                    response = callback(
                        text=request.text,
                        language=request.language,
                        voice_id=request.voice_id,
                        style=request.style.value,
                        volume=request.volume,
                        rate=request.rate,
                        pitch=request.pitch,
                        output_format=request.output_format.value,
                        stream=request.stream,
                        context=self._context_to_dict(context),
                        metadata=request.metadata,
                    )

                    result = self._provider_response_to_result(
                        response=response,
                        provider=selected,
                        request=request,
                    )

                    if result.success:
                        return result

                    last_error = result.message or "TTS provider returned failed result."

                except Exception as exc:
                    last_error = f"{selected.value} failed: {exc}"
                    logger.debug(last_error)

            if selected == TTSProvider.MOCK:
                return self._mock_synthesis(
                    request=request,
                    metadata={
                        "fallback_reason": last_error,
                    },
                )

        return TTSResult(
            success=False,
            provider=request.provider,
            text=request.text,
            language=request.language,
            voice_id=request.voice_id,
            style=request.style,
            output_format=request.output_format,
            volume=request.volume,
            rate=request.rate,
            pitch=request.pitch,
            is_stream=request.stream,
            message=last_error or "No TTS provider available.",
            raw_metadata=request.metadata,
        )

    def _provider_response_to_result(
        self,
        response: Dict[str, Any],
        provider: TTSProvider,
        request: TTSRequest,
    ) -> TTSResult:
        """
        Converts provider callback response into TTSResult.
        """

        if not isinstance(response, dict):
            return TTSResult(
                success=False,
                provider=provider,
                text=request.text,
                language=request.language,
                voice_id=request.voice_id,
                style=request.style,
                output_format=request.output_format,
                volume=request.volume,
                rate=request.rate,
                pitch=request.pitch,
                is_stream=request.stream,
                message="Provider response must be a dictionary.",
                raw_metadata=request.metadata,
            )

        audio_bytes = response.get("audio_bytes")
        if isinstance(audio_bytes, bytearray):
            audio_bytes = bytes(audio_bytes)
        if not isinstance(audio_bytes, bytes):
            audio_bytes = None

        audio_base64 = response.get("audio_base64")
        if not audio_base64 and audio_bytes:
            audio_base64 = base64.b64encode(audio_bytes).decode("utf-8")

        return TTSResult(
            success=bool(response.get("success", bool(audio_bytes or audio_base64 or response.get("audio_url") or response.get("audio_path")))),
            provider=provider,
            text=request.text,
            language=str(response.get("language", request.language)),
            voice_id=str(response.get("voice_id", request.voice_id)),
            style=request.style,
            output_format=request.output_format,
            audio_bytes=audio_bytes,
            audio_base64=str(audio_base64) if audio_base64 else None,
            audio_path=str(response.get("audio_path")) if response.get("audio_path") else None,
            audio_url=str(response.get("audio_url")) if response.get("audio_url") else None,
            duration_seconds=self._safe_optional_float(response.get("duration_seconds")),
            sample_rate=self._safe_optional_int(response.get("sample_rate")) or self.config.sample_rate,
            channels=self._safe_optional_int(response.get("channels")) or self.config.channels,
            volume=request.volume,
            rate=request.rate,
            pitch=request.pitch,
            is_stream=request.stream,
            stream_id=str(response.get("stream_id")) if response.get("stream_id") else None,
            message=str(response.get("message", "TTS provider synthesis completed.")),
            raw_metadata={
                **request.metadata,
                "provider_raw_metadata": response.get("metadata", {}),
            },
        )

    def _mock_synthesis(
        self,
        request: TTSRequest,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TTSResult:
        """
        Safe fallback mock provider.

        Generates a tiny silent WAV payload so integration can be tested
        without external TTS engines. It does not pretend to be real voice.
        """

        audio_bytes = self._generate_silent_wav(
            duration_seconds=max(0.15, min(1.5, len(request.text) / 180.0)),
            sample_rate=self.config.sample_rate,
            channels=self.config.channels,
            sample_width=self.config.sample_width,
        )

        return TTSResult(
            success=True,
            provider=TTSProvider.MOCK,
            text=request.text,
            language=request.language,
            voice_id=request.voice_id,
            style=request.style,
            output_format=TTSOutputFormat.WAV,
            audio_bytes=audio_bytes,
            audio_base64=base64.b64encode(audio_bytes).decode("utf-8"),
            duration_seconds=max(0.15, min(1.5, len(request.text) / 180.0)),
            sample_rate=self.config.sample_rate,
            channels=self.config.channels,
            volume=request.volume,
            rate=request.rate,
            pitch=request.pitch,
            is_stream=request.stream,
            message=(
                "Mock TTS generated silent WAV test audio. "
                "Connect a real local/browser/mobile/cloud provider for natural speech."
            ),
            raw_metadata={
                **request.metadata,
                **(metadata or {}),
                "mock_provider": True,
                "text_length": len(request.text),
            },
        )

    # -----------------------------------------------------------------
    # Finalization
    # -----------------------------------------------------------------

    def _finalize_tts_result(
        self,
        tts_result: TTSResult,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Finalizes TTS result with event, audit, memory, verification payloads.
        """

        job_id = str(uuid.uuid4())

        audio_hash = None
        audio_size = 0

        if tts_result.audio_bytes:
            audio_size = len(tts_result.audio_bytes)
            if self.config.enable_audio_hashing:
                audio_hash = hashlib.sha256(tts_result.audio_bytes).hexdigest()

        self.status = TTSStatus.READY if tts_result.success else TTSStatus.ERROR

        self._active_jobs[job_id] = {
            "job_id": job_id,
            "provider": tts_result.provider.value,
            "language": tts_result.language,
            "voice_id": tts_result.voice_id,
            "style": tts_result.style.value,
            "text_length": len(tts_result.text),
            "created_at": time.time(),
            "status": self.status.value,
        }

        verification_payload = (
            self._prepare_verification_payload(tts_result, context, job_id=job_id)
            if self.config.verification_enabled
            else None
        )

        memory_payload = (
            self._prepare_memory_payload(tts_result, context, job_id=job_id)
            if self.config.memory_enabled
            else None
        )

        event_type = "tts_synthesis_completed" if tts_result.success else "tts_synthesis_failed"

        self._emit_agent_event(
            event_type=event_type,
            payload={
                "job_id": job_id,
                "provider": tts_result.provider.value,
                "language": tts_result.language,
                "voice_id": tts_result.voice_id,
                "style": tts_result.style.value,
                "output_format": tts_result.output_format.value,
                "text_length": len(tts_result.text),
                "audio_size": audio_size,
                "is_stream": tts_result.is_stream,
                "context": self._context_to_public_dict(context),
            },
        )

        self._log_audit_event(
            action=event_type,
            context=context,
            details={
                "job_id": job_id,
                "provider": tts_result.provider.value,
                "language": tts_result.language,
                "voice_id": tts_result.voice_id,
                "style": tts_result.style.value,
                "output_format": tts_result.output_format.value,
                "text_length": len(tts_result.text),
                "audio_size": audio_size,
                "is_stream": tts_result.is_stream,
            },
        )

        if tts_result.success and self.memory_callback and memory_payload:
            try:
                self.memory_callback(memory_payload)
            except Exception:
                logger.exception("Failed to send TTS payload to Memory Agent.")

        if self.verification_callback and verification_payload:
            try:
                self.verification_callback(verification_payload)
            except Exception:
                logger.exception("Failed to send TTS payload to Verification Agent.")

        return self._safe_result(
            message=tts_result.message or "TTS synthesis completed.",
            data={
                "job_id": job_id,
                "success": tts_result.success,
                "provider": tts_result.provider.value,
                "text": tts_result.text,
                "text_length": len(tts_result.text),
                "language": tts_result.language,
                "voice_id": tts_result.voice_id,
                "style": tts_result.style.value,
                "output_format": tts_result.output_format.value,
                "audio_base64": tts_result.audio_base64,
                "audio_path": tts_result.audio_path,
                "audio_url": tts_result.audio_url,
                "audio_hash": audio_hash,
                "audio_size": audio_size,
                "duration_seconds": tts_result.duration_seconds,
                "sample_rate": tts_result.sample_rate,
                "channels": tts_result.channels,
                "volume": tts_result.volume,
                "rate": tts_result.rate,
                "pitch": tts_result.pitch,
                "is_stream": tts_result.is_stream,
                "stream_id": tts_result.stream_id,
                "status": self.status.value,
            },
            metadata={
                "context": self._context_to_public_dict(context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "raw_metadata": tts_result.raw_metadata,
                "request_id": self._get_request_id(context),
            },
        )

    # -----------------------------------------------------------------
    # Request building / validation
    # -----------------------------------------------------------------

    def _build_tts_request(
        self,
        text: str,
        language: Optional[str],
        voice_id: Optional[str],
        style: Optional[Union[VoiceStyle, str]],
        volume: Optional[float],
        rate: Optional[float],
        pitch: Optional[float],
        provider: Optional[Union[TTSProvider, str]],
        output_format: Optional[Union[TTSOutputFormat, str]],
        stream: bool,
        ssml: bool,
        metadata: Optional[Dict[str, Any]],
    ) -> TTSRequest:
        """
        Builds and validates a TTSRequest.
        """

        selected_language = self._validate_language(language or self.config.default_language)
        selected_voice_id = self._validate_voice_id(voice_id, selected_language)
        selected_style = self._parse_style(style or self.config.default_style)
        selected_provider = self._parse_provider(provider or self.config.default_provider)
        selected_format = self._parse_output_format(output_format or self.config.output_format)

        clean_text = self._prepare_text(text, ssml=ssml)

        if not clean_text:
            raise ValueError("text cannot be empty.")

        if len(clean_text) > self.config.max_text_chars:
            raise ValueError(
                f"text length {len(clean_text)} exceeds max_text_chars {self.config.max_text_chars}."
            )

        if ssml and not self.config.enable_ssml:
            raise PermissionError("SSML is disabled in TTSEngineConfig.")

        return TTSRequest(
            text=clean_text,
            language=selected_language,
            voice_id=selected_voice_id,
            style=selected_style,
            volume=self._clamp_float(volume, self.config.default_volume, self.config.min_volume, self.config.max_volume),
            rate=self._clamp_float(rate, self.config.default_rate, self.config.min_rate, self.config.max_rate),
            pitch=self._clamp_float(pitch, self.config.default_pitch, self.config.min_pitch, self.config.max_pitch),
            provider=selected_provider,
            output_format=selected_format,
            stream=stream,
            ssml=ssml,
            metadata=metadata or {},
        )

    def _prepare_text(self, text: str, ssml: bool = False) -> str:
        """
        Cleans text for TTS.

        If SSML is enabled and ssml=True, it preserves basic XML-like tags.
        """

        if not isinstance(text, str):
            text = str(text)

        cleaned = text.strip()

        if not cleaned:
            return ""

        if not ssml and self.config.enable_text_cleanup:
            cleaned = re.sub(r"<[^>]+>", "", cleaned)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            cleaned = cleaned.replace("```", "")
            cleaned = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", cleaned)

        if ssml:
            cleaned = re.sub(r"\s+", " ", cleaned).strip()

        return cleaned

    def _chunk_text(self, text: str, chunk_chars: int) -> List[str]:
        """
        Splits text into natural chunks for streaming.
        """

        if len(text) <= chunk_chars:
            return [text]

        sentences = re.split(r"(?<=[.!?])\s+", text)
        chunks: List[str] = []
        current = ""

        for sentence in sentences:
            if not sentence:
                continue

            if len(current) + len(sentence) + 1 <= chunk_chars:
                current = f"{current} {sentence}".strip()
            else:
                if current:
                    chunks.append(current)
                current = sentence

        if current:
            chunks.append(current)

        final_chunks: List[str] = []

        for chunk in chunks:
            if len(chunk) <= chunk_chars:
                final_chunks.append(chunk)
            else:
                for index in range(0, len(chunk), chunk_chars):
                    final_chunks.append(chunk[index:index + chunk_chars])

        return final_chunks

    # -----------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Union[TTSContext, Dict[str, Any]]],
        allow_missing: bool = False,
    ) -> Dict[str, Any]:
        """
        Validates SaaS user/workspace context.

        Prevents speech jobs, logs, task history, generated audio metadata,
        and analytics from mixing between users/workspaces.
        """

        if allow_missing and context is None:
            return self._safe_result(
                message="Context validation skipped because missing context is allowed.",
                data={"valid": True},
            )

        if context is None:
            if self.config.require_user_context or self.config.require_workspace_context:
                return self._error_result(
                    "Context validation failed.",
                    ValueError("user_id and workspace_id are required."),
                    metadata={"missing_context": True},
                )

            return self._safe_result(
                message="Context validation passed.",
                data={"valid": True},
            )

        ctx = self._context_to_dict(context)
        user_id = ctx.get("user_id")
        workspace_id = ctx.get("workspace_id")

        if self.config.require_user_context and (user_id is None or str(user_id).strip() == ""):
            return self._error_result(
                "Context validation failed.",
                ValueError("user_id is required."),
                metadata={"missing_user_id": True},
            )

        if self.config.require_workspace_context and (
            workspace_id is None or str(workspace_id).strip() == ""
        ):
            return self._error_result(
                "Context validation failed.",
                ValueError("workspace_id is required."),
                metadata={"missing_workspace_id": True},
            )

        return self._safe_result(
            message="Context validation passed.",
            data={
                "valid": True,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(
        self,
        request: TTSRequest,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
    ) -> bool:
        """
        Determines if Security Agent approval is required.

        Security required when:
            - cloud TTS is requested
            - voice cloning is requested/enabled
            - generated audio storage is enabled
            - SSML is requested
            - context is invalid
        """

        context_valid = self._validate_task_context(context)
        if not context_valid.get("success"):
            return True

        if request.provider == TTSProvider.CLOUD:
            return True

        if self.config.allow_voice_cloning:
            return True

        if self.config.store_generated_audio:
            return True

        if request.ssml:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Requests Security Agent approval through callback if available.
        """

        payload = {
            "action": action,
            "agent": "TTSEngine",
            "agent_type": "voice_agent",
            "context": self._context_to_public_dict(context),
            "details": details or {},
            "timestamp": time.time(),
        }

        if self.security_callback is None:
            provider = str((details or {}).get("provider", ""))

            if provider == TTSProvider.CLOUD.value:
                return self._error_result(
                    "Security approval required for cloud TTS.",
                    PermissionError(
                        "Cloud TTS requested but security_callback is not configured."
                    ),
                    metadata={"security_payload": payload},
                )

            if self.config.allow_voice_cloning:
                return self._error_result(
                    "Security approval required for voice cloning.",
                    PermissionError(
                        "Voice cloning is enabled but security_callback is not configured."
                    ),
                    metadata={"security_payload": payload},
                )

            return self._safe_result(
                message="Security callback not configured; default local approval applied.",
                data={
                    "approved": True,
                    "fallback": True,
                    "payload": payload,
                },
            )

        try:
            response = self.security_callback(payload)
            approved = bool(response.get("approved", response.get("success", False)))

            if not approved:
                return self._error_result(
                    "Security approval denied.",
                    PermissionError("Security Agent denied TTS action."),
                    metadata={"security_response": response},
                )

            return self._safe_result(
                message="Security approval granted.",
                data=response,
            )

        except Exception as exc:
            return self._error_result("Security approval request failed.", exc)

    def _prepare_verification_payload(
        self,
        tts_result: TTSResult,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Verification Agent compatible payload.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": "TTSEngine",
            "agent_type": "voice_agent",
            "event": "tts_synthesis_completed",
            "job_id": job_id,
            "success": tts_result.success,
            "provider": tts_result.provider.value,
            "language": tts_result.language,
            "voice_id": tts_result.voice_id,
            "style": tts_result.style.value,
            "output_format": tts_result.output_format.value,
            "text_length": len(tts_result.text),
            "has_audio": bool(tts_result.audio_bytes or tts_result.audio_base64 or tts_result.audio_url or tts_result.audio_path),
            "is_stream": tts_result.is_stream,
            "context": self._context_to_public_dict(context),
            "timestamp": time.time(),
            "requires_followup_verification": False,
        }

    def _prepare_memory_payload(
        self,
        tts_result: TTSResult,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Memory Agent compatible payload.

        Stores safe speech metadata and spoken text. Raw audio is never included.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": "TTSEngine",
            "agent_type": "voice_agent",
            "memory_type": "voice_output",
            "context": self._context_to_public_dict(context),
            "content": {
                "job_id": job_id,
                "spoken_text": tts_result.text,
                "language": tts_result.language,
                "voice_id": tts_result.voice_id,
                "style": tts_result.style.value,
                "provider": tts_result.provider.value,
                "output_format": tts_result.output_format.value,
                "is_stream": tts_result.is_stream,
            },
            "metadata": {
                "safe_to_store": True,
                "contains_raw_audio": False,
                "text_length": len(tts_result.text),
                "duration_seconds": tts_result.duration_seconds,
                "timestamp": time.time(),
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emits event to dashboard/event bus callback.
        """

        if not self.config.emit_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": "TTSEngine",
            "agent_type": "voice_agent",
            "payload": payload or {},
            "timestamp": time.time(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
        except Exception:
            logger.exception("Failed to emit TTSEngine event.")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Union[TTSContext, Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Logs audit event.
        """

        if not self.config.audit_enabled:
            return

        audit = {
            "audit_id": str(uuid.uuid4()),
            "agent": "TTSEngine",
            "agent_type": "voice_agent",
            "action": action,
            "context": self._context_to_public_dict(context),
            "details": details or {},
            "timestamp": time.time(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit)
        except Exception:
            logger.exception("Failed to log TTSEngine audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                **self._base_metadata(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Exception,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """

        logger.debug("%s: %s", message, error)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "type": error.__class__.__name__,
                "message": str(error),
            },
            "metadata": {
                **self._base_metadata(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------
    # Playback helpers
    # -----------------------------------------------------------------

    def _send_playback_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends playback command to audio_router/device/browser callback.

        Safe no-op if playback_callback is missing.
        """

        try:
            if self.playback_callback:
                response = self.playback_callback(payload)

                if isinstance(response, dict):
                    return self._safe_result(
                        message="Playback callback processed command.",
                        data=response,
                    )

                return self._safe_result(
                    message="Playback callback processed command.",
                    data={
                        "response": response,
                    },
                )

            return self._safe_result(
                message="No playback callback configured; command prepared only.",
                data={
                    "prepared": True,
                    "payload": payload,
                },
            )

        except Exception as exc:
            return self._error_result("Playback command failed.", exc)

    def _latest_job_id(self) -> Optional[str]:
        """
        Returns latest active job id.
        """

        if not self._active_jobs:
            return None

        return max(
            self._active_jobs.items(),
            key=lambda item: item[1].get("created_at", 0.0),
        )[0]

    # -----------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------

    def _parse_provider(self, provider: Union[TTSProvider, str, None]) -> TTSProvider:
        """
        Converts provider string to TTSProvider.
        """

        if isinstance(provider, TTSProvider):
            return provider

        if provider is None:
            return self.config.default_provider

        value = str(provider).strip().lower()

        for item in TTSProvider:
            if item.value == value:
                return item

        return TTSProvider.AUTO

    def _parse_style(self, style: Union[VoiceStyle, str, None]) -> VoiceStyle:
        """
        Converts style string to VoiceStyle.
        """

        if isinstance(style, VoiceStyle):
            return style

        if style is None:
            return self.config.default_style

        value = str(style).strip().lower()

        for item in VoiceStyle:
            if item.value == value:
                return item

        return VoiceStyle.DEFAULT

    def _parse_output_format(
        self,
        output_format: Union[TTSOutputFormat, str, None],
    ) -> TTSOutputFormat:
        """
        Converts output format string to TTSOutputFormat.
        """

        if isinstance(output_format, TTSOutputFormat):
            return output_format

        if output_format is None:
            return self.config.output_format

        value = str(output_format).strip().lower()

        for item in TTSOutputFormat:
            if item.value == value:
                return item

        return self.config.output_format

    def _validate_language(self, language: Optional[str]) -> str:
        """
        Validates language code.
        """

        if not language:
            return self.config.default_language

        normalized = str(language).strip().lower()

        if normalized in self.config.supported_languages:
            return normalized

        return self.config.default_language

    def _validate_voice_id(
        self,
        voice_id: Optional[str],
        language: Optional[str] = None,
    ) -> str:
        """
        Validates voice id and falls back to language-compatible default.
        """

        if voice_id and voice_id in self.config.voice_map:
            return voice_id

        if language:
            for candidate_id, voice in self.config.voice_map.items():
                if voice.get("language") == language:
                    return candidate_id

        return self.config.default_voice_id

    def _clamp_float(
        self,
        value: Optional[float],
        default: float,
        minimum: float,
        maximum: float,
    ) -> float:
        """
        Safely converts and clamps float.
        """

        try:
            number = float(value) if value is not None else float(default)
        except Exception:
            number = float(default)

        return max(minimum, min(maximum, number))

    def _safe_optional_float(self, value: Any) -> Optional[float]:
        """
        Safely converts optional value to float.
        """

        if value is None:
            return None

        try:
            return float(value)
        except Exception:
            return None

    def _safe_optional_int(self, value: Any) -> Optional[int]:
        """
        Safely converts optional value to int.
        """

        if value is None:
            return None

        try:
            return int(value)
        except Exception:
            return None

    def _safe_identifier(self, value: str) -> str:
        """
        Converts text into safe identifier.
        """

        cleaned = re.sub(r"[^a-zA-Z0-9_\-]+", "_", value.strip())
        cleaned = re.sub(r"_+", "_", cleaned).strip("_")

        return cleaned or f"voice_{uuid.uuid4().hex[:8]}"

    def _generate_silent_wav(
        self,
        duration_seconds: float,
        sample_rate: int,
        channels: int,
        sample_width: int,
    ) -> bytes:
        """
        Generates tiny silent WAV bytes for safe mock provider.
        """

        import io

        frame_count = int(sample_rate * duration_seconds)
        silence = b"\x00" * frame_count * channels * sample_width

        buffer = io.BytesIO()

        with wave.open(buffer, "wb") as wav:
            wav.setnchannels(channels)
            wav.setsampwidth(sample_width)
            wav.setframerate(sample_rate)
            wav.writeframes(silence)

        return buffer.getvalue()

    def _context_to_dict(
        self,
        context: Optional[Union[TTSContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Converts context dataclass/dict to dict.
        """

        if context is None:
            return {}

        if isinstance(context, TTSContext):
            return asdict(context)

        if isinstance(context, dict):
            return dict(context)

        return {}

    def _context_to_public_dict(
        self,
        context: Optional[Union[TTSContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Returns safe public context without secrets/tokens.
        """

        ctx = self._context_to_dict(context)

        allowed_keys = {
            "user_id",
            "workspace_id",
            "device_id",
            "session_id",
            "request_id",
            "role",
            "subscription_plan",
        }

        public = {key: ctx.get(key) for key in allowed_keys if key in ctx}

        metadata = ctx.get("metadata")
        if isinstance(metadata, dict):
            public["metadata_keys"] = list(metadata.keys())

        permissions = ctx.get("permissions")
        if isinstance(permissions, list):
            public["permissions_count"] = len(permissions)

        return public

    def _get_request_id(
        self,
        context: Optional[Union[TTSContext, Dict[str, Any]]],
    ) -> str:
        """
        Returns existing request_id or creates one.
        """

        ctx = self._context_to_dict(context)
        request_id = ctx.get("request_id")

        if request_id:
            return str(request_id)

        return str(uuid.uuid4())

    def _base_metadata(self) -> Dict[str, Any]:
        """
        Base metadata attached to every result.
        """

        return {
            "agent": "TTSEngine",
            "agent_type": "voice_agent",
            "module": "agents.voice_agent.tts_engine",
            "timestamp": time.time(),
            "version": "1.0.0",
        }


# ---------------------------------------------------------------------
# Optional simple self-test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = TTSEngine()

    demo_context = TTSContext(
        user_id="demo_user",
        workspace_id="demo_workspace",
        device_id="demo_device",
        session_id="demo_session",
        request_id="demo_request",
    )

    print(
        engine.synthesize(
            text="Hello, I am William. Your voice system is ready.",
            context=demo_context,
            language="en",
            style="professional",
            volume=0.9,
        )
    )

    stream = engine.start_stream(
        context=demo_context,
        language="en",
        style="friendly",
    )

    stream_id = stream["data"]["stream_id"]

    print(
        engine.push_stream_text(
            stream_id=stream_id,
            text="This is a streaming text to speech test. The full provider can be connected later.",
            context=demo_context,
        )
    )

    print(
        engine.finish_stream(
            stream_id=stream_id,
            context=demo_context,
        )
    )

    print(
        engine.interrupt(
            context=demo_context,
            reason="demo_interruption",
        )
    )