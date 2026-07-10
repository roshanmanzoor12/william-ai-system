"""
agents/voice_agent/stt_engine.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Converts speech to text with multilingual, streaming, offline fallback,
    and correction support for the Voice Agent.

This file is designed to be:
    - Import-safe
    - SaaS user/workspace aware
    - Compatible with BaseAgent / Agent Registry / Agent Loader / Master Agent
    - Ready for FastAPI/dashboard integration
    - Ready for future Whisper, Vosk, browser STT, mobile STT, cloud STT,
      and streaming audio modules

Important:
    This file does not directly open microphones, record users, call paid APIs,
    or send audio outside the system by default.

    Audio input must be passed into this class by another safe module such as:
        - device_stream.py
        - audio_router.py
        - voice_loop.py
        - browser/mobile client
        - dashboard/API upload endpoint
"""

from __future__ import annotations

import hashlib
import logging
import os
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

        Keeps stt_engine.py import-safe while the full William architecture
        is still being created.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger("william.voice_agent.stt_engine")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# Enums / Dataclasses
# ---------------------------------------------------------------------

class STTProvider(str, Enum):
    """Supported STT provider labels."""

    AUTO = "auto"
    OFFLINE = "offline"
    WHISPER_LOCAL = "whisper_local"
    VOSK_LOCAL = "vosk_local"
    CLOUD = "cloud"
    MOCK = "mock"


class STTStatus(str, Enum):
    """Runtime status for STTEngine."""

    IDLE = "idle"
    READY = "ready"
    TRANSCRIBING = "transcribing"
    STREAMING = "streaming"
    ERROR = "error"
    DISABLED = "disabled"


class AudioInputType(str, Enum):
    """Supported audio input types."""

    FILE_PATH = "file_path"
    BYTES = "bytes"
    CHUNKS = "chunks"
    TEXT_TEST = "text_test"
    UNKNOWN = "unknown"


@dataclass
class STTEngineConfig:
    """
    Runtime configuration for STTEngine.

    This config is database/dashboard friendly and avoids hardcoded secrets.
    """

    default_provider: STTProvider = STTProvider.AUTO
    offline_provider_order: List[STTProvider] = field(
        default_factory=lambda: [
            STTProvider.WHISPER_LOCAL,
            STTProvider.VOSK_LOCAL,
            STTProvider.MOCK,
        ]
    )

    default_language: str = "auto"
    supported_languages: List[str] = field(
        default_factory=lambda: [
            "auto",
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

    enable_multilingual: bool = True
    enable_streaming: bool = True
    enable_offline_fallback: bool = True
    enable_correction: bool = True
    enable_punctuation_cleanup: bool = True
    enable_sensitive_audio_hashing: bool = True

    min_confidence: float = 0.50
    max_audio_size_mb: float = 50.0
    max_stream_chunks: int = 600
    stream_partial_min_chars: int = 2

    require_user_context: bool = True
    require_workspace_context: bool = True

    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    store_raw_audio: bool = False
    allow_cloud_stt: bool = False

    custom_corrections: Dict[str, str] = field(default_factory=dict)
    common_corrections: Dict[str, str] = field(
        default_factory=lambda: {
            "will iam": "William",
            "williams": "William",
            "jar vess": "Jarvis",
            "jar verse": "Jarvis",
            "digital pro motix": "Digital Promotix",
            "digital promotics": "Digital Promotix",
            "open dash board": "open dashboard",
            "lock screen": "lockscreen",
            "log in": "login",
            "sign in": "signin",
        }
    )


@dataclass
class STTContext:
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
class STTResult:
    """
    Internal STT result before conversion to public structured dict.
    """

    transcript: str
    success: bool
    provider: STTProvider
    confidence: float = 0.0
    language: str = "unknown"
    is_partial: bool = False
    duration_seconds: Optional[float] = None
    words: List[Dict[str, Any]] = field(default_factory=list)
    corrections_applied: List[Dict[str, str]] = field(default_factory=list)
    message: str = ""
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------
# STTEngine
# ---------------------------------------------------------------------

class STTEngine(BaseAgent):
    """
    Speech-to-text engine for William Voice Agent.

    Responsibilities:
        - Convert speech/audio into text
        - Support multilingual language config
        - Support streaming chunk transcription interface
        - Support offline fallback provider routing
        - Support correction/cleanup pipeline
        - Return safe structured JSON/dict results
        - Prepare Security, Memory, Verification, Audit, and Dashboard payloads

    How this connects to William/Jarvis architecture:
        - Master Agent:
            Receives final transcript and routes it to WakeWordDetector,
            Voice Agent, or Master Agent command pipeline.

        - Voice Agent:
            Uses this file after audio capture from device_stream.py or
            audio_router.py.

        - Security Agent:
            Cloud STT, raw audio storage, or sensitive speech handling can be
            blocked unless approved.

        - Memory Agent:
            Stores safe transcript metadata and optionally transcript snippets
            if allowed by policy.

        - Verification Agent:
            Receives payload confirming provider, language, confidence, and
            correction result.

        - Dashboard/API:
            Results are structured for task history, analytics, session logs,
            streaming partials, and audit trails.

        - Agent Registry / Loader:
            Public metadata is exposed through get_agent_manifest().
    """

    def __init__(
        self,
        config: Optional[STTEngineConfig] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        provider_callbacks: Optional[Dict[str, Callable[..., Dict[str, Any]]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="STTEngine", agent_type="voice_agent", **kwargs)

        self.config = config or STTEngineConfig()
        self.status = STTStatus.READY

        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.security_callback = security_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self.provider_callbacks = provider_callbacks or {}

        self._stream_buffers: Dict[str, List[bytes]] = {}
        self._stream_started_at: Dict[str, float] = {}

    # -----------------------------------------------------------------
    # Public metadata
    # -----------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Registry/Loader compatible manifest.
        """

        return self._safe_result(
            message="STTEngine manifest loaded.",
            data={
                "agent_name": "STTEngine",
                "agent_type": "voice_agent",
                "module": "agents.voice_agent.stt_engine",
                "class_name": "STTEngine",
                "version": "1.0.0",
                "status": self.status.value,
                "capabilities": [
                    "speech_to_text",
                    "multilingual_transcription",
                    "streaming_transcription_interface",
                    "offline_fallback_routing",
                    "transcript_correction",
                    "punctuation_cleanup",
                    "saas_context_validation",
                    "audit_event_payloads",
                    "memory_payloads",
                    "verification_payloads",
                    "dashboard_api_ready_results",
                ],
                "public_methods": [
                    "transcribe",
                    "transcribe_file",
                    "transcribe_bytes",
                    "start_stream",
                    "transcribe_stream_chunk",
                    "finish_stream",
                    "correct_transcript",
                    "detect_language_hint",
                    "get_config",
                    "update_config",
                    "health_check",
                    "reset_runtime_state",
                ],
                "supported_providers": [provider.value for provider in STTProvider],
                "supported_languages": self.config.supported_languages,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Returns STTEngine health for dashboard/API.
        """

        try:
            available_callbacks = sorted(list(self.provider_callbacks.keys()))

            return self._safe_result(
                message="STTEngine is healthy.",
                data={
                    "status": self.status.value,
                    "default_provider": self.config.default_provider.value,
                    "offline_fallback_enabled": self.config.enable_offline_fallback,
                    "streaming_enabled": self.config.enable_streaming,
                    "correction_enabled": self.config.enable_correction,
                    "cloud_stt_allowed": self.config.allow_cloud_stt,
                    "provider_callbacks": available_callbacks,
                    "active_streams": len(self._stream_buffers),
                },
            )
        except Exception as exc:
            return self._error_result("STTEngine health check failed.", exc)

    # -----------------------------------------------------------------
    # Config methods
    # -----------------------------------------------------------------

    def get_config(self) -> Dict[str, Any]:
        """
        Returns safe config snapshot.
        """

        config = asdict(self.config)
        config["default_provider"] = self.config.default_provider.value
        config["offline_provider_order"] = [
            provider.value if isinstance(provider, STTProvider) else str(provider)
            for provider in self.config.offline_provider_order
        ]

        return self._safe_result(
            message="STT config loaded.",
            data=config,
        )

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates config safely.

        Args:
            updates: Dictionary of STTEngineConfig fields.

        Returns:
            Structured result.
        """

        try:
            if not isinstance(updates, dict):
                return self._error_result(
                    "STT config update failed.",
                    ValueError("updates must be a dictionary."),
                )

            valid_fields = set(STTEngineConfig.__dataclass_fields__.keys())
            changed: Dict[str, Any] = {}

            for key, value in updates.items():
                if key not in valid_fields:
                    continue

                if key == "default_provider":
                    value = self._parse_provider(value)

                if key == "offline_provider_order":
                    value = [self._parse_provider(item) for item in value]

                setattr(self.config, key, value)
                changed[key] = value.value if isinstance(value, STTProvider) else value

            self._emit_agent_event(
                event_type="stt_config_updated",
                payload={
                    "changed_keys": list(changed.keys()),
                },
            )

            return self._safe_result(
                message="STT config updated.",
                data={
                    "changed": changed,
                    "config": self.get_config().get("data", {}),
                },
            )

        except Exception as exc:
            return self._error_result("STT config update failed.", exc)

    def reset_runtime_state(self) -> Dict[str, Any]:
        """
        Clears active streams and resets runtime status.
        """

        try:
            self._stream_buffers.clear()
            self._stream_started_at.clear()
            self.status = STTStatus.READY

            return self._safe_result(
                message="STTEngine runtime state reset.",
                data={
                    "status": self.status.value,
                    "active_streams": 0,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to reset STTEngine runtime state.", exc)

    # -----------------------------------------------------------------
    # Main transcription methods
    # -----------------------------------------------------------------

    def transcribe(
        self,
        audio_input: Union[str, Path, bytes, bytearray, Dict[str, Any]],
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        provider: Union[STTProvider, str, None] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main transcription entrypoint.

        Args:
            audio_input:
                - File path string / Path
                - Audio bytes
                - Dict input for test/future integrations:
                    {"type": "text_test", "text": "hello"}
                    {"type": "bytes", "data": b"..."}
                    {"type": "file_path", "path": "/path/audio.wav"}

            context:
                SaaS user/workspace context.

            language:
                Language hint. Use "auto" for detection.

            provider:
                STT provider label.

            metadata:
                Optional dashboard/session metadata.

        Returns:
            Structured transcription result.
        """

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = STTStatus.ERROR
                return validation

            input_type = self._detect_audio_input_type(audio_input)
            selected_language = self._validate_language(language or self.config.default_language)
            selected_provider = self._parse_provider(provider or self.config.default_provider)

            if self._requires_security_check(selected_provider, context=context):
                approval = self._request_security_approval(
                    action="transcribe_audio",
                    context=context,
                    details={
                        "provider": selected_provider.value,
                        "input_type": input_type.value,
                        "language": selected_language,
                    },
                )
                if not approval["success"]:
                    return approval

            if input_type == AudioInputType.FILE_PATH:
                return self.transcribe_file(
                    file_path=audio_input,  # type: ignore[arg-type]
                    context=context,
                    language=selected_language,
                    provider=selected_provider,
                    metadata=metadata,
                )

            if input_type == AudioInputType.BYTES:
                return self.transcribe_bytes(
                    audio_bytes=bytes(audio_input),  # type: ignore[arg-type]
                    context=context,
                    language=selected_language,
                    provider=selected_provider,
                    metadata=metadata,
                )

            if input_type == AudioInputType.TEXT_TEST:
                text = str(audio_input.get("text", ""))  # type: ignore[union-attr]
                return self._finalize_stt_result(
                    STTResult(
                        transcript=text,
                        success=True,
                        provider=STTProvider.MOCK,
                        confidence=1.0,
                        language=selected_language if selected_language != "auto" else "unknown",
                        is_partial=False,
                        message="Text test transcription completed.",
                        raw_metadata={
                            **(metadata or {}),
                            "input_type": input_type.value,
                        },
                    ),
                    context=context,
                )

            if isinstance(audio_input, dict):
                declared_type = str(audio_input.get("type", "")).strip().lower()

                if declared_type == "bytes":
                    raw = audio_input.get("data", b"")
                    return self.transcribe_bytes(
                        audio_bytes=bytes(raw),
                        context=context,
                        language=selected_language,
                        provider=selected_provider,
                        metadata=metadata,
                    )

                if declared_type == "file_path":
                    path = audio_input.get("path", "")
                    return self.transcribe_file(
                        file_path=str(path),
                        context=context,
                        language=selected_language,
                        provider=selected_provider,
                        metadata=metadata,
                    )

            return self._error_result(
                "Unsupported audio input.",
                ValueError("audio_input must be file path, bytes, or supported dict input."),
            )

        except Exception as exc:
            self.status = STTStatus.ERROR
            return self._error_result("STT transcription failed.", exc)

    def transcribe_file(
        self,
        file_path: Union[str, Path],
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        provider: Union[STTProvider, str, None] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Transcribes an audio file.

        This method validates file size and path but does not store raw audio
        unless explicitly enabled in config.
        """

        try:
            self.status = STTStatus.TRANSCRIBING

            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = STTStatus.ERROR
                return validation

            path = Path(file_path).expanduser().resolve()

            if not path.exists():
                return self._error_result(
                    "Audio file does not exist.",
                    FileNotFoundError(str(path)),
                )

            if not path.is_file():
                return self._error_result(
                    "Audio path is not a file.",
                    ValueError(str(path)),
                )

            file_size = path.stat().st_size
            max_bytes = int(self.config.max_audio_size_mb * 1024 * 1024)

            if file_size > max_bytes:
                return self._error_result(
                    "Audio file is too large.",
                    ValueError(
                        f"File size {file_size} exceeds max allowed {max_bytes} bytes."
                    ),
                )

            selected_language = self._validate_language(language or self.config.default_language)
            selected_provider = self._parse_provider(provider or self.config.default_provider)

            audio_metadata = self._inspect_audio_file(path)
            audio_hash = self._hash_file(path) if self.config.enable_sensitive_audio_hashing else None

            provider_result = self._run_provider(
                provider=selected_provider,
                audio_source=path,
                input_type=AudioInputType.FILE_PATH,
                language=selected_language,
                context=context,
                metadata={
                    **(metadata or {}),
                    "file_name": path.name,
                    "file_size": file_size,
                    "audio_hash": audio_hash,
                    "audio_metadata": audio_metadata,
                },
            )

            return self._finalize_stt_result(provider_result, context=context)

        except Exception as exc:
            self.status = STTStatus.ERROR
            return self._error_result("File transcription failed.", exc)

    def transcribe_bytes(
        self,
        audio_bytes: Union[bytes, bytearray],
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        provider: Union[STTProvider, str, None] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Transcribes raw audio bytes.

        The bytes may represent WAV/PCM/encoded audio depending on the provider.
        Provider callback should know how to handle the supplied format.
        """

        try:
            self.status = STTStatus.TRANSCRIBING

            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = STTStatus.ERROR
                return validation

            raw = bytes(audio_bytes)

            if not raw:
                return self._error_result(
                    "Audio bytes are empty.",
                    ValueError("audio_bytes cannot be empty."),
                )

            max_bytes = int(self.config.max_audio_size_mb * 1024 * 1024)
            if len(raw) > max_bytes:
                return self._error_result(
                    "Audio bytes are too large.",
                    ValueError(
                        f"Byte length {len(raw)} exceeds max allowed {max_bytes} bytes."
                    ),
                )

            selected_language = self._validate_language(language or self.config.default_language)
            selected_provider = self._parse_provider(provider or self.config.default_provider)

            audio_hash = self._hash_bytes(raw) if self.config.enable_sensitive_audio_hashing else None

            provider_result = self._run_provider(
                provider=selected_provider,
                audio_source=raw,
                input_type=AudioInputType.BYTES,
                language=selected_language,
                context=context,
                metadata={
                    **(metadata or {}),
                    "byte_length": len(raw),
                    "audio_hash": audio_hash,
                },
            )

            return self._finalize_stt_result(provider_result, context=context)

        except Exception as exc:
            self.status = STTStatus.ERROR
            return self._error_result("Byte transcription failed.", exc)

    # -----------------------------------------------------------------
    # Streaming interface
    # -----------------------------------------------------------------

    def start_stream(
        self,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        stream_id: Optional[str] = None,
        language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Starts a streaming STT session.

        This does not open a microphone. It only creates a stream buffer where
        future audio chunks can be pushed by device_stream.py/audio_router.py.
        """

        try:
            if not self.config.enable_streaming:
                return self._error_result(
                    "Streaming STT is disabled.",
                    PermissionError("enable_streaming is False."),
                )

            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            sid = stream_id or str(uuid.uuid4())

            if sid in self._stream_buffers:
                return self._error_result(
                    "Stream already exists.",
                    ValueError(f"stream_id already active: {sid}"),
                )

            self._stream_buffers[sid] = []
            self._stream_started_at[sid] = time.time()
            self.status = STTStatus.STREAMING

            self._emit_agent_event(
                event_type="stt_stream_started",
                payload={
                    "stream_id": sid,
                    "language": self._validate_language(language or self.config.default_language),
                    "context": self._context_to_public_dict(context),
                    **(metadata or {}),
                },
            )

            return self._safe_result(
                message="STT stream started.",
                data={
                    "stream_id": sid,
                    "status": self.status.value,
                    "language": self._validate_language(language or self.config.default_language),
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            self.status = STTStatus.ERROR
            return self._error_result("Failed to start STT stream.", exc)

    def transcribe_stream_chunk(
        self,
        stream_id: str,
        audio_chunk: Union[bytes, bytearray],
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        provider: Union[STTProvider, str, None] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Adds a stream chunk and optionally returns a partial transcript.

        In production, provider_callbacks can support real streaming. Without
        provider callbacks, this returns a safe partial status result.
        """

        try:
            if not self.config.enable_streaming:
                return self._error_result(
                    "Streaming STT is disabled.",
                    PermissionError("enable_streaming is False."),
                )

            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            if stream_id not in self._stream_buffers:
                return self._error_result(
                    "Stream not found.",
                    KeyError(stream_id),
                )

            chunk = bytes(audio_chunk)
            if not chunk:
                return self._error_result(
                    "Audio stream chunk is empty.",
                    ValueError("audio_chunk cannot be empty."),
                )

            if len(self._stream_buffers[stream_id]) >= self.config.max_stream_chunks:
                return self._error_result(
                    "Stream chunk limit reached.",
                    ValueError("max_stream_chunks exceeded."),
                )

            self._stream_buffers[stream_id].append(chunk)

            selected_language = self._validate_language(language or self.config.default_language)
            selected_provider = self._parse_provider(provider or self.config.default_provider)

            streaming_callback = self.provider_callbacks.get(f"{selected_provider.value}_stream")
            if streaming_callback:
                callback_response = streaming_callback(
                    audio_chunk=chunk,
                    stream_id=stream_id,
                    language=selected_language,
                    context=self._context_to_dict(context),
                    metadata=metadata or {},
                )

                result = self._provider_response_to_result(
                    response=callback_response,
                    provider=selected_provider,
                    language=selected_language,
                    is_partial=True,
                    metadata={
                        **(metadata or {}),
                        "stream_id": stream_id,
                    },
                )

                return self._finalize_stt_result(result, context=context)

            return self._safe_result(
                message="Stream chunk accepted.",
                data={
                    "stream_id": stream_id,
                    "accepted": True,
                    "is_partial": True,
                    "partial_transcript": "",
                    "chunks_received": len(self._stream_buffers[stream_id]),
                    "provider": selected_provider.value,
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                    "stream_age_seconds": round(time.time() - self._stream_started_at[stream_id], 4),
                    **(metadata or {}),
                },
            )

        except Exception as exc:
            self.status = STTStatus.ERROR
            return self._error_result("Stream chunk transcription failed.", exc)

    def finish_stream(
        self,
        stream_id: str,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        provider: Union[STTProvider, str, None] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Finishes a stream and transcribes accumulated audio.
        """

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            if stream_id not in self._stream_buffers:
                return self._error_result(
                    "Stream not found.",
                    KeyError(stream_id),
                )

            chunks = self._stream_buffers.pop(stream_id)
            started_at = self._stream_started_at.pop(stream_id, time.time())

            combined = b"".join(chunks)
            duration = time.time() - started_at

            self.status = STTStatus.TRANSCRIBING

            result = self.transcribe_bytes(
                audio_bytes=combined,
                context=context,
                language=language,
                provider=provider,
                metadata={
                    **(metadata or {}),
                    "stream_id": stream_id,
                    "stream_chunks": len(chunks),
                    "stream_duration_seconds": round(duration, 4),
                },
            )

            self._emit_agent_event(
                event_type="stt_stream_finished",
                payload={
                    "stream_id": stream_id,
                    "chunks": len(chunks),
                    "duration_seconds": round(duration, 4),
                    "context": self._context_to_public_dict(context),
                },
            )

            return result

        except Exception as exc:
            self.status = STTStatus.ERROR
            return self._error_result("Failed to finish STT stream.", exc)

    # -----------------------------------------------------------------
    # Correction / language helpers
    # -----------------------------------------------------------------

    def correct_transcript(
        self,
        transcript: str,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Applies transcript correction and punctuation cleanup.
        """

        try:
            validation = self._validate_task_context(context, allow_missing=True)
            if not validation["success"]:
                return validation

            corrected, corrections = self._apply_corrections(transcript)

            return self._safe_result(
                message="Transcript correction completed.",
                data={
                    "original": transcript,
                    "corrected": corrected,
                    "corrections_applied": corrections,
                    "language": self._validate_language(language or self.config.default_language),
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                    **(metadata or {}),
                },
            )

        except Exception as exc:
            return self._error_result("Transcript correction failed.", exc)

    def detect_language_hint(self, text: str) -> Dict[str, Any]:
        """
        Lightweight language hint detection.

        This is not a full language model. It provides a safe heuristic until
        language_engine.py or an STT provider returns a reliable language.
        """

        try:
            if not isinstance(text, str) or not text.strip():
                return self._safe_result(
                    message="No language hint detected.",
                    data={
                        "language": "unknown",
                        "confidence": 0.0,
                    },
                )

            sample = text.strip()

            urdu_arabic_chars = len(re.findall(r"[\u0600-\u06FF]", sample))
            devanagari_chars = len(re.findall(r"[\u0900-\u097F]", sample))
            latin_chars = len(re.findall(r"[A-Za-z]", sample))

            total = max(1, urdu_arabic_chars + devanagari_chars + latin_chars)

            if urdu_arabic_chars / total > 0.35:
                language = "ur"
                confidence = urdu_arabic_chars / total
            elif devanagari_chars / total > 0.35:
                language = "hi"
                confidence = devanagari_chars / total
            elif latin_chars / total > 0.35:
                language = "en"
                confidence = latin_chars / total
            else:
                language = "unknown"
                confidence = 0.0

            return self._safe_result(
                message="Language hint detected.",
                data={
                    "language": language,
                    "confidence": round(confidence, 4),
                },
            )

        except Exception as exc:
            return self._error_result("Language hint detection failed.", exc)

    # -----------------------------------------------------------------
    # Provider routing
    # -----------------------------------------------------------------

    def _run_provider(
        self,
        provider: STTProvider,
        audio_source: Union[Path, bytes],
        input_type: AudioInputType,
        language: str,
        context: Optional[Union[STTContext, Dict[str, Any]]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> STTResult:
        """
        Routes transcription to selected provider with offline fallback.

        Real STT providers can be injected through provider_callbacks:
            {
                "whisper_local": callable,
                "vosk_local": callable,
                "cloud": callable,
                "mock": callable
            }

        Callback expected output:
            {
                "success": True,
                "transcript": "...",
                "confidence": 0.91,
                "language": "en",
                "words": []
            }
        """

        if provider == STTProvider.AUTO:
            provider_order = list(self.config.offline_provider_order)
            if self.config.allow_cloud_stt:
                provider_order.append(STTProvider.CLOUD)
        else:
            provider_order = [provider]

        if self.config.enable_offline_fallback:
            for fallback_provider in self.config.offline_provider_order:
                if fallback_provider not in provider_order and fallback_provider != STTProvider.CLOUD:
                    provider_order.append(fallback_provider)

        last_error: Optional[str] = None

        for selected in provider_order:
            if selected == STTProvider.CLOUD and not self.config.allow_cloud_stt:
                last_error = "Cloud STT is disabled."
                continue

            callback = self.provider_callbacks.get(selected.value)

            if callback:
                try:
                    response = callback(
                        audio_source=audio_source,
                        input_type=input_type.value,
                        language=language,
                        context=self._context_to_dict(context),
                        metadata=metadata or {},
                    )

                    result = self._provider_response_to_result(
                        response=response,
                        provider=selected,
                        language=language,
                        is_partial=False,
                        metadata=metadata,
                    )

                    if result.success and result.confidence >= self.config.min_confidence:
                        return result

                    last_error = result.message or "Provider returned low-confidence result."

                except Exception as exc:
                    last_error = f"{selected.value} failed: {exc}"
                    logger.debug(last_error)

            if selected == STTProvider.MOCK:
                return self._mock_transcription(
                    audio_source=audio_source,
                    input_type=input_type,
                    language=language,
                    metadata={
                        **(metadata or {}),
                        "fallback_reason": last_error,
                    },
                )

        return STTResult(
            transcript="",
            success=False,
            provider=provider,
            confidence=0.0,
            language=language,
            message=last_error or "No STT provider available.",
            raw_metadata=metadata or {},
        )

    def _provider_response_to_result(
        self,
        response: Dict[str, Any],
        provider: STTProvider,
        language: str,
        is_partial: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> STTResult:
        """
        Converts provider callback response into STTResult.
        """

        if not isinstance(response, dict):
            return STTResult(
                transcript="",
                success=False,
                provider=provider,
                confidence=0.0,
                language=language,
                is_partial=is_partial,
                message="Provider response must be a dictionary.",
                raw_metadata=metadata or {},
            )

        transcript = str(response.get("transcript", "") or "")
        confidence = self._safe_float(response.get("confidence"), default=0.0)
        detected_language = str(response.get("language", language) or language)

        corrected_text = transcript
        corrections: List[Dict[str, str]] = []

        if self.config.enable_correction and transcript:
            corrected_text, corrections = self._apply_corrections(transcript)

        return STTResult(
            transcript=corrected_text,
            success=bool(response.get("success", bool(corrected_text))),
            provider=provider,
            confidence=confidence,
            language=detected_language,
            is_partial=is_partial,
            duration_seconds=self._safe_optional_float(response.get("duration_seconds")),
            words=list(response.get("words", []) or []),
            corrections_applied=corrections,
            message=str(response.get("message", "STT provider transcription completed.")),
            raw_metadata={
                **(metadata or {}),
                "provider_raw_metadata": response.get("metadata", {}),
            },
        )

    def _mock_transcription(
        self,
        audio_source: Union[Path, bytes],
        input_type: AudioInputType,
        language: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> STTResult:
        """
        Safe fallback mock provider.

        This is useful while real Whisper/Vosk/cloud integrations are not yet
        installed. It never pretends to accurately transcribe audio.
        """

        if isinstance(audio_source, Path):
            source_label = audio_source.name
        else:
            source_label = f"{len(audio_source)} bytes"

        return STTResult(
            transcript="",
            success=False,
            provider=STTProvider.MOCK,
            confidence=0.0,
            language=language,
            is_partial=False,
            message=(
                "No real STT provider is configured yet. "
                "Audio was accepted but not transcribed."
            ),
            raw_metadata={
                **(metadata or {}),
                "input_type": input_type.value,
                "source_label": source_label,
                "mock_provider": True,
            },
        )

    # -----------------------------------------------------------------
    # Finalization
    # -----------------------------------------------------------------

    def _finalize_stt_result(
        self,
        stt_result: STTResult,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Finalizes STT result with events, audit, memory, and verification payload.
        """

        self.status = STTStatus.READY if stt_result.success else STTStatus.ERROR

        verification_payload = (
            self._prepare_verification_payload(stt_result, context)
            if self.config.verification_enabled
            else None
        )

        memory_payload = (
            self._prepare_memory_payload(stt_result, context)
            if self.config.memory_enabled
            else None
        )

        event_type = "stt_transcription_completed" if stt_result.success else "stt_transcription_failed"

        self._emit_agent_event(
            event_type=event_type,
            payload={
                "provider": stt_result.provider.value,
                "language": stt_result.language,
                "confidence": stt_result.confidence,
                "is_partial": stt_result.is_partial,
                "transcript_length": len(stt_result.transcript),
                "context": self._context_to_public_dict(context),
            },
        )

        self._log_audit_event(
            action=event_type,
            context=context,
            details={
                "provider": stt_result.provider.value,
                "language": stt_result.language,
                "confidence": stt_result.confidence,
                "is_partial": stt_result.is_partial,
                "transcript_length": len(stt_result.transcript),
                "corrections_count": len(stt_result.corrections_applied),
            },
        )

        if stt_result.success and self.memory_callback and memory_payload:
            try:
                self.memory_callback(memory_payload)
            except Exception:
                logger.exception("Failed to send STT payload to Memory Agent.")

        if self.verification_callback and verification_payload:
            try:
                self.verification_callback(verification_payload)
            except Exception:
                logger.exception("Failed to send STT payload to Verification Agent.")

        return self._safe_result(
            message=stt_result.message or "STT transcription completed.",
            data={
                "transcript": stt_result.transcript,
                "success": stt_result.success,
                "provider": stt_result.provider.value,
                "confidence": round(float(stt_result.confidence), 4),
                "language": stt_result.language,
                "is_partial": stt_result.is_partial,
                "duration_seconds": stt_result.duration_seconds,
                "words": stt_result.words,
                "corrections_applied": stt_result.corrections_applied,
                "status": self.status.value,
            },
            metadata={
                "context": self._context_to_public_dict(context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "raw_metadata": stt_result.raw_metadata,
                "request_id": self._get_request_id(context),
            },
        )

    # -----------------------------------------------------------------
    # Correction internals
    # -----------------------------------------------------------------

    def _apply_corrections(self, transcript: str) -> Tuple[str, List[Dict[str, str]]]:
        """
        Applies common and custom correction dictionaries.
        """

        if not isinstance(transcript, str):
            return "", []

        text = transcript.strip()
        corrections_applied: List[Dict[str, str]] = []

        if not text:
            return "", corrections_applied

        correction_map = {}
        correction_map.update(self.config.common_corrections)
        correction_map.update(self.config.custom_corrections)

        if self.config.enable_correction:
            for wrong, right in correction_map.items():
                if not wrong:
                    continue

                pattern = re.compile(rf"\b{re.escape(wrong)}\b", flags=re.IGNORECASE)
                if pattern.search(text):
                    text = pattern.sub(right, text)
                    corrections_applied.append(
                        {
                            "from": wrong,
                            "to": right,
                        }
                    )

        if self.config.enable_punctuation_cleanup:
            text = self._cleanup_punctuation(text)

        return text, corrections_applied

    def _cleanup_punctuation(self, text: str) -> str:
        """
        Cleans spacing and simple punctuation.
        """

        cleaned = re.sub(r"\s+", " ", text).strip()
        cleaned = re.sub(r"\s+([,.!?;:])", r"\1", cleaned)
        cleaned = re.sub(r"([,.!?;:])([^\s])", r"\1 \2", cleaned)

        if cleaned and cleaned[0].isalpha():
            cleaned = cleaned[0].upper() + cleaned[1:]

        return cleaned

    # -----------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Union[STTContext, Dict[str, Any]]],
        allow_missing: bool = False,
    ) -> Dict[str, Any]:
        """
        Validates SaaS user/workspace context.

        Prevents transcript/session data from mixing between users/workspaces.
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
        provider: STTProvider,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
    ) -> bool:
        """
        Determines if Security Agent approval is required.

        Security required when:
            - cloud STT is requested
            - raw audio storage is enabled
            - context is invalid
        """

        context_valid = self._validate_task_context(context)
        if not context_valid.get("success"):
            return True

        if provider == STTProvider.CLOUD:
            return True

        if self.config.store_raw_audio:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Requests Security Agent approval through callback if available.
        """

        payload = {
            "action": action,
            "agent": "STTEngine",
            "agent_type": "voice_agent",
            "context": self._context_to_public_dict(context),
            "details": details or {},
            "timestamp": time.time(),
        }

        if self.security_callback is None:
            if details and details.get("provider") == STTProvider.CLOUD.value:
                return self._error_result(
                    "Security approval required for cloud STT.",
                    PermissionError(
                        "Cloud STT requested but security_callback is not configured."
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
                    PermissionError("Security Agent denied STT action."),
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
        stt_result: STTResult,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Verification Agent compatible payload.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": "STTEngine",
            "agent_type": "voice_agent",
            "event": "stt_transcription_completed",
            "success": stt_result.success,
            "provider": stt_result.provider.value,
            "confidence": stt_result.confidence,
            "language": stt_result.language,
            "is_partial": stt_result.is_partial,
            "transcript_length": len(stt_result.transcript),
            "corrections_count": len(stt_result.corrections_applied),
            "context": self._context_to_public_dict(context),
            "timestamp": time.time(),
            "requires_followup_verification": False,
        }

    def _prepare_memory_payload(
        self,
        stt_result: STTResult,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Memory Agent compatible payload.

        Stores safe transcript metadata. Transcript content is included because
        STT output is usually needed for conversation memory, but raw audio is
        never included.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": "STTEngine",
            "agent_type": "voice_agent",
            "memory_type": "voice_transcript",
            "context": self._context_to_public_dict(context),
            "content": {
                "transcript": stt_result.transcript,
                "language": stt_result.language,
                "provider": stt_result.provider.value,
                "confidence": stt_result.confidence,
                "is_partial": stt_result.is_partial,
            },
            "metadata": {
                "safe_to_store": True,
                "contains_raw_audio": False,
                "corrections_count": len(stt_result.corrections_applied),
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
            "agent": "STTEngine",
            "agent_type": "voice_agent",
            "payload": payload or {},
            "timestamp": time.time(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
        except Exception:
            logger.exception("Failed to emit STTEngine event.")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Union[STTContext, Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Logs audit event.
        """

        if not self.config.audit_enabled:
            return

        audit = {
            "audit_id": str(uuid.uuid4()),
            "agent": "STTEngine",
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
            logger.exception("Failed to log STTEngine audit event.")

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
    # Utility helpers
    # -----------------------------------------------------------------

    def _detect_audio_input_type(
        self,
        audio_input: Union[str, Path, bytes, bytearray, Dict[str, Any]],
    ) -> AudioInputType:
        """
        Detects input type.
        """

        if isinstance(audio_input, (str, Path)):
            return AudioInputType.FILE_PATH

        if isinstance(audio_input, (bytes, bytearray)):
            return AudioInputType.BYTES

        if isinstance(audio_input, dict):
            declared = str(audio_input.get("type", "")).strip().lower()

            if declared == "text_test":
                return AudioInputType.TEXT_TEST

            if declared == "bytes":
                return AudioInputType.BYTES

            if declared == "file_path":
                return AudioInputType.FILE_PATH

        return AudioInputType.UNKNOWN

    def _parse_provider(self, provider: Union[STTProvider, str, None]) -> STTProvider:
        """
        Converts provider string to STTProvider.
        """

        if isinstance(provider, STTProvider):
            return provider

        if provider is None:
            return self.config.default_provider

        value = str(provider).strip().lower()

        for item in STTProvider:
            if item.value == value:
                return item

        return STTProvider.AUTO

    def _validate_language(self, language: Optional[str]) -> str:
        """
        Validates language hint.
        """

        if not language:
            return self.config.default_language

        normalized = str(language).strip().lower()

        if normalized in self.config.supported_languages:
            return normalized

        if self.config.enable_multilingual:
            return normalized

        return self.config.default_language

    def _inspect_audio_file(self, path: Path) -> Dict[str, Any]:
        """
        Extracts lightweight local audio metadata when possible.
        """

        metadata: Dict[str, Any] = {
            "suffix": path.suffix.lower(),
            "size_bytes": path.stat().st_size,
        }

        if path.suffix.lower() == ".wav":
            try:
                with wave.open(str(path), "rb") as wav:
                    frames = wav.getnframes()
                    rate = wav.getframerate()
                    channels = wav.getnchannels()
                    sample_width = wav.getsampwidth()

                    metadata.update(
                        {
                            "format": "wav",
                            "frames": frames,
                            "sample_rate": rate,
                            "channels": channels,
                            "sample_width": sample_width,
                            "duration_seconds": round(frames / float(rate), 4) if rate else None,
                        }
                    )
            except Exception as exc:
                metadata["wav_inspection_error"] = str(exc)

        return metadata

    def _hash_file(self, path: Path) -> str:
        """
        Returns SHA256 hash of file contents.
        """

        sha = hashlib.sha256()

        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                sha.update(chunk)

        return sha.hexdigest()

    def _hash_bytes(self, raw: bytes) -> str:
        """
        Returns SHA256 hash of bytes.
        """

        return hashlib.sha256(raw).hexdigest()

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """
        Safely converts value to float.
        """

        try:
            return float(value)
        except Exception:
            return default

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

    def _context_to_dict(
        self,
        context: Optional[Union[STTContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Converts context dataclass/dict to dict.
        """

        if context is None:
            return {}

        if isinstance(context, STTContext):
            return asdict(context)

        if isinstance(context, dict):
            return dict(context)

        return {}

    def _context_to_public_dict(
        self,
        context: Optional[Union[STTContext, Dict[str, Any]]],
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
        context: Optional[Union[STTContext, Dict[str, Any]]],
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
            "agent": "STTEngine",
            "agent_type": "voice_agent",
            "module": "agents.voice_agent.stt_engine",
            "timestamp": time.time(),
            "version": "1.0.0",
        }


# ---------------------------------------------------------------------
# Optional simple self-test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = STTEngine()

    demo_context = STTContext(
        user_id="demo_user",
        workspace_id="demo_workspace",
        device_id="demo_device",
        session_id="demo_session",
        request_id="demo_request",
    )

    print(
        engine.transcribe(
            audio_input={
                "type": "text_test",
                "text": "will iam open dash board for digital promotics",
            },
            context=demo_context,
            language="en",
        )
    )

    stream = engine.start_stream(context=demo_context)
    stream_id = stream["data"]["stream_id"]

    print(
        engine.transcribe_stream_chunk(
            stream_id=stream_id,
            audio_chunk=b"fake-audio-chunk",
            context=demo_context,
        )
    )

    print(
        engine.finish_stream(
            stream_id=stream_id,
            context=demo_context,
        )
    )