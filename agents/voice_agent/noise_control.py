"""
agents/voice_agent/noise_control.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Noise suppression, echo cancellation, wind/crowd filtering,
    and gain normalization for the Voice Agent.

This file is:
    - production-level
    - import-safe
    - testable without real microphone access
    - SaaS user/workspace isolated
    - compatible with BaseAgent, Agent Registry, Agent Loader,
      Agent Router, Master Agent, Security Agent, Memory Agent,
      Verification Agent, Dashboard/API, and future plugins.

Important:
    This file does not perform destructive or sensitive system actions.
    It only processes audio-like input safely and returns structured results.
"""

from __future__ import annotations

import asyncio
import audioop
import logging
import math
import time
import uuid
import wave
from dataclasses import dataclass, field, asdict
from enum import Enum
from io import BytesIO
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Optional NumPy Import
# =============================================================================

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore


# =============================================================================
# Optional / Safe BaseAgent Import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the real William BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent run executed.",
                "data": task,
                "error": None,
                "metadata": {"fallback": True},
            }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Callback Types
# =============================================================================

AsyncCallback = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
SyncCallback = Callable[[Dict[str, Any]], Dict[str, Any]]
Callback = Union[AsyncCallback, SyncCallback]


# =============================================================================
# Enums / Data Classes
# =============================================================================

class NoiseControlMode(str, Enum):
    """
    Audio cleanup processing modes.
    """

    OFF = "off"
    LIGHT = "light"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    MEETING = "meeting"
    OUTDOOR = "outdoor"
    CAR = "car"
    STUDIO = "studio"


class AudioFormat(str, Enum):
    """
    Supported raw PCM audio formats.

    PCM16 is the default and recommended format.
    """

    PCM16 = "pcm16"
    PCM8 = "pcm8"
    FLOAT32 = "float32"
    WAV = "wav"


class NoiseEventType(str, Enum):
    """
    Dashboard/API event types.
    """

    PROCESS_STARTED = "noise_control.process_started"
    PROCESS_COMPLETED = "noise_control.process_completed"
    PROCESS_FAILED = "noise_control.process_failed"
    SECURITY_REQUIRED = "noise_control.security_required"
    VERIFICATION_READY = "noise_control.verification_ready"
    MEMORY_READY = "noise_control.memory_ready"
    AUDIT_LOGGED = "noise_control.audit_logged"


@dataclass
class NoiseControlContext:
    """
    SaaS-safe execution context.

    user_id and workspace_id are required for user-specific processing.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    subscription_plan: Optional[str] = None
    locale: str = "en"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NoiseControlConfig:
    """
    Noise control configuration.

    This can later be moved into agents/voice_agent/config.py.
    """

    mode: NoiseControlMode = NoiseControlMode.BALANCED
    audio_format: AudioFormat = AudioFormat.PCM16
    sample_rate: int = 16000
    sample_width: int = 2
    channels: int = 1

    enable_noise_suppression: bool = True
    enable_echo_cancellation: bool = True
    enable_wind_filter: bool = True
    enable_crowd_filter: bool = True
    enable_gain_normalization: bool = True
    enable_dc_offset_removal: bool = True
    enable_silence_gate: bool = True
    enable_clipping_protection: bool = True

    target_rms: int = 3500
    max_gain: float = 4.0
    min_gain: float = 0.25
    silence_threshold_rms: int = 90
    noise_floor_rms: int = 180
    high_pass_strength: float = 0.92
    low_pass_strength: float = 0.82
    echo_reference_decay: float = 0.58
    echo_reduction_strength: float = 0.45
    crowd_smoothing_strength: float = 0.30
    wind_reduction_strength: float = 0.38

    max_audio_bytes: int = 20 * 1024 * 1024
    emit_dashboard_events: bool = True
    enable_audit_logs: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True

    allow_processing_without_numpy: bool = True
    store_audio_in_memory_payload: bool = False


@dataclass
class AudioMetrics:
    """
    Audio quality metrics before/after processing.
    """

    rms: float = 0.0
    peak: float = 0.0
    duration_seconds: float = 0.0
    sample_count: int = 0
    sample_rate: int = 16000
    channels: int = 1
    sample_width: int = 2
    zero_crossing_rate: float = 0.0
    clipping_detected: bool = False
    silence_detected: bool = False
    estimated_noise_floor: float = 0.0


@dataclass
class NoiseProcessingResult:
    """
    Internal structured processing result.
    """

    request_id: str
    processed_audio: bytes
    original_size: int
    processed_size: int
    mode: NoiseControlMode
    audio_format: AudioFormat
    before_metrics: AudioMetrics
    after_metrics: AudioMetrics
    applied_filters: List[str]
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    session_id: str
    device_id: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# NoiseControl
# =============================================================================

class NoiseControl(BaseAgent):
    """
    Voice Agent noise control module.

    Responsibilities:
        - suppress background noise
        - reduce echo using optional reference audio
        - reduce wind rumble
        - smooth crowd noise
        - normalize gain
        - protect against clipping
        - return structured SaaS-safe results

    Integration:
        - Master Agent:
            Can call this through Agent Router before STT.

        - Security Agent:
            This file can request approval for suspicious/oversized audio tasks.

        - Memory Agent:
            Stores only metrics/context by default, not raw audio.

        - Verification Agent:
            Receives processing summary and quality metrics.

        - Dashboard/API:
            Events and audit logs can be emitted through callbacks.

        - Registry/Loader:
            Import-safe with fallback BaseAgent.
    """

    SECURITY_RELEVANT_ACTIONS: Tuple[str, ...] = (
        "process_external_audio_url",
        "process_sensitive_call_recording",
        "store_raw_audio",
        "export_audio",
    )

    def __init__(
        self,
        config: Optional[NoiseControlConfig] = None,
        context: Optional[NoiseControlContext] = None,
        security_agent_callback: Optional[Callback] = None,
        verification_agent_callback: Optional[Callback] = None,
        memory_agent_callback: Optional[Callback] = None,
        event_callback: Optional[Callback] = None,
        audit_callback: Optional[Callback] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", "NoiseControl"),
            agent_id=kwargs.get("agent_id", "noise_control"),
        )

        self.config = config or NoiseControlConfig()
        self.context = context

        self.security_agent_callback = security_agent_callback
        self.verification_agent_callback = verification_agent_callback
        self.memory_agent_callback = memory_agent_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self.logger = logger_instance or logger

        self._event_history: List[Dict[str, Any]] = []
        self._processing_history: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible task runner.

        Supported actions:
            - process
            - analyze
            - normalize_gain
            - suppress_noise
            - cancel_echo
            - filter_wind
            - filter_crowd
            - state
        """

        action = str(task.get("action", "state")).strip().lower()

        context_payload = task.get("context")
        if isinstance(context_payload, dict):
            self.context = NoiseControlContext(
                user_id=context_payload.get("user_id"),
                workspace_id=context_payload.get("workspace_id"),
                session_id=context_payload.get("session_id") or str(uuid.uuid4()),
                device_id=context_payload.get("device_id"),
                role=context_payload.get("role"),
                permissions=list(context_payload.get("permissions") or []),
                subscription_plan=context_payload.get("subscription_plan"),
                locale=context_payload.get("locale", "en"),
                metadata=dict(context_payload.get("metadata") or {}),
            )

        if action == "state":
            return self._safe_result(
                message="NoiseControl state retrieved.",
                data=self.get_state(),
            )

        validation = self._validate_task_context()
        if not validation["success"]:
            return validation

        if self._requires_security_check(task):
            approval = await self._request_security_approval(task)
            if not approval["success"]:
                return approval

        audio_data = task.get("audio_data", b"")
        reference_audio = task.get("reference_audio")
        audio_format = task.get("audio_format")
        mode = task.get("mode")

        if action == "process":
            return await self.process_audio(
                audio_data=audio_data,
                reference_audio=reference_audio,
                audio_format=audio_format,
                mode=mode,
                metadata=dict(task.get("metadata") or {}),
            )

        if action == "analyze":
            return await self.analyze_audio(
                audio_data=audio_data,
                audio_format=audio_format,
            )

        if action == "normalize_gain":
            return await self.normalize_gain(
                audio_data=audio_data,
                audio_format=audio_format,
            )

        if action == "suppress_noise":
            return await self.suppress_noise(
                audio_data=audio_data,
                audio_format=audio_format,
            )

        if action == "cancel_echo":
            return await self.cancel_echo(
                audio_data=audio_data,
                reference_audio=reference_audio,
                audio_format=audio_format,
            )

        if action == "filter_wind":
            return await self.filter_wind(
                audio_data=audio_data,
                audio_format=audio_format,
            )

        if action == "filter_crowd":
            return await self.filter_crowd(
                audio_data=audio_data,
                audio_format=audio_format,
            )

        return self._error_result(
            message=f"Unsupported NoiseControl action: {action}",
            error="UNSUPPORTED_ACTION",
            data={
                "supported_actions": [
                    "process",
                    "analyze",
                    "normalize_gain",
                    "suppress_noise",
                    "cancel_echo",
                    "filter_wind",
                    "filter_crowd",
                    "state",
                ]
            },
        )

    async def process_audio(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        reference_audio: Optional[Union[bytes, bytearray, memoryview, List[int], List[float]]] = None,
        audio_format: Optional[Union[str, AudioFormat]] = None,
        mode: Optional[Union[str, NoiseControlMode]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full audio cleanup pipeline.

        Pipeline:
            1. Decode audio
            2. Analyze before metrics
            3. DC offset removal
            4. Silence gate
            5. Noise suppression
            6. Echo cancellation
            7. Wind filtering
            8. Crowd filtering
            9. Gain normalization
            10. Clipping protection
            11. Encode back to original/default format
        """

        request_id = str(uuid.uuid4())
        started_at = time.time()

        validation = self._validate_task_context()
        if not validation["success"]:
            return validation

        fmt = self._resolve_audio_format(audio_format)
        processing_mode = self._resolve_mode(mode)

        await self._emit_agent_event(
            NoiseEventType.PROCESS_STARTED,
            {
                "request_id": request_id,
                "mode": processing_mode.value,
                "audio_format": fmt.value,
            },
        )

        await self._log_audit_event(
            action="noise_processing_started",
            details={
                "request_id": request_id,
                "mode": processing_mode.value,
                "audio_format": fmt.value,
            },
        )

        try:
            raw_bytes = self._coerce_audio_to_bytes(audio_data, fmt)
            self._validate_audio_size(raw_bytes)

            samples, wav_info = self._decode_audio(raw_bytes, fmt)
            before_metrics = self._calculate_metrics(samples, wav_info)

            processed = samples[:]
            applied_filters: List[str] = []

            if self.config.enable_dc_offset_removal:
                processed = self._remove_dc_offset(processed)
                applied_filters.append("dc_offset_removal")

            if self.config.enable_silence_gate:
                processed, silence_applied = self._apply_silence_gate(processed)
                if silence_applied:
                    applied_filters.append("silence_gate")

            if self.config.enable_noise_suppression and processing_mode != NoiseControlMode.OFF:
                processed = self._suppress_noise_samples(processed, processing_mode)
                applied_filters.append("noise_suppression")

            if (
                self.config.enable_echo_cancellation
                and reference_audio is not None
                and processing_mode != NoiseControlMode.OFF
            ):
                reference_bytes = self._coerce_audio_to_bytes(reference_audio, fmt)
                reference_samples, _ = self._decode_audio(reference_bytes, fmt)
                processed = self._cancel_echo_samples(processed, reference_samples, processing_mode)
                applied_filters.append("echo_cancellation")

            if self.config.enable_wind_filter and processing_mode in {
                NoiseControlMode.BALANCED,
                NoiseControlMode.AGGRESSIVE,
                NoiseControlMode.OUTDOOR,
                NoiseControlMode.CAR,
            }:
                processed = self._filter_wind_samples(processed, processing_mode)
                applied_filters.append("wind_filter")

            if self.config.enable_crowd_filter and processing_mode in {
                NoiseControlMode.BALANCED,
                NoiseControlMode.AGGRESSIVE,
                NoiseControlMode.MEETING,
                NoiseControlMode.CAR,
            }:
                processed = self._filter_crowd_samples(processed, processing_mode)
                applied_filters.append("crowd_filter")

            if self.config.enable_gain_normalization:
                processed = self._normalize_gain_samples(processed, processing_mode)
                applied_filters.append("gain_normalization")

            if self.config.enable_clipping_protection:
                processed = self._protect_clipping(processed)
                applied_filters.append("clipping_protection")

            after_metrics = self._calculate_metrics(processed, wav_info)
            processed_bytes = self._encode_audio(processed, fmt, wav_info)

            result = NoiseProcessingResult(
                request_id=request_id,
                processed_audio=processed_bytes,
                original_size=len(raw_bytes),
                processed_size=len(processed_bytes),
                mode=processing_mode,
                audio_format=fmt,
                before_metrics=before_metrics,
                after_metrics=after_metrics,
                applied_filters=applied_filters,
                user_id=self.context.user_id if self.context else "unknown",
                workspace_id=self.context.workspace_id if self.context else "unknown",
                session_id=self.context.session_id if self.context else str(uuid.uuid4()),
                device_id=self.context.device_id if self.context else None,
                metadata={
                    **(metadata or {}),
                    "duration_ms": round((time.time() - started_at) * 1000, 3),
                    "numpy_available": bool(np is not None),
                },
            )

            result_dict = self._processing_result_to_dict(result)

            self._processing_history.append({
                **result_dict,
                "processed_audio": f"<{len(processed_bytes)} bytes>",
            })
            self._processing_history = self._processing_history[-100:]

            verification_payload = self._prepare_verification_payload(result)
            memory_payload = self._prepare_memory_payload(result)

            if verification_payload and self.config.enable_verification_payloads:
                await self._send_to_verification_agent(verification_payload)
                await self._emit_agent_event(NoiseEventType.VERIFICATION_READY, verification_payload)

            if memory_payload and self.config.enable_memory_payloads:
                await self._send_to_memory_agent(memory_payload)
                await self._emit_agent_event(NoiseEventType.MEMORY_READY, memory_payload)

            await self._emit_agent_event(
                NoiseEventType.PROCESS_COMPLETED,
                {
                    "request_id": request_id,
                    "applied_filters": applied_filters,
                    "before_metrics": asdict(before_metrics),
                    "after_metrics": asdict(after_metrics),
                },
            )

            await self._log_audit_event(
                action="noise_processing_completed",
                details={
                    "request_id": request_id,
                    "applied_filters": applied_filters,
                    "original_size": len(raw_bytes),
                    "processed_size": len(processed_bytes),
                },
            )

            return self._safe_result(
                message="Audio processed successfully.",
                data=result_dict,
                metadata={
                    "request_id": request_id,
                    "duration_ms": round((time.time() - started_at) * 1000, 3),
                },
            )

        except Exception as exc:
            self.logger.exception("NoiseControl processing failed: %s", exc)

            await self._emit_agent_event(
                NoiseEventType.PROCESS_FAILED,
                {
                    "request_id": request_id,
                    "error": str(exc),
                },
            )

            await self._log_audit_event(
                action="noise_processing_failed",
                details={
                    "request_id": request_id,
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="Audio processing failed.",
                error=str(exc),
                data={
                    "request_id": request_id,
                },
            )

    async def analyze_audio(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        audio_format: Optional[Union[str, AudioFormat]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze audio quality without changing it.
        """

        try:
            fmt = self._resolve_audio_format(audio_format)
            raw_bytes = self._coerce_audio_to_bytes(audio_data, fmt)
            self._validate_audio_size(raw_bytes)

            samples, wav_info = self._decode_audio(raw_bytes, fmt)
            metrics = self._calculate_metrics(samples, wav_info)

            return self._safe_result(
                message="Audio analyzed successfully.",
                data={
                    "metrics": asdict(metrics),
                    "audio_format": fmt.value,
                    "size_bytes": len(raw_bytes),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Audio analysis failed.",
                error=str(exc),
            )

    async def normalize_gain(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        audio_format: Optional[Union[str, AudioFormat]] = None,
    ) -> Dict[str, Any]:
        """
        Run gain normalization only.
        """

        return await self._single_filter_process(
            audio_data=audio_data,
            audio_format=audio_format,
            filter_name="gain_normalization",
            filter_func=lambda samples: self._normalize_gain_samples(samples, self.config.mode),
        )

    async def suppress_noise(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        audio_format: Optional[Union[str, AudioFormat]] = None,
    ) -> Dict[str, Any]:
        """
        Run noise suppression only.
        """

        return await self._single_filter_process(
            audio_data=audio_data,
            audio_format=audio_format,
            filter_name="noise_suppression",
            filter_func=lambda samples: self._suppress_noise_samples(samples, self.config.mode),
        )

    async def cancel_echo(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        reference_audio: Optional[Union[bytes, bytearray, memoryview, List[int], List[float]]] = None,
        audio_format: Optional[Union[str, AudioFormat]] = None,
    ) -> Dict[str, Any]:
        """
        Run echo cancellation only.
        """

        if reference_audio is None:
            return self._error_result(
                message="Echo cancellation requires reference_audio.",
                error="MISSING_REFERENCE_AUDIO",
            )

        try:
            fmt = self._resolve_audio_format(audio_format)
            raw_bytes = self._coerce_audio_to_bytes(audio_data, fmt)
            ref_bytes = self._coerce_audio_to_bytes(reference_audio, fmt)

            samples, wav_info = self._decode_audio(raw_bytes, fmt)
            reference_samples, _ = self._decode_audio(ref_bytes, fmt)

            processed = self._cancel_echo_samples(samples, reference_samples, self.config.mode)
            processed_bytes = self._encode_audio(processed, fmt, wav_info)

            return self._safe_result(
                message="Echo cancellation completed.",
                data={
                    "processed_audio": processed_bytes,
                    "applied_filters": ["echo_cancellation"],
                    "metrics": {
                        "before": asdict(self._calculate_metrics(samples, wav_info)),
                        "after": asdict(self._calculate_metrics(processed, wav_info)),
                    },
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Echo cancellation failed.",
                error=str(exc),
            )

    async def filter_wind(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        audio_format: Optional[Union[str, AudioFormat]] = None,
    ) -> Dict[str, Any]:
        """
        Run wind filtering only.
        """

        return await self._single_filter_process(
            audio_data=audio_data,
            audio_format=audio_format,
            filter_name="wind_filter",
            filter_func=lambda samples: self._filter_wind_samples(samples, self.config.mode),
        )

    async def filter_crowd(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        audio_format: Optional[Union[str, AudioFormat]] = None,
    ) -> Dict[str, Any]:
        """
        Run crowd filtering only.
        """

        return await self._single_filter_process(
            audio_data=audio_data,
            audio_format=audio_format,
            filter_name="crowd_filter",
            filter_func=lambda samples: self._filter_crowd_samples(samples, self.config.mode),
        )

    def get_state(self) -> Dict[str, Any]:
        """
        Return current NoiseControl state.
        """

        return {
            "agent": "NoiseControl",
            "config": {
                "mode": self.config.mode.value,
                "audio_format": self.config.audio_format.value,
                "sample_rate": self.config.sample_rate,
                "sample_width": self.config.sample_width,
                "channels": self.config.channels,
                "enable_noise_suppression": self.config.enable_noise_suppression,
                "enable_echo_cancellation": self.config.enable_echo_cancellation,
                "enable_wind_filter": self.config.enable_wind_filter,
                "enable_crowd_filter": self.config.enable_crowd_filter,
                "enable_gain_normalization": self.config.enable_gain_normalization,
                "target_rms": self.config.target_rms,
                "max_audio_bytes": self.config.max_audio_bytes,
                "numpy_available": bool(np is not None),
            },
            "context": self._context_to_dict(),
            "history": {
                "events": self._event_history[-25:],
                "processing": self._processing_history[-25:],
            },
        }

    # -------------------------------------------------------------------------
    # Single Filter Helper
    # -------------------------------------------------------------------------

    async def _single_filter_process(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        audio_format: Optional[Union[str, AudioFormat]],
        filter_name: str,
        filter_func: Callable[[List[int]], List[int]],
    ) -> Dict[str, Any]:
        """
        Utility for methods that run only one filter.
        """

        try:
            fmt = self._resolve_audio_format(audio_format)
            raw_bytes = self._coerce_audio_to_bytes(audio_data, fmt)
            self._validate_audio_size(raw_bytes)

            samples, wav_info = self._decode_audio(raw_bytes, fmt)
            before = self._calculate_metrics(samples, wav_info)

            processed = filter_func(samples)
            processed = self._protect_clipping(processed)

            after = self._calculate_metrics(processed, wav_info)
            processed_bytes = self._encode_audio(processed, fmt, wav_info)

            return self._safe_result(
                message=f"{filter_name} completed.",
                data={
                    "processed_audio": processed_bytes,
                    "applied_filters": [filter_name, "clipping_protection"],
                    "metrics": {
                        "before": asdict(before),
                        "after": asdict(after),
                    },
                    "audio_format": fmt.value,
                },
            )

        except Exception as exc:
            return self._error_result(
                message=f"{filter_name} failed.",
                error=str(exc),
            )

    # -------------------------------------------------------------------------
    # Core Audio Algorithms
    # -------------------------------------------------------------------------

    def _suppress_noise_samples(
        self,
        samples: List[int],
        mode: NoiseControlMode,
    ) -> List[int]:
        """
        Basic noise suppression.

        Uses noise gate + soft spectral-style smoothing.
        This remains dependency-light and import-safe.
        """

        if not samples:
            return samples

        strength = self._mode_strength(mode)
        noise_floor = max(self.config.noise_floor_rms, int(self._estimate_noise_floor(samples)))

        output: List[int] = []
        prev = 0

        for sample in samples:
            abs_sample = abs(sample)

            if abs_sample < noise_floor:
                reduced = int(sample * (0.18 + (0.25 * (1.0 - strength))))
            else:
                reduced = sample

            smoothed = int((self.config.low_pass_strength * reduced) + ((1.0 - self.config.low_pass_strength) * prev))
            prev = smoothed
            output.append(smoothed)

        return output

    def _cancel_echo_samples(
        self,
        samples: List[int],
        reference_samples: List[int],
        mode: NoiseControlMode,
    ) -> List[int]:
        """
        Lightweight echo cancellation using reference subtraction.

        In a future production version, this can be replaced with WebRTC AEC.
        """

        if not samples or not reference_samples:
            return samples

        strength = self.config.echo_reduction_strength * self._mode_strength(mode)
        decay = self.config.echo_reference_decay
        output: List[int] = []

        reference_len = len(reference_samples)
        echo_memory = 0.0

        for idx, sample in enumerate(samples):
            ref = reference_samples[idx % reference_len]
            echo_memory = (decay * echo_memory) + ((1.0 - decay) * ref)
            cleaned = sample - int(echo_memory * strength)
            output.append(cleaned)

        return output

    def _filter_wind_samples(
        self,
        samples: List[int],
        mode: NoiseControlMode,
    ) -> List[int]:
        """
        Reduce low-frequency wind rumble using high-pass style filtering.
        """

        if not samples:
            return samples

        strength = self.config.wind_reduction_strength * self._mode_strength(mode)
        alpha = min(0.99, max(0.70, self.config.high_pass_strength + (strength * 0.05)))

        output: List[int] = []
        prev_input = samples[0]
        prev_output = samples[0]

        for sample in samples:
            high_passed = int(alpha * (prev_output + sample - prev_input))
            prev_input = sample
            prev_output = high_passed
            mixed = int((sample * (1.0 - strength)) + (high_passed * strength))
            output.append(mixed)

        return output

    def _filter_crowd_samples(
        self,
        samples: List[int],
        mode: NoiseControlMode,
    ) -> List[int]:
        """
        Smooth crowd/background chatter noise.

        This is intentionally conservative to avoid damaging speech.
        """

        if not samples:
            return samples

        strength = self.config.crowd_smoothing_strength * self._mode_strength(mode)
        window = 3 if mode in {NoiseControlMode.LIGHT, NoiseControlMode.STUDIO} else 5

        output: List[int] = []

        for idx, sample in enumerate(samples):
            start = max(0, idx - window)
            end = min(len(samples), idx + window + 1)
            local = samples[start:end]
            median_like = sorted(local)[len(local) // 2]
            mixed = int((sample * (1.0 - strength)) + (median_like * strength))
            output.append(mixed)

        return output

    def _normalize_gain_samples(
        self,
        samples: List[int],
        mode: NoiseControlMode,
    ) -> List[int]:
        """
        Normalize audio gain toward target RMS.
        """

        if not samples:
            return samples

        rms = self._rms(samples)
        if rms <= 0:
            return samples

        target = self.config.target_rms

        if mode == NoiseControlMode.STUDIO:
            target = int(target * 1.05)
        elif mode == NoiseControlMode.OUTDOOR:
            target = int(target * 1.15)
        elif mode == NoiseControlMode.LIGHT:
            target = int(target * 0.90)

        gain = target / rms
        gain = max(self.config.min_gain, min(self.config.max_gain, gain))

        return [int(sample * gain) for sample in samples]

    def _remove_dc_offset(self, samples: List[int]) -> List[int]:
        """
        Remove DC offset by subtracting mean sample value.
        """

        if not samples:
            return samples

        mean_value = sum(samples) / len(samples)
        return [int(sample - mean_value) for sample in samples]

    def _apply_silence_gate(self, samples: List[int]) -> Tuple[List[int], bool]:
        """
        Reduce near-silent background noise.
        """

        if not samples:
            return samples, False

        rms = self._rms(samples)
        if rms > self.config.silence_threshold_rms:
            return samples, False

        gated = [int(sample * 0.10) for sample in samples]
        return gated, True

    def _protect_clipping(self, samples: List[int]) -> List[int]:
        """
        Clamp samples to PCM16-safe range.
        """

        return [max(-32768, min(32767, int(sample))) for sample in samples]

    # -------------------------------------------------------------------------
    # Decode / Encode
    # -------------------------------------------------------------------------

    def _decode_audio(
        self,
        raw_bytes: bytes,
        fmt: AudioFormat,
    ) -> Tuple[List[int], Dict[str, Any]]:
        """
        Decode audio bytes into PCM16 sample list.
        """

        if fmt == AudioFormat.WAV:
            return self._decode_wav(raw_bytes)

        if fmt == AudioFormat.PCM16:
            if len(raw_bytes) % 2 != 0:
                raw_bytes = raw_bytes[:-1]

            samples = [
                int.from_bytes(raw_bytes[i:i + 2], byteorder="little", signed=True)
                for i in range(0, len(raw_bytes), 2)
            ]

            return samples, {
                "sample_rate": self.config.sample_rate,
                "sample_width": 2,
                "channels": self.config.channels,
                "format": AudioFormat.PCM16.value,
            }

        if fmt == AudioFormat.PCM8:
            samples = [(byte - 128) * 256 for byte in raw_bytes]
            return samples, {
                "sample_rate": self.config.sample_rate,
                "sample_width": 1,
                "channels": self.config.channels,
                "format": AudioFormat.PCM8.value,
            }

        if fmt == AudioFormat.FLOAT32:
            if np is None:
                if not self.config.allow_processing_without_numpy:
                    raise RuntimeError("FLOAT32 audio requires numpy.")
                raise RuntimeError("FLOAT32 audio is not supported without numpy.")

            arr = np.frombuffer(raw_bytes, dtype=np.float32)
            clipped = np.clip(arr, -1.0, 1.0)
            samples = [int(value * 32767) for value in clipped]

            return samples, {
                "sample_rate": self.config.sample_rate,
                "sample_width": 4,
                "channels": self.config.channels,
                "format": AudioFormat.FLOAT32.value,
            }

        raise ValueError(f"Unsupported audio format: {fmt}")

    def _encode_audio(
        self,
        samples: List[int],
        fmt: AudioFormat,
        wav_info: Dict[str, Any],
    ) -> bytes:
        """
        Encode PCM16 sample list back into requested format.
        """

        samples = self._protect_clipping(samples)

        if fmt == AudioFormat.WAV:
            return self._encode_wav(samples, wav_info)

        if fmt == AudioFormat.PCM16:
            return b"".join(
                int(sample).to_bytes(2, byteorder="little", signed=True)
                for sample in samples
            )

        if fmt == AudioFormat.PCM8:
            return bytes(
                max(0, min(255, int((sample / 256) + 128)))
                for sample in samples
            )

        if fmt == AudioFormat.FLOAT32:
            if np is None:
                raise RuntimeError("FLOAT32 encoding requires numpy.")
            arr = np.array([sample / 32767.0 for sample in samples], dtype=np.float32)
            return arr.tobytes()

        raise ValueError(f"Unsupported audio format: {fmt}")

    def _decode_wav(self, raw_bytes: bytes) -> Tuple[List[int], Dict[str, Any]]:
        """
        Decode WAV bytes into PCM16 samples.
        """

        with wave.open(BytesIO(raw_bytes), "rb") as wav:
            channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            sample_rate = wav.getframerate()
            frames = wav.readframes(wav.getnframes())

        if sample_width == 2:
            pcm16 = frames
        elif sample_width == 1:
            pcm16 = audioop.lin2lin(frames, 1, 2)
        elif sample_width == 4:
            pcm16 = audioop.lin2lin(frames, 4, 2)
        else:
            raise ValueError(f"Unsupported WAV sample width: {sample_width}")

        if channels > 1:
            pcm16 = audioop.tomono(pcm16, 2, 0.5, 0.5)

        samples = [
            int.from_bytes(pcm16[i:i + 2], byteorder="little", signed=True)
            for i in range(0, len(pcm16), 2)
        ]

        return samples, {
            "sample_rate": sample_rate,
            "sample_width": 2,
            "channels": 1,
            "original_channels": channels,
            "format": AudioFormat.WAV.value,
        }

    def _encode_wav(
        self,
        samples: List[int],
        wav_info: Dict[str, Any],
    ) -> bytes:
        """
        Encode PCM16 samples as WAV.
        """

        buffer = BytesIO()
        sample_rate = int(wav_info.get("sample_rate", self.config.sample_rate))

        frames = b"".join(
            int(sample).to_bytes(2, byteorder="little", signed=True)
            for sample in samples
        )

        with wave.open(buffer, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(sample_rate)
            wav.writeframes(frames)

        return buffer.getvalue()

    # -------------------------------------------------------------------------
    # Metrics
    # -------------------------------------------------------------------------

    def _calculate_metrics(
        self,
        samples: List[int],
        wav_info: Dict[str, Any],
    ) -> AudioMetrics:
        """
        Calculate audio metrics for dashboard/STT quality checks.
        """

        sample_rate = int(wav_info.get("sample_rate", self.config.sample_rate))
        channels = int(wav_info.get("channels", self.config.channels))
        sample_width = int(wav_info.get("sample_width", self.config.sample_width))

        if not samples:
            return AudioMetrics(
                rms=0.0,
                peak=0.0,
                duration_seconds=0.0,
                sample_count=0,
                sample_rate=sample_rate,
                channels=channels,
                sample_width=sample_width,
                zero_crossing_rate=0.0,
                clipping_detected=False,
                silence_detected=True,
                estimated_noise_floor=0.0,
            )

        rms = self._rms(samples)
        peak = max(abs(sample) for sample in samples)
        duration = len(samples) / float(sample_rate) if sample_rate > 0 else 0.0
        zcr = self._zero_crossing_rate(samples)
        clipping = peak >= 32760
        silence = rms < self.config.silence_threshold_rms
        noise_floor = self._estimate_noise_floor(samples)

        return AudioMetrics(
            rms=float(round(rms, 3)),
            peak=float(peak),
            duration_seconds=float(round(duration, 4)),
            sample_count=len(samples),
            sample_rate=sample_rate,
            channels=channels,
            sample_width=sample_width,
            zero_crossing_rate=float(round(zcr, 6)),
            clipping_detected=bool(clipping),
            silence_detected=bool(silence),
            estimated_noise_floor=float(round(noise_floor, 3)),
        )

    def _rms(self, samples: List[int]) -> float:
        """
        Root mean square amplitude.
        """

        if not samples:
            return 0.0

        square_sum = sum(float(sample) * float(sample) for sample in samples)
        return math.sqrt(square_sum / len(samples))

    def _zero_crossing_rate(self, samples: List[int]) -> float:
        """
        Estimate zero crossing rate.
        """

        if len(samples) < 2:
            return 0.0

        crossings = 0
        previous = samples[0]

        for sample in samples[1:]:
            if (previous >= 0 > sample) or (previous < 0 <= sample):
                crossings += 1
            previous = sample

        return crossings / float(len(samples) - 1)

    def _estimate_noise_floor(self, samples: List[int]) -> float:
        """
        Estimate low-level noise floor from quietest sample amplitudes.
        """

        if not samples:
            return 0.0

        abs_samples = sorted(abs(sample) for sample in samples)
        quiet_count = max(1, int(len(abs_samples) * 0.10))
        quiet_samples = abs_samples[:quiet_count]

        if not quiet_samples:
            return 0.0

        return sum(quiet_samples) / len(quiet_samples)

    # -------------------------------------------------------------------------
    # Validation / Resolving
    # -------------------------------------------------------------------------

    def _resolve_audio_format(
        self,
        audio_format: Optional[Union[str, AudioFormat]],
    ) -> AudioFormat:
        """
        Resolve requested audio format.
        """

        if audio_format is None:
            return self.config.audio_format

        if isinstance(audio_format, AudioFormat):
            return audio_format

        try:
            return AudioFormat(str(audio_format).lower())
        except ValueError as exc:
            raise ValueError(
                f"Invalid audio format: {audio_format}. "
                f"Allowed: {[item.value for item in AudioFormat]}"
            ) from exc

    def _resolve_mode(
        self,
        mode: Optional[Union[str, NoiseControlMode]],
    ) -> NoiseControlMode:
        """
        Resolve requested processing mode.
        """

        if mode is None:
            return self.config.mode

        if isinstance(mode, NoiseControlMode):
            return mode

        try:
            return NoiseControlMode(str(mode).lower())
        except ValueError as exc:
            raise ValueError(
                f"Invalid noise control mode: {mode}. "
                f"Allowed: {[item.value for item in NoiseControlMode]}"
            ) from exc

    def _coerce_audio_to_bytes(
        self,
        audio_data: Union[bytes, bytearray, memoryview, List[int], List[float]],
        fmt: AudioFormat,
    ) -> bytes:
        """
        Convert supported audio input into bytes.
        """

        if isinstance(audio_data, bytes):
            return audio_data

        if isinstance(audio_data, bytearray):
            return bytes(audio_data)

        if isinstance(audio_data, memoryview):
            return audio_data.tobytes()

        if isinstance(audio_data, list):
            if fmt == AudioFormat.FLOAT32:
                if np is None:
                    raise RuntimeError("List[float] FLOAT32 conversion requires numpy.")
                return np.array(audio_data, dtype=np.float32).tobytes()

            samples = [max(-32768, min(32767, int(value))) for value in audio_data]
            return b"".join(
                sample.to_bytes(2, byteorder="little", signed=True)
                for sample in samples
            )

        raise TypeError(
            "audio_data must be bytes, bytearray, memoryview, List[int], or List[float]."
        )

    def _validate_audio_size(self, raw_bytes: bytes) -> None:
        """
        Prevent oversized audio payloads.
        """

        if not raw_bytes:
            raise ValueError("audio_data is empty.")

        if len(raw_bytes) > self.config.max_audio_bytes:
            raise ValueError(
                f"audio_data exceeds max size. "
                f"Got {len(raw_bytes)} bytes, max is {self.config.max_audio_bytes} bytes."
            )

    def _mode_strength(self, mode: NoiseControlMode) -> float:
        """
        Convert processing mode to filter strength.
        """

        if mode == NoiseControlMode.OFF:
            return 0.0
        if mode == NoiseControlMode.LIGHT:
            return 0.45
        if mode == NoiseControlMode.BALANCED:
            return 0.70
        if mode == NoiseControlMode.AGGRESSIVE:
            return 1.00
        if mode == NoiseControlMode.MEETING:
            return 0.75
        if mode == NoiseControlMode.OUTDOOR:
            return 0.90
        if mode == NoiseControlMode.CAR:
            return 0.85
        if mode == NoiseControlMode.STUDIO:
            return 0.50
        return 0.70

    # -------------------------------------------------------------------------
    # Required Compatibility Hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Every user-specific task requires user_id and workspace_id.
        """

        if self.context is None:
            return self._error_result(
                message="NoiseControl requires context before user-specific execution.",
                error="MISSING_CONTEXT",
                data={"required": ["user_id", "workspace_id"]},
            )

        if self.context.user_id in (None, "", 0):
            return self._error_result(
                message="NoiseControl context is missing user_id.",
                error="MISSING_USER_ID",
                data={"required": ["user_id"]},
            )

        if self.context.workspace_id in (None, "", 0):
            return self._error_result(
                message="NoiseControl context is missing workspace_id.",
                error="MISSING_WORKSPACE_ID",
                data={"required": ["workspace_id"]},
            )

        return self._safe_result(
            message="NoiseControl context validated.",
            data={
                "user_id": self.context.user_id,
                "workspace_id": self.context.workspace_id,
                "session_id": self.context.session_id,
            },
        )

    def _requires_security_check(self, task: Dict[str, Any]) -> bool:
        """
        Decide whether Security Agent approval is required.

        Most normal noise cleanup does not require Security Agent approval.
        Security is required for raw audio storage/export or sensitive recordings.
        """

        action = str(task.get("action", "")).lower().strip()

        if action in self.SECURITY_RELEVANT_ACTIONS:
            return True

        metadata = task.get("metadata") or {}
        if isinstance(metadata, dict):
            if metadata.get("sensitive") is True:
                return True
            if metadata.get("store_raw_audio") is True:
                return True
            if metadata.get("external_audio_url"):
                return True

        return False

    async def _request_security_approval(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request Security Agent approval for sensitive audio processing.
        """

        payload = {
            "type": "security_approval_request",
            "source_agent": "NoiseControl",
            "action": task.get("action"),
            "user_id": self.context.user_id if self.context else None,
            "workspace_id": self.context.workspace_id if self.context else None,
            "session_id": self.context.session_id if self.context else None,
            "device_id": self.context.device_id if self.context else None,
            "reason": "Sensitive or raw audio operation requested.",
            "metadata": {
                "created_at": time.time(),
                "task_metadata": task.get("metadata", {}),
            },
        }

        await self._emit_agent_event(NoiseEventType.SECURITY_REQUIRED, payload)

        if self.security_agent_callback is None:
            return self._error_result(
                message="Security approval required but Security Agent callback is not connected.",
                error="SECURITY_AGENT_NOT_CONNECTED",
                data={
                    "approval_required": True,
                    "approved": False,
                    "payload": payload,
                },
            )

        result = await self._execute_callback(self.security_agent_callback, payload)

        approved = bool(
            result.get("approved")
            or result.get("data", {}).get("approved")
            or result.get("success") is True
        )

        if not approved:
            return self._error_result(
                message="Security Agent did not approve this audio operation.",
                error="SECURITY_APPROVAL_DENIED",
                data={
                    "approval_required": True,
                    "approved": False,
                    "security_result": result,
                },
            )

        return self._safe_result(
            message="Security approval granted.",
            data={
                "approval_required": True,
                "approved": True,
                "security_result": result,
            },
        )

    def _prepare_verification_payload(
        self,
        result: NoiseProcessingResult,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.
        """

        return {
            "type": "verification_payload",
            "source_agent": "NoiseControl",
            "request_id": result.request_id,
            "user_id": result.user_id,
            "workspace_id": result.workspace_id,
            "session_id": result.session_id,
            "device_id": result.device_id,
            "mode": result.mode.value,
            "audio_format": result.audio_format.value,
            "applied_filters": result.applied_filters,
            "quality_checks": {
                "before_metrics": asdict(result.before_metrics),
                "after_metrics": asdict(result.after_metrics),
                "clipping_after": result.after_metrics.clipping_detected,
                "silence_after": result.after_metrics.silence_detected,
                "size_changed": result.original_size != result.processed_size,
            },
            "metadata": {
                "created_at": time.time(),
                **result.metadata,
            },
        }

    def _prepare_memory_payload(
        self,
        result: NoiseProcessingResult,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        By default, raw audio is NOT stored. Only metrics/context are saved.
        """

        content: Dict[str, Any] = {
            "request_id": result.request_id,
            "mode": result.mode.value,
            "audio_format": result.audio_format.value,
            "applied_filters": result.applied_filters,
            "before_metrics": asdict(result.before_metrics),
            "after_metrics": asdict(result.after_metrics),
        }

        if self.config.store_audio_in_memory_payload:
            content["processed_audio"] = result.processed_audio

        return {
            "type": "memory_payload",
            "source_agent": "NoiseControl",
            "user_id": result.user_id,
            "workspace_id": result.workspace_id,
            "session_id": result.session_id,
            "device_id": result.device_id,
            "memory_scope": "workspace",
            "content": content,
            "privacy": {
                "contains_raw_audio": self.config.store_audio_in_memory_payload,
                "store_allowed": True,
            },
            "metadata": {
                "created_at": time.time(),
            },
        }

    async def _emit_agent_event(
        self,
        event_type: Union[NoiseEventType, str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit structured dashboard/API event.
        """

        event_name = event_type.value if isinstance(event_type, NoiseEventType) else str(event_type)

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_name,
            "source_agent": "NoiseControl",
            "user_id": self.context.user_id if self.context else None,
            "workspace_id": self.context.workspace_id if self.context else None,
            "session_id": self.context.session_id if self.context else None,
            "device_id": self.context.device_id if self.context else None,
            "payload": payload,
            "created_at": time.time(),
        }

        self._event_history.append(event)
        self._event_history = self._event_history[-500:]

        if self.config.emit_dashboard_events and self.event_callback:
            try:
                event["callback_result"] = await self._execute_callback(self.event_callback, event)
            except Exception as exc:
                self.logger.warning("NoiseControl event callback failed: %s", exc)

        return self._safe_result(
            message="NoiseControl event emitted.",
            data=event,
        )

    async def _log_audit_event(
        self,
        action: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event for dashboard/security review.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "source_agent": "NoiseControl",
            "action": action,
            "user_id": self.context.user_id if self.context else None,
            "workspace_id": self.context.workspace_id if self.context else None,
            "session_id": self.context.session_id if self.context else None,
            "device_id": self.context.device_id if self.context else None,
            "details": details or {},
            "created_at": time.time(),
        }

        if self.config.enable_audit_logs and self.audit_callback:
            try:
                audit_event["callback_result"] = await self._execute_callback(
                    self.audit_callback,
                    audit_event,
                )
            except Exception as exc:
                self.logger.warning("NoiseControl audit callback failed: %s", exc)

        return self._safe_result(
            message="NoiseControl audit event logged.",
            data=audit_event,
        )

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
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
        message: str = "Error.",
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "UNKNOWN_ERROR",
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Callback Senders
    # -------------------------------------------------------------------------

    async def _send_to_memory_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send payload to Memory Agent if connected.
        """

        if self.memory_agent_callback is None:
            return {
                "sent": False,
                "message": "Memory Agent callback not connected.",
            }

        result = await self._execute_callback(self.memory_agent_callback, payload)
        return {
            "sent": True,
            "message": "Memory payload sent.",
            "result": result,
        }

    async def _send_to_verification_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send payload to Verification Agent if connected.
        """

        if self.verification_agent_callback is None:
            return {
                "sent": False,
                "message": "Verification Agent callback not connected.",
            }

        result = await self._execute_callback(self.verification_agent_callback, payload)
        return {
            "sent": True,
            "message": "Verification payload sent.",
            "result": result,
        }

    async def _execute_callback(
        self,
        callback: Callback,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute sync or async callback safely.
        """

        result = callback(payload)
        if asyncio.iscoroutine(result):
            result = await result

        if isinstance(result, dict):
            return result

        return {
            "success": True,
            "message": "Callback executed.",
            "data": {"result": result},
            "error": None,
            "metadata": {
                "result_type": type(result).__name__,
            },
        }

    # -------------------------------------------------------------------------
    # Serialization Helpers
    # -------------------------------------------------------------------------

    def _processing_result_to_dict(
        self,
        result: NoiseProcessingResult,
    ) -> Dict[str, Any]:
        """
        Convert processing result to structured dict.

        processed_audio remains included because the caller needs it for STT.
        """

        return {
            "request_id": result.request_id,
            "processed_audio": result.processed_audio,
            "original_size": result.original_size,
            "processed_size": result.processed_size,
            "mode": result.mode.value,
            "audio_format": result.audio_format.value,
            "before_metrics": asdict(result.before_metrics),
            "after_metrics": asdict(result.after_metrics),
            "applied_filters": result.applied_filters,
            "user_id": result.user_id,
            "workspace_id": result.workspace_id,
            "session_id": result.session_id,
            "device_id": result.device_id,
            "metadata": result.metadata,
        }

    def _context_to_dict(self) -> Optional[Dict[str, Any]]:
        """
        Convert context to safe dict.
        """

        if self.context is None:
            return None

        return {
            "user_id": self.context.user_id,
            "workspace_id": self.context.workspace_id,
            "session_id": self.context.session_id,
            "device_id": self.context.device_id,
            "role": self.context.role,
            "permissions": self.context.permissions,
            "subscription_plan": self.context.subscription_plan,
            "locale": self.context.locale,
            "metadata": self.context.metadata,
        }


# =============================================================================
# Factory Helper
# =============================================================================

def create_noise_control(
    user_id: Union[str, int],
    workspace_id: Union[str, int],
    device_id: Optional[str] = None,
    session_id: Optional[str] = None,
    config: Optional[NoiseControlConfig] = None,
    **kwargs: Any,
) -> NoiseControl:
    """
    Factory helper for API/dashboard/registry usage.
    """

    context = NoiseControlContext(
        user_id=user_id,
        workspace_id=workspace_id,
        session_id=session_id or str(uuid.uuid4()),
        device_id=device_id,
        role=kwargs.pop("role", None),
        permissions=list(kwargs.pop("permissions", []) or []),
        subscription_plan=kwargs.pop("subscription_plan", None),
        locale=kwargs.pop("locale", "en"),
        metadata=dict(kwargs.pop("metadata", {}) or {}),
    )

    return NoiseControl(
        config=config,
        context=context,
        **kwargs,
    )


# =============================================================================
# Manual Test
# =============================================================================

async def _manual_test() -> Dict[str, Any]:
    """
    Lightweight manual test.

    Run:
        python -m agents.voice_agent.noise_control
    """

    processor = create_noise_control(
        user_id="test_user",
        workspace_id="test_workspace",
        device_id="test_device",
    )

    sample_rate = 16000
    duration_seconds = 1
    frequency = 440

    samples: List[int] = []
    for i in range(sample_rate * duration_seconds):
        clean = math.sin(2 * math.pi * frequency * (i / sample_rate)) * 6000
        noise = math.sin(2 * math.pi * 80 * (i / sample_rate)) * 1000
        samples.append(int(clean + noise))

    result = await processor.process_audio(
        audio_data=samples,
        audio_format=AudioFormat.PCM16,
        mode=NoiseControlMode.BALANCED,
        metadata={"manual_test": True},
    )

    return {
        "success": True,
        "message": "Manual NoiseControl test complete.",
        "data": {
            "processing_success": result.get("success"),
            "state": processor.get_state(),
            "result_summary": {
                "message": result.get("message"),
                "error": result.get("error"),
                "applied_filters": result.get("data", {}).get("applied_filters"),
                "before_metrics": result.get("data", {}).get("before_metrics"),
                "after_metrics": result.get("data", {}).get("after_metrics"),
            },
        },
        "error": None,
        "metadata": {},
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    output = asyncio.run(_manual_test())
    print(output)