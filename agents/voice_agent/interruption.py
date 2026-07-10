"""
agents/voice_agent/interruption.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Stops current speech output when the user interrupts and captures the new command.

This file provides:
    - InterruptionHandler class
    - SaaS-safe user_id / workspace_id validation
    - Speech interruption detection state
    - TTS stop/cancel integration hooks
    - New command capture integration hooks
    - Security Agent compatibility
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard/API event emission
    - Audit logging hooks
    - Safe structured result format

Design Notes:
    This file is import-safe. If BaseAgent, Security Agent, Memory Agent,
    Verification Agent, or event systems are not yet created, fallback stubs
    keep the module usable during development.

    The InterruptionHandler does not directly perform destructive actions.
    It only stops/cancels speech playback and captures user interruption text/audio
    through injected adapters or safe defaults.

Public Class:
    InterruptionHandler
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William BaseAgent exists.
        The real BaseAgent should provide routing, lifecycle, permissions,
        agent identity, and shared utility hooks.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.voice_agent.interruption")
logger.addHandler(logging.NullHandler())


# =============================================================================
# Type aliases
# =============================================================================

StructuredResult = Dict[str, Any]
ContextDict = Dict[str, Any]
EventCallback = Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
CommandCallback = Callable[[str, Dict[str, Any]], Union[None, Awaitable[None]]]
StopSpeechCallback = Callable[[Dict[str, Any]], Union[bool, StructuredResult, Awaitable[Union[bool, StructuredResult]]]]
CaptureCommandCallback = Callable[[Dict[str, Any]], Union[str, StructuredResult, Awaitable[Union[str, StructuredResult]]]]


# =============================================================================
# Enums
# =============================================================================

class InterruptionState(str, Enum):
    """
    Current interruption lifecycle state.
    """

    IDLE = "idle"
    LISTENING_FOR_INTERRUPT = "listening_for_interrupt"
    INTERRUPT_DETECTED = "interrupt_detected"
    STOPPING_SPEECH = "stopping_speech"
    CAPTURING_COMMAND = "capturing_command"
    COMPLETED = "completed"
    FAILED = "failed"


class InterruptionSource(str, Enum):
    """
    Where interruption came from.
    """

    VOICE = "voice"
    WAKE_WORD = "wake_word"
    BUTTON = "button"
    DASHBOARD = "dashboard"
    API = "api"
    GESTURE = "gesture"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class InterruptionPriority(str, Enum):
    """
    Interruption priority.

    NORMAL:
        Default user correction or new question.

    HIGH:
        User explicitly says stop, cancel, wait, pause, no, etc.

    EMERGENCY:
        Future support for urgent safety events.
    """

    NORMAL = "normal"
    HIGH = "high"
    EMERGENCY = "emergency"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class InterruptionConfig:
    """
    Runtime configuration for interruption handling.

    This config is intentionally conservative and safe by default.
    """

    enabled: bool = True

    # If True, actively stop TTS when an interruption is detected.
    stop_speech_on_interrupt: bool = True

    # If True, immediately capture the new user command after stopping speech.
    capture_command_after_interrupt: bool = True

    # Delay after stopping speech before capturing the new command.
    post_stop_capture_delay_seconds: float = 0.15

    # Maximum duration to wait for a new command.
    command_capture_timeout_seconds: float = 12.0

    # Minimum length for text command to be accepted.
    min_command_chars: int = 1

    # Common phrases that count as high-priority interruptions.
    high_priority_phrases: Tuple[str, ...] = (
        "stop",
        "wait",
        "pause",
        "cancel",
        "no",
        "hold on",
        "listen",
        "wrong",
        "that's wrong",
        "not that",
        "change it",
        "shut up",
        "be quiet",
        "one second",
    )

    # Common phrases that count as normal follow-up interruption.
    normal_interrupt_phrases: Tuple[str, ...] = (
        "william",
        "hey william",
        "jarvis",
        "actually",
        "also",
        "but",
        "can you",
        "i mean",
        "wait",
    )

    # Whether interruption events should be emitted for dashboard/API.
    emit_events: bool = True

    # Whether audit logs should be created.
    audit_enabled: bool = True

    # Whether useful interruption context should be prepared for memory.
    memory_payload_enabled: bool = True

    # Whether completed interruption should prepare verification payload.
    verification_payload_enabled: bool = True

    # If True, this handler uses a thread lock around state transitions.
    thread_safe: bool = True

    # Future integrations can use this to mark required security for some sources.
    require_security_for_dashboard_interrupt: bool = False
    require_security_for_api_interrupt: bool = False

    # Metadata passed to dashboard/analytics.
    analytics_enabled: bool = True


@dataclass
class InterruptionEvent:
    """
    Represents one interruption event.
    """

    interruption_id: str
    user_id: str
    workspace_id: str
    source: InterruptionSource = InterruptionSource.UNKNOWN
    priority: InterruptionPriority = InterruptionPriority.NORMAL
    phrase: Optional[str] = None
    raw_input: Optional[Any] = None
    captured_command: Optional[str] = None
    previous_speech_id: Optional[str] = None
    previous_text: Optional[str] = None
    state: InterruptionState = InterruptionState.IDLE
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert event to JSON-safe dict.
        """
        data = asdict(self)
        data["source"] = self.source.value
        data["priority"] = self.priority.value
        data["state"] = self.state.value
        return data


@dataclass
class SpeechState:
    """
    Tracks currently active speech output.

    The TTS engine, VoiceAgent, or voice_loop.py can update this state.
    """

    is_speaking: bool = False
    speech_id: Optional[str] = None
    text: Optional[str] = None
    started_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def start(self, text: Optional[str] = None, speech_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.is_speaking = True
        self.speech_id = speech_id or str(uuid.uuid4())
        self.text = text
        self.started_at = time.time()
        self.metadata = metadata or {}

    def stop(self) -> None:
        self.is_speaking = False
        self.metadata["stopped_at"] = time.time()

    def clear(self) -> None:
        self.is_speaking = False
        self.speech_id = None
        self.text = None
        self.started_at = None
        self.metadata = {}


# =============================================================================
# Helper functions
# =============================================================================

def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_str(value: Any, max_length: int = 5000) -> str:
    """
    Convert any value to safe string.
    """
    try:
        text = "" if value is None else str(value)
    except Exception:
        text = "<unprintable>"
    if len(text) > max_length:
        return text[:max_length] + "...[truncated]"
    return text


def _normalize_text(text: Optional[str]) -> str:
    """
    Normalize text for phrase detection.
    """
    if not text:
        return ""
    return " ".join(text.lower().strip().split())


async def _maybe_await(value: Any) -> Any:
    """
    Await value only if awaitable.
    """
    if inspect.isawaitable(value):
        return await value
    return value


# =============================================================================
# Main class
# =============================================================================

class InterruptionHandler(BaseAgent):
    """
    Handles voice interruptions for William / Jarvis Voice Agent.

    Main responsibilities:
        1. Detect interruption intent from voice/wake/button/API/dashboard events.
        2. Stop currently speaking TTS output.
        3. Capture the new command after interruption.
        4. Return structured dict results.
        5. Protect SaaS user/workspace isolation.
        6. Prepare payloads for Security, Verification, Memory, Dashboard, Audit.

    Typical usage from voice_loop.py:

        handler = InterruptionHandler(
            stop_speech_callback=tts_engine.stop_current_speech,
            capture_command_callback=stt_engine.listen_once,
        )

        handler.mark_speaking(
            user_id="u1",
            workspace_id="w1",
            text="Here is the answer...",
            speech_id="speech-123",
        )

        result = await handler.handle_interruption(
            user_id="u1",
            workspace_id="w1",
            raw_input="wait, change that",
            source="voice",
        )

    This class is intentionally adapter-based:
        - It does not depend on a specific TTS engine.
        - It does not depend on a specific STT engine.
        - It can be wired into FastAPI, dashboard websockets, mobile app,
          desktop app, or voice_loop.py later.
    """

    def __init__(
        self,
        config: Optional[InterruptionConfig] = None,
        stop_speech_callback: Optional[StopSpeechCallback] = None,
        capture_command_callback: Optional[CaptureCommandCallback] = None,
        event_callback: Optional[EventCallback] = None,
        command_callback: Optional[CommandCallback] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        agent_name: str = "voice_interruption_handler",
        agent_id: str = "voice_agent.interruption",
        **kwargs: Any,
    ) -> None:
        """
        Initialize interruption handler.

        Args:
            config:
                InterruptionConfig instance.

            stop_speech_callback:
                Adapter function to stop TTS/current speech output.

            capture_command_callback:
                Adapter function to capture new command from STT/audio.

            event_callback:
                Optional event emitter for dashboard/API/WebSocket.

            command_callback:
                Optional callback after a new command is captured.

            security_agent:
                Optional SecurityAgent instance.

            verification_agent:
                Optional VerificationAgent instance.

            memory_agent:
                Optional MemoryAgent instance.

            audit_logger:
                Optional audit logger callback.

            agent_name:
                BaseAgent compatible name.

            agent_id:
                Registry/router compatible id.
        """
        super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)

        self.config = config or InterruptionConfig()
        self.stop_speech_callback = stop_speech_callback
        self.capture_command_callback = capture_command_callback
        self.event_callback = event_callback
        self.command_callback = command_callback
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger

        self.state: InterruptionState = InterruptionState.IDLE
        self.speech_state = SpeechState()

        self._lock = threading.RLock()
        self._event_history: List[InterruptionEvent] = []
        self._last_interruption: Optional[InterruptionEvent] = None

        self._stats: Dict[str, Any] = {
            "total_interruptions": 0,
            "successful_interruptions": 0,
            "failed_interruptions": 0,
            "commands_captured": 0,
            "speech_stops_requested": 0,
            "speech_stops_successful": 0,
            "created_at": time.time(),
            "updated_at": time.time(),
        }

    # =========================================================================
    # Public speech state methods
    # =========================================================================

    def mark_speaking(
        self,
        user_id: str,
        workspace_id: str,
        text: Optional[str] = None,
        speech_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Mark that William is currently speaking.

        VoiceAgent or TTS engine should call this when speech begins.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._guard():
            self.speech_state.start(
                text=text,
                speech_id=speech_id,
                metadata={
                    **(metadata or {}),
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            self.state = InterruptionState.LISTENING_FOR_INTERRUPT

        self._emit_agent_event_sync({
            "event_type": "speech_started",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "speech_id": self.speech_state.speech_id,
            "timestamp_ms": _now_ms(),
        })

        return self._safe_result(
            message="Speech state marked as speaking.",
            data={
                "is_speaking": self.speech_state.is_speaking,
                "speech_id": self.speech_state.speech_id,
                "state": self.state.value,
            },
            metadata={
                "agent": self.agent_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def mark_speech_finished(
        self,
        user_id: str,
        workspace_id: str,
        speech_id: Optional[str] = None,
        clear: bool = True,
    ) -> StructuredResult:
        """
        Mark speech as finished normally.

        This should be called by TTS engine when speech output ends.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._guard():
            if speech_id and self.speech_state.speech_id and speech_id != self.speech_state.speech_id:
                return self._error_result(
                    message="Speech ID mismatch. Current speech was not modified.",
                    error="speech_id_mismatch",
                    data={
                        "provided_speech_id": speech_id,
                        "current_speech_id": self.speech_state.speech_id,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            if clear:
                self.speech_state.clear()
            else:
                self.speech_state.stop()

            self.state = InterruptionState.IDLE

        self._emit_agent_event_sync({
            "event_type": "speech_finished",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "speech_id": speech_id,
            "timestamp_ms": _now_ms(),
        })

        return self._safe_result(
            message="Speech state marked as finished.",
            data={
                "is_speaking": self.speech_state.is_speaking,
                "state": self.state.value,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def get_speech_state(self) -> StructuredResult:
        """
        Get current speech state.
        """
        return self._safe_result(
            message="Speech state retrieved.",
            data={
                "is_speaking": self.speech_state.is_speaking,
                "speech_id": self.speech_state.speech_id,
                "text": self.speech_state.text,
                "started_at": self.speech_state.started_at,
                "metadata": dict(self.speech_state.metadata),
                "handler_state": self.state.value,
            },
        )

    # =========================================================================
    # Public interruption methods
    # =========================================================================

    def detect_interruption(
        self,
        raw_input: Any,
        source: Union[str, InterruptionSource] = InterruptionSource.UNKNOWN,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Detect whether input should be treated as an interruption.

        This method is lightweight and safe to call frequently from voice_loop.py.
        It can process text transcripts, wake word hits, dashboard button events,
        or API events.

        Args:
            raw_input:
                Input text/event/audio metadata. Usually text from partial STT.

            source:
                InterruptionSource value.

            metadata:
                Additional event metadata.

        Returns:
            Structured result with detection decision.
        """
        if not self.config.enabled:
            return self._safe_result(
                message="Interruption detection is disabled.",
                data={
                    "detected": False,
                    "reason": "disabled",
                },
            )

        src = self._parse_source(source)
        normalized = _normalize_text(_safe_str(raw_input))
        meta = metadata or {}

        detected = False
        priority = InterruptionPriority.NORMAL
        matched_phrase: Optional[str] = None
        reason = "no_interrupt_phrase_detected"

        if src in {
            InterruptionSource.BUTTON,
            InterruptionSource.DASHBOARD,
            InterruptionSource.API,
            InterruptionSource.GESTURE,
            InterruptionSource.SYSTEM,
        }:
            detected = True
            priority = InterruptionPriority.HIGH if src in {
                InterruptionSource.BUTTON,
                InterruptionSource.DASHBOARD,
                InterruptionSource.API,
            } else InterruptionPriority.NORMAL
            reason = f"{src.value}_interrupt_event"

        if not detected and normalized:
            for phrase in self.config.high_priority_phrases:
                if phrase and phrase.lower() in normalized:
                    detected = True
                    priority = InterruptionPriority.HIGH
                    matched_phrase = phrase
                    reason = "high_priority_phrase_detected"
                    break

        if not detected and normalized:
            for phrase in self.config.normal_interrupt_phrases:
                if phrase and phrase.lower() in normalized:
                    detected = True
                    priority = InterruptionPriority.NORMAL
                    matched_phrase = phrase
                    reason = "normal_interrupt_phrase_detected"
                    break

        if not detected and meta.get("wake_word_detected") is True:
            detected = True
            priority = InterruptionPriority.NORMAL
            reason = "wake_word_metadata_detected"

        if not detected and meta.get("interrupt") is True:
            detected = True
            priority = InterruptionPriority.HIGH
            reason = "explicit_interrupt_metadata"

        return self._safe_result(
            message="Interruption detection completed.",
            data={
                "detected": detected,
                "priority": priority.value,
                "matched_phrase": matched_phrase,
                "source": src.value,
                "reason": reason,
                "is_currently_speaking": self.speech_state.is_speaking,
            },
            metadata={
                "input_preview": normalized[:120],
                "timestamp_ms": _now_ms(),
            },
        )

    async def handle_interruption(
        self,
        user_id: str,
        workspace_id: str,
        raw_input: Any = None,
        source: Union[str, InterruptionSource] = InterruptionSource.UNKNOWN,
        metadata: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> StructuredResult:
        """
        Main async interruption flow.

        Steps:
            1. Validate SaaS context.
            2. Detect interruption unless forced.
            3. Security check if needed.
            4. Stop current speech.
            5. Capture new command.
            6. Prepare verification and memory payloads.
            7. Emit dashboard/API event.
            8. Return structured result.

        Args:
            user_id:
                Current SaaS user id.

            workspace_id:
                Current workspace id.

            raw_input:
                User interruption text/event.

            source:
                Interruption source.

            metadata:
                Optional context metadata.

            force:
                If True, handle as interruption even if phrase detection fails.

        Returns:
            Structured dict result.
        """
        started_at = time.time()
        metadata = metadata or {}

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        src = self._parse_source(source)

        detection = self.detect_interruption(
            raw_input=raw_input,
            source=src,
            metadata=metadata,
        )

        detected = bool(detection.get("data", {}).get("detected"))
        if not detected and not force:
            return self._safe_result(
                message="No interruption detected.",
                data={
                    "interrupted": False,
                    "detection": detection.get("data", {}),
                    "current_state": self.state.value,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "source": src.value,
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

        priority = self._parse_priority(detection.get("data", {}).get("priority"))
        matched_phrase = detection.get("data", {}).get("matched_phrase")

        event = InterruptionEvent(
            interruption_id=str(uuid.uuid4()),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            source=src,
            priority=priority,
            phrase=matched_phrase,
            raw_input=raw_input,
            previous_speech_id=self.speech_state.speech_id,
            previous_text=self.speech_state.text,
            state=InterruptionState.INTERRUPT_DETECTED,
            metadata={
                **metadata,
                "force": force,
                "detected": detected,
                "detection": detection.get("data", {}),
            },
        )

        with self._guard():
            self.state = InterruptionState.INTERRUPT_DETECTED
            self._last_interruption = event
            self._event_history.append(event)
            self._stats["total_interruptions"] += 1
            self._stats["updated_at"] = time.time()

        await self._emit_agent_event({
            "event_type": "interruption_detected",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "interruption": event.to_dict(),
            "timestamp_ms": _now_ms(),
        })

        security_result = None
        if self._requires_security_check(source=src, priority=priority, metadata=metadata):
            security_result = await self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="voice_interruption",
                payload=event.to_dict(),
            )
            if not security_result.get("success"):
                event.state = InterruptionState.FAILED
                event.error = security_result.get("error") or "security_denied"
                with self._guard():
                    self.state = InterruptionState.FAILED
                    self._stats["failed_interruptions"] += 1

                await self._log_audit_event({
                    "event_type": "interruption_security_denied",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "interruption_id": event.interruption_id,
                    "security_result": security_result,
                    "timestamp_ms": _now_ms(),
                })

                return self._error_result(
                    message="Interruption was blocked by security approval.",
                    error=event.error,
                    data={
                        "interrupted": False,
                        "interruption": event.to_dict(),
                        "security_result": security_result,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        stop_result = await self.stop_current_speech(
            user_id=user_id,
            workspace_id=workspace_id,
            interruption_id=event.interruption_id,
            reason="user_interruption",
            metadata={
                **metadata,
                "source": src.value,
                "priority": priority.value,
            },
        )

        captured_command: Optional[str] = None
        capture_result: Optional[StructuredResult] = None

        if self.config.capture_command_after_interrupt:
            with self._guard():
                self.state = InterruptionState.CAPTURING_COMMAND
                event.state = InterruptionState.CAPTURING_COMMAND
                event.updated_at = time.time()

            if self.config.post_stop_capture_delay_seconds > 0:
                await asyncio.sleep(self.config.post_stop_capture_delay_seconds)

            capture_result = await self.capture_new_command(
                user_id=user_id,
                workspace_id=workspace_id,
                interruption_id=event.interruption_id,
                raw_input=raw_input,
                source=src,
                metadata=metadata,
            )

            if capture_result.get("success"):
                captured_command = capture_result.get("data", {}).get("command")
                event.captured_command = captured_command
                with self._guard():
                    self._stats["commands_captured"] += 1

                if captured_command and self.command_callback:
                    await _maybe_await(self.command_callback(
                        captured_command,
                        {
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                            "interruption_id": event.interruption_id,
                            "source": src.value,
                            "priority": priority.value,
                            "metadata": metadata,
                        },
                    ))

        event.state = InterruptionState.COMPLETED
        event.updated_at = time.time()

        with self._guard():
            self.state = InterruptionState.COMPLETED
            self._last_interruption = event
            self._stats["successful_interruptions"] += 1
            self._stats["updated_at"] = time.time()

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            stop_result=stop_result,
            capture_result=capture_result,
        )

        memory_payload = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            stop_result=stop_result,
            capture_result=capture_result,
        )

        audit_payload = {
            "event_type": "voice_interruption_completed",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "interruption_id": event.interruption_id,
            "source": src.value,
            "priority": priority.value,
            "speech_stopped": bool(stop_result.get("success")),
            "command_captured": bool(captured_command),
            "duration_ms": int((time.time() - started_at) * 1000),
            "timestamp_ms": _now_ms(),
        }
        await self._log_audit_event(audit_payload)

        await self._emit_agent_event({
            "event_type": "interruption_completed",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "interruption": event.to_dict(),
            "stop_result": stop_result,
            "capture_result": capture_result,
            "timestamp_ms": _now_ms(),
        })

        return self._safe_result(
            message="Interruption handled successfully.",
            data={
                "interrupted": True,
                "interruption": event.to_dict(),
                "speech_stop": stop_result,
                "capture": capture_result,
                "captured_command": captured_command,
                "security_result": security_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "duration_ms": int((time.time() - started_at) * 1000),
            },
        )

    def handle_interruption_sync(
        self,
        user_id: str,
        workspace_id: str,
        raw_input: Any = None,
        source: Union[str, InterruptionSource] = InterruptionSource.UNKNOWN,
        metadata: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> StructuredResult:
        """
        Synchronous wrapper for handle_interruption.

        Useful for non-async dashboard/API integrations.
        """
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                return self._error_result(
                    message="Cannot run sync interruption handler inside an active event loop. Use await handle_interruption(...).",
                    error="event_loop_already_running",
                    data={
                        "interrupted": False,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )
        except RuntimeError:
            pass

        return asyncio.run(self.handle_interruption(
            user_id=user_id,
            workspace_id=workspace_id,
            raw_input=raw_input,
            source=source,
            metadata=metadata,
            force=force,
        ))

    async def stop_current_speech(
        self,
        user_id: str,
        workspace_id: str,
        interruption_id: Optional[str] = None,
        reason: str = "interruption",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Stop current TTS/speech output.

        This method uses the injected stop_speech_callback when available.
        If no callback exists, it safely updates local speech state only.

        It never directly performs unsafe system actions.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        metadata = metadata or {}

        with self._guard():
            self.state = InterruptionState.STOPPING_SPEECH
            self._stats["speech_stops_requested"] += 1
            was_speaking = self.speech_state.is_speaking
            speech_id = self.speech_state.speech_id
            speech_text = self.speech_state.text

        callback_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "interruption_id": interruption_id,
            "reason": reason,
            "speech_id": speech_id,
            "was_speaking": was_speaking,
            "metadata": metadata,
        }

        callback_result: Optional[Any] = None

        try:
            if self.config.stop_speech_on_interrupt and self.stop_speech_callback:
                callback_result = await _maybe_await(self.stop_speech_callback(callback_payload))

            with self._guard():
                self.speech_state.stop()
                self._stats["speech_stops_successful"] += 1
                self._stats["updated_at"] = time.time()

            await self._emit_agent_event({
                "event_type": "speech_stop_requested",
                "agent": self.agent_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "interruption_id": interruption_id,
                "speech_id": speech_id,
                "was_speaking": was_speaking,
                "timestamp_ms": _now_ms(),
            })

            return self._safe_result(
                message="Current speech stopped successfully.",
                data={
                    "speech_stopped": True,
                    "was_speaking": was_speaking,
                    "speech_id": speech_id,
                    "speech_text": speech_text,
                    "callback_result": self._normalize_callback_result(callback_result),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "interruption_id": interruption_id,
                    "reason": reason,
                },
            )

        except Exception as exc:
            logger.exception("Failed to stop current speech.")
            return self._error_result(
                message="Failed to stop current speech.",
                error=_safe_str(exc),
                data={
                    "speech_stopped": False,
                    "was_speaking": was_speaking,
                    "speech_id": speech_id,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "interruption_id": interruption_id,
                    "reason": reason,
                },
            )

    async def capture_new_command(
        self,
        user_id: str,
        workspace_id: str,
        interruption_id: Optional[str] = None,
        raw_input: Any = None,
        source: Union[str, InterruptionSource] = InterruptionSource.UNKNOWN,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Capture new command after user interruption.

        If capture_command_callback is provided, this method calls it.
        If no callback exists, it attempts to safely reuse raw_input as command text
        when raw_input looks like text.

        This gives a working development fallback before STT engine is complete.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        metadata = metadata or {}
        src = self._parse_source(source)

        capture_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "interruption_id": interruption_id,
            "source": src.value,
            "raw_input": raw_input,
            "timeout_seconds": self.config.command_capture_timeout_seconds,
            "metadata": metadata,
        }

        try:
            command: Optional[str] = None
            raw_capture_result: Optional[Any] = None

            if self.capture_command_callback:
                raw_capture_result = await _maybe_await(self.capture_command_callback(capture_payload))

                if isinstance(raw_capture_result, dict):
                    data = raw_capture_result.get("data", {})
                    command = (
                        raw_capture_result.get("command")
                        or data.get("command")
                        or data.get("text")
                        or raw_capture_result.get("text")
                    )
                elif isinstance(raw_capture_result, str):
                    command = raw_capture_result
                elif raw_capture_result is not None:
                    command = _safe_str(raw_capture_result)

            else:
                text = _safe_str(raw_input).strip()
                if text and text.lower() not in {"none", "null", "<unprintable>"}:
                    command = text

            command = self._clean_captured_command(command)

            if not command or len(command) < self.config.min_command_chars:
                return self._safe_result(
                    success=False,
                    message="No valid command captured after interruption.",
                    data={
                        "command": None,
                        "source": src.value,
                        "raw_capture_result": self._normalize_callback_result(raw_capture_result),
                    },
                    error="empty_command",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "interruption_id": interruption_id,
                    },
                )

            await self._emit_agent_event({
                "event_type": "new_command_captured_after_interruption",
                "agent": self.agent_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "interruption_id": interruption_id,
                "command_preview": command[:160],
                "source": src.value,
                "timestamp_ms": _now_ms(),
            })

            return self._safe_result(
                message="New command captured successfully.",
                data={
                    "command": command,
                    "source": src.value,
                    "raw_capture_result": self._normalize_callback_result(raw_capture_result),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "interruption_id": interruption_id,
                },
            )

        except asyncio.TimeoutError:
            return self._error_result(
                message="Command capture timed out.",
                error="capture_timeout",
                data={
                    "command": None,
                    "timeout_seconds": self.config.command_capture_timeout_seconds,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "interruption_id": interruption_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to capture new command after interruption.")
            return self._error_result(
                message="Failed to capture new command after interruption.",
                error=_safe_str(exc),
                data={
                    "command": None,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "interruption_id": interruption_id,
                },
            )

    # =========================================================================
    # Dashboard/API helper methods
    # =========================================================================

    def get_status(self) -> StructuredResult:
        """
        Get current handler status for dashboard/API.
        """
        with self._guard():
            data = {
                "agent": self.agent_id,
                "state": self.state.value,
                "enabled": self.config.enabled,
                "speech_state": {
                    "is_speaking": self.speech_state.is_speaking,
                    "speech_id": self.speech_state.speech_id,
                    "text": self.speech_state.text,
                    "started_at": self.speech_state.started_at,
                    "metadata": dict(self.speech_state.metadata),
                },
                "last_interruption": self._last_interruption.to_dict() if self._last_interruption else None,
                "stats": dict(self._stats),
            }

        return self._safe_result(
            message="Interruption handler status retrieved.",
            data=data,
        )

    def get_event_history(
        self,
        limit: int = 50,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> StructuredResult:
        """
        Get recent interruption history.

        SaaS-safe filtering is included. If user_id/workspace_id are provided,
        only matching events are returned.
        """
        limit = max(1, min(int(limit), 500))

        with self._guard():
            events = list(self._event_history)

        if user_id is not None:
            events = [event for event in events if str(event.user_id) == str(user_id)]

        if workspace_id is not None:
            events = [event for event in events if str(event.workspace_id) == str(workspace_id)]

        events = events[-limit:]

        return self._safe_result(
            message="Interruption event history retrieved.",
            data={
                "events": [event.to_dict() for event in events],
                "count": len(events),
                "limit": limit,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def clear_event_history(
        self,
        user_id: str,
        workspace_id: str,
    ) -> StructuredResult:
        """
        Clear event history only for a specific user/workspace.

        This preserves SaaS isolation and avoids clearing another user's history.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._guard():
            before = len(self._event_history)
            self._event_history = [
                event for event in self._event_history
                if not (
                    str(event.user_id) == str(user_id)
                    and str(event.workspace_id) == str(workspace_id)
                )
            ]
            after = len(self._event_history)

        return self._safe_result(
            message="Interruption history cleared for user/workspace.",
            data={
                "removed": before - after,
                "remaining": after,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def enable(self) -> StructuredResult:
        """
        Enable interruption handling.
        """
        self.config.enabled = True
        return self._safe_result(
            message="Interruption handling enabled.",
            data={"enabled": self.config.enabled},
        )

    def disable(self) -> StructuredResult:
        """
        Disable interruption handling.
        """
        self.config.enabled = False
        return self._safe_result(
            message="Interruption handling disabled.",
            data={"enabled": self.config.enabled},
        )

    def update_config(self, **kwargs: Any) -> StructuredResult:
        """
        Safely update config values.

        Only existing InterruptionConfig fields can be updated.
        """
        allowed = set(InterruptionConfig.__dataclass_fields__.keys())
        changed: Dict[str, Any] = {}
        rejected: Dict[str, Any] = {}

        for key, value in kwargs.items():
            if key in allowed:
                setattr(self.config, key, value)
                changed[key] = value
            else:
                rejected[key] = value

        return self._safe_result(
            message="Interruption config updated.",
            data={
                "changed": changed,
                "rejected": rejected,
                "config": asdict(self.config),
            },
        )

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Validate SaaS user/workspace context.

        Required by William global architecture:
            - Every task must support user_id and workspace_id.
            - Never mix memory, files, logs, analytics, or audit data between users/workspaces.
        """
        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing required user_id.",
                error="missing_user_id",
                data={
                    "valid": False,
                },
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing required workspace_id.",
                error="missing_workspace_id",
                data={
                    "valid": False,
                },
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "valid": True,
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        source: Union[str, InterruptionSource] = InterruptionSource.UNKNOWN,
        priority: Union[str, InterruptionPriority] = InterruptionPriority.NORMAL,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Interruption itself is low-risk, but dashboard/API-triggered interruption
        can be security-checked depending on config.

        Sensitive or remote interruption commands can be expanded later.
        """
        src = self._parse_source(source)
        metadata = metadata or {}

        if metadata.get("requires_security") is True:
            return True

        if src == InterruptionSource.DASHBOARD and self.config.require_security_for_dashboard_interrupt:
            return True

        if src == InterruptionSource.API and self.config.require_security_for_api_interrupt:
            return True

        return False

    async def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Dict[str, Any],
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Request approval from Security Agent.

        Uses injected security_agent when available.
        Otherwise returns allow=True for non-sensitive fallback behavior.
        """
        try:
            security_agent = self.security_agent

            if security_agent is None and SecurityAgent is not None:
                try:
                    security_agent = SecurityAgent()
                except Exception:
                    security_agent = None

            if security_agent is None:
                return self._safe_result(
                    message="Security Agent not available. Safe fallback approval granted for non-destructive interruption.",
                    data={
                        "approved": True,
                        "fallback": True,
                        "action": action,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            approval_method = None
            for method_name in (
                "approve_action",
                "request_approval",
                "check_permission",
                "validate_action",
            ):
                if hasattr(security_agent, method_name):
                    approval_method = getattr(security_agent, method_name)
                    break

            if approval_method is None:
                return self._safe_result(
                    message="Security Agent has no compatible approval method. Safe fallback approval granted.",
                    data={
                        "approved": True,
                        "fallback": True,
                        "action": action,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            result = await _maybe_await(approval_method(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                payload=payload,
            ))

            if isinstance(result, dict):
                approved = bool(
                    result.get("approved")
                    or result.get("allowed")
                    or result.get("success")
                    or result.get("data", {}).get("approved")
                )
                if approved:
                    return self._safe_result(
                        message="Security approval granted.",
                        data={
                            "approved": True,
                            "security_result": result,
                        },
                        metadata={
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                        },
                    )

                return self._error_result(
                    message="Security approval denied.",
                    error=result.get("error") or "security_denied",
                    data={
                        "approved": False,
                        "security_result": result,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            if bool(result):
                return self._safe_result(
                    message="Security approval granted.",
                    data={
                        "approved": True,
                        "security_result": result,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            return self._error_result(
                message="Security approval denied.",
                error="security_denied",
                data={
                    "approved": False,
                    "security_result": result,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Security approval failed.")
            return self._error_result(
                message="Security approval failed.",
                error=_safe_str(exc),
                data={
                    "approved": False,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "action": action,
                },
            )

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        event: InterruptionEvent,
        stop_result: Optional[StructuredResult] = None,
        capture_result: Optional[StructuredResult] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can later confirm:
            - Speech stopped successfully.
            - New command was captured.
            - User/workspace context remained isolated.
        """
        if not self.config.verification_payload_enabled:
            return {
                "enabled": False,
                "reason": "verification_payload_disabled",
            }

        return {
            "verification_type": "voice_interruption",
            "agent": self.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "interruption_id": event.interruption_id,
            "expected_outcome": {
                "speech_stopped": True,
                "command_capture_attempted": self.config.capture_command_after_interrupt,
            },
            "observed": {
                "event_state": event.state.value,
                "speech_stop_success": bool(stop_result and stop_result.get("success")),
                "capture_success": bool(capture_result and capture_result.get("success")),
                "captured_command_present": bool(event.captured_command),
            },
            "evidence": {
                "source": event.source.value,
                "priority": event.priority.value,
                "previous_speech_id": event.previous_speech_id,
                "phrase": event.phrase,
                "created_at": event.created_at,
                "updated_at": event.updated_at,
            },
            "metadata": {
                "created_by": self.agent_id,
                "timestamp_ms": _now_ms(),
            },
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        event: InterruptionEvent,
        stop_result: Optional[StructuredResult] = None,
        capture_result: Optional[StructuredResult] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Memory Agent.

        Memory Agent may use this to learn:
            - User corrected the assistant.
            - User gave a new command mid-speech.
            - User dislikes long answers or wrong direction.

        The payload remains user/workspace isolated.
        """
        if not self.config.memory_payload_enabled:
            return {
                "enabled": False,
                "reason": "memory_payload_disabled",
            }

        should_store = bool(event.captured_command) or event.priority in {
            InterruptionPriority.HIGH,
            InterruptionPriority.EMERGENCY,
        }

        return {
            "memory_type": "voice_interruption_context",
            "agent": self.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "should_store": should_store,
            "interruption_id": event.interruption_id,
            "summary": self._build_memory_summary(event),
            "data": {
                "source": event.source.value,
                "priority": event.priority.value,
                "phrase": event.phrase,
                "captured_command": event.captured_command,
                "previous_speech_preview": (event.previous_text or "")[:300],
                "speech_stop_success": bool(stop_result and stop_result.get("success")),
                "capture_success": bool(capture_result and capture_result.get("success")),
            },
            "metadata": {
                "timestamp_ms": _now_ms(),
                "created_by": self.agent_id,
            },
        }

    async def _emit_agent_event(
        self,
        payload: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """
        Emit event for dashboard/API/analytics.

        This is intentionally safe. Event callback failures do not crash
        interruption handling.
        """
        if not self.config.emit_events:
            return

        try:
            if self.event_callback:
                await _maybe_await(self.event_callback(payload))
            else:
                logger.debug("Agent event: %s", payload)
        except Exception:
            logger.exception("Failed to emit interruption event.")

    def _emit_agent_event_sync(self, payload: Dict[str, Any]) -> None:
        """
        Sync-safe event emission.

        Used by sync methods where awaiting is not convenient.
        """
        if not self.config.emit_events:
            return

        try:
            if self.event_callback:
                result = self.event_callback(payload)
                if inspect.isawaitable(result):
                    try:
                        loop = asyncio.get_running_loop()
                        if loop.is_running():
                            loop.create_task(result)  # type: ignore[arg-type]
                        else:
                            asyncio.run(result)  # type: ignore[arg-type]
                    except RuntimeError:
                        asyncio.run(result)  # type: ignore[arg-type]
            else:
                logger.debug("Agent event: %s", payload)
        except Exception:
            logger.exception("Failed to emit sync interruption event.")

    async def _log_audit_event(
        self,
        payload: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """
        Log audit event.

        In production, this should connect to a central AuditLog model/table.
        """
        if not self.config.audit_enabled:
            return

        try:
            payload = {
                **payload,
                "audit_agent": self.agent_id,
                "audit_timestamp_ms": _now_ms(),
            }

            if self.audit_logger:
                await _maybe_await(self.audit_logger(payload))
            else:
                logger.info("Audit event: %s", payload)
        except Exception:
            logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Standard William structured result format.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.agent_id,
                "timestamp_ms": _now_ms(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Standard William structured error format.
        """
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=_safe_str(error),
            metadata=metadata or {},
        )

    # =========================================================================
    # Internal utilities
    # =========================================================================

    def _guard(self) -> Any:
        """
        Return a context manager for state locking.

        If thread_safe is disabled, returns a no-op context manager.
        """
        if self.config.thread_safe:
            return self._lock

        class _NoopLock:
            def __enter__(self) -> None:
                return None

            def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
                return False

        return _NoopLock()

    def _parse_source(self, source: Union[str, InterruptionSource]) -> InterruptionSource:
        """
        Parse source into InterruptionSource enum.
        """
        if isinstance(source, InterruptionSource):
            return source

        try:
            return InterruptionSource(str(source).lower().strip())
        except Exception:
            return InterruptionSource.UNKNOWN

    def _parse_priority(self, priority: Union[str, InterruptionPriority, None]) -> InterruptionPriority:
        """
        Parse priority into InterruptionPriority enum.
        """
        if isinstance(priority, InterruptionPriority):
            return priority

        if priority is None:
            return InterruptionPriority.NORMAL

        try:
            return InterruptionPriority(str(priority).lower().strip())
        except Exception:
            return InterruptionPriority.NORMAL

    def _clean_captured_command(self, command: Optional[Any]) -> Optional[str]:
        """
        Clean captured user command.
        """
        if command is None:
            return None

        text = _safe_str(command, max_length=10000).strip()
        text = " ".join(text.split())

        if not text:
            return None

        # Remove common interruption-only prefixes while preserving meaning.
        removable_prefixes = (
            "william ",
            "hey william ",
            "jarvis ",
            "hey jarvis ",
            "wait ",
            "stop ",
            "hold on ",
            "actually ",
        )

        lowered = text.lower()
        for prefix in removable_prefixes:
            if lowered.startswith(prefix):
                text = text[len(prefix):].strip()
                break

        return text or None

    def _normalize_callback_result(self, value: Any) -> Any:
        """
        Convert callback result to JSON-safe data.
        """
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, dict):
            return value

        if isinstance(value, (list, tuple)):
            return list(value)

        return _safe_str(value)

    def _build_memory_summary(self, event: InterruptionEvent) -> str:
        """
        Build concise memory summary.
        """
        if event.captured_command:
            return (
                f"User interrupted William during speech and gave a new command: "
                f"{event.captured_command[:240]}"
            )

        if event.phrase:
            return (
                f"User interrupted William during speech with phrase: "
                f"{event.phrase}"
            )

        return (
            f"User interrupted William during speech from source "
            f"{event.source.value}."
        )


# =============================================================================
# Convenience factory
# =============================================================================

def create_interruption_handler(
    config: Optional[InterruptionConfig] = None,
    stop_speech_callback: Optional[StopSpeechCallback] = None,
    capture_command_callback: Optional[CaptureCommandCallback] = None,
    event_callback: Optional[EventCallback] = None,
    command_callback: Optional[CommandCallback] = None,
    **kwargs: Any,
) -> InterruptionHandler:
    """
    Factory helper for Voice Agent / Agent Loader / Registry.

    This keeps creation consistent for future plugin-style loading.
    """
    return InterruptionHandler(
        config=config,
        stop_speech_callback=stop_speech_callback,
        capture_command_callback=capture_command_callback,
        event_callback=event_callback,
        command_callback=command_callback,
        **kwargs,
    )


# =============================================================================
# Module metadata for Agent Registry / Agent Loader
# =============================================================================

AGENT_MODULE = "voice_agent"
AGENT_FILE = "interruption.py"
AGENT_CLASS = "InterruptionHandler"
AGENT_VERSION = "1.0.0"
AGENT_DESCRIPTION = "Stops speech when user interrupts and captures the new command."
AGENT_CAPABILITIES = [
    "detect_voice_interruption",
    "stop_current_speech",
    "capture_new_command",
    "prepare_verification_payload",
    "prepare_memory_payload",
    "emit_dashboard_events",
    "audit_interruption_events",
]
AGENT_REQUIRES_USER_CONTEXT = True
AGENT_REQUIRES_WORKSPACE_CONTEXT = True


__all__ = [
    "InterruptionHandler",
    "InterruptionConfig",
    "InterruptionEvent",
    "SpeechState",
    "InterruptionState",
    "InterruptionSource",
    "InterruptionPriority",
    "create_interruption_handler",
    "AGENT_MODULE",
    "AGENT_FILE",
    "AGENT_CLASS",
    "AGENT_VERSION",
    "AGENT_DESCRIPTION",
    "AGENT_CAPABILITIES",
    "AGENT_REQUIRES_USER_CONTEXT",
    "AGENT_REQUIRES_WORKSPACE_CONTEXT",
]


# =============================================================================
# Lightweight self-test
# =============================================================================

if __name__ == "__main__":
    async def _demo() -> None:
        async def fake_stop(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fake TTS stopped.",
                "data": payload,
            }

        async def fake_capture(payload: Dict[str, Any]) -> str:
            return "open the dashboard instead"

        handler = InterruptionHandler(
            stop_speech_callback=fake_stop,
            capture_command_callback=fake_capture,
        )

        print(handler.mark_speaking(
            user_id="demo-user",
            workspace_id="demo-workspace",
            text="I am currently explaining something long.",
            speech_id="speech-demo-1",
        ))

        result = await handler.handle_interruption(
            user_id="demo-user",
            workspace_id="demo-workspace",
            raw_input="wait",
            source="voice",
            force=False,
        )

        print(result)
        print(handler.get_status())

    asyncio.run(_demo())