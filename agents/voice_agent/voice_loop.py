"""
agents/voice_agent/voice_loop.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Always-listening background loop for the Voice Agent with:
    - idle mode
    - active mode
    - conversation mode
    - private mode
    - sleep mode

This file is designed to be:
    - production-ready
    - import-safe
    - testable without real microphone/audio dependencies
    - compatible with SaaS user/workspace isolation
    - compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent, Security Agent, Memory Agent, Verification Agent, and Dashboard/API

Important:
    This file does NOT directly execute dangerous system/browser/call/message actions.
    It only captures and structures voice loop events and prepares routing payloads
    for the Master Agent or Voice Agent.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Optional / Safe Imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # fallback stub
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even if the real BaseAgent has not
        been created yet. The real system should replace this automatically
        when agents.base_agent exists.
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
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.voice_agent.wake_word import WakeWordDetector  # type: ignore
except Exception:  # pragma: no cover
    class WakeWordDetector:
        """
        Fallback wake word detector.

        The real wake_word.py file should provide production wake word detection.
        """

        def __init__(self, wake_words: Optional[List[str]] = None, **kwargs: Any) -> None:
            self.wake_words = wake_words or ["william", "jarvis"]

        async def detect(self, audio_chunk: Any = None, text: Optional[str] = None) -> Dict[str, Any]:
            candidate = (text or "").lower()
            detected = any(word.lower() in candidate for word in self.wake_words)
            return {
                "success": True,
                "detected": detected,
                "wake_word": next((w for w in self.wake_words if w.lower() in candidate), None),
                "confidence": 1.0 if detected else 0.0,
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.voice_agent.stt_engine import STTEngine  # type: ignore
except Exception:  # pragma: no cover
    class STTEngine:
        """
        Fallback STT engine.

        The real stt_engine.py file should convert audio into text.
        """

        async def transcribe(self, audio_chunk: Any = None, **kwargs: Any) -> Dict[str, Any]:
            text = ""
            if isinstance(audio_chunk, str):
                text = audio_chunk

            return {
                "success": True,
                "message": "Fallback STT transcription complete.",
                "data": {
                    "text": text,
                    "language": "en",
                    "confidence": 1.0 if text else 0.0,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.voice_agent.tts_engine import TTSEngine  # type: ignore
except Exception:  # pragma: no cover
    class TTSEngine:
        """
        Fallback TTS engine.

        The real tts_engine.py file should speak generated responses.
        """

        async def speak(self, text: str, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback TTS speak skipped.",
                "data": {
                    "spoken_text": text,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.voice_agent.language_engine import LanguageEngine  # type: ignore
except Exception:  # pragma: no cover
    class LanguageEngine:
        """
        Fallback language detector.

        The real language_engine.py file should detect language and localization.
        """

        async def detect_language(self, text: str, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback language detection complete.",
                "data": {
                    "language": "en",
                    "confidence": 0.70,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.voice_agent.device_stream import DeviceStream  # type: ignore
except Exception:  # pragma: no cover
    class DeviceStream:
        """
        Fallback device stream.

        The real device_stream.py file should connect microphone/device input.
        """

        def __init__(self, **kwargs: Any) -> None:
            self.is_open = False

        async def open(self) -> Dict[str, Any]:
            self.is_open = True
            return {
                "success": True,
                "message": "Fallback device stream opened.",
                "data": {},
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }

        async def close(self) -> Dict[str, Any]:
            self.is_open = False
            return {
                "success": True,
                "message": "Fallback device stream closed.",
                "data": {},
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }

        async def read_chunk(self) -> Any:
            await asyncio.sleep(0.01)
            return None


try:
    from agents.voice_agent.interruption import InterruptionManager  # type: ignore
except Exception:  # pragma: no cover
    class InterruptionManager:
        """
        Fallback interruption manager.

        The real interruption.py file should detect stop/pause/interrupt events.
        """

        async def check_interruption(self, text: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
            candidate = (text or "").lower().strip()
            interrupted = candidate in {"stop", "cancel", "pause", "sleep"}
            return {
                "success": True,
                "message": "Fallback interruption check complete.",
                "data": {
                    "interrupted": interrupted,
                    "reason": candidate if interrupted else None,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums / Data Structures
# =============================================================================

class VoiceLoopMode(str, Enum):
    """
    Supported VoiceLoop modes.

    IDLE:
        Passive listening for wake word.

    ACTIVE:
        Wake word detected. Ready to receive a single command.

    CONVERSATION:
        Multi-turn conversation mode.

    PRIVATE:
        Sensitive/private mode. Restricts memory and output behavior.

    SLEEP:
        Low-activity mode. Ignores normal commands until wake/sleep-exit phrase.
    """

    IDLE = "idle"
    ACTIVE = "active"
    CONVERSATION = "conversation"
    PRIVATE = "private"
    SLEEP = "sleep"


class VoiceLoopStatus(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    ERROR = "error"


class VoiceEventType(str, Enum):
    LOOP_STARTED = "voice_loop.started"
    LOOP_STOPPED = "voice_loop.stopped"
    LOOP_PAUSED = "voice_loop.paused"
    LOOP_RESUMED = "voice_loop.resumed"
    MODE_CHANGED = "voice_loop.mode_changed"
    WAKE_WORD_DETECTED = "voice_loop.wake_word_detected"
    TRANSCRIPTION_RECEIVED = "voice_loop.transcription_received"
    COMMAND_READY = "voice_loop.command_ready"
    INTERRUPTION_DETECTED = "voice_loop.interruption_detected"
    SECURITY_REQUIRED = "voice_loop.security_required"
    VERIFICATION_READY = "voice_loop.verification_ready"
    MEMORY_READY = "voice_loop.memory_ready"
    ERROR = "voice_loop.error"


@dataclass
class VoiceLoopConfig:
    """
    Voice loop configuration.

    This can later be moved to agents/voice_agent/config.py while keeping
    this file compatible.
    """

    wake_words: List[str] = field(default_factory=lambda: ["william", "jarvis"])
    sleep_exit_phrases: List[str] = field(
        default_factory=lambda: [
            "wake up",
            "william wake up",
            "jarvis wake up",
            "start listening",
        ]
    )
    sleep_enter_phrases: List[str] = field(
        default_factory=lambda: [
            "go to sleep",
            "sleep mode",
            "stop listening",
        ]
    )
    private_enter_phrases: List[str] = field(
        default_factory=lambda: [
            "private mode",
            "go private",
            "start private mode",
        ]
    )
    private_exit_phrases: List[str] = field(
        default_factory=lambda: [
            "exit private mode",
            "normal mode",
            "leave private mode",
        ]
    )
    conversation_enter_phrases: List[str] = field(
        default_factory=lambda: [
            "conversation mode",
            "keep listening",
            "let's talk",
            "lets talk",
        ]
    )
    conversation_exit_phrases: List[str] = field(
        default_factory=lambda: [
            "exit conversation",
            "stop conversation",
            "single command mode",
        ]
    )

    loop_interval_seconds: float = 0.05
    idle_timeout_seconds: float = 60.0
    active_timeout_seconds: float = 20.0
    conversation_timeout_seconds: float = 180.0
    private_timeout_seconds: float = 120.0

    allow_memory_in_private_mode: bool = False
    allow_tts_in_private_mode: bool = True
    require_security_for_private_mode: bool = True
    require_security_for_sensitive_commands: bool = True

    max_empty_chunks_before_idle: int = 100
    max_errors_before_stop: int = 10
    emit_dashboard_events: bool = True
    enable_audit_logs: bool = True
    enable_verification_payloads: bool = True
    enable_memory_payloads: bool = True
    auto_open_device_stream: bool = True
    auto_close_device_stream: bool = True


@dataclass
class VoiceLoopContext:
    """
    SaaS-safe context for one voice loop session.

    user_id and workspace_id are required for user-specific execution.
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
class VoiceCommand:
    """
    Structured voice command prepared for Master Agent routing.
    """

    command_id: str
    text: str
    language: str
    confidence: float
    mode: VoiceLoopMode
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    session_id: str
    device_id: Optional[str] = None
    requires_security: bool = False
    security_reason: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Callback Types
# =============================================================================

AsyncCallback = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
SyncCallback = Callable[[Dict[str, Any]], Dict[str, Any]]
Callback = Union[AsyncCallback, SyncCallback]


# =============================================================================
# VoiceLoop
# =============================================================================

class VoiceLoop(BaseAgent):
    """
    Always-listening Voice Agent loop.

    This class owns the state machine for voice activity and prepares structured
    payloads for the rest of the William/Jarvis system.

    It connects with:
        - Master Agent:
            by producing command payloads that can be routed.

        - Security Agent:
            by identifying sensitive commands or private mode actions.

        - Memory Agent:
            by preparing memory-safe payloads, respecting private mode settings.

        - Verification Agent:
            by preparing final verification payloads for completed voice commands.

        - Dashboard/API:
            by emitting structured event/audit payloads.

        - Registry/Loader/Router:
            by remaining import-safe and exposing public async methods.
    """

    SENSITIVE_KEYWORDS: Tuple[str, ...] = (
        "delete",
        "remove",
        "send email",
        "send message",
        "call",
        "transfer",
        "payment",
        "pay",
        "purchase",
        "buy",
        "login",
        "password",
        "secret",
        "api key",
        "token",
        "bank",
        "finance",
        "trade",
        "deploy",
        "shutdown",
        "restart",
        "format",
        "wipe",
        "browser action",
        "system command",
    )

    def __init__(
        self,
        config: Optional[VoiceLoopConfig] = None,
        context: Optional[VoiceLoopContext] = None,
        wake_word_detector: Optional[Any] = None,
        stt_engine: Optional[Any] = None,
        tts_engine: Optional[Any] = None,
        language_engine: Optional[Any] = None,
        device_stream: Optional[Any] = None,
        interruption_manager: Optional[Any] = None,
        master_agent_callback: Optional[Callback] = None,
        security_agent_callback: Optional[Callback] = None,
        verification_agent_callback: Optional[Callback] = None,
        memory_agent_callback: Optional[Callback] = None,
        event_callback: Optional[Callback] = None,
        audit_callback: Optional[Callback] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", "VoiceLoop"),
            agent_id=kwargs.get("agent_id", "voice_loop"),
        )

        self.config = config or VoiceLoopConfig()
        self.context = context

        self.wake_word_detector = wake_word_detector or WakeWordDetector(
            wake_words=self.config.wake_words
        )
        self.stt_engine = stt_engine or STTEngine()
        self.tts_engine = tts_engine or TTSEngine()
        self.language_engine = language_engine or LanguageEngine()
        self.device_stream = device_stream or DeviceStream()
        self.interruption_manager = interruption_manager or InterruptionManager()

        self.master_agent_callback = master_agent_callback
        self.security_agent_callback = security_agent_callback
        self.verification_agent_callback = verification_agent_callback
        self.memory_agent_callback = memory_agent_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self.logger = logger_instance or logger

        self.status = VoiceLoopStatus.STOPPED
        self.mode = VoiceLoopMode.IDLE
        self.previous_mode = VoiceLoopMode.IDLE

        self._running = False
        self._paused = False
        self._loop_task: Optional[asyncio.Task[Any]] = None
        self._last_activity_at = time.time()
        self._started_at: Optional[float] = None
        self._stopped_at: Optional[float] = None
        self._empty_chunk_count = 0
        self._error_count = 0

        self._event_history: List[Dict[str, Any]] = []
        self._command_history: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def start(
        self,
        context: Optional[VoiceLoopContext] = None,
        background: bool = True,
    ) -> Dict[str, Any]:
        """
        Start the always-listening voice loop.

        Args:
            context:
                SaaS-safe user/workspace context.
            background:
                If True, creates an asyncio background task.
                If False, runs the loop until stopped.

        Returns:
            Structured result dict.
        """

        if context is not None:
            self.context = context

        validation = self._validate_task_context()
        if not validation["success"]:
            return validation

        if self._running:
            return self._safe_result(
                message="Voice loop is already running.",
                data=self.get_state(),
                metadata={
                    "status": self.status.value,
                },
            )

        self.status = VoiceLoopStatus.STARTING
        self._running = True
        self._paused = False
        self._started_at = time.time()
        self._stopped_at = None
        self._last_activity_at = time.time()
        self._empty_chunk_count = 0
        self._error_count = 0

        if self.config.auto_open_device_stream:
            await self._safe_open_stream()

        self.status = VoiceLoopStatus.RUNNING

        await self._emit_agent_event(
            VoiceEventType.LOOP_STARTED,
            {
                "mode": self.mode.value,
                "status": self.status.value,
            },
        )

        await self._log_audit_event(
            action="voice_loop_started",
            details={
                "mode": self.mode.value,
                "status": self.status.value,
            },
        )

        if background:
            self._loop_task = asyncio.create_task(self._run_loop())
            return self._safe_result(
                message="Voice loop started in background.",
                data=self.get_state(),
            )

        await self._run_loop()
        return self._safe_result(
            message="Voice loop completed.",
            data=self.get_state(),
        )

    async def stop(self, reason: str = "manual_stop") -> Dict[str, Any]:
        """
        Stop the voice loop safely.
        """

        if not self._running and self.status == VoiceLoopStatus.STOPPED:
            return self._safe_result(
                message="Voice loop is already stopped.",
                data=self.get_state(),
            )

        self.status = VoiceLoopStatus.STOPPING
        self._running = False
        self._paused = False
        self._stopped_at = time.time()

        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self.logger.warning("Voice loop task stop warning: %s", exc)

        if self.config.auto_close_device_stream:
            await self._safe_close_stream()

        self.status = VoiceLoopStatus.STOPPED
        self.mode = VoiceLoopMode.IDLE

        await self._emit_agent_event(
            VoiceEventType.LOOP_STOPPED,
            {
                "reason": reason,
                "status": self.status.value,
            },
        )

        await self._log_audit_event(
            action="voice_loop_stopped",
            details={
                "reason": reason,
                "status": self.status.value,
            },
        )

        return self._safe_result(
            message="Voice loop stopped.",
            data=self.get_state(),
            metadata={
                "reason": reason,
            },
        )

    async def pause(self, reason: str = "manual_pause") -> Dict[str, Any]:
        """
        Pause the voice loop without closing the stream.
        """

        if not self._running:
            return self._error_result(
                message="Cannot pause because voice loop is not running.",
                error="VOICE_LOOP_NOT_RUNNING",
                data=self.get_state(),
            )

        self._paused = True
        self.status = VoiceLoopStatus.PAUSED

        await self._emit_agent_event(
            VoiceEventType.LOOP_PAUSED,
            {
                "reason": reason,
            },
        )

        await self._log_audit_event(
            action="voice_loop_paused",
            details={
                "reason": reason,
            },
        )

        return self._safe_result(
            message="Voice loop paused.",
            data=self.get_state(),
            metadata={
                "reason": reason,
            },
        )

    async def resume(self, reason: str = "manual_resume") -> Dict[str, Any]:
        """
        Resume a paused voice loop.
        """

        if not self._running:
            return self._error_result(
                message="Cannot resume because voice loop is not running.",
                error="VOICE_LOOP_NOT_RUNNING",
                data=self.get_state(),
            )

        self._paused = False
        self.status = VoiceLoopStatus.RUNNING
        self._last_activity_at = time.time()

        await self._emit_agent_event(
            VoiceEventType.LOOP_RESUMED,
            {
                "reason": reason,
            },
        )

        await self._log_audit_event(
            action="voice_loop_resumed",
            details={
                "reason": reason,
            },
        )

        return self._safe_result(
            message="Voice loop resumed.",
            data=self.get_state(),
            metadata={
                "reason": reason,
            },
        )

    async def set_mode(
        self,
        mode: Union[VoiceLoopMode, str],
        reason: str = "manual_mode_change",
    ) -> Dict[str, Any]:
        """
        Change the current voice loop mode.
        """

        try:
            next_mode = mode if isinstance(mode, VoiceLoopMode) else VoiceLoopMode(str(mode))
        except ValueError:
            return self._error_result(
                message=f"Invalid voice loop mode: {mode}",
                error="INVALID_VOICE_LOOP_MODE",
                data={
                    "allowed_modes": [item.value for item in VoiceLoopMode],
                },
            )

        old_mode = self.mode
        self.previous_mode = old_mode
        self.mode = next_mode
        self._last_activity_at = time.time()

        await self._emit_agent_event(
            VoiceEventType.MODE_CHANGED,
            {
                "old_mode": old_mode.value,
                "new_mode": next_mode.value,
                "reason": reason,
            },
        )

        await self._log_audit_event(
            action="voice_loop_mode_changed",
            details={
                "old_mode": old_mode.value,
                "new_mode": next_mode.value,
                "reason": reason,
            },
        )

        return self._safe_result(
            message=f"Voice loop mode changed to {next_mode.value}.",
            data=self.get_state(),
            metadata={
                "old_mode": old_mode.value,
                "new_mode": next_mode.value,
                "reason": reason,
            },
        )

    async def process_audio_chunk(self, audio_chunk: Any) -> Dict[str, Any]:
        """
        Process one audio chunk.

        This method is useful for testing and for dashboard/API controlled input.
        """

        validation = self._validate_task_context()
        if not validation["success"]:
            return validation

        try:
            if self.mode == VoiceLoopMode.SLEEP:
                return await self._handle_sleep_mode(audio_chunk)

            if self.mode == VoiceLoopMode.IDLE:
                return await self._handle_idle_mode(audio_chunk)

            if self.mode == VoiceLoopMode.ACTIVE:
                return await self._handle_active_mode(audio_chunk)

            if self.mode == VoiceLoopMode.CONVERSATION:
                return await self._handle_conversation_mode(audio_chunk)

            if self.mode == VoiceLoopMode.PRIVATE:
                return await self._handle_private_mode(audio_chunk)

            return self._error_result(
                message="Unsupported voice loop mode.",
                error="UNSUPPORTED_MODE",
                data={
                    "mode": self.mode.value,
                },
            )

        except Exception as exc:
            self._error_count += 1
            self.logger.exception("VoiceLoop process_audio_chunk failed: %s", exc)
            await self._emit_agent_event(
                VoiceEventType.ERROR,
                {
                    "error": str(exc),
                    "mode": self.mode.value,
                },
            )

            if self._error_count >= self.config.max_errors_before_stop:
                await self.stop(reason="max_errors_reached")

            return self._error_result(
                message="Failed to process audio chunk.",
                error=str(exc),
                data={
                    "mode": self.mode.value,
                    "error_count": self._error_count,
                },
            )

    async def process_text_input(self, text: str) -> Dict[str, Any]:
        """
        Process text as if it came from STT.

        This makes the voice loop easy to test without microphone access.
        """

        return await self.process_audio_chunk(text)

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible task runner.

        Supported actions:
            - start
            - stop
            - pause
            - resume
            - set_mode
            - process_text
            - process_audio
            - state
        """

        action = str(task.get("action", "state")).strip().lower()

        context_payload = task.get("context")
        if isinstance(context_payload, dict):
            self.context = VoiceLoopContext(
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

        if action == "start":
            return await self.start(background=bool(task.get("background", True)))

        if action == "stop":
            return await self.stop(reason=str(task.get("reason", "task_stop")))

        if action == "pause":
            return await self.pause(reason=str(task.get("reason", "task_pause")))

        if action == "resume":
            return await self.resume(reason=str(task.get("reason", "task_resume")))

        if action == "set_mode":
            return await self.set_mode(
                mode=task.get("mode", VoiceLoopMode.IDLE.value),
                reason=str(task.get("reason", "task_mode_change")),
            )

        if action == "process_text":
            return await self.process_text_input(str(task.get("text", "")))

        if action == "process_audio":
            return await self.process_audio_chunk(task.get("audio_chunk"))

        if action == "state":
            return self._safe_result(
                message="Voice loop state retrieved.",
                data=self.get_state(),
            )

        return self._error_result(
            message=f"Unsupported VoiceLoop action: {action}",
            error="UNSUPPORTED_ACTION",
            data={
                "supported_actions": [
                    "start",
                    "stop",
                    "pause",
                    "resume",
                    "set_mode",
                    "process_text",
                    "process_audio",
                    "state",
                ],
            },
        )

    def get_state(self) -> Dict[str, Any]:
        """
        Return current loop state.
        """

        return {
            "agent": "VoiceLoop",
            "status": self.status.value,
            "mode": self.mode.value,
            "previous_mode": self.previous_mode.value,
            "running": self._running,
            "paused": self._paused,
            "started_at": self._started_at,
            "stopped_at": self._stopped_at,
            "last_activity_at": self._last_activity_at,
            "empty_chunk_count": self._empty_chunk_count,
            "error_count": self._error_count,
            "context": self._context_to_dict(),
            "config": {
                "wake_words": self.config.wake_words,
                "loop_interval_seconds": self.config.loop_interval_seconds,
                "idle_timeout_seconds": self.config.idle_timeout_seconds,
                "active_timeout_seconds": self.config.active_timeout_seconds,
                "conversation_timeout_seconds": self.config.conversation_timeout_seconds,
                "private_timeout_seconds": self.config.private_timeout_seconds,
                "allow_memory_in_private_mode": self.config.allow_memory_in_private_mode,
                "allow_tts_in_private_mode": self.config.allow_tts_in_private_mode,
                "require_security_for_private_mode": self.config.require_security_for_private_mode,
                "require_security_for_sensitive_commands": self.config.require_security_for_sensitive_commands,
            },
            "history": {
                "events": self._event_history[-25:],
                "commands": self._command_history[-25:],
            },
        }

    # -------------------------------------------------------------------------
    # Main Loop
    # -------------------------------------------------------------------------

    async def _run_loop(self) -> None:
        """
        Internal always-listening loop.
        """

        try:
            while self._running:
                if self._paused:
                    await asyncio.sleep(self.config.loop_interval_seconds)
                    continue

                audio_chunk = await self._safe_read_chunk()

                if audio_chunk is None:
                    self._empty_chunk_count += 1
                    await self._handle_empty_chunk()
                    await asyncio.sleep(self.config.loop_interval_seconds)
                    continue

                self._empty_chunk_count = 0
                await self.process_audio_chunk(audio_chunk)
                await self._check_timeouts()

                await asyncio.sleep(self.config.loop_interval_seconds)

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            self.status = VoiceLoopStatus.ERROR
            self._running = False
            self.logger.exception("VoiceLoop run loop failed: %s", exc)
            await self._emit_agent_event(
                VoiceEventType.ERROR,
                {
                    "error": str(exc),
                    "status": self.status.value,
                },
            )

        finally:
            if self.config.auto_close_device_stream:
                await self._safe_close_stream()

    async def _safe_open_stream(self) -> None:
        try:
            open_method = getattr(self.device_stream, "open", None)
            if callable(open_method):
                result = open_method()
                if asyncio.iscoroutine(result):
                    await result
        except Exception as exc:
            self.logger.warning("Device stream open failed: %s", exc)

    async def _safe_close_stream(self) -> None:
        try:
            close_method = getattr(self.device_stream, "close", None)
            if callable(close_method):
                result = close_method()
                if asyncio.iscoroutine(result):
                    await result
        except Exception as exc:
            self.logger.warning("Device stream close failed: %s", exc)

    async def _safe_read_chunk(self) -> Any:
        try:
            read_method = getattr(self.device_stream, "read_chunk", None)
            if not callable(read_method):
                return None

            result = read_method()
            if asyncio.iscoroutine(result):
                return await result
            return result
        except Exception as exc:
            self.logger.warning("Device stream read failed: %s", exc)
            return None

    async def _handle_empty_chunk(self) -> None:
        if self._empty_chunk_count >= self.config.max_empty_chunks_before_idle:
            if self.mode in {VoiceLoopMode.ACTIVE, VoiceLoopMode.CONVERSATION, VoiceLoopMode.PRIVATE}:
                await self.set_mode(VoiceLoopMode.IDLE, reason="too_many_empty_chunks")

    async def _check_timeouts(self) -> None:
        now = time.time()
        inactive_for = now - self._last_activity_at

        if self.mode == VoiceLoopMode.ACTIVE and inactive_for > self.config.active_timeout_seconds:
            await self.set_mode(VoiceLoopMode.IDLE, reason="active_timeout")

        elif self.mode == VoiceLoopMode.CONVERSATION and inactive_for > self.config.conversation_timeout_seconds:
            await self.set_mode(VoiceLoopMode.IDLE, reason="conversation_timeout")

        elif self.mode == VoiceLoopMode.PRIVATE and inactive_for > self.config.private_timeout_seconds:
            await self.set_mode(VoiceLoopMode.IDLE, reason="private_timeout")

    # -------------------------------------------------------------------------
    # Mode Handlers
    # -------------------------------------------------------------------------

    async def _handle_idle_mode(self, audio_chunk: Any) -> Dict[str, Any]:
        """
        Idle mode listens only for wake word.
        """

        transcription = await self._transcribe(audio_chunk)
        text = self._extract_text(transcription)

        if not text:
            return self._safe_result(
                message="Idle mode: no speech detected.",
                data={
                    "mode": self.mode.value,
                },
            )

        wake_result = await self._detect_wake_word(audio_chunk=audio_chunk, text=text)
        if wake_result.get("detected"):
            self._last_activity_at = time.time()

            await self._emit_agent_event(
                VoiceEventType.WAKE_WORD_DETECTED,
                {
                    "text": text,
                    "wake_word": wake_result.get("wake_word"),
                    "confidence": wake_result.get("confidence"),
                },
            )

            await self.set_mode(VoiceLoopMode.ACTIVE, reason="wake_word_detected")

            cleaned_text = self._remove_wake_words(text)
            if cleaned_text:
                return await self._handle_command_text(
                    text=cleaned_text,
                    transcription=transcription,
                    source_mode=VoiceLoopMode.ACTIVE,
                )

            return self._safe_result(
                message="Wake word detected. Voice loop is active.",
                data={
                    "mode": self.mode.value,
                    "wake_word": wake_result.get("wake_word"),
                },
            )

        return self._safe_result(
            message="Idle mode: wake word not detected.",
            data={
                "mode": self.mode.value,
                "text_detected": bool(text),
            },
        )

    async def _handle_active_mode(self, audio_chunk: Any) -> Dict[str, Any]:
        """
        Active mode accepts a single command and normally returns to idle unless
        conversation/private/sleep mode is requested.
        """

        transcription = await self._transcribe(audio_chunk)
        text = self._extract_text(transcription)

        if not text:
            return self._safe_result(
                message="Active mode: no command detected.",
                data={
                    "mode": self.mode.value,
                },
            )

        self._last_activity_at = time.time()

        mode_change = await self._handle_mode_phrase(text)
        if mode_change["success"] and mode_change.get("data", {}).get("mode_changed"):
            return mode_change

        result = await self._handle_command_text(
            text=text,
            transcription=transcription,
            source_mode=VoiceLoopMode.ACTIVE,
        )

        if self.mode == VoiceLoopMode.ACTIVE:
            await self.set_mode(VoiceLoopMode.IDLE, reason="single_command_completed")

        return result

    async def _handle_conversation_mode(self, audio_chunk: Any) -> Dict[str, Any]:
        """
        Conversation mode keeps listening across turns.
        """

        transcription = await self._transcribe(audio_chunk)
        text = self._extract_text(transcription)

        if not text:
            return self._safe_result(
                message="Conversation mode: no speech detected.",
                data={
                    "mode": self.mode.value,
                },
            )

        self._last_activity_at = time.time()

        mode_change = await self._handle_mode_phrase(text)
        if mode_change["success"] and mode_change.get("data", {}).get("mode_changed"):
            return mode_change

        interruption = await self._check_interruption(text)
        if interruption.get("interrupted"):
            await self._emit_agent_event(
                VoiceEventType.INTERRUPTION_DETECTED,
                {
                    "text": text,
                    "reason": interruption.get("reason"),
                },
            )
            return self._safe_result(
                message="Interruption detected.",
                data={
                    "interrupted": True,
                    "reason": interruption.get("reason"),
                },
            )

        return await self._handle_command_text(
            text=text,
            transcription=transcription,
            source_mode=VoiceLoopMode.CONVERSATION,
        )

    async def _handle_private_mode(self, audio_chunk: Any) -> Dict[str, Any]:
        """
        Private mode keeps listening but restricts memory and may require
        additional security approval.
        """

        transcription = await self._transcribe(audio_chunk)
        text = self._extract_text(transcription)

        if not text:
            return self._safe_result(
                message="Private mode: no speech detected.",
                data={
                    "mode": self.mode.value,
                },
            )

        self._last_activity_at = time.time()

        mode_change = await self._handle_mode_phrase(text)
        if mode_change["success"] and mode_change.get("data", {}).get("mode_changed"):
            return mode_change

        return await self._handle_command_text(
            text=text,
            transcription=transcription,
            source_mode=VoiceLoopMode.PRIVATE,
        )

    async def _handle_sleep_mode(self, audio_chunk: Any) -> Dict[str, Any]:
        """
        Sleep mode ignores commands until a sleep-exit phrase or wake word.
        """

        transcription = await self._transcribe(audio_chunk)
        text = self._extract_text(transcription).lower().strip()

        if not text:
            return self._safe_result(
                message="Sleep mode: no wake phrase detected.",
                data={
                    "mode": self.mode.value,
                },
            )

        wake_result = await self._detect_wake_word(audio_chunk=audio_chunk, text=text)
        exit_phrase_detected = self._contains_any_phrase(text, self.config.sleep_exit_phrases)

        if wake_result.get("detected") or exit_phrase_detected:
            self._last_activity_at = time.time()
            await self.set_mode(VoiceLoopMode.IDLE, reason="sleep_exit_detected")
            return self._safe_result(
                message="Sleep mode exited.",
                data={
                    "mode": self.mode.value,
                    "wake_word_detected": wake_result.get("detected", False),
                    "exit_phrase_detected": exit_phrase_detected,
                },
            )

        return self._safe_result(
            message="Sleep mode: command ignored.",
            data={
                "mode": self.mode.value,
            },
        )

    # -------------------------------------------------------------------------
    # Command Handling
    # -------------------------------------------------------------------------

    async def _handle_command_text(
        self,
        text: str,
        transcription: Dict[str, Any],
        source_mode: VoiceLoopMode,
    ) -> Dict[str, Any]:
        """
        Convert text into structured VoiceCommand, run safety checks, prepare
        memory/verification payloads, and route to Master Agent if available.
        """

        text = text.strip()
        if not text:
            return self._error_result(
                message="Cannot handle empty voice command.",
                error="EMPTY_COMMAND",
            )

        language_result = await self._detect_language(text)
        language = language_result.get("language", "en")
        language_confidence = float(language_result.get("confidence", 0.0))

        requires_security, security_reason = self._requires_security_check(text, source_mode)

        command = VoiceCommand(
            command_id=str(uuid.uuid4()),
            text=text,
            language=language,
            confidence=float(self._extract_confidence(transcription)),
            mode=source_mode,
            user_id=self.context.user_id if self.context else "unknown",
            workspace_id=self.context.workspace_id if self.context else "unknown",
            session_id=self.context.session_id if self.context else str(uuid.uuid4()),
            device_id=self.context.device_id if self.context else None,
            requires_security=requires_security,
            security_reason=security_reason,
            raw={
                "transcription": transcription,
                "language_result": language_result,
            },
            metadata={
                "language_confidence": language_confidence,
                "created_at": time.time(),
            },
        )

        await self._emit_agent_event(
            VoiceEventType.TRANSCRIPTION_RECEIVED,
            {
                "command_id": command.command_id,
                "text": command.text,
                "language": command.language,
                "mode": command.mode.value,
            },
        )

        if requires_security:
            await self._emit_agent_event(
                VoiceEventType.SECURITY_REQUIRED,
                {
                    "command_id": command.command_id,
                    "reason": security_reason,
                },
            )

            security_result = await self._request_security_approval(command)
            if not security_result["success"]:
                return security_result

        command_payload = self._voice_command_to_dict(command)
        self._command_history.append(command_payload)

        await self._emit_agent_event(
            VoiceEventType.COMMAND_READY,
            {
                "command_id": command.command_id,
                "mode": command.mode.value,
            },
        )

        memory_payload = self._prepare_memory_payload(command)
        verification_payload = self._prepare_verification_payload(command)

        if memory_payload and self.config.enable_memory_payloads:
            await self._emit_agent_event(
                VoiceEventType.MEMORY_READY,
                memory_payload,
            )
            await self._send_to_memory_agent(memory_payload)

        if verification_payload and self.config.enable_verification_payloads:
            await self._emit_agent_event(
                VoiceEventType.VERIFICATION_READY,
                verification_payload,
            )
            await self._send_to_verification_agent(verification_payload)

        master_result = await self._send_to_master_agent(command_payload)

        await self._log_audit_event(
            action="voice_command_processed",
            details={
                "command_id": command.command_id,
                "mode": command.mode.value,
                "requires_security": command.requires_security,
                "master_agent_routed": bool(master_result.get("routed")),
            },
        )

        return self._safe_result(
            message="Voice command processed.",
            data={
                "command": command_payload,
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
                "master_agent_result": master_result,
            },
        )

    async def _handle_mode_phrase(self, text: str) -> Dict[str, Any]:
        """
        Detect and apply mode-changing phrases.
        """

        candidate = text.lower().strip()

        if self._contains_any_phrase(candidate, self.config.sleep_enter_phrases):
            await self.set_mode(VoiceLoopMode.SLEEP, reason="sleep_phrase_detected")
            return self._safe_result(
                message="Sleep mode enabled.",
                data={
                    "mode_changed": True,
                    "mode": VoiceLoopMode.SLEEP.value,
                },
            )

        if self._contains_any_phrase(candidate, self.config.private_enter_phrases):
            if self.config.require_security_for_private_mode:
                temp_command = VoiceCommand(
                    command_id=str(uuid.uuid4()),
                    text=text,
                    language="unknown",
                    confidence=1.0,
                    mode=self.mode,
                    user_id=self.context.user_id if self.context else "unknown",
                    workspace_id=self.context.workspace_id if self.context else "unknown",
                    session_id=self.context.session_id if self.context else str(uuid.uuid4()),
                    device_id=self.context.device_id if self.context else None,
                    requires_security=True,
                    security_reason="private_mode_requested",
                )
                security_result = await self._request_security_approval(temp_command)
                if not security_result["success"]:
                    return security_result

            await self.set_mode(VoiceLoopMode.PRIVATE, reason="private_phrase_detected")
            return self._safe_result(
                message="Private mode enabled.",
                data={
                    "mode_changed": True,
                    "mode": VoiceLoopMode.PRIVATE.value,
                },
            )

        if self._contains_any_phrase(candidate, self.config.private_exit_phrases):
            await self.set_mode(VoiceLoopMode.IDLE, reason="private_exit_phrase_detected")
            return self._safe_result(
                message="Private mode disabled.",
                data={
                    "mode_changed": True,
                    "mode": VoiceLoopMode.IDLE.value,
                },
            )

        if self._contains_any_phrase(candidate, self.config.conversation_enter_phrases):
            await self.set_mode(
                VoiceLoopMode.CONVERSATION,
                reason="conversation_phrase_detected",
            )
            return self._safe_result(
                message="Conversation mode enabled.",
                data={
                    "mode_changed": True,
                    "mode": VoiceLoopMode.CONVERSATION.value,
                },
            )

        if self._contains_any_phrase(candidate, self.config.conversation_exit_phrases):
            await self.set_mode(
                VoiceLoopMode.IDLE,
                reason="conversation_exit_phrase_detected",
            )
            return self._safe_result(
                message="Conversation mode disabled.",
                data={
                    "mode_changed": True,
                    "mode": VoiceLoopMode.IDLE.value,
                },
            )

        return self._safe_result(
            message="No mode phrase detected.",
            data={
                "mode_changed": False,
                "mode": self.mode.value,
            },
        )

    # -------------------------------------------------------------------------
    # STT / Wake / Language / Interruption
    # -------------------------------------------------------------------------

    async def _transcribe(self, audio_chunk: Any) -> Dict[str, Any]:
        transcribe = getattr(self.stt_engine, "transcribe", None)
        if not callable(transcribe):
            return {
                "success": False,
                "message": "STT engine does not expose transcribe().",
                "data": {
                    "text": "",
                    "confidence": 0.0,
                    "language": "unknown",
                },
                "error": "STT_TRANSCRIBE_NOT_AVAILABLE",
                "metadata": {},
            }

        result = transcribe(audio_chunk)
        if asyncio.iscoroutine(result):
            result = await result

        if not isinstance(result, dict):
            return {
                "success": False,
                "message": "Invalid STT result.",
                "data": {
                    "text": "",
                    "confidence": 0.0,
                    "language": "unknown",
                },
                "error": "INVALID_STT_RESULT",
                "metadata": {
                    "raw_type": type(result).__name__,
                },
            }

        return result

    async def _detect_wake_word(self, audio_chunk: Any = None, text: Optional[str] = None) -> Dict[str, Any]:
        detect = getattr(self.wake_word_detector, "detect", None)
        if not callable(detect):
            candidate = (text or "").lower()
            detected = any(word.lower() in candidate for word in self.config.wake_words)
            return {
                "success": True,
                "detected": detected,
                "wake_word": None,
                "confidence": 1.0 if detected else 0.0,
            }

        try:
            result = detect(audio_chunk=audio_chunk, text=text)
        except TypeError:
            result = detect(text)

        if asyncio.iscoroutine(result):
            result = await result

        if not isinstance(result, dict):
            return {
                "success": False,
                "detected": False,
                "wake_word": None,
                "confidence": 0.0,
                "error": "INVALID_WAKE_WORD_RESULT",
            }

        return {
            "success": bool(result.get("success", True)),
            "detected": bool(result.get("detected", False)),
            "wake_word": result.get("wake_word"),
            "confidence": float(result.get("confidence", 0.0)),
            "metadata": result.get("metadata", {}),
        }

    async def _detect_language(self, text: str) -> Dict[str, Any]:
        detect_language = getattr(self.language_engine, "detect_language", None)
        if not callable(detect_language):
            return {
                "language": "en",
                "confidence": 0.0,
            }

        result = detect_language(text)
        if asyncio.iscoroutine(result):
            result = await result

        if isinstance(result, dict):
            data = result.get("data", result)
            return {
                "language": data.get("language", "en"),
                "confidence": float(data.get("confidence", 0.0)),
            }

        return {
            "language": "en",
            "confidence": 0.0,
        }

    async def _check_interruption(self, text: str) -> Dict[str, Any]:
        check = getattr(self.interruption_manager, "check_interruption", None)
        if not callable(check):
            return {
                "interrupted": False,
                "reason": None,
            }

        result = check(text=text)
        if asyncio.iscoroutine(result):
            result = await result

        if isinstance(result, dict):
            data = result.get("data", result)
            return {
                "interrupted": bool(data.get("interrupted", False)),
                "reason": data.get("reason"),
            }

        return {
            "interrupted": False,
            "reason": None,
        }

    # -------------------------------------------------------------------------
    # Required Compatibility Hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Every user-specific execution must contain user_id and workspace_id.
        """

        if self.context is None:
            return self._error_result(
                message="VoiceLoop requires context before user-specific execution.",
                error="MISSING_CONTEXT",
                data={
                    "required": ["user_id", "workspace_id"],
                },
            )

        if self.context.user_id in (None, "", 0):
            return self._error_result(
                message="VoiceLoop context is missing user_id.",
                error="MISSING_USER_ID",
                data={
                    "required": ["user_id"],
                },
            )

        if self.context.workspace_id in (None, "", 0):
            return self._error_result(
                message="VoiceLoop context is missing workspace_id.",
                error="MISSING_WORKSPACE_ID",
                data={
                    "required": ["workspace_id"],
                },
            )

        return self._safe_result(
            message="VoiceLoop context validated.",
            data={
                "user_id": self.context.user_id,
                "workspace_id": self.context.workspace_id,
                "session_id": self.context.session_id,
            },
        )

    def _requires_security_check(
        self,
        text: str,
        mode: Optional[VoiceLoopMode] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Decide whether a voice command should go through Security Agent.
        """

        candidate = text.lower().strip()
        active_mode = mode or self.mode

        if active_mode == VoiceLoopMode.PRIVATE and self.config.require_security_for_private_mode:
            return True, "private_mode_command"

        if self.config.require_security_for_sensitive_commands:
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in candidate:
                    return True, f"sensitive_keyword_detected:{keyword}"

        return False, None

    async def _request_security_approval(self, command: VoiceCommand) -> Dict[str, Any]:
        """
        Request approval from Security Agent if configured.

        If no Security Agent callback is connected, this method blocks sensitive
        action execution by default but still returns a safe structured response.
        """

        payload = {
            "type": "security_approval_request",
            "agent": "VoiceLoop",
            "command_id": command.command_id,
            "text": command.text,
            "reason": command.security_reason,
            "mode": command.mode.value,
            "user_id": command.user_id,
            "workspace_id": command.workspace_id,
            "session_id": command.session_id,
            "device_id": command.device_id,
            "metadata": {
                "created_at": time.time(),
            },
        }

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
                message="Security Agent did not approve this voice command.",
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

    def _prepare_verification_payload(self, command: VoiceCommand) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after command processing.
        """

        return {
            "type": "verification_payload",
            "source_agent": "VoiceLoop",
            "command_id": command.command_id,
            "user_id": command.user_id,
            "workspace_id": command.workspace_id,
            "session_id": command.session_id,
            "device_id": command.device_id,
            "mode": command.mode.value,
            "input": {
                "text": command.text,
                "language": command.language,
                "confidence": command.confidence,
            },
            "checks": {
                "requires_security": command.requires_security,
                "security_reason": command.security_reason,
                "private_mode": command.mode == VoiceLoopMode.PRIVATE,
                "saas_context_present": bool(command.user_id and command.workspace_id),
            },
            "metadata": {
                "created_at": time.time(),
            },
        }

    def _prepare_memory_payload(self, command: VoiceCommand) -> Optional[Dict[str, Any]]:
        """
        Prepare Memory Agent payload.

        Private mode memory can be disabled by configuration.
        """

        if command.mode == VoiceLoopMode.PRIVATE and not self.config.allow_memory_in_private_mode:
            return None

        return {
            "type": "memory_payload",
            "source_agent": "VoiceLoop",
            "command_id": command.command_id,
            "user_id": command.user_id,
            "workspace_id": command.workspace_id,
            "session_id": command.session_id,
            "device_id": command.device_id,
            "memory_scope": "workspace",
            "content": {
                "text": command.text,
                "language": command.language,
                "mode": command.mode.value,
            },
            "privacy": {
                "private_mode": command.mode == VoiceLoopMode.PRIVATE,
                "store_allowed": not (
                    command.mode == VoiceLoopMode.PRIVATE
                    and not self.config.allow_memory_in_private_mode
                ),
            },
            "metadata": {
                "created_at": time.time(),
            },
        }

    async def _emit_agent_event(
        self,
        event_type: Union[VoiceEventType, str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit structured event for dashboard/API/agent registry.

        Keeps event isolated by user_id/workspace_id.
        """

        event_name = event_type.value if isinstance(event_type, VoiceEventType) else str(event_type)

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_name,
            "source_agent": "VoiceLoop",
            "user_id": self.context.user_id if self.context else None,
            "workspace_id": self.context.workspace_id if self.context else None,
            "session_id": self.context.session_id if self.context else None,
            "device_id": self.context.device_id if self.context else None,
            "mode": self.mode.value,
            "status": self.status.value,
            "payload": payload,
            "created_at": time.time(),
        }

        self._event_history.append(event)

        if len(self._event_history) > 500:
            self._event_history = self._event_history[-500:]

        if self.config.emit_dashboard_events and self.event_callback:
            try:
                callback_result = await self._execute_callback(self.event_callback, event)
                event["callback_result"] = callback_result
            except Exception as exc:
                self.logger.warning("Event callback failed: %s", exc)

        return self._safe_result(
            message="Agent event emitted.",
            data=event,
        )

    async def _log_audit_event(
        self,
        action: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event for SaaS dashboard/security review.

        This method never mixes users/workspaces because the context is attached.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "source_agent": "VoiceLoop",
            "action": action,
            "user_id": self.context.user_id if self.context else None,
            "workspace_id": self.context.workspace_id if self.context else None,
            "session_id": self.context.session_id if self.context else None,
            "device_id": self.context.device_id if self.context else None,
            "mode": self.mode.value,
            "status": self.status.value,
            "details": details or {},
            "created_at": time.time(),
        }

        if self.config.enable_audit_logs and self.audit_callback:
            try:
                callback_result = await self._execute_callback(self.audit_callback, audit_event)
                audit_event["callback_result"] = callback_result
            except Exception as exc:
                self.logger.warning("Audit callback failed: %s", exc)

        return self._safe_result(
            message="Audit event logged.",
            data=audit_event,
        )

    def _safe_result(
        self,
        message: str = "Success.",
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
        Standard error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "UNKNOWN_ERROR",
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Agent Callback Senders
    # -------------------------------------------------------------------------

    async def _send_to_master_agent(self, command_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route command payload to Master Agent if callback is connected.
        """

        payload = {
            "type": "voice_command",
            "source_agent": "VoiceLoop",
            "routing_target": "master_agent",
            "command": command_payload,
            "user_id": command_payload.get("user_id"),
            "workspace_id": command_payload.get("workspace_id"),
            "session_id": command_payload.get("session_id"),
            "metadata": {
                "created_at": time.time(),
            },
        }

        if self.master_agent_callback is None:
            return {
                "routed": False,
                "message": "Master Agent callback not connected. Command payload prepared only.",
                "payload": payload,
            }

        result = await self._execute_callback(self.master_agent_callback, payload)
        return {
            "routed": True,
            "message": "Command routed to Master Agent.",
            "result": result,
        }

    async def _send_to_memory_agent(self, memory_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send memory payload to Memory Agent if connected.
        """

        if self.memory_agent_callback is None:
            return {
                "sent": False,
                "message": "Memory Agent callback not connected.",
            }

        result = await self._execute_callback(self.memory_agent_callback, memory_payload)
        return {
            "sent": True,
            "message": "Memory payload sent.",
            "result": result,
        }

    async def _send_to_verification_agent(self, verification_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send verification payload to Verification Agent if connected.
        """

        if self.verification_agent_callback is None:
            return {
                "sent": False,
                "message": "Verification Agent callback not connected.",
            }

        result = await self._execute_callback(self.verification_agent_callback, verification_payload)
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
            "data": {
                "result": result,
            },
            "error": None,
            "metadata": {
                "result_type": type(result).__name__,
            },
        }

    # -------------------------------------------------------------------------
    # Utility Helpers
    # -------------------------------------------------------------------------

    def _extract_text(self, transcription: Dict[str, Any]) -> str:
        """
        Extract text from different possible STT result formats.
        """

        if not isinstance(transcription, dict):
            return ""

        data = transcription.get("data", {})
        if isinstance(data, dict):
            text = data.get("text")
            if isinstance(text, str):
                return text.strip()

        text = transcription.get("text")
        if isinstance(text, str):
            return text.strip()

        return ""

    def _extract_confidence(self, transcription: Dict[str, Any]) -> float:
        """
        Extract confidence from different STT result formats.
        """

        if not isinstance(transcription, dict):
            return 0.0

        data = transcription.get("data", {})
        if isinstance(data, dict):
            try:
                return float(data.get("confidence", 0.0))
            except Exception:
                return 0.0

        try:
            return float(transcription.get("confidence", 0.0))
        except Exception:
            return 0.0

    def _contains_any_phrase(self, text: str, phrases: List[str]) -> bool:
        """
        Check whether text contains one of the configured phrases.
        """

        candidate = text.lower().strip()
        return any(phrase.lower().strip() in candidate for phrase in phrases)

    def _remove_wake_words(self, text: str) -> str:
        """
        Remove wake words from a transcribed command.
        """

        cleaned = text
        for wake_word in self.config.wake_words:
            cleaned = cleaned.replace(wake_word, "")
            cleaned = cleaned.replace(wake_word.title(), "")
            cleaned = cleaned.replace(wake_word.upper(), "")

        return " ".join(cleaned.split()).strip(" ,.!?")

    def _voice_command_to_dict(self, command: VoiceCommand) -> Dict[str, Any]:
        """
        Convert VoiceCommand dataclass to JSON-safe dict.
        """

        payload = asdict(command)
        payload["mode"] = command.mode.value
        return payload

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

def create_voice_loop(
    user_id: Union[str, int],
    workspace_id: Union[str, int],
    device_id: Optional[str] = None,
    session_id: Optional[str] = None,
    config: Optional[VoiceLoopConfig] = None,
    **kwargs: Any,
) -> VoiceLoop:
    """
    Factory helper for dashboard/API/registry usage.
    """

    context = VoiceLoopContext(
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

    return VoiceLoop(
        config=config,
        context=context,
        **kwargs,
    )


# =============================================================================
# Simple Manual Test
# =============================================================================

async def _manual_test() -> Dict[str, Any]:
    """
    Lightweight manual test.

    Run:
        python -m agents.voice_agent.voice_loop

    This does not require microphone access because it uses process_text_input().
    """

    async def fake_master_agent(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Fake Master Agent received command.",
            "data": payload,
            "error": None,
            "metadata": {},
        }

    async def fake_security_agent(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "approved": True,
            "message": "Fake Security Agent approved.",
            "data": payload,
            "error": None,
            "metadata": {},
        }

    loop = create_voice_loop(
        user_id="test_user",
        workspace_id="test_workspace",
        device_id="test_device",
        master_agent_callback=fake_master_agent,
        security_agent_callback=fake_security_agent,
    )

    results = []
    results.append(await loop.start(background=True))
    results.append(await loop.process_text_input("William open conversation mode"))
    results.append(await loop.process_text_input("What is my schedule today?"))
    results.append(await loop.process_text_input("private mode"))
    results.append(await loop.process_text_input("send email to client"))
    results.append(await loop.process_text_input("exit private mode"))
    results.append(await loop.process_text_input("go to sleep"))
    results.append(await loop.process_text_input("William wake up"))
    results.append(await loop.stop(reason="manual_test_complete"))

    return {
        "success": True,
        "message": "Manual test complete.",
        "data": {
            "results": results,
            "final_state": loop.get_state(),
        },
        "error": None,
        "metadata": {},
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    output = asyncio.run(_manual_test())
    print(output)