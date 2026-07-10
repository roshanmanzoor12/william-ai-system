"""
agents/voice_agent/voice_agent.py

Main Voice Agent Controller for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    This file controls the full voice interaction layer:
    - Wake word detection
    - Speech-to-text orchestration
    - Text-to-speech orchestration
    - Language detection
    - Device audio streaming
    - Interruption handling
    - Voice session lifecycle
    - Master Agent routing compatibility
    - Security Agent compatibility
    - Verification Agent compatibility
    - Memory Agent compatibility
    - Dashboard/API-ready structured events

Architecture:
    William is a Jarvis-style multi-agent AI SaaS system with:
    - Master Agent
    - Voice Agent
    - System Agent
    - Browser Agent
    - Code Agent
    - Memory Agent
    - Security Agent
    - Verification Agent
    - Visual Agent
    - Workflow Agent
    - Hologram Agent
    - Call Agent
    - Business Agent
    - Finance Agent
    - Creator Agent

Important:
    This file is import-safe.
    It does not require wake_word.py, stt_engine.py, tts_engine.py,
    language_engine.py, device_stream.py, or interruption.py to exist yet.

Author:
    Digital Promotix / William AI System
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Safe Optional Imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe while the full William system is being built.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent run executed.",
                "data": None,
                "error": None,
                "metadata": {"fallback": True},
            }


try:
    from agents.agent_config import AgentSystemConfig  # type: ignore
except Exception:  # pragma: no cover
    class AgentSystemConfig:  # type: ignore
        """
        Fallback config stub.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.security = type("Security", (), {"safe_mode": True})()
            self.verification = type("Verification", (), {"enabled": True})()
            self.memory = type("Memory", (), {"enabled": True})()

        def _safe_result(
            self,
            message: str = "Success.",
            data: Optional[Any] = None,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": message,
                "data": data,
                "error": None,
                "metadata": metadata or {},
            }

        def _error_result(
            self,
            message: str = "Error.",
            error: Optional[Any] = None,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            return {
                "success": False,
                "message": message,
                "data": None,
                "error": error or {"code": "UNKNOWN_ERROR", "details": message},
                "metadata": metadata or {},
            }


try:
    from agents.voice_agent.wake_word import WakeWordEngine  # type: ignore
except Exception:  # pragma: no cover
    class WakeWordEngine:  # type: ignore
        """
        Fallback wake word engine.

        Future file:
            agents/voice_agent/wake_word.py
        """

        def __init__(self, wake_words: Optional[List[str]] = None, **kwargs: Any) -> None:
            self.wake_words = wake_words or ["william", "jarvis"]
            self.enabled = True

        def detect(self, audio_input: Any = None, text_input: Optional[str] = None) -> Dict[str, Any]:
            text = (text_input or "").lower()
            detected_words = [word for word in self.wake_words if word.lower() in text]
            return {
                "success": True,
                "message": "Fallback wake word detection completed.",
                "data": {
                    "detected": bool(detected_words),
                    "wake_words": detected_words,
                    "confidence": 0.75 if detected_words else 0.0,
                },
                "error": None,
                "metadata": {"fallback": True},
            }

        def start(self) -> Dict[str, Any]:
            self.enabled = True
            return {
                "success": True,
                "message": "Fallback wake word engine started.",
                "data": {"enabled": True},
                "error": None,
                "metadata": {"fallback": True},
            }

        def stop(self) -> Dict[str, Any]:
            self.enabled = False
            return {
                "success": True,
                "message": "Fallback wake word engine stopped.",
                "data": {"enabled": False},
                "error": None,
                "metadata": {"fallback": True},
            }


try:
    from agents.voice_agent.stt_engine import STTEngine  # type: ignore
except Exception:  # pragma: no cover
    class STTEngine:  # type: ignore
        """
        Fallback speech-to-text engine.

        Future file:
            agents/voice_agent/stt_engine.py
        """

        def transcribe(
            self,
            audio_input: Any = None,
            language: Optional[str] = None,
            **kwargs: Any,
        ) -> Dict[str, Any]:
            text = ""
            if isinstance(audio_input, str):
                text = audio_input

            return {
                "success": True,
                "message": "Fallback transcription completed.",
                "data": {
                    "text": text,
                    "language": language or "auto",
                    "confidence": 0.5 if text else 0.0,
                },
                "error": None,
                "metadata": {"fallback": True},
            }


try:
    from agents.voice_agent.tts_engine import TTSEngine  # type: ignore
except Exception:  # pragma: no cover
    class TTSEngine:  # type: ignore
        """
        Fallback text-to-speech engine.

        Future file:
            agents/voice_agent/tts_engine.py
        """

        def synthesize(
            self,
            text: str,
            language: Optional[str] = None,
            voice_profile: Optional[str] = None,
            **kwargs: Any,
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback TTS synthesis completed.",
                "data": {
                    "text": text,
                    "language": language or "auto",
                    "voice_profile": voice_profile or "default",
                    "audio_output": None,
                },
                "error": None,
                "metadata": {"fallback": True},
            }

        def speak(
            self,
            text: str,
            language: Optional[str] = None,
            voice_profile: Optional[str] = None,
            **kwargs: Any,
        ) -> Dict[str, Any]:
            return self.synthesize(
                text=text,
                language=language,
                voice_profile=voice_profile,
                **kwargs,
            )


try:
    from agents.voice_agent.language_engine import LanguageEngine  # type: ignore
except Exception:  # pragma: no cover
    class LanguageEngine:  # type: ignore
        """
        Fallback language detector.

        Future file:
            agents/voice_agent/language_engine.py
        """

        def detect_language(self, text: str, **kwargs: Any) -> Dict[str, Any]:
            clean = (text or "").strip()

            detected = "en"
            if any(char in clean for char in "اآبپتٹثجچحخدڈذرڑزژسشصضطظعغفقکگلمنوہیے"):
                detected = "ur"

            return {
                "success": True,
                "message": "Fallback language detection completed.",
                "data": {
                    "language": detected,
                    "confidence": 0.65 if clean else 0.0,
                },
                "error": None,
                "metadata": {"fallback": True},
            }


try:
    from agents.voice_agent.device_stream import DeviceStream  # type: ignore
except Exception:  # pragma: no cover
    class DeviceStream:  # type: ignore
        """
        Fallback device audio stream.

        Future file:
            agents/voice_agent/device_stream.py
        """

        def __init__(self, **kwargs: Any) -> None:
            self.active = False
            self.device_id = kwargs.get("device_id")

        def start_stream(self, **kwargs: Any) -> Dict[str, Any]:
            self.active = True
            return {
                "success": True,
                "message": "Fallback device stream started.",
                "data": {"active": True, "device_id": self.device_id},
                "error": None,
                "metadata": {"fallback": True},
            }

        def stop_stream(self, **kwargs: Any) -> Dict[str, Any]:
            self.active = False
            return {
                "success": True,
                "message": "Fallback device stream stopped.",
                "data": {"active": False, "device_id": self.device_id},
                "error": None,
                "metadata": {"fallback": True},
            }

        def read_audio(self, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback audio read completed.",
                "data": {"audio_input": None},
                "error": None,
                "metadata": {"fallback": True},
            }


try:
    from agents.voice_agent.interruption import InterruptionManager  # type: ignore
except Exception:  # pragma: no cover
    class InterruptionManager:  # type: ignore
        """
        Fallback interruption manager.

        Future file:
            agents/voice_agent/interruption.py
        """

        def __init__(self, **kwargs: Any) -> None:
            self.interrupted = False

        def check_interruption(self, text_input: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
            text = (text_input or "").lower()
            commands = ["stop", "cancel", "pause", "enough", "abort", "خاموش", "رکو"]
            detected = any(command in text for command in commands)
            self.interrupted = detected

            return {
                "success": True,
                "message": "Fallback interruption check completed.",
                "data": {
                    "interrupted": detected,
                    "reason": "voice_command" if detected else None,
                },
                "error": None,
                "metadata": {"fallback": True},
            }

        def interrupt(self, reason: str = "manual") -> Dict[str, Any]:
            self.interrupted = True
            return {
                "success": True,
                "message": "Fallback interruption triggered.",
                "data": {"interrupted": True, "reason": reason},
                "error": None,
                "metadata": {"fallback": True},
            }

        def reset(self) -> Dict[str, Any]:
            self.interrupted = False
            return {
                "success": True,
                "message": "Fallback interruption reset.",
                "data": {"interrupted": False},
                "error": None,
                "metadata": {"fallback": True},
            }


# =============================================================================
# Enums
# =============================================================================

class VoiceAgentState(str, Enum):
    """Runtime state of VoiceAgent."""

    IDLE = "idle"
    LISTENING = "listening"
    WAKE_DETECTED = "wake_detected"
    TRANSCRIBING = "transcribing"
    THINKING = "thinking"
    SPEAKING = "speaking"
    INTERRUPTED = "interrupted"
    ERROR = "error"
    STOPPED = "stopped"


class VoiceInputType(str, Enum):
    """Input type supported by VoiceAgent."""

    AUDIO = "audio"
    TEXT = "text"
    STREAM = "stream"


class VoiceOutputType(str, Enum):
    """Output type supported by VoiceAgent."""

    TEXT = "text"
    AUDIO = "audio"
    BOTH = "both"
    NONE = "none"


class VoiceSecurityLevel(str, Enum):
    """Voice task security level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class VoiceAgentConfig:
    """
    Configuration for the VoiceAgent controller.

    This config intentionally stays engine-neutral. Actual STT/TTS/wake engines
    can be swapped later without breaking Master Agent routing.
    """

    enabled: bool = True
    wake_words: List[str] = field(default_factory=lambda: ["william", "jarvis"])
    require_wake_word: bool = True
    allow_text_input_without_wake_word: bool = True
    default_language: str = "auto"
    fallback_language: str = "en"
    default_voice_profile: str = "default"
    input_timeout_seconds: int = 30
    response_timeout_seconds: int = 120
    max_transcript_chars: int = 10000
    max_response_chars: int = 20000
    enable_language_detection: bool = True
    enable_interruption: bool = True
    enable_device_streaming: bool = True
    enable_tts: bool = True
    enable_stt: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True
    enable_dashboard_events: bool = True
    enable_audit_logs: bool = True
    safe_mode: bool = True
    block_sensitive_voice_actions_without_security: bool = True
    store_voice_history: bool = True
    max_voice_history_items: int = 500
    allow_background_listening: bool = False
    allow_continuous_conversation: bool = True
    allow_device_microphone: bool = False
    allow_remote_device_stream: bool = False

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if not isinstance(self.wake_words, list) or not self.wake_words:
            errors.append("wake_words must be a non-empty list.")

        if self.input_timeout_seconds <= 0:
            errors.append("input_timeout_seconds must be greater than 0.")

        if self.response_timeout_seconds <= 0:
            errors.append("response_timeout_seconds must be greater than 0.")

        if self.max_transcript_chars <= 0:
            errors.append("max_transcript_chars must be greater than 0.")

        if self.max_response_chars <= 0:
            errors.append("max_response_chars must be greater than 0.")

        if self.max_voice_history_items < 0:
            errors.append("max_voice_history_items cannot be negative.")

        if self.allow_background_listening and not self.require_wake_word:
            errors.append(
                "allow_background_listening should not be enabled without wake word requirement."
            )

        return len(errors) == 0, errors


@dataclass
class VoiceSession:
    """
    A single voice interaction session.

    Every session supports user_id and workspace_id for SaaS isolation.
    """

    session_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    device_id: Optional[str] = None
    language: str = "auto"
    voice_profile: str = "default"
    state: VoiceAgentState = VoiceAgentState.IDLE
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    transcript: str = ""
    response_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.updated_at = time.time()

    def end(self) -> None:
        self.ended_at = time.time()
        self.state = VoiceAgentState.STOPPED
        self.touch()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value if isinstance(self.state, VoiceAgentState) else self.state
        return data


@dataclass
class VoiceTurn:
    """
    A single user-assistant voice turn.
    """

    turn_id: str
    session_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    input_type: VoiceInputType
    output_type: VoiceOutputType
    transcript: str = ""
    detected_language: str = "auto"
    wake_word_detected: bool = False
    response_text: str = ""
    interrupted: bool = False
    security_required: bool = False
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def complete(self) -> None:
        self.completed_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["input_type"] = (
            self.input_type.value if isinstance(self.input_type, VoiceInputType) else self.input_type
        )
        data["output_type"] = (
            self.output_type.value if isinstance(self.output_type, VoiceOutputType) else self.output_type
        )
        return data


# =============================================================================
# Voice Agent
# =============================================================================

class VoiceAgent(BaseAgent):
    """
    Main Voice Agent controller.

    Responsibilities:
        - Listen for wake words.
        - Transcribe voice input.
        - Detect language.
        - Route command text to Master Agent or injected router callback.
        - Speak response using TTS.
        - Handle interruptions.
        - Prepare Security, Verification, Memory, Audit, and Event payloads.
        - Keep user/workspace isolation strict.

    This class is intentionally designed as an orchestrator, not a low-level
    audio processing implementation. Dedicated submodules handle wake word,
    STT, TTS, language detection, device streaming, and interruption.
    """

    agent_name: str = "voice"
    agent_type: str = "voice_agent"
    agent_version: str = "1.0.0"

    def __init__(
        self,
        config: Optional[VoiceAgentConfig] = None,
        system_config: Optional[AgentSystemConfig] = None,
        master_router: Optional[Callable[..., Union[Dict[str, Any], Awaitable[Dict[str, Any]]]]] = None,
        wake_word_engine: Optional[Any] = None,
        stt_engine: Optional[Any] = None,
        tts_engine: Optional[Any] = None,
        language_engine: Optional[Any] = None,
        device_stream: Optional[Any] = None,
        interruption_manager: Optional[Any] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                **kwargs,
            )
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.config: VoiceAgentConfig = config or VoiceAgentConfig()
        self.system_config: AgentSystemConfig = system_config or AgentSystemConfig()

        self.master_router = master_router

        self.user_id = user_id
        self.workspace_id = workspace_id
        self.device_id = device_id

        self.wake_word_engine = wake_word_engine or WakeWordEngine(
            wake_words=self.config.wake_words
        )
        self.stt_engine = stt_engine or STTEngine()
        self.tts_engine = tts_engine or TTSEngine()
        self.language_engine = language_engine or LanguageEngine()
        self.device_stream = device_stream or DeviceStream(device_id=device_id)
        self.interruption_manager = interruption_manager or InterruptionManager()

        self.state: VoiceAgentState = VoiceAgentState.IDLE
        self.current_session: Optional[VoiceSession] = None
        self.voice_history: List[Dict[str, Any]] = []
        self.audit_events: List[Dict[str, Any]] = []
        self.runtime_events: List[Dict[str, Any]] = []

        self.created_at = time.time()
        self.updated_at = self.created_at

        valid, errors = self.config.validate()
        if not valid:
            logger.warning("VoiceAgentConfig validation errors: %s", errors)

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        require_user_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Voice data must never be mixed between users or workspaces.
        """

        context = copy.deepcopy(task_context or {})

        user_id = context.get("user_id", self.user_id)
        workspace_id = context.get("workspace_id", self.workspace_id)
        device_id = context.get("device_id", self.device_id)

        errors: List[str] = []

        if require_user_workspace:
            if not user_id:
                errors.append("Missing required user_id for VoiceAgent task.")

            if not workspace_id:
                errors.append("Missing required workspace_id for VoiceAgent task.")

        context.update(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "device_id": device_id,
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
            }
        )

        if errors:
            return self._error_result(
                message="VoiceAgent task context validation failed.",
                error={
                    "code": "VOICE_TASK_CONTEXT_INVALID",
                    "details": errors,
                },
                metadata={
                    "hook": "_validate_task_context",
                    "context": context,
                },
            )

        return self._safe_result(
            message="VoiceAgent task context validated.",
            data=context,
            metadata={
                "hook": "_validate_task_context",
            },
        )

    def _requires_security_check(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        transcript: Optional[str] = None,
        action: Optional[str] = None,
    ) -> bool:
        """
        Determine whether a voice task requires Security Agent approval.
        """

        if self.config.block_sensitive_voice_actions_without_security:
            text = f"{transcript or ''} {action or ''}".lower()

            sensitive_keywords = [
                "delete",
                "remove",
                "shutdown",
                "restart",
                "send money",
                "payment",
                "transfer",
                "call",
                "message",
                "email",
                "login",
                "password",
                "credential",
                "api key",
                "system command",
                "terminal",
                "shell",
                "browser login",
                "download",
                "upload",
                "execute",
                "run command",
                "financial",
                "bank",
            ]

            if any(keyword in text for keyword in sensitive_keywords):
                return True

        if task_context:
            security_level = str(
                task_context.get("security_level", VoiceSecurityLevel.LOW.value)
            ).lower()

            if security_level in {
                VoiceSecurityLevel.HIGH.value,
                VoiceSecurityLevel.CRITICAL.value,
            }:
                return True

            if task_context.get("requires_security") is True:
                return True

        system_requires = getattr(self.system_config, "_requires_security_check", None)
        if callable(system_requires):
            try:
                return bool(
                    system_requires(
                        agent_name=self.agent_name,
                        action=action or transcript or "voice_interaction",
                        task_context=task_context,
                    )
                )
            except Exception:
                logger.exception("System config security check failed.")

        return False

    def _request_security_approval(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        transcript: Optional[str] = None,
        action: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent-compatible approval payload.

        This method does not perform the sensitive action directly.
        """

        context_result = self._validate_task_context(task_context or {})
        requires_security = self._requires_security_check(
            task_context=task_context,
            transcript=transcript,
            action=action,
        )

        payload = {
            "security_request_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "action": action or "voice_interaction",
            "transcript_preview": self._safe_preview(transcript or ""),
            "requires_security_check": requires_security,
            "task_context": context_result.get("data") or task_context or {},
            "created_at": time.time(),
        }

        system_security = getattr(self.system_config, "_request_security_approval", None)
        if callable(system_security):
            try:
                system_result = system_security(
                    agent_name=self.agent_name,
                    action=action or transcript or "voice_interaction",
                    task_context=payload["task_context"],
                )
                payload["system_security_result"] = system_result
            except Exception as exc:
                payload["system_security_error"] = str(exc)

        self._emit_agent_event(
            event_type="voice.security_approval_requested",
            payload=payload,
        )

        self._log_audit_event(
            event_type="voice_security_approval_requested",
            details=payload,
        )

        return self._safe_result(
            message="Voice security approval payload prepared.",
            data=payload,
            metadata={
                "hook": "_request_security_approval",
                "requires_security_check": requires_security,
            },
        )

    def _prepare_verification_payload(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        voice_turn: Optional[VoiceTurn] = None,
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """

        if not self.config.enable_verification_payloads:
            return self._safe_result(
                message="Voice verification payloads are disabled.",
                data={
                    "verification_enabled": False,
                    "payload": None,
                },
                metadata={
                    "hook": "_prepare_verification_payload",
                },
            )

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "voice_turn": voice_turn.to_dict() if voice_turn else None,
            "result": result or {},
            "task_context": task_context or {},
            "created_at": time.time(),
        }

        system_verification = getattr(self.system_config, "_prepare_verification_payload", None)
        if callable(system_verification):
            try:
                system_result = system_verification(
                    agent_name=self.agent_name,
                    action="voice_interaction",
                    result=result or {},
                    task_context=task_context or {},
                )
                payload["system_verification_result"] = system_result
            except Exception as exc:
                payload["system_verification_error"] = str(exc)

        self._emit_agent_event(
            event_type="voice.verification_payload_prepared",
            payload=payload,
        )

        return self._safe_result(
            message="Voice verification payload prepared.",
            data=payload,
            metadata={
                "hook": "_prepare_verification_payload",
            },
        )

    def _prepare_memory_payload(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        voice_turn: Optional[VoiceTurn] = None,
        useful_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This does not directly store memory. It prepares a safe payload for
        Memory Agent or dashboard/API workers.
        """

        if not self.config.enable_memory_payloads:
            return self._safe_result(
                message="Voice memory payloads are disabled.",
                data={
                    "memory_enabled": False,
                    "payload": None,
                },
                metadata={
                    "hook": "_prepare_memory_payload",
                },
            )

        safe_turn = voice_turn.to_dict() if voice_turn else {}
        safe_turn["transcript"] = self._safe_preview(safe_turn.get("transcript", ""))
        safe_turn["response_text"] = self._safe_preview(safe_turn.get("response_text", ""))

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "event_type": "voice_interaction",
            "voice_turn": safe_turn,
            "useful_context": self._redact_sensitive_values(useful_context or {}),
            "task_context": task_context or {},
            "created_at": time.time(),
        }

        system_memory = getattr(self.system_config, "_prepare_memory_payload", None)
        if callable(system_memory):
            try:
                system_result = system_memory(
                    event_type="voice_interaction",
                    content=payload,
                    task_context=task_context or {},
                )
                payload["system_memory_result"] = system_result
            except Exception as exc:
                payload["system_memory_error"] = str(exc)

        self._emit_agent_event(
            event_type="voice.memory_payload_prepared",
            payload=payload,
        )

        return self._safe_result(
            message="Voice memory payload prepared.",
            data=payload,
            metadata={
                "hook": "_prepare_memory_payload",
            },
        )

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit dashboard/API-ready VoiceAgent event.
        """

        if not self.config.enable_dashboard_events:
            return self._safe_result(
                message="Voice dashboard events disabled.",
                data=None,
                metadata={
                    "hook": "_emit_agent_event",
                },
            )

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "state": self.state.value,
            "payload": self._redact_sensitive_values(payload),
            "created_at": time.time(),
        }

        self.runtime_events.append(event)

        system_emit = getattr(self.system_config, "_emit_agent_event", None)
        if callable(system_emit):
            try:
                system_emit(event_type=event_type, payload=event)
            except Exception:
                logger.exception("Failed to emit through system_config.")

        return self._safe_result(
            message="Voice agent event emitted.",
            data=event,
            metadata={
                "hook": "_emit_agent_event",
            },
        )

    def _log_audit_event(
        self,
        event_type: str,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Log local audit event for VoiceAgent.
        """

        if not self.config.enable_audit_logs:
            return self._safe_result(
                message="Voice audit logs disabled.",
                data=None,
                metadata={
                    "hook": "_log_audit_event",
                },
            )

        event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "details": self._redact_sensitive_values(details),
            "created_at": time.time(),
        }

        self.audit_events.append(event)

        system_audit = getattr(self.system_config, "_log_audit_event", None)
        if callable(system_audit):
            try:
                system_audit(event_type=event_type, details=event)
            except Exception:
                logger.exception("Failed to log audit through system_config.")

        return self._safe_result(
            message="Voice audit event logged.",
            data=event,
            metadata={
                "hook": "_log_audit_event",
            },
        )

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data,
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error response.
        """

        return {
            "success": False,
            "message": message,
            "data": None,
            "error": error or {
                "code": "VOICE_AGENT_ERROR",
                "details": message,
            },
            "metadata": metadata or {},
        }

    # =========================================================================
    # Session Lifecycle
    # =========================================================================

    def start_session(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        language: Optional[str] = None,
        voice_profile: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Start a new voice session.

        A session is always scoped to user_id/workspace_id.
        """

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        context = context_result["data"]

        session = VoiceSession(
            session_id=str(uuid.uuid4()),
            user_id=context.get("user_id"),
            workspace_id=context.get("workspace_id"),
            device_id=device_id or context.get("device_id"),
            language=language or self.config.default_language,
            voice_profile=voice_profile or self.config.default_voice_profile,
            state=VoiceAgentState.IDLE,
            metadata={
                "created_by": self.agent_name,
                "safe_mode": self.config.safe_mode,
            },
        )

        self.current_session = session
        self._set_state(VoiceAgentState.IDLE)

        self._emit_agent_event(
            event_type="voice.session_started",
            payload=session.to_dict(),
        )

        self._log_audit_event(
            event_type="voice_session_started",
            details=session.to_dict(),
        )

        return self._safe_result(
            message="Voice session started.",
            data=session.to_dict(),
        )

    def stop_session(
        self,
        reason: str = "manual",
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Stop the active voice session.
        """

        if not self.current_session:
            self._set_state(VoiceAgentState.STOPPED)
            return self._safe_result(
                message="No active voice session to stop.",
                data={
                    "stopped": False,
                    "reason": reason,
                },
            )

        self.current_session.end()
        session_data = self.current_session.to_dict()
        session_data["stop_reason"] = reason

        self._set_state(VoiceAgentState.STOPPED)

        try:
            self.stop_device_stream(task_context=task_context)
        except Exception:
            logger.exception("Failed to stop device stream during session stop.")

        self._emit_agent_event(
            event_type="voice.session_stopped",
            payload=session_data,
        )

        self._log_audit_event(
            event_type="voice_session_stopped",
            details=session_data,
        )

        self.current_session = None

        return self._safe_result(
            message="Voice session stopped.",
            data=session_data,
        )

    def get_current_session(self) -> Dict[str, Any]:
        """
        Return current voice session.
        """

        return self._safe_result(
            message="Current voice session loaded.",
            data=self.current_session.to_dict() if self.current_session else None,
        )

    # =========================================================================
    # Device Stream
    # =========================================================================

    def start_device_stream(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Start device audio stream.

        This does not force microphone access unless the configured stream engine
        supports and allows it.
        """

        if not self.config.enable_device_streaming:
            return self._error_result(
                message="Device streaming is disabled.",
                error={
                    "code": "DEVICE_STREAMING_DISABLED",
                },
            )

        if not self.config.allow_device_microphone and not self.config.allow_remote_device_stream:
            return self._error_result(
                message="Device microphone/remote streaming is not allowed by config.",
                error={
                    "code": "DEVICE_STREAM_PERMISSION_BLOCKED",
                },
            )

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        try:
            result = self._call_engine_method(
                self.device_stream,
                ["start_stream", "start", "open"],
                task_context=context_result["data"],
                **kwargs,
            )

            self._emit_agent_event(
                event_type="voice.device_stream_started",
                payload={
                    "result": result,
                    "task_context": context_result["data"],
                },
            )

            return self._safe_result(
                message="Device stream start requested.",
                data=result,
            )

        except Exception as exc:
            logger.exception("Failed to start device stream.")
            self._set_state(VoiceAgentState.ERROR)
            return self._error_result(
                message="Failed to start device stream.",
                error={
                    "code": "DEVICE_STREAM_START_FAILED",
                    "details": str(exc),
                },
            )

    def stop_device_stream(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Stop device audio stream.
        """

        try:
            result = self._call_engine_method(
                self.device_stream,
                ["stop_stream", "stop", "close"],
                task_context=task_context or {},
                **kwargs,
            )

            self._emit_agent_event(
                event_type="voice.device_stream_stopped",
                payload={
                    "result": result,
                    "task_context": task_context or {},
                },
            )

            return self._safe_result(
                message="Device stream stop requested.",
                data=result,
            )

        except Exception as exc:
            logger.exception("Failed to stop device stream.")
            return self._error_result(
                message="Failed to stop device stream.",
                error={
                    "code": "DEVICE_STREAM_STOP_FAILED",
                    "details": str(exc),
                },
            )

    # =========================================================================
    # Wake Word / STT / Language / TTS
    # =========================================================================

    def detect_wake_word(
        self,
        audio_input: Any = None,
        text_input: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect wake word from text or audio.
        """

        try:
            result = self._call_engine_method(
                self.wake_word_engine,
                ["detect", "detect_wake_word", "process"],
                audio_input=audio_input,
                text_input=text_input,
                task_context=task_context or {},
            )

            detected = bool(
                self._get_nested_value(result, ["data", "detected"], default=False)
            )

            if detected:
                self._set_state(VoiceAgentState.WAKE_DETECTED)

            return self._safe_result(
                message="Wake word detection completed.",
                data={
                    "detected": detected,
                    "raw_result": result,
                },
            )

        except Exception as exc:
            logger.exception("Wake word detection failed.")
            self._set_state(VoiceAgentState.ERROR)
            return self._error_result(
                message="Wake word detection failed.",
                error={
                    "code": "WAKE_WORD_DETECTION_FAILED",
                    "details": str(exc),
                },
            )

    def transcribe_audio(
        self,
        audio_input: Any,
        language: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convert audio input to text using STT engine.
        """

        if not self.config.enable_stt:
            return self._error_result(
                message="Speech-to-text is disabled.",
                error={
                    "code": "STT_DISABLED",
                },
            )

        self._set_state(VoiceAgentState.TRANSCRIBING)

        try:
            result = self._call_engine_method(
                self.stt_engine,
                ["transcribe", "speech_to_text", "process"],
                audio_input=audio_input,
                language=language or self.config.default_language,
                task_context=task_context or {},
                **kwargs,
            )

            transcript = str(
                self._get_nested_value(result, ["data", "text"], default="")
            ).strip()

            if len(transcript) > self.config.max_transcript_chars:
                transcript = transcript[: self.config.max_transcript_chars]

            return self._safe_result(
                message="Audio transcription completed.",
                data={
                    "text": transcript,
                    "raw_result": result,
                },
            )

        except Exception as exc:
            logger.exception("Audio transcription failed.")
            self._set_state(VoiceAgentState.ERROR)
            return self._error_result(
                message="Audio transcription failed.",
                error={
                    "code": "STT_FAILED",
                    "details": str(exc),
                },
            )

    def detect_language(
        self,
        text: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect language from transcript text.
        """

        if not self.config.enable_language_detection:
            return self._safe_result(
                message="Language detection disabled. Using default language.",
                data={
                    "language": self.config.fallback_language,
                    "confidence": 0.0,
                },
            )

        try:
            result = self._call_engine_method(
                self.language_engine,
                ["detect_language", "detect", "process"],
                text=text,
                task_context=task_context or {},
            )

            language = str(
                self._get_nested_value(
                    result,
                    ["data", "language"],
                    default=self.config.fallback_language,
                )
            )

            confidence = self._get_nested_value(
                result,
                ["data", "confidence"],
                default=0.0,
            )

            return self._safe_result(
                message="Language detection completed.",
                data={
                    "language": language,
                    "confidence": confidence,
                    "raw_result": result,
                },
            )

        except Exception as exc:
            logger.exception("Language detection failed.")
            return self._safe_result(
                message="Language detection failed. Fallback language selected.",
                data={
                    "language": self.config.fallback_language,
                    "confidence": 0.0,
                    "error": str(exc),
                },
            )

    def speak_text(
        self,
        text: str,
        language: Optional[str] = None,
        voice_profile: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convert response text to speech.
        """

        if not self.config.enable_tts:
            return self._safe_result(
                message="TTS disabled. Returning text only.",
                data={
                    "text": text,
                    "audio_output": None,
                },
            )

        self._set_state(VoiceAgentState.SPEAKING)

        try:
            safe_text = text[: self.config.max_response_chars]

            result = self._call_engine_method(
                self.tts_engine,
                ["speak", "synthesize", "text_to_speech", "process"],
                text=safe_text,
                language=language or self.config.fallback_language,
                voice_profile=voice_profile or self.config.default_voice_profile,
                task_context=task_context or {},
                **kwargs,
            )

            return self._safe_result(
                message="Text-to-speech completed.",
                data={
                    "text": safe_text,
                    "raw_result": result,
                },
            )

        except Exception as exc:
            logger.exception("TTS failed.")
            self._set_state(VoiceAgentState.ERROR)
            return self._error_result(
                message="Text-to-speech failed.",
                error={
                    "code": "TTS_FAILED",
                    "details": str(exc),
                },
            )

    # =========================================================================
    # Interruption
    # =========================================================================

    def check_interruption(
        self,
        text_input: Optional[str] = None,
        audio_input: Any = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether the current response/task should be interrupted.
        """

        if not self.config.enable_interruption:
            return self._safe_result(
                message="Interruption handling disabled.",
                data={
                    "interrupted": False,
                },
            )

        try:
            result = self._call_engine_method(
                self.interruption_manager,
                ["check_interruption", "check", "detect"],
                text_input=text_input,
                audio_input=audio_input,
                task_context=task_context or {},
            )

            interrupted = bool(
                self._get_nested_value(result, ["data", "interrupted"], default=False)
            )

            if interrupted:
                self._set_state(VoiceAgentState.INTERRUPTED)
                self._emit_agent_event(
                    event_type="voice.interrupted",
                    payload={
                        "text_preview": self._safe_preview(text_input or ""),
                        "raw_result": result,
                    },
                )

            return self._safe_result(
                message="Interruption check completed.",
                data={
                    "interrupted": interrupted,
                    "raw_result": result,
                },
            )

        except Exception as exc:
            logger.exception("Interruption check failed.")
            return self._error_result(
                message="Interruption check failed.",
                error={
                    "code": "INTERRUPTION_CHECK_FAILED",
                    "details": str(exc),
                },
            )

    def interrupt(
        self,
        reason: str = "manual",
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Manually interrupt the active voice flow.
        """

        self._set_state(VoiceAgentState.INTERRUPTED)

        try:
            result = self._call_engine_method(
                self.interruption_manager,
                ["interrupt", "stop", "cancel"],
                reason=reason,
                task_context=task_context or {},
            )
        except Exception as exc:
            result = {
                "success": False,
                "message": "Interruption manager failed.",
                "error": str(exc),
            }

        payload = {
            "reason": reason,
            "interruption_result": result,
            "task_context": task_context or {},
        }

        self._emit_agent_event(
            event_type="voice.interrupt_requested",
            payload=payload,
        )

        self._log_audit_event(
            event_type="voice_interrupt_requested",
            details=payload,
        )

        return self._safe_result(
            message="Voice interruption requested.",
            data=payload,
        )

    # =========================================================================
    # Main Voice Processing
    # =========================================================================

    def process_voice_input(
        self,
        audio_input: Any = None,
        text_input: Optional[str] = None,
        input_type: Union[str, VoiceInputType] = VoiceInputType.TEXT,
        output_type: Union[str, VoiceOutputType] = VoiceOutputType.BOTH,
        task_context: Optional[Dict[str, Any]] = None,
        require_wake_word: Optional[bool] = None,
        route_to_master: bool = True,
        speak_response: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Main sync voice interaction method.

        Flow:
            1. Validate context.
            2. Start/reuse session.
            3. Detect wake word if required.
            4. Transcribe audio if needed.
            5. Detect language.
            6. Check interruption.
            7. Check security requirement.
            8. Route to Master Agent.
            9. Speak response.
            10. Prepare verification and memory payloads.
        """

        try:
            return self._run_async_sync(
                self.process_voice_input_async(
                    audio_input=audio_input,
                    text_input=text_input,
                    input_type=input_type,
                    output_type=output_type,
                    task_context=task_context,
                    require_wake_word=require_wake_word,
                    route_to_master=route_to_master,
                    speak_response=speak_response,
                    **kwargs,
                )
            )
        except Exception as exc:
            logger.exception("Voice input processing failed.")
            self._set_state(VoiceAgentState.ERROR)
            return self._error_result(
                message="Voice input processing failed.",
                error={
                    "code": "VOICE_PROCESSING_FAILED",
                    "details": str(exc),
                },
            )

    async def process_voice_input_async(
        self,
        audio_input: Any = None,
        text_input: Optional[str] = None,
        input_type: Union[str, VoiceInputType] = VoiceInputType.TEXT,
        output_type: Union[str, VoiceOutputType] = VoiceOutputType.BOTH,
        task_context: Optional[Dict[str, Any]] = None,
        require_wake_word: Optional[bool] = None,
        route_to_master: bool = True,
        speak_response: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Async version of process_voice_input().
        """

        if not self.config.enabled:
            return self._error_result(
                message="VoiceAgent is disabled.",
                error={
                    "code": "VOICE_AGENT_DISABLED",
                },
            )

        input_type_enum = self._normalize_input_type(input_type)
        output_type_enum = self._normalize_output_type(output_type)

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        context = context_result["data"]

        if not self.current_session:
            session_result = self.start_session(
                task_context=context,
                language=self.config.default_language,
                voice_profile=self.config.default_voice_profile,
                device_id=context.get("device_id"),
            )
            if not session_result.get("success"):
                return session_result

        session = self.current_session
        assert session is not None

        self._set_state(VoiceAgentState.LISTENING)

        turn = VoiceTurn(
            turn_id=str(uuid.uuid4()),
            session_id=session.session_id,
            user_id=context.get("user_id"),
            workspace_id=context.get("workspace_id"),
            input_type=input_type_enum,
            output_type=output_type_enum,
            metadata={
                "device_id": context.get("device_id"),
                "route_to_master": route_to_master,
                "speak_response": speak_response,
            },
        )

        transcript = text_input or ""

        should_require_wake = (
            self.config.require_wake_word
            if require_wake_word is None
            else require_wake_word
        )

        if input_type_enum == VoiceInputType.AUDIO:
            transcription = self.transcribe_audio(
                audio_input=audio_input,
                language=session.language,
                task_context=context,
                **kwargs,
            )
            if not transcription.get("success"):
                return transcription

            transcript = transcription.get("data", {}).get("text", "")

        elif input_type_enum == VoiceInputType.STREAM:
            stream_audio = self._call_engine_method(
                self.device_stream,
                ["read_audio", "read", "receive"],
                task_context=context,
            )
            audio_data = self._get_nested_value(
                stream_audio,
                ["data", "audio_input"],
                default=audio_input,
            )

            transcription = self.transcribe_audio(
                audio_input=audio_data,
                language=session.language,
                task_context=context,
                **kwargs,
            )
            if not transcription.get("success"):
                return transcription

            transcript = transcription.get("data", {}).get("text", "")

        transcript = (transcript or "").strip()
        transcript = transcript[: self.config.max_transcript_chars]

        turn.transcript = transcript
        session.transcript = transcript
        session.touch()

        if not transcript:
            return self._error_result(
                message="No transcript detected from voice input.",
                error={
                    "code": "EMPTY_TRANSCRIPT",
                },
                metadata={
                    "turn": turn.to_dict(),
                },
            )

        if should_require_wake:
            wake_result = self.detect_wake_word(
                audio_input=audio_input,
                text_input=transcript,
                task_context=context,
            )
            if not wake_result.get("success"):
                return wake_result

            wake_detected = bool(
                wake_result.get("data", {}).get("detected", False)
            )
            turn.wake_word_detected = wake_detected

            if not wake_detected:
                if not (
                    input_type_enum == VoiceInputType.TEXT
                    and self.config.allow_text_input_without_wake_word
                ):
                    return self._safe_result(
                        message="Wake word not detected. VoiceAgent did not process command.",
                        data={
                            "processed": False,
                            "wake_word_detected": False,
                            "turn": turn.to_dict(),
                        },
                    )

        language_result = self.detect_language(
            text=transcript,
            task_context=context,
        )
        detected_language = language_result.get("data", {}).get(
            "language",
            self.config.fallback_language,
        )
        turn.detected_language = detected_language
        session.language = detected_language
        session.touch()

        interruption_result = self.check_interruption(
            text_input=transcript,
            audio_input=audio_input,
            task_context=context,
        )
        interrupted = bool(
            interruption_result.get("data", {}).get("interrupted", False)
        )
        turn.interrupted = interrupted

        if interrupted:
            turn.complete()
            self._store_turn(turn)
            return self._safe_result(
                message="Voice input interrupted.",
                data={
                    "processed": False,
                    "interrupted": True,
                    "turn": turn.to_dict(),
                },
            )

        security_required = self._requires_security_check(
            task_context=context,
            transcript=transcript,
            action="voice_interaction",
        )
        turn.security_required = security_required

        if security_required:
            security_payload = self._request_security_approval(
                task_context=context,
                transcript=transcript,
                action="voice_interaction",
            )
            context["security_payload"] = security_payload

        self._set_state(VoiceAgentState.THINKING)

        master_result: Dict[str, Any]
        if route_to_master:
            master_result = await self._route_to_master_async(
                transcript=transcript,
                task_context=context,
                language=detected_language,
                voice_turn=turn,
                **kwargs,
            )
        else:
            master_result = self._safe_result(
                message="Master routing skipped.",
                data={
                    "response_text": transcript,
                    "echo": True,
                },
            )

        response_text = self._extract_response_text(master_result)
        response_text = response_text[: self.config.max_response_chars]

        turn.response_text = response_text
        session.response_text = response_text
        session.touch()

        tts_result: Optional[Dict[str, Any]] = None
        if speak_response and output_type_enum in {VoiceOutputType.AUDIO, VoiceOutputType.BOTH}:
            tts_result = self.speak_text(
                text=response_text,
                language=detected_language,
                voice_profile=session.voice_profile,
                task_context=context,
                **kwargs,
            )

        turn.complete()
        self._store_turn(turn)

        result_payload = {
            "processed": True,
            "session": session.to_dict(),
            "turn": turn.to_dict(),
            "transcript": transcript,
            "detected_language": detected_language,
            "security_required": security_required,
            "master_result": master_result,
            "response_text": response_text,
            "tts_result": tts_result,
        }

        verification_payload = self._prepare_verification_payload(
            task_context=context,
            voice_turn=turn,
            result=result_payload,
        )

        memory_payload = self._prepare_memory_payload(
            task_context=context,
            voice_turn=turn,
            useful_context={
                "detected_language": detected_language,
                "security_required": security_required,
                "response_preview": self._safe_preview(response_text),
            },
        )

        result_payload["verification_payload"] = verification_payload
        result_payload["memory_payload"] = memory_payload

        self._emit_agent_event(
            event_type="voice.turn_completed",
            payload=result_payload,
        )

        self._log_audit_event(
            event_type="voice_turn_completed",
            details={
                "turn_id": turn.turn_id,
                "session_id": turn.session_id,
                "user_id": turn.user_id,
                "workspace_id": turn.workspace_id,
                "security_required": security_required,
                "detected_language": detected_language,
            },
        )

        self._set_state(VoiceAgentState.IDLE)

        return self._safe_result(
            message="Voice input processed successfully.",
            data=result_payload,
        )

    # =========================================================================
    # Master Agent Routing
    # =========================================================================

    async def _route_to_master_async(
        self,
        transcript: str,
        task_context: Dict[str, Any],
        language: str,
        voice_turn: VoiceTurn,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Route text command to Master Agent or injected router callback.

        The router callback can be:
            - async callable
            - sync callable
            - object with route()
            - object with process()
            - object with run()
        """

        if self.master_router is None:
            return self._safe_result(
                message="No Master Agent router attached. Returning fallback response.",
                data={
                    "response_text": (
                        "I heard you. Master Agent routing is not connected yet."
                    ),
                    "fallback": True,
                    "transcript": transcript,
                    "language": language,
                },
            )

        payload = {
            "source_agent": self.agent_name,
            "input": transcript,
            "language": language,
            "task_context": task_context,
            "voice_turn": voice_turn.to_dict(),
            "metadata": {
                "input_mode": "voice",
                "requires_response": True,
                "created_at": time.time(),
            },
        }

        try:
            router = self.master_router

            if callable(router):
                result = router(payload)
                if inspect.isawaitable(result):
                    result = await result
                return self._ensure_structured_result(result)

            for method_name in ["route", "process", "run", "handle"]:
                method = getattr(router, method_name, None)
                if callable(method):
                    result = method(payload)
                    if inspect.isawaitable(result):
                        result = await result
                    return self._ensure_structured_result(result)

            return self._error_result(
                message="Master router has no supported callable method.",
                error={
                    "code": "MASTER_ROUTER_INVALID",
                },
            )

        except Exception as exc:
            logger.exception("Master routing failed.")
            return self._error_result(
                message="Master Agent routing failed.",
                error={
                    "code": "MASTER_ROUTING_FAILED",
                    "details": str(exc),
                },
            )

    def attach_master_router(
        self,
        master_router: Callable[..., Union[Dict[str, Any], Awaitable[Dict[str, Any]]]],
    ) -> Dict[str, Any]:
        """
        Attach Master Agent router after initialization.
        """

        self.master_router = master_router

        self._emit_agent_event(
            event_type="voice.master_router_attached",
            payload={
                "attached": True,
                "router_type": type(master_router).__name__,
            },
        )

        return self._safe_result(
            message="Master router attached to VoiceAgent.",
            data={
                "attached": True,
                "router_type": type(master_router).__name__,
            },
        )

    # =========================================================================
    # BaseAgent / Registry / Router Public Methods
    # =========================================================================

    def run(
        self,
        task: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        BaseAgent-compatible run method.

        Expected task format:
            {
                "text_input": "William, open my dashboard",
                "audio_input": ...,
                "input_type": "text",
                "output_type": "both",
                "user_id": 1,
                "workspace_id": 10
            }
        """

        task = task or {}

        task_context = task.get("task_context") or {
            "user_id": task.get("user_id", self.user_id),
            "workspace_id": task.get("workspace_id", self.workspace_id),
            "device_id": task.get("device_id", self.device_id),
            "security_level": task.get("security_level", VoiceSecurityLevel.LOW.value),
        }

        return self.process_voice_input(
            audio_input=task.get("audio_input"),
            text_input=task.get("text_input") or task.get("text") or task.get("input"),
            input_type=task.get("input_type", VoiceInputType.TEXT.value),
            output_type=task.get("output_type", VoiceOutputType.BOTH.value),
            task_context=task_context,
            require_wake_word=task.get("require_wake_word"),
            route_to_master=task.get("route_to_master", True),
            speak_response=task.get("speak_response", True),
            **kwargs,
        )

    async def arun(
        self,
        task: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Async BaseAgent-compatible run method.
        """

        task = task or {}

        task_context = task.get("task_context") or {
            "user_id": task.get("user_id", self.user_id),
            "workspace_id": task.get("workspace_id", self.workspace_id),
            "device_id": task.get("device_id", self.device_id),
            "security_level": task.get("security_level", VoiceSecurityLevel.LOW.value),
        }

        return await self.process_voice_input_async(
            audio_input=task.get("audio_input"),
            text_input=task.get("text_input") or task.get("text") or task.get("input"),
            input_type=task.get("input_type", VoiceInputType.TEXT.value),
            output_type=task.get("output_type", VoiceOutputType.BOTH.value),
            task_context=task_context,
            require_wake_word=task.get("require_wake_word"),
            route_to_master=task.get("route_to_master", True),
            speak_response=task.get("speak_response", True),
            **kwargs,
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Registry/Loader/Dashboard-compatible health check.
        """

        config_valid, config_errors = self.config.validate()

        engines = {
            "wake_word_engine": self.wake_word_engine is not None,
            "stt_engine": self.stt_engine is not None,
            "tts_engine": self.tts_engine is not None,
            "language_engine": self.language_engine is not None,
            "device_stream": self.device_stream is not None,
            "interruption_manager": self.interruption_manager is not None,
            "master_router": self.master_router is not None,
        }

        healthy = bool(config_valid and all(value is True for value in engines.values() if value is not None))

        return self._safe_result(
            message="VoiceAgent health check completed.",
            data={
                "healthy": healthy,
                "state": self.state.value,
                "config_valid": config_valid,
                "config_errors": config_errors,
                "engines": engines,
                "current_session": (
                    self.current_session.to_dict() if self.current_session else None
                ),
                "history_count": len(self.voice_history),
                "audit_events_count": len(self.audit_events),
                "runtime_events_count": len(self.runtime_events),
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            },
        )

    def capabilities(self) -> Dict[str, Any]:
        """
        Return VoiceAgent capabilities for registry/dashboard.
        """

        return self._safe_result(
            message="VoiceAgent capabilities loaded.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "capabilities": [
                    "wake_word_detection",
                    "speech_to_text",
                    "text_to_speech",
                    "language_detection",
                    "device_streaming",
                    "interruption_handling",
                    "master_agent_voice_routing",
                    "voice_session_management",
                    "voice_turn_history",
                    "security_payload_preparation",
                    "verification_payload_preparation",
                    "memory_payload_preparation",
                    "dashboard_events",
                    "audit_logs",
                    "saas_user_workspace_isolation",
                ],
                "supported_input_types": [item.value for item in VoiceInputType],
                "supported_output_types": [item.value for item in VoiceOutputType],
                "safe_mode": self.config.safe_mode,
            },
        )

    def dashboard_status(self) -> Dict[str, Any]:
        """
        Return dashboard-safe runtime status.
        """

        return self._safe_result(
            message="VoiceAgent dashboard status prepared.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "state": self.state.value,
                "enabled": self.config.enabled,
                "safe_mode": self.config.safe_mode,
                "current_session": (
                    self.current_session.to_dict() if self.current_session else None
                ),
                "voice_history_count": len(self.voice_history),
                "runtime_events_count": len(self.runtime_events),
                "audit_events_count": len(self.audit_events),
                "wake_words": self.config.wake_words,
                "language": (
                    self.current_session.language
                    if self.current_session
                    else self.config.default_language
                ),
                "device_id": self.device_id,
                "updated_at": self.updated_at,
            },
        )

    # =========================================================================
    # History
    # =========================================================================

    def get_voice_history(
        self,
        limit: int = 50,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Return voice history, filtered by user/workspace when provided.
        """

        rows = self.voice_history

        if user_id is not None:
            rows = [row for row in rows if row.get("user_id") == user_id]

        if workspace_id is not None:
            rows = [row for row in rows if row.get("workspace_id") == workspace_id]

        if limit > 0:
            rows = rows[-limit:]

        return self._safe_result(
            message="Voice history loaded.",
            data={
                "items": rows,
                "count": len(rows),
                "total_available": len(self.voice_history),
            },
        )

    def clear_voice_history(
        self,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Clear local voice history.

        This requires valid user/workspace context.
        """

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        count = len(self.voice_history)
        self.voice_history = []

        self._log_audit_event(
            event_type="voice_history_cleared",
            details={
                "cleared_count": count,
                "task_context": context_result["data"],
            },
        )

        return self._safe_result(
            message="Voice history cleared.",
            data={
                "cleared_count": count,
            },
        )

    def _store_turn(self, turn: VoiceTurn) -> None:
        if not self.config.store_voice_history:
            return

        self.voice_history.append(turn.to_dict())

        max_items = self.config.max_voice_history_items
        if max_items and len(self.voice_history) > max_items:
            self.voice_history = self.voice_history[-max_items:]

    # =========================================================================
    # Helpers
    # =========================================================================

    def _set_state(self, state: VoiceAgentState) -> None:
        self.state = state
        self.updated_at = time.time()

        if self.current_session:
            self.current_session.state = state
            self.current_session.touch()

    def _normalize_input_type(
        self,
        input_type: Union[str, VoiceInputType],
    ) -> VoiceInputType:
        if isinstance(input_type, VoiceInputType):
            return input_type

        try:
            return VoiceInputType(str(input_type).lower())
        except ValueError:
            return VoiceInputType.TEXT

    def _normalize_output_type(
        self,
        output_type: Union[str, VoiceOutputType],
    ) -> VoiceOutputType:
        if isinstance(output_type, VoiceOutputType):
            return output_type

        try:
            return VoiceOutputType(str(output_type).lower())
        except ValueError:
            return VoiceOutputType.BOTH

    def _call_engine_method(
        self,
        engine: Any,
        method_names: List[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Call the first available method on an engine.

        Filters unsupported kwargs based on method signature when possible.
        """

        for method_name in method_names:
            method = getattr(engine, method_name, None)
            if callable(method):
                try:
                    filtered_kwargs = self._filter_kwargs_for_callable(method, kwargs)
                    result = method(**filtered_kwargs)
                    return self._ensure_structured_result(result)
                except TypeError:
                    result = method()
                    return self._ensure_structured_result(result)

        raise AttributeError(
            f"Engine {type(engine).__name__} does not support methods: {method_names}"
        )

    def _filter_kwargs_for_callable(
        self,
        func: Callable[..., Any],
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            signature = inspect.signature(func)
            parameters = signature.parameters

            if any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values()):
                return kwargs

            return {
                key: value
                for key, value in kwargs.items()
                if key in parameters
            }
        except Exception:
            return kwargs

    def _ensure_structured_result(self, result: Any) -> Dict[str, Any]:
        """
        Normalize any result into William structured dict format.
        """

        if isinstance(result, dict):
            return {
                "success": bool(result.get("success", True)),
                "message": result.get("message", "Operation completed."),
                "data": result.get("data", result if "data" not in result else result.get("data")),
                "error": result.get("error"),
                "metadata": result.get("metadata", {}),
            }

        return {
            "success": True,
            "message": "Operation completed.",
            "data": result,
            "error": None,
            "metadata": {
                "normalized": True,
            },
        }

    def _extract_response_text(self, result: Dict[str, Any]) -> str:
        """
        Extract response text from a Master Agent result.
        """

        if not isinstance(result, dict):
            return str(result)

        data = result.get("data")

        if isinstance(data, dict):
            for key in [
                "response_text",
                "response",
                "message",
                "text",
                "output",
                "answer",
            ]:
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        for key in [
            "response_text",
            "response",
            "message",
            "text",
            "output",
            "answer",
        ]:
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        if result.get("success") is False:
            error = result.get("error") or {}
            if isinstance(error, dict):
                return str(error.get("details") or error.get("code") or "I could not complete that.")
            return str(error or "I could not complete that.")

        return "Done."

    def _get_nested_value(
        self,
        data: Any,
        path: List[str],
        default: Any = None,
    ) -> Any:
        current = data

        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default

        return current

    def _safe_preview(self, text: str, limit: int = 300) -> str:
        text = text or ""
        if len(text) <= limit:
            return text
        return text[:limit] + "...[truncated]"

    def _redact_sensitive_values(self, value: Any) -> Any:
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "credential",
            "private_key",
            "access_key",
            "refresh_token",
            "client_secret",
        }

        if isinstance(value, dict):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                key_lower = str(key).lower()
                if any(sensitive in key_lower for sensitive in sensitive_keys):
                    redacted[key] = "***redacted***"
                else:
                    redacted[key] = self._redact_sensitive_values(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_sensitive_values(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive_values(item) for item in value)

        return value

    def _run_async_sync(self, awaitable: Awaitable[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run async method from sync context safely.

        If already inside an event loop, this creates a temporary task strategy
        only when possible. For most FastAPI usage, call arun/process async
        directly instead.
        """

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                raise RuntimeError(
                    "Cannot run sync VoiceAgent method inside an active event loop. "
                    "Use await voice_agent.arun(...) instead."
                )
        except RuntimeError as exc:
            if "Use await voice_agent.arun" in str(exc):
                raise
            return asyncio.run(awaitable)

        return asyncio.run(awaitable)


# =============================================================================
# Factory Helpers
# =============================================================================

def create_voice_agent(
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
    device_id: Optional[str] = None,
    master_router: Optional[Callable[..., Union[Dict[str, Any], Awaitable[Dict[str, Any]]]]] = None,
    config: Optional[VoiceAgentConfig] = None,
) -> VoiceAgent:
    """
    Factory helper for dashboard/API/registry usage.
    """

    return VoiceAgent(
        user_id=user_id,
        workspace_id=workspace_id,
        device_id=device_id,
        master_router=master_router,
        config=config,
    )


# =============================================================================
# Safe Local Test
# =============================================================================

if __name__ == "__main__":
    def demo_master_router(payload: Dict[str, Any]) -> Dict[str, Any]:
        text = payload.get("input", "")
        return {
            "success": True,
            "message": "Demo Master Router response.",
            "data": {
                "response_text": f"I received your voice command: {text}"
            },
            "error": None,
            "metadata": {
                "demo": True,
            },
        }

    voice_agent = VoiceAgent(
        user_id="demo_user",
        workspace_id="demo_workspace",
        device_id="demo_device",
        master_router=demo_master_router,
    )

    result = voice_agent.run(
        {
            "text_input": "William, test the voice agent",
            "input_type": "text",
            "output_type": "text",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "device_id": "demo_device",
            "speak_response": False,
        }
    )

    print(result)