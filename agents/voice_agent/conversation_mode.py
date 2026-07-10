"""
agents/voice_agent/conversation_mode.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Continuous real-time conversation mode after wake word with follow-up context.

This module provides:
    - Wake-word activated continuous conversation state
    - Follow-up context tracking
    - Turn-by-turn conversation memory preparation
    - Security approval hooks for sensitive actions
    - Verification payload preparation after completed turns
    - SaaS user/workspace isolation
    - Dashboard/API friendly structured results
    - Import-safe fallback compatibility with future William modules

Architecture Connections:
    - Master Agent:
        Receives routed voice conversation tasks and returns structured response data.
    - Voice Agent:
        Uses this class to keep the conversation alive after wake word activation.
    - Security Agent:
        Sensitive or risky voice commands can be routed for permission checks.
    - Memory Agent:
        Useful conversation context is converted into memory-compatible payloads.
    - Verification Agent:
        Completed user/assistant turns can be verified through payloads.
    - Dashboard/API:
        Emits structured events, metadata, audit logs, and task history payloads.
    - Agent Registry / Agent Loader:
        Import-safe class with clear public methods for plugin-style loading.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Import-safe optional compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even before the real William BaseAgent
        exists. The real BaseAgent can replace this automatically when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.name = kwargs.get("name", self.__class__.__name__)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


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

logger = logging.getLogger("william.voice_agent.conversation_mode")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums and data structures
# =============================================================================

class ConversationState(str, Enum):
    """Conversation mode lifecycle state."""

    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    SPEAKING = "speaking"
    WAITING_FOLLOW_UP = "waiting_follow_up"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


class ConversationEndReason(str, Enum):
    """Reasons a conversation session can end."""

    USER_STOPPED = "user_stopped"
    TIMEOUT = "timeout"
    INTERRUPTION = "interruption"
    SECURITY_DENIED = "security_denied"
    ERROR = "error"
    MANUAL_RESET = "manual_reset"
    MAX_TURNS_REACHED = "max_turns_reached"


class TurnRole(str, Enum):
    """Conversation turn role."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"


class SensitivityLevel(str, Enum):
    """Command sensitivity level for security routing."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ConversationConfig:
    """
    Runtime configuration for continuous conversation mode.

    This can later be loaded from:
        - agents/voice_agent/config.py
        - dashboard settings
        - workspace settings
        - per-user voice preferences
    """

    wake_word: str = "William"
    follow_up_timeout_seconds: float = 18.0
    max_session_seconds: float = 900.0
    max_turns_per_session: int = 50
    max_context_turns: int = 12
    enable_follow_up_context: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True
    enable_audit_logs: bool = True
    enable_agent_events: bool = True
    require_security_for_sensitive_actions: bool = True
    auto_pause_during_tts: bool = True
    allow_interruption: bool = True
    language: str = "auto"
    default_workspace_id: Optional[str] = None
    default_user_id: Optional[str] = None
    debug: bool = False


@dataclass
class ConversationTurn:
    """Single conversation turn."""

    role: TurnRole
    text: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    turn_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    language: Optional[str] = None
    intent: Optional[str] = None
    emotion: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationSession:
    """Continuous conversation session after wake word activation."""

    session_id: str
    user_id: str
    workspace_id: str
    state: ConversationState = ConversationState.IDLE
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ended_at: Optional[str] = None
    end_reason: Optional[ConversationEndReason] = None
    turns: List[ConversationTurn] = field(default_factory=list)
    active_task_id: Optional[str] = None
    last_user_text: Optional[str] = None
    last_assistant_text: Optional[str] = None
    follow_up_expected: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """Update session timestamp."""
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_turn(self, turn: ConversationTurn, max_context_turns: int = 12) -> None:
        """Add a conversation turn and keep context bounded."""
        self.turns.append(turn)

        if turn.role == TurnRole.USER:
            self.last_user_text = turn.text
        elif turn.role == TurnRole.ASSISTANT:
            self.last_assistant_text = turn.text

        if max_context_turns > 0 and len(self.turns) > max_context_turns * 2:
            self.turns = self.turns[-max_context_turns * 2:]

        self.touch()


# =============================================================================
# ConversationMode
# =============================================================================

class ConversationMode(BaseAgent):
    """
    Continuous real-time conversation manager.

    Public responsibilities:
        - start_session()
        - stop_session()
        - pause_session()
        - resume_session()
        - process_user_text()
        - process_voice_turn()
        - get_session_context()
        - reset_session()
        - run()

    This class does not directly perform destructive actions.
    It prepares routed payloads for the Master Agent and checks sensitive actions
    through the Security Agent hooks.
    """

    agent_name = "voice_agent.conversation_mode"
    agent_type = "voice_agent_helper"
    file_path = "agents/voice_agent/conversation_mode.py"

    def __init__(
        self,
        config: Optional[ConversationConfig] = None,
        master_agent: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]] = None,
        stt_callback: Optional[Callable[..., Union[str, Dict[str, Any], Awaitable[Union[str, Dict[str, Any]]]]]] = None,
        tts_callback: Optional[Callable[..., Union[None, Dict[str, Any], Awaitable[Union[None, Dict[str, Any]]]]]] = None,
        router_callback: Optional[Callable[[Dict[str, Any]], Union[Dict[str, Any], Awaitable[Dict[str, Any]]]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=self.agent_name, **kwargs)

        self.config = config or ConversationConfig()

        self.master_agent = master_agent
        self.security_agent = security_agent or self._create_optional_agent(SecurityAgent)
        self.memory_agent = memory_agent or self._create_optional_agent(MemoryAgent)
        self.verification_agent = verification_agent or self._create_optional_agent(VerificationAgent)

        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.stt_callback = stt_callback
        self.tts_callback = tts_callback
        self.router_callback = router_callback

        self._sessions: Dict[str, ConversationSession] = {}
        self._user_workspace_active_sessions: Dict[Tuple[str, str], str] = {}
        self._locks: Dict[str, asyncio.Lock] = {}

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible entry point.

        Expected task format:
            {
                "action": "start_session" | "stop_session" | "process_user_text"
                          | "process_voice_turn" | "get_context" | "pause_session"
                          | "resume_session" | "reset_session",
                "user_id": "...",
                "workspace_id": "...",
                "session_id": "...",
                "text": "...",
                "audio": ...,
                "metadata": {}
            }
        """

        validation = self._validate_task_context(task)
        if not validation["success"]:
            return validation

        action = str(task.get("action", "")).strip().lower()
        user_id = str(task.get("user_id") or self.config.default_user_id or "")
        workspace_id = str(task.get("workspace_id") or self.config.default_workspace_id or "")
        session_id = task.get("session_id")
        metadata = dict(task.get("metadata") or {})

        try:
            if action == "start_session":
                return await self.start_session(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata,
                )

            if action == "stop_session":
                return await self.stop_session(
                    session_id=str(session_id or ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    reason=ConversationEndReason.USER_STOPPED,
                )

            if action == "pause_session":
                return await self.pause_session(
                    session_id=str(session_id or ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                )

            if action == "resume_session":
                return await self.resume_session(
                    session_id=str(session_id or ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                )

            if action == "process_user_text":
                return await self.process_user_text(
                    text=str(task.get("text") or ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    session_id=str(session_id or ""),
                    metadata=metadata,
                )

            if action == "process_voice_turn":
                return await self.process_voice_turn(
                    audio=task.get("audio"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    session_id=str(session_id or ""),
                    metadata=metadata,
                )

            if action in {"get_context", "get_session_context"}:
                return await self.get_session_context(
                    session_id=str(session_id or ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                )

            if action == "reset_session":
                return await self.reset_session(
                    session_id=str(session_id or ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                )

            return self._error_result(
                message="Unsupported conversation mode action.",
                error="UNSUPPORTED_ACTION",
                metadata={
                    "action": action,
                    "supported_actions": [
                        "start_session",
                        "stop_session",
                        "pause_session",
                        "resume_session",
                        "process_user_text",
                        "process_voice_turn",
                        "get_context",
                        "reset_session",
                    ],
                },
            )

        except Exception as exc:
            logger.exception("ConversationMode.run failed")
            return self._error_result(
                message="Conversation mode task failed.",
                error=str(exc),
                metadata={"action": action},
            )

    async def start_session(
        self,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Start continuous conversation mode after wake word.

        A user/workspace pair gets one active conversation session at a time.
        """

        context_task = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": "start_session",
        }
        validation = self._validate_task_context(context_task)
        if not validation["success"]:
            return validation

        active_key = (user_id, workspace_id)
        old_session_id = self._user_workspace_active_sessions.get(active_key)

        if old_session_id and old_session_id in self._sessions:
            old_session = self._sessions[old_session_id]
            if old_session.state not in {ConversationState.STOPPED, ConversationState.ERROR}:
                return self._safe_result(
                    message="Conversation session already active.",
                    data={
                        "session": self._serialize_session(old_session),
                        "already_active": True,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        session_id = str(uuid.uuid4())
        session = ConversationSession(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            state=ConversationState.LISTENING,
            metadata={
                "wake_word": self.config.wake_word,
                "source": self.agent_name,
                **(metadata or {}),
            },
        )

        self._sessions[session_id] = session
        self._user_workspace_active_sessions[active_key] = session_id
        self._locks[session_id] = asyncio.Lock()

        await self._emit_agent_event(
            event_type="conversation_started",
            session=session,
            payload={
                "message": "Continuous conversation mode started.",
            },
        )

        await self._log_audit_event(
            event_type="voice_conversation_started",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            metadata=session.metadata,
        )

        return self._safe_result(
            message="Conversation mode started.",
            data={
                "session": self._serialize_session(session),
                "state": session.state.value,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "session_id": session_id,
            },
        )

    async def stop_session(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
        reason: ConversationEndReason = ConversationEndReason.USER_STOPPED,
    ) -> Dict[str, Any]:
        """Stop continuous conversation mode."""

        session_result = self._get_authorized_session(session_id, user_id, workspace_id)
        if not session_result["success"]:
            return session_result

        session: ConversationSession = session_result["data"]["session"]

        async with self._session_lock(session_id):
            session.state = ConversationState.STOPPED
            session.ended_at = datetime.now(timezone.utc).isoformat()
            session.end_reason = reason
            session.touch()

            active_key = (user_id, workspace_id)
            if self._user_workspace_active_sessions.get(active_key) == session_id:
                self._user_workspace_active_sessions.pop(active_key, None)

        await self._emit_agent_event(
            event_type="conversation_stopped",
            session=session,
            payload={"reason": reason.value},
        )

        await self._log_audit_event(
            event_type="voice_conversation_stopped",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            metadata={"reason": reason.value},
        )

        return self._safe_result(
            message="Conversation mode stopped.",
            data={
                "session": self._serialize_session(session),
                "reason": reason.value,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "session_id": session_id,
            },
        )

    async def pause_session(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Pause an active conversation session."""

        session_result = self._get_authorized_session(session_id, user_id, workspace_id)
        if not session_result["success"]:
            return session_result

        session: ConversationSession = session_result["data"]["session"]

        async with self._session_lock(session_id):
            if session.state == ConversationState.STOPPED:
                return self._error_result(
                    message="Cannot pause a stopped conversation session.",
                    error="SESSION_ALREADY_STOPPED",
                    metadata={"session_id": session_id},
                )

            session.state = ConversationState.PAUSED
            session.touch()

        await self._emit_agent_event(
            event_type="conversation_paused",
            session=session,
            payload={},
        )

        return self._safe_result(
            message="Conversation mode paused.",
            data={"session": self._serialize_session(session)},
            metadata={"session_id": session_id},
        )

    async def resume_session(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Resume a paused conversation session."""

        session_result = self._get_authorized_session(session_id, user_id, workspace_id)
        if not session_result["success"]:
            return session_result

        session: ConversationSession = session_result["data"]["session"]

        async with self._session_lock(session_id):
            if session.state == ConversationState.STOPPED:
                return self._error_result(
                    message="Cannot resume a stopped conversation session.",
                    error="SESSION_ALREADY_STOPPED",
                    metadata={"session_id": session_id},
                )

            session.state = ConversationState.LISTENING
            session.touch()

        await self._emit_agent_event(
            event_type="conversation_resumed",
            session=session,
            payload={},
        )

        return self._safe_result(
            message="Conversation mode resumed.",
            data={"session": self._serialize_session(session)},
            metadata={"session_id": session_id},
        )

    async def process_voice_turn(
        self,
        audio: Any,
        user_id: str,
        workspace_id: str,
        session_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process one voice turn.

        Flow:
            audio -> STT -> process_user_text -> optional TTS
        """

        if not self.stt_callback:
            return self._error_result(
                message="STT callback is not configured.",
                error="STT_CALLBACK_MISSING",
                metadata={"session_id": session_id},
            )

        try:
            stt_result = await self._maybe_await(
                self.stt_callback(
                    audio=audio,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    session_id=session_id,
                    metadata=metadata or {},
                )
            )

            if isinstance(stt_result, dict):
                text = str(stt_result.get("text") or "")
                stt_metadata = dict(stt_result.get("metadata") or {})
            else:
                text = str(stt_result or "")
                stt_metadata = {}

            if not text.strip():
                return self._error_result(
                    message="No speech text detected.",
                    error="EMPTY_STT_RESULT",
                    metadata={
                        "session_id": session_id,
                        "stt_metadata": stt_metadata,
                    },
                )

            merged_metadata = {
                **(metadata or {}),
                "stt": stt_metadata,
                "input_type": "voice",
            }

            return await self.process_user_text(
                text=text,
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                metadata=merged_metadata,
            )

        except Exception as exc:
            logger.exception("process_voice_turn failed")
            return self._error_result(
                message="Voice turn processing failed.",
                error=str(exc),
                metadata={"session_id": session_id},
            )

    async def process_user_text(
        self,
        text: str,
        user_id: str,
        workspace_id: str,
        session_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process a user text turn inside continuous conversation mode.

        This method:
            - Finds or creates an active session
            - Adds the user turn
            - Builds follow-up context
            - Checks security for sensitive commands
            - Routes the request to Master Agent/router
            - Adds assistant response turn
            - Prepares memory and verification payloads
            - Optionally speaks response through TTS callback
        """

        text = str(text or "").strip()
        if not text:
            return self._error_result(
                message="User text cannot be empty.",
                error="EMPTY_TEXT",
                metadata={"session_id": session_id},
            )

        context_task = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": "process_user_text",
        }
        validation = self._validate_task_context(context_task)
        if not validation["success"]:
            return validation

        session = await self._get_or_create_session_for_turn(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            metadata=metadata or {},
        )

        async with self._session_lock(session.session_id):
            if session.state == ConversationState.STOPPED:
                return self._error_result(
                    message="Conversation session is stopped.",
                    error="SESSION_STOPPED",
                    metadata={"session_id": session.session_id},
                )

            if session.state == ConversationState.PAUSED:
                return self._error_result(
                    message="Conversation session is paused.",
                    error="SESSION_PAUSED",
                    metadata={"session_id": session.session_id},
                )

            session.state = ConversationState.THINKING
            session.touch()

            user_turn = ConversationTurn(
                role=TurnRole.USER,
                text=text,
                language=(metadata or {}).get("language") or self.config.language,
                emotion=(metadata or {}).get("emotion"),
                confidence=(metadata or {}).get("confidence"),
                metadata={
                    "input_type": (metadata or {}).get("input_type", "text"),
                    "raw_metadata": metadata or {},
                },
            )
            session.add_turn(user_turn, self.config.max_context_turns)

        await self._emit_agent_event(
            event_type="conversation_user_turn",
            session=session,
            payload={
                "turn_id": user_turn.turn_id,
                "text": text,
            },
        )

        timeout_result = await self._check_session_limits(session)
        if not timeout_result["success"]:
            return timeout_result

        route_payload = self._build_master_agent_payload(
            session=session,
            user_text=text,
            metadata=metadata or {},
        )

        sensitivity = self._detect_sensitivity(text=text, metadata=metadata or {})
        route_payload["sensitivity"] = sensitivity.value

        if self._requires_security_check(route_payload):
            approval = await self._request_security_approval(
                task=route_payload,
                sensitivity=sensitivity,
            )
            if not approval["success"]:
                await self.stop_session(
                    session_id=session.session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    reason=ConversationEndReason.SECURITY_DENIED,
                )
                return approval

        routed_result = await self._route_to_master_or_callback(route_payload)

        assistant_text = self._extract_assistant_text(routed_result)

        async with self._session_lock(session.session_id):
            assistant_turn = ConversationTurn(
                role=TurnRole.ASSISTANT,
                text=assistant_text,
                language=routed_result.get("language") if isinstance(routed_result, dict) else None,
                intent=routed_result.get("intent") if isinstance(routed_result, dict) else None,
                confidence=routed_result.get("confidence") if isinstance(routed_result, dict) else None,
                metadata={
                    "router_result": routed_result,
                    "source": "master_agent",
                },
            )

            session.add_turn(assistant_turn, self.config.max_context_turns)
            session.follow_up_expected = self._should_wait_for_follow_up(
                user_text=text,
                assistant_text=assistant_text,
                routed_result=routed_result,
            )
            session.state = (
                ConversationState.WAITING_FOLLOW_UP
                if session.follow_up_expected
                else ConversationState.LISTENING
            )
            session.touch()

        memory_payload = self._prepare_memory_payload(session, user_turn, assistant_turn)
        verification_payload = self._prepare_verification_payload(
            session=session,
            user_turn=user_turn,
            assistant_turn=assistant_turn,
            routed_result=routed_result,
        )

        await self._emit_agent_event(
            event_type="conversation_assistant_turn",
            session=session,
            payload={
                "turn_id": assistant_turn.turn_id,
                "text": assistant_text,
                "follow_up_expected": session.follow_up_expected,
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
            },
        )

        await self._log_audit_event(
            event_type="voice_conversation_turn_completed",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session.session_id,
            metadata={
                "user_turn_id": user_turn.turn_id,
                "assistant_turn_id": assistant_turn.turn_id,
                "sensitivity": sensitivity.value,
                "follow_up_expected": session.follow_up_expected,
            },
        )

        tts_result = None
        if self.tts_callback and assistant_text:
            tts_result = await self._speak_response(
                assistant_text=assistant_text,
                session=session,
                metadata=metadata or {},
            )

        return self._safe_result(
            message="Conversation turn processed.",
            data={
                "session": self._serialize_session(session),
                "user_turn": self._serialize_turn(user_turn),
                "assistant_turn": self._serialize_turn(assistant_turn),
                "assistant_text": assistant_text,
                "routed_result": routed_result,
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
                "tts_result": tts_result,
                "follow_up_expected": session.follow_up_expected,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "session_id": session.session_id,
                "state": session.state.value,
            },
        )

    async def get_session_context(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Return current session context for Master Agent/dashboard."""

        session_result = self._get_authorized_session(session_id, user_id, workspace_id)
        if not session_result["success"]:
            return session_result

        session: ConversationSession = session_result["data"]["session"]

        return self._safe_result(
            message="Conversation session context loaded.",
            data={
                "session": self._serialize_session(session),
                "context": self._build_context_window(session),
            },
            metadata={
                "session_id": session_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    async def reset_session(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Reset and remove a session safely."""

        session_result = self._get_authorized_session(session_id, user_id, workspace_id)
        if not session_result["success"]:
            return session_result

        session: ConversationSession = session_result["data"]["session"]

        async with self._session_lock(session_id):
            session.state = ConversationState.STOPPED
            session.ended_at = datetime.now(timezone.utc).isoformat()
            session.end_reason = ConversationEndReason.MANUAL_RESET
            session.touch()

            self._sessions.pop(session_id, None)
            self._locks.pop(session_id, None)

            active_key = (user_id, workspace_id)
            if self._user_workspace_active_sessions.get(active_key) == session_id:
                self._user_workspace_active_sessions.pop(active_key, None)

        await self._emit_agent_event(
            event_type="conversation_reset",
            session=session,
            payload={"reason": ConversationEndReason.MANUAL_RESET.value},
        )

        await self._log_audit_event(
            event_type="voice_conversation_reset",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            metadata={"reason": ConversationEndReason.MANUAL_RESET.value},
        )

        return self._safe_result(
            message="Conversation session reset.",
            data={
                "session_id": session_id,
                "removed": True,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def list_active_sessions(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List active sessions for dashboard/admin views."""

        sessions: List[Dict[str, Any]] = []

        for session in self._sessions.values():
            if user_id and session.user_id != user_id:
                continue
            if workspace_id and session.workspace_id != workspace_id:
                continue
            if session.state in {ConversationState.STOPPED, ConversationState.ERROR}:
                continue
            sessions.append(self._serialize_session(session))

        return self._safe_result(
            message="Active conversation sessions listed.",
            data={"sessions": sessions, "count": len(sessions)},
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user-specific task must include user_id and workspace_id.
        This prevents memory/log/task leakage between SaaS tenants.
        """

        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error="INVALID_TASK_TYPE",
            )

        user_id = task.get("user_id") or self.config.default_user_id
        workspace_id = task.get("workspace_id") or self.config.default_workspace_id

        if not user_id:
            return self._error_result(
                message="Missing user_id. Voice conversation tasks require SaaS user isolation.",
                error="MISSING_USER_ID",
            )

        if not workspace_id:
            return self._error_result(
                message="Missing workspace_id. Voice conversation tasks require workspace isolation.",
                error="MISSING_WORKSPACE_ID",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(self, task: Dict[str, Any]) -> bool:
        """
        Decide if a task needs Security Agent approval.

        Sensitive examples:
            - financial actions
            - system commands
            - browser transactions
            - sending messages/calls
            - deleting files
            - external API actions
            - account/security changes
        """

        if not self.config.require_security_for_sensitive_actions:
            return False

        sensitivity = str(task.get("sensitivity") or SensitivityLevel.NONE.value)
        if sensitivity in {
            SensitivityLevel.MEDIUM.value,
            SensitivityLevel.HIGH.value,
            SensitivityLevel.CRITICAL.value,
        }:
            return True

        text = str(task.get("text") or task.get("user_text") or "").lower()

        sensitive_keywords = [
            "delete",
            "remove file",
            "format",
            "shutdown",
            "restart computer",
            "send money",
            "transfer",
            "pay invoice",
            "buy",
            "purchase",
            "sell",
            "trade",
            "send email",
            "send message",
            "call him",
            "call her",
            "call this number",
            "open bank",
            "change password",
            "reset password",
            "share password",
            "api key",
            "secret key",
            "deploy",
            "publish live",
            "run command",
            "terminal",
            "shell",
            "execute",
        ]

        return any(keyword in text for keyword in sensitive_keywords)

    async def _request_security_approval(
        self,
        task: Dict[str, Any],
        sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval before sensitive execution.

        The fallback behavior is safe:
            - If no Security Agent exists and the command is high/critical,
              deny the action.
            - Medium can be allowed only as a prepared route payload,
              not as direct execution.
        """

        approval_payload = {
            "action": "approve_voice_conversation_task",
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "session_id": task.get("session_id"),
            "agent": self.agent_name,
            "sensitivity": sensitivity.value,
            "task": task,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self.security_agent and hasattr(self.security_agent, "run"):
            try:
                result = await self._maybe_await(self.security_agent.run(approval_payload))
                if isinstance(result, dict) and result.get("success") is True:
                    return self._safe_result(
                        message="Security approval granted.",
                        data={"approval": result},
                        metadata={"sensitivity": sensitivity.value},
                    )

                return self._error_result(
                    message="Security approval denied.",
                    error="SECURITY_APPROVAL_DENIED",
                    data={"approval": result},
                    metadata={"sensitivity": sensitivity.value},
                )
            except Exception as exc:
                logger.exception("Security approval failed")
                return self._error_result(
                    message="Security approval check failed.",
                    error=str(exc),
                    metadata={"sensitivity": sensitivity.value},
                )

        if sensitivity in {SensitivityLevel.HIGH, SensitivityLevel.CRITICAL}:
            return self._error_result(
                message="Security Agent unavailable. High-risk voice action denied by default.",
                error="SECURITY_AGENT_UNAVAILABLE",
                metadata={"sensitivity": sensitivity.value},
            )

        return self._safe_result(
            message="Security Agent unavailable. Medium-risk task allowed only as routed payload.",
            data={"approval": "fallback_safe_route_only"},
            metadata={"sensitivity": sensitivity.value},
        )

    def _prepare_verification_payload(
        self,
        session: ConversationSession,
        user_turn: ConversationTurn,
        assistant_turn: ConversationTurn,
        routed_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        Verification can later check:
            - Was the response grounded?
            - Was the action safe?
            - Did the routed agent return success?
            - Was the correct user/workspace used?
        """

        if not self.config.enable_verification_payloads:
            return {}

        return {
            "type": "voice_conversation_turn_verification",
            "agent": self.agent_name,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "session_id": session.session_id,
            "user_turn_id": user_turn.turn_id,
            "assistant_turn_id": assistant_turn.turn_id,
            "input": {
                "text": user_turn.text,
                "language": user_turn.language,
                "emotion": user_turn.emotion,
            },
            "output": {
                "text": assistant_turn.text,
                "intent": assistant_turn.intent,
                "confidence": assistant_turn.confidence,
            },
            "routed_result": routed_result,
            "metadata": {
                "state": session.state.value,
                "follow_up_expected": session.follow_up_expected,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

    def _prepare_memory_payload(
        self,
        session: ConversationSession,
        user_turn: ConversationTurn,
        assistant_turn: ConversationTurn,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not directly store memory unless the Memory Agent is connected.
        It safely packages useful conversation context for later memory ingestion.
        """

        if not self.config.enable_memory_payloads:
            return {}

        return {
            "type": "voice_conversation_context",
            "agent": self.agent_name,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "session_id": session.session_id,
            "memory_scope": "user_workspace",
            "content": {
                "user_text": user_turn.text,
                "assistant_text": assistant_turn.text,
                "recent_context": self._build_context_window(session),
            },
            "metadata": {
                "user_turn_id": user_turn.turn_id,
                "assistant_turn_id": assistant_turn.turn_id,
                "language": user_turn.language,
                "emotion": user_turn.emotion,
                "intent": assistant_turn.intent,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        }

    async def _emit_agent_event(
        self,
        event_type: str,
        session: Optional[ConversationSession] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboard, task history, websocket, or analytics.

        Import-safe:
            - Uses callback if provided
            - Otherwise logs event locally
        """

        if not self.config.enable_agent_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "session_id": session.session_id if session else None,
            "user_id": session.user_id if session else None,
            "workspace_id": session.workspace_id if session else None,
            "state": session.state.value if session else None,
            "payload": payload or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self.event_callback:
            with contextlib.suppress(Exception):
                await self._maybe_await(self.event_callback(event))
            return

        if self.config.debug:
            logger.info("Agent event: %s", event)

    async def _log_audit_event(
        self,
        event_type: str,
        user_id: str,
        workspace_id: str,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for SaaS compliance.

        This never mixes users/workspaces.
        """

        if not self.config.enable_audit_logs:
            return

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self.audit_callback:
            with contextlib.suppress(Exception):
                await self._maybe_await(self.audit_callback(audit_event))
            return

        if self.config.debug:
            logger.info("Audit event: %s", audit_event)

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis success result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error or message,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _create_optional_agent(self, cls: Any) -> Optional[Any]:
        """Create optional agent safely if available."""

        if cls is None:
            return None

        try:
            return cls()
        except Exception:
            return None

    async def _get_or_create_session_for_turn(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ConversationSession:
        """Find session by id, active key, or create a new session."""

        if session_id:
            existing = self._sessions.get(session_id)
            if existing and existing.user_id == user_id and existing.workspace_id == workspace_id:
                return existing

        active_key = (user_id, workspace_id)
        active_session_id = self._user_workspace_active_sessions.get(active_key)

        if active_session_id and active_session_id in self._sessions:
            session = self._sessions[active_session_id]
            if session.state not in {ConversationState.STOPPED, ConversationState.ERROR}:
                return session

        start_result = await self.start_session(
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata or {},
        )

        new_session_data = start_result.get("data", {}).get("session", {})
        new_session_id = new_session_data.get("session_id")

        if not new_session_id or new_session_id not in self._sessions:
            raise RuntimeError("Failed to create conversation session.")

        return self._sessions[new_session_id]

    def _get_authorized_session(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Load session and enforce user/workspace isolation."""

        if not session_id:
            active_id = self._user_workspace_active_sessions.get((user_id, workspace_id))
            if active_id:
                session_id = active_id

        if not session_id:
            return self._error_result(
                message="Missing session_id and no active conversation session found.",
                error="MISSING_SESSION_ID",
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        session = self._sessions.get(session_id)
        if not session:
            return self._error_result(
                message="Conversation session not found.",
                error="SESSION_NOT_FOUND",
                metadata={"session_id": session_id},
            )

        if session.user_id != user_id or session.workspace_id != workspace_id:
            return self._error_result(
                message="Session access denied. User/workspace mismatch.",
                error="SESSION_ACCESS_DENIED",
                metadata={
                    "session_id": session_id,
                    "requested_user_id": user_id,
                    "requested_workspace_id": workspace_id,
                },
            )

        return self._safe_result(
            message="Session authorized.",
            data={"session": session},
            metadata={"session_id": session_id},
        )

    @contextlib.asynccontextmanager
    async def _session_lock(self, session_id: str) -> Any:
        """Get or create async lock for session."""

        if session_id not in self._locks:
            self._locks[session_id] = asyncio.Lock()

        async with self._locks[session_id]:
            yield

    def _build_master_agent_payload(
        self,
        session: ConversationSession,
        user_text: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build payload for Master Agent or Agent Router."""

        return {
            "action": "route_voice_conversation",
            "source_agent": self.agent_name,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "session_id": session.session_id,
            "text": user_text,
            "user_text": user_text,
            "conversation_context": self._build_context_window(session),
            "follow_up_context": self._build_follow_up_context(session),
            "metadata": {
                "voice_mode": True,
                "continuous_conversation": True,
                "state": session.state.value,
                "wake_word": self.config.wake_word,
                **metadata,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _build_context_window(self, session: ConversationSession) -> List[Dict[str, Any]]:
        """Build bounded context window for follow-up conversations."""

        if not self.config.enable_follow_up_context:
            return []

        turns = session.turns[-self.config.max_context_turns * 2:]
        return [self._serialize_turn(turn) for turn in turns]

    def _build_follow_up_context(self, session: ConversationSession) -> Dict[str, Any]:
        """Build follow-up context summary."""

        return {
            "follow_up_expected": session.follow_up_expected,
            "last_user_text": session.last_user_text,
            "last_assistant_text": session.last_assistant_text,
            "recent_turn_count": len(session.turns),
            "session_started_at": session.started_at,
            "session_updated_at": session.updated_at,
        }

    async def _route_to_master_or_callback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route text to Master Agent/router.

        Priority:
            1. router_callback
            2. master_agent.run()
            3. safe fallback response
        """

        try:
            if self.router_callback:
                result = await self._maybe_await(self.router_callback(payload))
                if isinstance(result, dict):
                    return result
                return {
                    "success": True,
                    "message": "Router callback returned non-dict result.",
                    "response": str(result),
                    "data": {},
                    "metadata": {},
                }

            if self.master_agent and hasattr(self.master_agent, "run"):
                result = await self._maybe_await(self.master_agent.run(payload))
                if isinstance(result, dict):
                    return result
                return {
                    "success": True,
                    "message": "Master Agent returned non-dict result.",
                    "response": str(result),
                    "data": {},
                    "metadata": {},
                }

            return {
                "success": True,
                "message": "Master Agent unavailable. Fallback conversation response generated.",
                "response": (
                    "I heard you. Master Agent routing is not connected yet, "
                    "but conversation mode is active and ready for integration."
                ),
                "data": {
                    "fallback": True,
                    "received_text": payload.get("text"),
                },
                "metadata": {
                    "agent": self.agent_name,
                    "router_connected": False,
                },
            }

        except Exception as exc:
            logger.exception("Master routing failed")
            return {
                "success": False,
                "message": "Master Agent routing failed.",
                "response": "I ran into a routing issue while processing that.",
                "data": {},
                "error": str(exc),
                "metadata": {
                    "agent": self.agent_name,
                },
            }

    def _extract_assistant_text(self, routed_result: Dict[str, Any]) -> str:
        """Extract assistant text from various possible result shapes."""

        if not isinstance(routed_result, dict):
            return str(routed_result)

        candidates = [
            routed_result.get("response"),
            routed_result.get("message"),
            routed_result.get("text"),
            routed_result.get("assistant_text"),
            routed_result.get("data", {}).get("response") if isinstance(routed_result.get("data"), dict) else None,
            routed_result.get("data", {}).get("message") if isinstance(routed_result.get("data"), dict) else None,
            routed_result.get("data", {}).get("text") if isinstance(routed_result.get("data"), dict) else None,
        ]

        for candidate in candidates:
            if candidate:
                return str(candidate)

        if routed_result.get("success") is False:
            return "I could not complete that request safely."

        return "Done."

    def _should_wait_for_follow_up(
        self,
        user_text: str,
        assistant_text: str,
        routed_result: Dict[str, Any],
    ) -> bool:
        """
        Decide whether the session should wait for follow-up.

        Conversation mode usually remains active unless:
            - user explicitly ends it
            - max turns/session timeout reached
            - routed result requests stop
        """

        lower_user = user_text.lower().strip()
        stop_phrases = [
            "stop listening",
            "stop conversation",
            "that's all",
            "that is all",
            "goodbye",
            "bye william",
            "sleep william",
            "go to sleep",
            "exit conversation",
            "end conversation",
        ]

        if any(phrase in lower_user for phrase in stop_phrases):
            return False

        if isinstance(routed_result, dict):
            metadata = routed_result.get("metadata") or {}
            data = routed_result.get("data") or {}

            if metadata.get("end_conversation") is True:
                return False
            if data.get("end_conversation") is True:
                return False

        return True

    async def _speak_response(
        self,
        assistant_text: str,
        session: ConversationSession,
        metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Speak assistant response through TTS callback."""

        if not self.tts_callback:
            return None

        try:
            if self.config.auto_pause_during_tts:
                session.state = ConversationState.SPEAKING
                session.touch()

            result = await self._maybe_await(
                self.tts_callback(
                    text=assistant_text,
                    user_id=session.user_id,
                    workspace_id=session.workspace_id,
                    session_id=session.session_id,
                    metadata=metadata,
                )
            )

            if self.config.auto_pause_during_tts and session.state != ConversationState.STOPPED:
                session.state = (
                    ConversationState.WAITING_FOLLOW_UP
                    if session.follow_up_expected
                    else ConversationState.LISTENING
                )
                session.touch()

            if isinstance(result, dict):
                return result

            return {
                "success": True,
                "message": "TTS completed.",
                "data": {},
                "metadata": {},
            }

        except Exception as exc:
            logger.exception("TTS callback failed")
            return {
                "success": False,
                "message": "TTS callback failed.",
                "data": {},
                "error": str(exc),
                "metadata": {},
            }

    async def _check_session_limits(self, session: ConversationSession) -> Dict[str, Any]:
        """Check max turns and max session duration."""

        now = datetime.now(timezone.utc)

        try:
            started = datetime.fromisoformat(session.started_at)
        except Exception:
            started = now

        elapsed_seconds = (now - started).total_seconds()

        if elapsed_seconds > self.config.max_session_seconds:
            return await self.stop_session(
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                reason=ConversationEndReason.TIMEOUT,
            )

        user_turn_count = len([turn for turn in session.turns if turn.role == TurnRole.USER])
        if user_turn_count > self.config.max_turns_per_session:
            return await self.stop_session(
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                reason=ConversationEndReason.MAX_TURNS_REACHED,
            )

        return self._safe_result(
            message="Session limits OK.",
            data={
                "elapsed_seconds": elapsed_seconds,
                "user_turn_count": user_turn_count,
            },
        )

    def _detect_sensitivity(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SensitivityLevel:
        """
        Lightweight sensitivity detection.

        Final execution permissions should still be handled by Security Agent.
        """

        metadata = metadata or {}
        explicit = str(metadata.get("sensitivity") or "").lower().strip()
        if explicit in {level.value for level in SensitivityLevel}:
            return SensitivityLevel(explicit)

        lower = text.lower()

        critical_terms = [
            "send money",
            "wire transfer",
            "delete database",
            "format disk",
            "wipe",
            "share password",
            "api secret",
            "private key",
        ]

        high_terms = [
            "purchase",
            "buy now",
            "sell stock",
            "trade crypto",
            "send email",
            "send message",
            "make a call",
            "call this number",
            "deploy live",
            "run terminal",
            "execute command",
            "change password",
        ]

        medium_terms = [
            "open website",
            "login",
            "download",
            "upload",
            "create account",
            "schedule meeting",
            "book appointment",
            "connect account",
        ]

        if any(term in lower for term in critical_terms):
            return SensitivityLevel.CRITICAL

        if any(term in lower for term in high_terms):
            return SensitivityLevel.HIGH

        if any(term in lower for term in medium_terms):
            return SensitivityLevel.MEDIUM

        if any(word in lower for word in ["remember", "save this", "note this"]):
            return SensitivityLevel.LOW

        return SensitivityLevel.NONE

    def _serialize_session(self, session: ConversationSession) -> Dict[str, Any]:
        """Serialize session to dict."""

        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "state": session.state.value,
            "started_at": session.started_at,
            "updated_at": session.updated_at,
            "ended_at": session.ended_at,
            "end_reason": session.end_reason.value if session.end_reason else None,
            "active_task_id": session.active_task_id,
            "last_user_text": session.last_user_text,
            "last_assistant_text": session.last_assistant_text,
            "follow_up_expected": session.follow_up_expected,
            "turn_count": len(session.turns),
            "turns": [self._serialize_turn(turn) for turn in session.turns],
            "metadata": session.metadata,
        }

    def _serialize_turn(self, turn: ConversationTurn) -> Dict[str, Any]:
        """Serialize conversation turn to dict."""

        data = asdict(turn)
        data["role"] = turn.role.value
        return data

    async def _maybe_await(self, value: Any) -> Any:
        """Await value if it is awaitable."""

        if asyncio.iscoroutine(value) or isinstance(value, Awaitable):
            return await value
        return value

    # -------------------------------------------------------------------------
    # Dashboard/API utility helpers
    # -------------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return manifest-like metadata for Agent Registry / dashboard.

        This does not register itself automatically.
        The Agent Loader can call this method.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "file_path": self.file_path,
            "class_name": self.__class__.__name__,
            "description": "Continuous real-time voice conversation mode after wake word with follow-up context.",
            "capabilities": [
                "wake_word_conversation_start",
                "continuous_conversation",
                "follow_up_context",
                "saas_user_workspace_isolation",
                "security_check_hooks",
                "memory_payload_preparation",
                "verification_payload_preparation",
                "dashboard_events",
                "audit_logs",
                "stt_callback_support",
                "tts_callback_support",
                "master_agent_routing",
            ],
            "public_methods": [
                "run",
                "start_session",
                "stop_session",
                "pause_session",
                "resume_session",
                "process_user_text",
                "process_voice_turn",
                "get_session_context",
                "reset_session",
                "list_active_sessions",
                "get_agent_manifest",
            ],
            "requires": {
                "user_id": True,
                "workspace_id": True,
                "security_agent": "optional",
                "memory_agent": "optional",
                "verification_agent": "optional",
                "master_agent": "optional",
            },
            "config": asdict(self.config),
        }


# =============================================================================
# Safe local smoke test
# =============================================================================

async def _demo() -> None:
    """
    Local non-destructive smoke test.

    Run:
        python agents/voice_agent/conversation_mode.py

    This does not call real system actions.
    """

    async def fake_router(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Fake router response.",
            "response": f"I heard: {payload.get('text')}",
            "data": {
                "end_conversation": False,
            },
            "metadata": {
                "demo": True,
            },
        }

    conversation = ConversationMode(
        config=ConversationConfig(debug=True),
        router_callback=fake_router,
    )

    start = await conversation.start_session(
        user_id="demo_user",
        workspace_id="demo_workspace",
        metadata={"demo": True},
    )
    print(start)

    session_id = start["data"]["session"]["session_id"]

    result = await conversation.process_user_text(
        text="William, what can you do?",
        user_id="demo_user",
        workspace_id="demo_workspace",
        session_id=session_id,
    )
    print(result)

    stop = await conversation.stop_session(
        session_id=session_id,
        user_id="demo_user",
        workspace_id="demo_workspace",
    )
    print(stop)


if __name__ == "__main__":
    asyncio.run(_demo())