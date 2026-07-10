"""
agents/voice_agent/session_manager.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Voice Agent - Session Manager

Purpose:
    Tracks active voice sessions, language, current topic, source device,
    session state, activity timestamps, and timeouts.

Architecture Compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - Master Agent routing compatible
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/API analytics compatible
    - SaaS user/workspace isolation compatible

Important:
    This file is import-safe. If William core files are not created yet,
    fallback stubs are used so this module can still be imported and tested.

    This file does not execute destructive, browser, call, message, financial,
    or system actions. It only manages in-memory voice session state.

    All public methods return William/Jarvis structured dict format:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": str | None,
            "metadata": dict
        }
"""

from __future__ import annotations

import enum
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Union


# =============================================================================
# Safe Optional BaseAgent Import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe until the real William/Jarvis BaseAgent
        exists. The real BaseAgent can later provide registry, permissions,
        routing, audit, analytics, memory, and verification integrations.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")
            self.version = kwargs.get("version", "1.0.0")


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.voice_agent.session_manager")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums
# =============================================================================

class VoiceSessionStatus(str, enum.Enum):
    """Voice session lifecycle state."""

    CREATED = "created"
    ACTIVE = "active"
    LISTENING = "listening"
    THINKING = "thinking"
    SPEAKING = "speaking"
    PAUSED = "paused"
    IDLE = "idle"
    TIMEOUT = "timeout"
    ENDED = "ended"
    ERROR = "error"


class VoiceSessionEventType(str, enum.Enum):
    """Supported event types that may update a voice session."""

    WAKE_WORD_DETECTED = "wake_word_detected"
    SPEECH_STARTED = "speech_started"
    SPEECH_ENDED = "speech_ended"
    USER_TEXT_CAPTURED = "user_text_captured"
    LANGUAGE_DETECTED = "language_detected"
    TOPIC_UPDATED = "topic_updated"
    MASTER_AGENT_ROUTED = "master_agent_routed"
    RESPONSE_STARTED = "response_started"
    RESPONSE_ENDED = "response_ended"
    INTERRUPTION_DETECTED = "interruption_detected"
    DEVICE_CHANGED = "device_changed"
    SESSION_PAUSED = "session_paused"
    SESSION_RESUMED = "session_resumed"
    SESSION_ENDED = "session_ended"
    ERROR = "error"


class VoiceSessionSource(str, enum.Enum):
    """Possible voice session source device families."""

    MOBILE = "mobile"
    DESKTOP = "desktop"
    SMARTWATCH = "smartwatch"
    GLASSES = "glasses"
    BLUETOOTH = "bluetooth"
    REMOTE = "remote"
    WEB = "web"
    EMBEDDED = "embedded"
    UNKNOWN = "unknown"


class SessionEndReason(str, enum.Enum):
    """Known reasons for ending a session."""

    USER_ENDED = "user_ended"
    TIMEOUT = "timeout"
    DEVICE_DISCONNECTED = "device_disconnected"
    SECURITY_BLOCKED = "security_blocked"
    ERROR = "error"
    SYSTEM_SHUTDOWN = "system_shutdown"
    REPLACED_BY_NEW_SESSION = "replaced_by_new_session"


# =============================================================================
# Constants
# =============================================================================

DEFAULT_SESSION_TIMEOUT_SECONDS = 300
DEFAULT_IDLE_TIMEOUT_SECONDS = 90
DEFAULT_TOPIC_TIMEOUT_SECONDS = 600
DEFAULT_MAX_EVENTS_PER_SESSION = 300
DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER = 10

SUPPORTED_LANGUAGE_CODES = {
    "en": "English",
    "roman_urdu": "Roman Urdu",
    "ur": "Urdu",
    "hi": "Hindi",
    "ar": "Arabic",
    "mixed": "Mixed",
    "unknown": "Unknown",
}

SAFE_PUBLIC_STATUSES = {
    VoiceSessionStatus.CREATED.value,
    VoiceSessionStatus.ACTIVE.value,
    VoiceSessionStatus.LISTENING.value,
    VoiceSessionStatus.THINKING.value,
    VoiceSessionStatus.SPEAKING.value,
    VoiceSessionStatus.PAUSED.value,
    VoiceSessionStatus.IDLE.value,
    VoiceSessionStatus.TIMEOUT.value,
    VoiceSessionStatus.ENDED.value,
    VoiceSessionStatus.ERROR.value,
}

SENSITIVE_SESSION_ACTIONS = {
    "export_session",
    "delete_session",
    "force_end_all_user_sessions",
    "admin_list_all_sessions",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class VoiceSessionManagerConfig:
    """
    Runtime configuration for VoiceSessionManager.
    """

    session_timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS
    idle_timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS
    topic_timeout_seconds: int = DEFAULT_TOPIC_TIMEOUT_SECONDS
    max_events_per_session: int = DEFAULT_MAX_EVENTS_PER_SESSION
    max_active_sessions_per_user: int = DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER
    default_language: str = "unknown"
    default_source: str = VoiceSessionSource.UNKNOWN.value
    auto_cleanup_enabled: bool = True
    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True
    store_transcript_snippets: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VoiceSessionEvent:
    """
    One event inside a voice session timeline.

    Event data must stay scoped to user_id/workspace_id through the parent
    session. Avoid storing secrets or unnecessary raw private content.
    """

    event_id: str
    event_type: str
    timestamp: float
    status_before: Optional[str] = None
    status_after: Optional[str] = None
    language_before: Optional[str] = None
    language_after: Optional[str] = None
    topic_before: Optional[str] = None
    topic_after: Optional[str] = None
    source_device_before: Optional[str] = None
    source_device_after: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "language_before": self.language_before,
            "language_after": self.language_after,
            "topic_before": self.topic_before,
            "topic_after": self.topic_after,
            "source_device_before": self.source_device_before,
            "source_device_after": self.source_device_after,
            "data": dict(self.data),
        }


@dataclass
class VoiceSession:
    """
    In-memory voice session state.

    A session is always scoped to a user/workspace pair. Never share session
    state between users or workspaces.
    """

    session_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    source_device_id: Optional[str] = None
    source_device_type: str = VoiceSessionSource.UNKNOWN.value
    language: str = "unknown"
    reply_language: str = "unknown"
    current_topic: Optional[str] = None
    status: str = VoiceSessionStatus.CREATED.value
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_activity_at: float = field(default_factory=time.time)
    last_user_speech_at: Optional[float] = None
    last_agent_response_at: Optional[float] = None
    last_topic_update_at: Optional[float] = None
    ended_at: Optional[float] = None
    end_reason: Optional[str] = None
    interaction_count: int = 0
    interruption_count: int = 0
    error_count: int = 0
    active_agent: Optional[str] = None
    active_route: Optional[str] = None
    stream_id: Optional[str] = None
    wake_word: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    events: List[VoiceSessionEvent] = field(default_factory=list)

    def to_dict(self, include_events: bool = True) -> Dict[str, Any]:
        data = {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "source_device_id": self.source_device_id,
            "source_device_type": self.source_device_type,
            "language": self.language,
            "reply_language": self.reply_language,
            "current_topic": self.current_topic,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_activity_at": self.last_activity_at,
            "last_user_speech_at": self.last_user_speech_at,
            "last_agent_response_at": self.last_agent_response_at,
            "last_topic_update_at": self.last_topic_update_at,
            "ended_at": self.ended_at,
            "end_reason": self.end_reason,
            "interaction_count": self.interaction_count,
            "interruption_count": self.interruption_count,
            "error_count": self.error_count,
            "active_agent": self.active_agent,
            "active_route": self.active_route,
            "stream_id": self.stream_id,
            "wake_word": self.wake_word,
            "metadata": dict(self.metadata),
        }

        if include_events:
            data["events"] = [event.to_dict() for event in self.events]
            data["event_count"] = len(self.events)
        else:
            data["event_count"] = len(self.events)

        return data


# =============================================================================
# Voice Session Manager
# =============================================================================

class VoiceSessionManager(BaseAgent):
    """
    Tracks active voice sessions for William/Jarvis Voice Agent.

    Responsibilities:
        - Create user/workspace-scoped voice sessions
        - Track active language and reply language
        - Track current topic and topic freshness
        - Track source device and stream ID
        - Track session status: listening/thinking/speaking/paused/etc.
        - Track activity timestamps and timeouts
        - Record safe session events
        - Clean stale/idle sessions
        - Prepare Memory Agent and Verification Agent payloads
        - Emit dashboard/API compatible analytics events
        - Stay compatible with BaseAgent, Registry, Router, and Master Agent

    This file is intentionally backend-agnostic and stores state in memory.
    A database-backed implementation can later wrap or extend this class.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[Union[VoiceSessionManagerConfig, Dict[str, Any]]] = None,
        event_bus: Optional[Any] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_client: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name="VoiceSessionManager",
            agent_type="voice_agent",
            version=self.VERSION,
            **kwargs,
        )

        if isinstance(config, VoiceSessionManagerConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = VoiceSessionManagerConfig(**{
                key: value for key, value in config.items()
                if key in VoiceSessionManagerConfig.__dataclass_fields__
            })
        else:
            self.config = VoiceSessionManagerConfig()

        self.event_bus = event_bus
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_client = audit_client
        self.logger = logger_instance or logger

        self.agent_name = "VoiceSessionManager"
        self.agent_module = "Voice Agent"
        self.file_path = "agents/voice_agent/session_manager.py"

        self._sessions: Dict[str, VoiceSession] = {}
        self._lock = threading.RLock()

    # =========================================================================
    # Public API - Session Lifecycle
    # =========================================================================

    def create_session(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        source_device_id: Optional[str] = None,
        source_device_type: str = VoiceSessionSource.UNKNOWN.value,
        language: Optional[str] = None,
        reply_language: Optional[str] = None,
        current_topic: Optional[str] = None,
        stream_id: Optional[str] = None,
        wake_word: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new voice session.

        Master Agent / Voice Loop should call this after wake word detection,
        user speech start, or a new device stream begins.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "module": self.agent_module,
        }

        try:
            context_result = self._validate_task_context(context)
            if not context_result["success"]:
                return context_result

            active_limit_result = self._validate_active_session_limit(user_id, workspace_id)
            if not active_limit_result["success"]:
                return active_limit_result

            safe_source = self._safe_source_device_type(source_device_type)
            safe_language = self._safe_language_code(language or self.config.default_language)
            safe_reply_language = self._safe_language_code(reply_language or safe_language)

            final_session_id = session_id or self._generate_session_id(user_id, workspace_id)
            now = time.time()

            with self._lock:
                if final_session_id in self._sessions:
                    existing = self._sessions[final_session_id]
                    if not self._same_saas_scope(existing.user_id, existing.workspace_id, user_id, workspace_id):
                        return self._error_result(
                            message="Session ID already belongs to another user/workspace scope.",
                            error="session_scope_conflict",
                            metadata={
                                "session_id": final_session_id,
                                "context": context,
                            },
                        )

                    return self._error_result(
                        message="Session ID already exists.",
                        error="session_id_exists",
                        metadata={
                            "session_id": final_session_id,
                            "context": context,
                        },
                    )

                session = VoiceSession(
                    session_id=final_session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    source_device_id=source_device_id,
                    source_device_type=safe_source,
                    language=safe_language,
                    reply_language=safe_reply_language,
                    current_topic=self._safe_topic(current_topic),
                    status=VoiceSessionStatus.ACTIVE.value,
                    created_at=now,
                    updated_at=now,
                    last_activity_at=now,
                    last_topic_update_at=now if current_topic else None,
                    stream_id=stream_id,
                    wake_word=wake_word,
                    metadata=metadata or {},
                )

                self._append_event_locked(
                    session=session,
                    event_type=VoiceSessionEventType.WAKE_WORD_DETECTED.value if wake_word else "session_created",
                    status_before=VoiceSessionStatus.CREATED.value,
                    status_after=session.status,
                    data={
                        "source_device_id": source_device_id,
                        "source_device_type": safe_source,
                        "stream_id": stream_id,
                        "wake_word_present": bool(wake_word),
                    },
                )

                self._sessions[final_session_id] = session

            verification_payload = self._prepare_verification_payload(
                action="create_session",
                result=session.to_dict(include_events=False),
                context=context,
            )

            memory_payload = self._prepare_memory_payload(
                action="create_session",
                session=session,
                context=context,
            )

            self._emit_agent_event({
                "event": "voice.session.created",
                "session_id": final_session_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "source_device_id": source_device_id,
                "source_device_type": safe_source,
                "language": safe_language,
                "reply_language": safe_reply_language,
                "timestamp": now,
            })

            self._log_audit_event(
                action="create_session",
                context=context,
                result_summary={
                    "session_id": final_session_id,
                    "status": session.status,
                    "source_device_type": safe_source,
                    "language": safe_language,
                },
            )

            return self._safe_result(
                message="Voice session created successfully.",
                data={
                    "session": session.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "context": context,
                    "engine": self.agent_name,
                    "version": self.VERSION,
                },
            )

        except Exception as exc:
            self.logger.exception("Create voice session failed")
            return self._error_result(
                message="Create voice session failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def get_session(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        include_events: bool = True,
    ) -> Dict[str, Any]:
        """Load one voice session with SaaS isolation check."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(session_id)

            if not session:
                return self._error_result(
                    message="Voice session not found.",
                    error="session_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Voice session does not belong to this user/workspace.",
                    error="session_scope_denied",
                    metadata={"context": context},
                )

            return self._safe_result(
                message="Voice session loaded successfully.",
                data={"session": session.to_dict(include_events=include_events)},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Get voice session failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def list_sessions(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        status: Optional[str] = None,
        source_device_id: Optional[str] = None,
        active_only: bool = False,
        include_events: bool = False,
        include_all_for_admin: bool = False,
    ) -> Dict[str, Any]:
        """
        List sessions for a user/workspace.

        Admin-wide listing must be protected by the caller/security layer.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "status": status,
            "source_device_id": source_device_id,
            "active_only": active_only,
            "include_all_for_admin": include_all_for_admin,
        }

        try:
            safe_status = self._safe_status(status) if status else None

            with self._lock:
                sessions = []

                for session in self._sessions.values():
                    if not include_all_for_admin:
                        if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                            continue

                    if safe_status and session.status != safe_status:
                        continue

                    if source_device_id and session.source_device_id != source_device_id:
                        continue

                    if active_only and not self._is_session_active_status(session.status):
                        continue

                    sessions.append(session.to_dict(include_events=include_events))

            return self._safe_result(
                message="Voice sessions listed successfully.",
                data={
                    "sessions": sessions,
                    "count": len(sessions),
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="List voice sessions failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def end_session(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        reason: str = SessionEndReason.USER_ENDED.value,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """End a voice session safely."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(session_id)

                if not session:
                    return self._error_result(
                        message="Voice session not found.",
                        error="session_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Voice session does not belong to this user/workspace.",
                        error="session_scope_denied",
                        metadata={"context": context},
                    )

                now = time.time()
                old_status = session.status

                session.status = VoiceSessionStatus.ENDED.value
                session.ended_at = now
                session.end_reason = reason
                session.updated_at = now
                session.last_activity_at = now

                if metadata:
                    session.metadata.setdefault("end_metadata", {}).update(metadata)

                self._append_event_locked(
                    session=session,
                    event_type=VoiceSessionEventType.SESSION_ENDED.value,
                    status_before=old_status,
                    status_after=session.status,
                    data={
                        "reason": reason,
                        "metadata": metadata or {},
                    },
                )

            verification_payload = self._prepare_verification_payload(
                action="end_session",
                result=session.to_dict(include_events=False),
                context=context,
            )

            memory_payload = self._prepare_memory_payload(
                action="end_session",
                session=session,
                context=context,
            )

            self._emit_agent_event({
                "event": "voice.session.ended",
                "session_id": session_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "reason": reason,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="end_session",
                context=context,
                result_summary={
                    "session_id": session_id,
                    "reason": reason,
                    "interaction_count": session.interaction_count,
                    "interruption_count": session.interruption_count,
                    "error_count": session.error_count,
                },
            )

            return self._safe_result(
                message="Voice session ended successfully.",
                data={
                    "session": session.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("End voice session failed")
            return self._error_result(
                message="End voice session failed.",
                error=str(exc),
                metadata={"context": context},
            )

    # =========================================================================
    # Public API - Session Updates
    # =========================================================================

    def update_session(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        status: Optional[str] = None,
        language: Optional[str] = None,
        reply_language: Optional[str] = None,
        current_topic: Optional[str] = None,
        source_device_id: Optional[str] = None,
        source_device_type: Optional[str] = None,
        active_agent: Optional[str] = None,
        active_route: Optional[str] = None,
        stream_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        event_type: str = "session_updated",
    ) -> Dict[str, Any]:
        """
        Generic update method for Voice Loop, Language Engine, Device Stream,
        Master Agent, and Dashboard/API.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(session_id)

                if not session:
                    return self._error_result(
                        message="Voice session not found.",
                        error="session_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Voice session does not belong to this user/workspace.",
                        error="session_scope_denied",
                        metadata={"context": context},
                    )

                old_status = session.status
                old_language = session.language
                old_topic = session.current_topic
                old_device = session.source_device_id

                if status is not None:
                    session.status = self._safe_status(status)

                if language is not None:
                    session.language = self._safe_language_code(language)

                if reply_language is not None:
                    session.reply_language = self._safe_language_code(reply_language)

                if current_topic is not None:
                    session.current_topic = self._safe_topic(current_topic)
                    session.last_topic_update_at = time.time()

                if source_device_id is not None:
                    session.source_device_id = source_device_id

                if source_device_type is not None:
                    session.source_device_type = self._safe_source_device_type(source_device_type)

                if active_agent is not None:
                    session.active_agent = active_agent

                if active_route is not None:
                    session.active_route = active_route

                if stream_id is not None:
                    session.stream_id = stream_id

                if metadata:
                    session.metadata.update(metadata)

                now = time.time()
                session.updated_at = now
                session.last_activity_at = now

                self._append_event_locked(
                    session=session,
                    event_type=event_type,
                    status_before=old_status,
                    status_after=session.status,
                    language_before=old_language,
                    language_after=session.language,
                    topic_before=old_topic,
                    topic_after=session.current_topic,
                    source_device_before=old_device,
                    source_device_after=session.source_device_id,
                    data={
                        "metadata": metadata or {},
                        "active_agent": active_agent,
                        "active_route": active_route,
                        "stream_id": stream_id,
                    },
                )

            self._emit_agent_event({
                "event": "voice.session.updated",
                "session_id": session_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "status": session.status,
                "language": session.language,
                "current_topic": session.current_topic,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="update_session",
                context=context,
                result_summary={
                    "session_id": session_id,
                    "status": session.status,
                    "language": session.language,
                    "topic": session.current_topic,
                },
            )

            return self._safe_result(
                message="Voice session updated successfully.",
                data={"session": session.to_dict()},
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("Update voice session failed")
            return self._error_result(
                message="Update voice session failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def update_language(
        self,
        session_id: str,
        language: str,
        reply_language: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        confidence: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update detected language and reply language for a voice session."""

        event_metadata = metadata or {}
        if confidence is not None:
            event_metadata["language_confidence"] = confidence

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            language=language,
            reply_language=reply_language or language,
            metadata=event_metadata,
            event_type=VoiceSessionEventType.LANGUAGE_DETECTED.value,
        )

    def update_topic(
        self,
        session_id: str,
        current_topic: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update current topic for a voice session."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            current_topic=current_topic,
            metadata=metadata,
            event_type=VoiceSessionEventType.TOPIC_UPDATED.value,
        )

    def update_source_device(
        self,
        session_id: str,
        source_device_id: str,
        source_device_type: str = VoiceSessionSource.UNKNOWN.value,
        stream_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update source device for a voice session."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            source_device_id=source_device_id,
            source_device_type=source_device_type,
            stream_id=stream_id,
            metadata=metadata,
            event_type=VoiceSessionEventType.DEVICE_CHANGED.value,
        )

    def set_status(
        self,
        session_id: str,
        status: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Set session status safely."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=status,
            metadata=metadata,
            event_type="status_updated",
        )

    def mark_listening(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Mark session as listening."""

        return self.set_status(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=VoiceSessionStatus.LISTENING.value,
            metadata={"state_reason": "listening_started"},
        )

    def mark_thinking(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        active_agent: Optional[str] = None,
        active_route: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark session as thinking and optionally store Master Agent route."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=VoiceSessionStatus.THINKING.value,
            active_agent=active_agent,
            active_route=active_route,
            metadata={"state_reason": "agent_processing"},
            event_type=VoiceSessionEventType.MASTER_AGENT_ROUTED.value,
        )

    def mark_speaking(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Mark session as speaking."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=VoiceSessionStatus.SPEAKING.value,
            metadata={"state_reason": "response_started"},
            event_type=VoiceSessionEventType.RESPONSE_STARTED.value,
        )

    def pause_session(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        reason: str = "manual_pause",
    ) -> Dict[str, Any]:
        """Pause session."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=VoiceSessionStatus.PAUSED.value,
            metadata={"pause_reason": reason},
            event_type=VoiceSessionEventType.SESSION_PAUSED.value,
        )

    def resume_session(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Resume paused session."""

        return self.update_session(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=VoiceSessionStatus.ACTIVE.value,
            metadata={"resume_reason": "manual_resume"},
            event_type=VoiceSessionEventType.SESSION_RESUMED.value,
        )

    # =========================================================================
    # Public API - Event Tracking
    # =========================================================================

    def record_user_speech(
        self,
        session_id: str,
        text: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        language: Optional[str] = None,
        topic: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record user speech activity.

        Raw text is not stored unless config.store_transcript_snippets=True.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(session_id)

                if not session:
                    return self._error_result(
                        message="Voice session not found.",
                        error="session_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Voice session does not belong to this user/workspace.",
                        error="session_scope_denied",
                        metadata={"context": context},
                    )

                old_status = session.status
                old_language = session.language
                old_topic = session.current_topic

                now = time.time()
                session.status = VoiceSessionStatus.LISTENING.value
                session.last_user_speech_at = now
                session.last_activity_at = now
                session.updated_at = now
                session.interaction_count += 1

                if language:
                    session.language = self._safe_language_code(language)
                    session.reply_language = session.reply_language or session.language

                if topic:
                    session.current_topic = self._safe_topic(topic)
                    session.last_topic_update_at = now

                safe_data = {
                    "text_present": bool(text),
                    "text_length": len(text) if isinstance(text, str) else 0,
                    "metadata": metadata or {},
                }

                if self.config.store_transcript_snippets and text:
                    safe_data["text_snippet"] = text[:240]

                self._append_event_locked(
                    session=session,
                    event_type=VoiceSessionEventType.USER_TEXT_CAPTURED.value,
                    status_before=old_status,
                    status_after=session.status,
                    language_before=old_language,
                    language_after=session.language,
                    topic_before=old_topic,
                    topic_after=session.current_topic,
                    data=safe_data,
                )

            self._emit_agent_event({
                "event": "voice.session.user_speech",
                "session_id": session_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "language": session.language,
                "topic": session.current_topic,
                "timestamp": time.time(),
            })

            return self._safe_result(
                message="User speech recorded successfully.",
                data={"session": session.to_dict()},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Record user speech failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def record_agent_response(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        response_text: Optional[str] = None,
        active_agent: Optional[str] = None,
        active_route: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record agent response completion.

        Raw response text is not stored unless config.store_transcript_snippets=True.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(session_id)

                if not session:
                    return self._error_result(
                        message="Voice session not found.",
                        error="session_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Voice session does not belong to this user/workspace.",
                        error="session_scope_denied",
                        metadata={"context": context},
                    )

                old_status = session.status
                now = time.time()

                session.status = VoiceSessionStatus.ACTIVE.value
                session.last_agent_response_at = now
                session.last_activity_at = now
                session.updated_at = now

                if active_agent:
                    session.active_agent = active_agent

                if active_route:
                    session.active_route = active_route

                safe_data = {
                    "response_present": bool(response_text),
                    "response_length": len(response_text) if isinstance(response_text, str) else 0,
                    "active_agent": active_agent,
                    "active_route": active_route,
                    "metadata": metadata or {},
                }

                if self.config.store_transcript_snippets and response_text:
                    safe_data["response_snippet"] = response_text[:240]

                self._append_event_locked(
                    session=session,
                    event_type=VoiceSessionEventType.RESPONSE_ENDED.value,
                    status_before=old_status,
                    status_after=session.status,
                    data=safe_data,
                )

            self._emit_agent_event({
                "event": "voice.session.agent_response",
                "session_id": session_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "active_agent": session.active_agent,
                "active_route": session.active_route,
                "timestamp": time.time(),
            })

            return self._safe_result(
                message="Agent response recorded successfully.",
                data={"session": session.to_dict()},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Record agent response failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def record_interruption(
        self,
        session_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        reason: str = "user_interruption",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record interruption event for interruption.py compatibility."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(session_id)

                if not session:
                    return self._error_result(
                        message="Voice session not found.",
                        error="session_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Voice session does not belong to this user/workspace.",
                        error="session_scope_denied",
                        metadata={"context": context},
                    )

                old_status = session.status
                now = time.time()

                session.status = VoiceSessionStatus.LISTENING.value
                session.interruption_count += 1
                session.last_activity_at = now
                session.updated_at = now

                self._append_event_locked(
                    session=session,
                    event_type=VoiceSessionEventType.INTERRUPTION_DETECTED.value,
                    status_before=old_status,
                    status_after=session.status,
                    data={
                        "reason": reason,
                        "metadata": metadata or {},
                    },
                )

            self._emit_agent_event({
                "event": "voice.session.interruption",
                "session_id": session_id,
                "reason": reason,
                "count": session.interruption_count,
                "timestamp": time.time(),
            })

            return self._safe_result(
                message="Interruption recorded successfully.",
                data={"session": session.to_dict()},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Record interruption failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def record_error(
        self,
        session_id: str,
        error: Union[str, Exception],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record session error safely."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
        }

        try:
            error_text = str(error)

            with self._lock:
                session = self._sessions.get(session_id)

                if not session:
                    return self._error_result(
                        message="Voice session not found.",
                        error="session_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Voice session does not belong to this user/workspace.",
                        error="session_scope_denied",
                        metadata={"context": context},
                    )

                old_status = session.status
                now = time.time()

                session.status = VoiceSessionStatus.ERROR.value
                session.error_count += 1
                session.last_activity_at = now
                session.updated_at = now
                session.metadata["last_error"] = error_text

                self._append_event_locked(
                    session=session,
                    event_type=VoiceSessionEventType.ERROR.value,
                    status_before=old_status,
                    status_after=session.status,
                    data={
                        "error": error_text,
                        "metadata": metadata or {},
                    },
                )

            self._log_audit_event(
                action="record_error",
                context=context,
                result_summary={
                    "session_id": session_id,
                    "error": error_text,
                    "error_count": session.error_count,
                },
            )

            return self._safe_result(
                message="Session error recorded successfully.",
                data={"session": session.to_dict()},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Record session error failed.",
                error=str(exc),
                metadata={"context": context},
            )

    # =========================================================================
    # Public API - Timeout / Cleanup
    # =========================================================================

    def check_timeouts(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        end_timed_out_sessions: bool = True,
    ) -> Dict[str, Any]:
        """
        Check sessions for idle/session/topic timeouts.

        Dashboard cron, Voice Loop, or Master Agent can call this periodically.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "end_timed_out_sessions": end_timed_out_sessions,
        }

        now = time.time()
        timed_out_sessions: List[Dict[str, Any]] = []
        topic_expired_sessions: List[Dict[str, Any]] = []

        try:
            with self._lock:
                for session in self._sessions.values():
                    if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                        continue

                    if not self._is_session_active_status(session.status):
                        continue

                    idle_age = now - session.last_activity_at
                    total_age = now - session.created_at

                    is_idle_timeout = idle_age >= self.config.idle_timeout_seconds
                    is_session_timeout = total_age >= self.config.session_timeout_seconds

                    if is_idle_timeout or is_session_timeout:
                        reason = SessionEndReason.TIMEOUT.value

                        if end_timed_out_sessions:
                            old_status = session.status
                            session.status = VoiceSessionStatus.TIMEOUT.value
                            session.ended_at = now
                            session.end_reason = reason
                            session.updated_at = now

                            self._append_event_locked(
                                session=session,
                                event_type="session_timeout",
                                status_before=old_status,
                                status_after=session.status,
                                data={
                                    "idle_age_seconds": round(idle_age, 3),
                                    "total_age_seconds": round(total_age, 3),
                                    "idle_timeout": is_idle_timeout,
                                    "session_timeout": is_session_timeout,
                                },
                            )

                        timed_out_sessions.append({
                            "session_id": session.session_id,
                            "idle_age_seconds": round(idle_age, 3),
                            "total_age_seconds": round(total_age, 3),
                            "idle_timeout": is_idle_timeout,
                            "session_timeout": is_session_timeout,
                            "status": session.status,
                        })

                    if session.current_topic and session.last_topic_update_at:
                        topic_age = now - session.last_topic_update_at
                        if topic_age >= self.config.topic_timeout_seconds:
                            old_topic = session.current_topic
                            session.current_topic = None
                            session.last_topic_update_at = None
                            session.updated_at = now

                            self._append_event_locked(
                                session=session,
                                event_type="topic_timeout",
                                topic_before=old_topic,
                                topic_after=None,
                                data={
                                    "topic_age_seconds": round(topic_age, 3),
                                },
                            )

                            topic_expired_sessions.append({
                                "session_id": session.session_id,
                                "expired_topic": old_topic,
                                "topic_age_seconds": round(topic_age, 3),
                            })

            if timed_out_sessions or topic_expired_sessions:
                self._emit_agent_event({
                    "event": "voice.session.timeouts_checked",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "timed_out_count": len(timed_out_sessions),
                    "topic_expired_count": len(topic_expired_sessions),
                    "timestamp": now,
                })

                self._log_audit_event(
                    action="check_timeouts",
                    context=context,
                    result_summary={
                        "timed_out_count": len(timed_out_sessions),
                        "topic_expired_count": len(topic_expired_sessions),
                    },
                )

            return self._safe_result(
                message="Voice session timeouts checked successfully.",
                data={
                    "timed_out_sessions": timed_out_sessions,
                    "topic_expired_sessions": topic_expired_sessions,
                    "timed_out_count": len(timed_out_sessions),
                    "topic_expired_count": len(topic_expired_sessions),
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Check voice session timeouts failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def cleanup_ended_sessions(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        older_than_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """
        Remove ended/timeout/error sessions from memory after retention window.

        This does not delete database records because this file is in-memory.
        Future persistence layer can archive before cleanup.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "older_than_seconds": older_than_seconds,
        }

        now = time.time()
        removed: List[str] = []

        try:
            with self._lock:
                for session_id, session in list(self._sessions.items()):
                    if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                        continue

                    if session.status not in {
                        VoiceSessionStatus.ENDED.value,
                        VoiceSessionStatus.TIMEOUT.value,
                        VoiceSessionStatus.ERROR.value,
                    }:
                        continue

                    reference_time = session.ended_at or session.updated_at or session.created_at
                    if now - reference_time >= older_than_seconds:
                        removed.append(session_id)
                        self._sessions.pop(session_id, None)

            if removed:
                self._emit_agent_event({
                    "event": "voice.session.cleanup",
                    "removed_session_ids": removed,
                    "removed_count": len(removed),
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "timestamp": now,
                })

            return self._safe_result(
                message="Ended voice sessions cleaned successfully.",
                data={
                    "removed_session_ids": removed,
                    "removed_count": len(removed),
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Cleanup ended voice sessions failed.",
                error=str(exc),
                metadata={"context": context},
            )

    # =========================================================================
    # Public API - Summary / Dashboard
    # =========================================================================

    def get_active_session(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        source_device_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get most recently active session for user/workspace/device.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_device_id": source_device_id,
        }

        try:
            with self._lock:
                candidates = []

                for session in self._sessions.values():
                    if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                        continue

                    if source_device_id and session.source_device_id != source_device_id:
                        continue

                    if not self._is_session_active_status(session.status):
                        continue

                    candidates.append(session)

                candidates.sort(key=lambda item: item.last_activity_at, reverse=True)

            if not candidates:
                return self._safe_result(
                    message="No active voice session found.",
                    data={"session": None},
                    metadata={"context": context},
                )

            return self._safe_result(
                message="Active voice session loaded successfully.",
                data={"session": candidates[0].to_dict()},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Get active voice session failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def get_session_summary(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Dashboard/API friendly summary of session counts and state.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
        }

        try:
            summary = {
                "total_sessions": 0,
                "active_sessions": 0,
                "ended_sessions": 0,
                "timeout_sessions": 0,
                "error_sessions": 0,
                "by_status": {},
                "by_language": {},
                "by_source_device_type": {},
                "current_topics": {},
            }

            with self._lock:
                for session in self._sessions.values():
                    if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                        continue

                    summary["total_sessions"] += 1

                    if self._is_session_active_status(session.status):
                        summary["active_sessions"] += 1

                    if session.status == VoiceSessionStatus.ENDED.value:
                        summary["ended_sessions"] += 1

                    if session.status == VoiceSessionStatus.TIMEOUT.value:
                        summary["timeout_sessions"] += 1

                    if session.status == VoiceSessionStatus.ERROR.value:
                        summary["error_sessions"] += 1

                    summary["by_status"][session.status] = summary["by_status"].get(session.status, 0) + 1
                    summary["by_language"][session.language] = summary["by_language"].get(session.language, 0) + 1
                    summary["by_source_device_type"][session.source_device_type] = (
                        summary["by_source_device_type"].get(session.source_device_type, 0) + 1
                    )

                    if session.current_topic:
                        summary["current_topics"][session.current_topic] = (
                            summary["current_topics"].get(session.current_topic, 0) + 1
                        )

            return self._safe_result(
                message="Voice session summary loaded successfully.",
                data={"summary": summary},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Get voice session summary failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def health_check(self) -> Dict[str, Any]:
        """Health check for Agent Registry / Dashboard."""

        with self._lock:
            total_sessions = len(self._sessions)
            active_sessions = sum(
                1 for session in self._sessions.values()
                if self._is_session_active_status(session.status)
            )

        return self._safe_result(
            message="VoiceSessionManager is healthy.",
            data={
                "status": "healthy",
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "supported_statuses": sorted(SAFE_PUBLIC_STATUSES),
                "supported_languages": SUPPORTED_LANGUAGE_CODES,
                "config": self.config.to_dict(),
            },
            metadata={
                "engine": self.agent_name,
                "module": self.agent_module,
                "version": self.VERSION,
                "file_path": self.file_path,
            },
        )

    # =========================================================================
    # BaseAgent-Compatible Run Method
    # =========================================================================

    def run(
        self,
        task: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generic BaseAgent-compatible runner.

        Expected task:
            {
                "action": "create_session" | "get_session" | "list_sessions"
                          | "update_session" | "end_session" | "check_timeouts"
                          | "get_active_session" | "get_session_summary"
                          | "health_check",
                "user_id": "...",
                "workspace_id": "...",
                ...
            }
        """

        task = task or {}
        action = task.get("action") or kwargs.get("action") or "health_check"

        payload = {**kwargs, **task}
        payload.pop("action", None)

        try:
            if action == "create_session":
                return self.create_session(**payload)

            if action == "get_session":
                return self.get_session(**payload)

            if action == "list_sessions":
                return self.list_sessions(**payload)

            if action == "update_session":
                return self.update_session(**payload)

            if action == "update_language":
                return self.update_language(**payload)

            if action == "update_topic":
                return self.update_topic(**payload)

            if action == "update_source_device":
                return self.update_source_device(**payload)

            if action == "record_user_speech":
                return self.record_user_speech(**payload)

            if action == "record_agent_response":
                return self.record_agent_response(**payload)

            if action == "record_interruption":
                return self.record_interruption(**payload)

            if action == "record_error":
                return self.record_error(**payload)

            if action == "pause_session":
                return self.pause_session(**payload)

            if action == "resume_session":
                return self.resume_session(**payload)

            if action == "end_session":
                return self.end_session(**payload)

            if action == "check_timeouts":
                return self.check_timeouts(**payload)

            if action == "cleanup_ended_sessions":
                return self.cleanup_ended_sessions(**payload)

            if action == "get_active_session":
                return self.get_active_session(**payload)

            if action == "get_session_summary":
                return self.get_session_summary(**payload)

            if action == "health_check":
                return self.health_check()

            return self._error_result(
                message=f"Unsupported VoiceSessionManager action: {action}",
                error="unsupported_action",
                metadata={"action": action},
            )

        except TypeError as exc:
            return self._error_result(
                message="Invalid arguments for VoiceSessionManager action.",
                error=str(exc),
                metadata={
                    "action": action,
                    "payload_keys": sorted(payload.keys()),
                },
            )
        except Exception as exc:
            self.logger.exception("VoiceSessionManager run failed")
            return self._error_result(
                message="VoiceSessionManager run failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _append_event_locked(
        self,
        session: VoiceSession,
        event_type: str,
        status_before: Optional[str] = None,
        status_after: Optional[str] = None,
        language_before: Optional[str] = None,
        language_after: Optional[str] = None,
        topic_before: Optional[str] = None,
        topic_after: Optional[str] = None,
        source_device_before: Optional[str] = None,
        source_device_after: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Append event while caller holds self._lock.
        """

        event = VoiceSessionEvent(
            event_id=self._generate_event_id(session.session_id),
            event_type=event_type,
            timestamp=time.time(),
            status_before=status_before,
            status_after=status_after,
            language_before=language_before,
            language_after=language_after,
            topic_before=topic_before,
            topic_after=topic_after,
            source_device_before=source_device_before,
            source_device_after=source_device_after,
            data=data or {},
        )

        session.events.append(event)

        if len(session.events) > self.config.max_events_per_session:
            session.events = session.events[-self.config.max_events_per_session:]

    def _validate_active_session_limit(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
    ) -> Dict[str, Any]:
        """Prevent one user/workspace from creating too many active sessions."""

        with self._lock:
            active_count = 0
            for session in self._sessions.values():
                if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                    continue

                if self._is_session_active_status(session.status):
                    active_count += 1

        if active_count >= self.config.max_active_sessions_per_user:
            return self._error_result(
                message="Maximum active voice sessions reached for this user/workspace.",
                error="active_session_limit_reached",
                metadata={
                    "active_count": active_count,
                    "max_active_sessions_per_user": self.config.max_active_sessions_per_user,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        return self._safe_result(
            message="Active session limit validated.",
            data={"active_count": active_count},
        )

    def _safe_language_code(self, language_code: Optional[str]) -> str:
        """Normalize supported language codes."""

        if not language_code:
            return "unknown"

        normalized = str(language_code).strip().lower().replace("-", "_")

        aliases = {
            "english": "en",
            "eng": "en",
            "en": "en",
            "roman": "roman_urdu",
            "romanurdu": "roman_urdu",
            "roman_urdu": "roman_urdu",
            "urdu_roman": "roman_urdu",
            "urdu": "ur",
            "ur": "ur",
            "hindi": "hi",
            "hi": "hi",
            "arabic": "ar",
            "ar": "ar",
            "mixed": "mixed",
            "auto": "unknown",
            "unknown": "unknown",
        }

        return aliases.get(normalized, "unknown")

    def _safe_source_device_type(self, source_device_type: Optional[str]) -> str:
        """Normalize source device type."""

        if not source_device_type:
            return VoiceSessionSource.UNKNOWN.value

        normalized = str(source_device_type).strip().lower()

        for item in VoiceSessionSource:
            if item.value == normalized:
                return item.value

        return VoiceSessionSource.UNKNOWN.value

    def _safe_status(self, status: Optional[str]) -> str:
        """Normalize session status."""

        if not status:
            return VoiceSessionStatus.ACTIVE.value

        normalized = str(status).strip().lower()

        if normalized in SAFE_PUBLIC_STATUSES:
            return normalized

        return VoiceSessionStatus.ACTIVE.value

    def _safe_topic(self, topic: Optional[str]) -> Optional[str]:
        """Sanitize topic text."""

        if topic is None:
            return None

        safe = str(topic).strip()

        if not safe:
            return None

        return safe[:180]

    def _same_saas_scope(
        self,
        session_user_id: Optional[Union[str, int]],
        session_workspace_id: Optional[Union[str, int]],
        requested_user_id: Optional[Union[str, int]],
        requested_workspace_id: Optional[Union[str, int]],
    ) -> bool:
        """
        Strict user/workspace isolation.

        If session has user_id/workspace_id, caller must match it.
        If caller has no IDs during local tests, only unscoped sessions match.
        """

        return (
            self._scope_value(session_user_id) == self._scope_value(requested_user_id)
            and self._scope_value(session_workspace_id) == self._scope_value(requested_workspace_id)
        )

    def _scope_value(self, value: Optional[Union[str, int]]) -> str:
        if value is None:
            return "__none__"
        return str(value).strip()

    def _is_session_active_status(self, status: str) -> bool:
        return status in {
            VoiceSessionStatus.CREATED.value,
            VoiceSessionStatus.ACTIVE.value,
            VoiceSessionStatus.LISTENING.value,
            VoiceSessionStatus.THINKING.value,
            VoiceSessionStatus.SPEAKING.value,
            VoiceSessionStatus.PAUSED.value,
            VoiceSessionStatus.IDLE.value,
        }

    def _generate_session_id(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
    ) -> str:
        user_part = str(user_id) if user_id is not None else "local"
        workspace_part = str(workspace_id) if workspace_id is not None else "default"
        safe_user = "".join(ch for ch in user_part if ch.isalnum() or ch in ("-", "_"))[:24]
        safe_workspace = "".join(ch for ch in workspace_part if ch.isalnum() or ch in ("-", "_"))[:24]
        return f"voice_session_{safe_user}_{safe_workspace}_{uuid.uuid4().hex[:16]}"

    def _generate_event_id(self, session_id: str) -> str:
        safe_session = "".join(ch for ch in session_id if ch.isalnum() or ch in ("-", "_"))[-24:]
        return f"voice_event_{safe_session}_{uuid.uuid4().hex[:12]}"

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        This manager allows local unscoped testing, but whenever user_id or
        workspace_id is present, both are preserved and enforced.
        """

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is not None and str(user_id).strip() == "":
            return self._error_result(
                message="Invalid user_id.",
                error="invalid_user_id",
                metadata={"context": context},
            )

        if workspace_id is not None and str(workspace_id).strip() == "":
            return self._error_result(
                message="Invalid workspace_id.",
                error="invalid_workspace_id",
                metadata={"context": context},
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context_valid": True},
            metadata={"context": context},
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Session state updates are normally safe.

        Sensitive admin/export/delete actions should go through Security Agent.
        """

        return action in SENSITIVE_SESSION_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.
        """

        context = context or {}
        metadata = metadata or {}

        if self.security_client and hasattr(self.security_client, "approve"):
            try:
                approval = self.security_client.approve(
                    action=action,
                    context=context,
                    metadata=metadata,
                )
                if isinstance(approval, dict):
                    return approval
            except Exception as exc:
                self.logger.warning("Security approval failed: %s", exc)
                return {
                    "approved": False,
                    "reason": "security_client_error",
                    "error": str(exc),
                }

        if not self._requires_security_check(action, context):
            return {
                "approved": True,
                "reason": "non_sensitive_session_manager_action",
            }

        return {
            "approved": False,
            "reason": "security_client_unavailable_for_sensitive_action",
        }

    def _prepare_verification_payload(
        self,
        action: str,
        result: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        if not self.config.verification_enabled:
            return {
                "enabled": False,
                "reason": "verification_disabled",
            }

        payload = {
            "enabled": True,
            "agent": self.agent_name,
            "module": self.agent_module,
            "file_path": self.file_path,
            "action": action,
            "context": context or {},
            "result_summary": {
                "session_id": result.get("session_id"),
                "status": result.get("status"),
                "language": result.get("language"),
                "reply_language": result.get("reply_language"),
                "current_topic": result.get("current_topic"),
                "source_device_id": result.get("source_device_id"),
                "source_device_type": result.get("source_device_type"),
            },
            "verification_checks": [
                "session_id_present",
                "saas_scope_preserved",
                "status_valid",
                "language_tracked",
                "device_source_tracked",
                "timestamps_present",
            ],
            "created_at": time.time(),
        }

        if self.verification_client and hasattr(self.verification_client, "prepare"):
            try:
                prepared = self.verification_client.prepare(payload)
                if isinstance(prepared, dict):
                    return prepared
            except Exception as exc:
                self.logger.warning("Verification payload preparation failed: %s", exc)
                payload["verification_client_error"] = str(exc)

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        session: VoiceSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This stores useful preference/session summary signals only.
        It does not store private raw transcript by default.
        """

        if not self.config.memory_enabled:
            return {
                "enabled": False,
                "reason": "memory_disabled",
            }

        context = context or {}

        payload = {
            "enabled": True,
            "agent": self.agent_name,
            "module": self.agent_module,
            "memory_type": "voice_session_signal",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "session_id": session.session_id,
            "action": action,
            "data": {
                "language": session.language,
                "reply_language": session.reply_language,
                "current_topic": session.current_topic,
                "source_device_type": session.source_device_type,
                "interaction_count": session.interaction_count,
                "interruption_count": session.interruption_count,
                "error_count": session.error_count,
                "active_agent": session.active_agent,
                "active_route": session.active_route,
                "end_reason": session.end_reason,
            },
            "privacy": {
                "stores_raw_text": False,
                "cross_user_allowed": False,
                "cross_workspace_allowed": False,
            },
            "created_at": time.time(),
        }

        if self.memory_client and hasattr(self.memory_client, "prepare"):
            try:
                prepared = self.memory_client.prepare(payload)
                if isinstance(prepared, dict):
                    return prepared
            except Exception as exc:
                self.logger.warning("Memory payload preparation failed: %s", exc)
                payload["memory_client_error"] = str(exc)

        return payload

    def _emit_agent_event(self, payload: Dict[str, Any]) -> None:
        """
        Emit event for Dashboard/API analytics or Agent Registry.
        """

        if not self.config.emit_events:
            return

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(payload)
                return

            self.logger.debug("VoiceSessionManager event: %s", payload)

        except Exception as exc:
            self.logger.warning("Failed to emit VoiceSessionManager event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        result_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event without crossing user/workspace boundaries.
        """

        if not self.config.audit_enabled:
            return

        payload = {
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "context": context or {},
            "result_summary": result_summary or {},
            "timestamp": time.time(),
        }

        try:
            if self.audit_client and hasattr(self.audit_client, "log"):
                self.audit_client.log(payload)
                return

            self.logger.debug("VoiceSessionManager audit: %s", payload)

        except Exception as exc:
            self.logger.warning("Failed to log VoiceSessionManager audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis success result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "unknown_error",
            "metadata": metadata or {},
        }


# =============================================================================
# Local Manual Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    manager = VoiceSessionManager()

    created = manager.create_session(
        user_id="local_user",
        workspace_id="main_workspace",
        source_device_id="desktop_mic_001",
        source_device_type="desktop",
        language="roman_urdu",
        reply_language="roman_urdu",
        current_topic="William voice agent testing",
        wake_word="William",
    )

    print("CREATE:")
    print(created)

    session_id = created["data"]["session"]["session_id"]

    print("\nUSER SPEECH:")
    print(manager.record_user_speech(
        session_id=session_id,
        user_id="local_user",
        workspace_id="main_workspace",
        text="bhai mujhe full final file do",
        language="roman_urdu",
        topic="Voice Agent Session Manager",
    ))

    print("\nTHINKING:")
    print(manager.mark_thinking(
        session_id=session_id,
        user_id="local_user",
        workspace_id="main_workspace",
        active_agent="MasterAgent",
        active_route="voice_agent.session_manager",
    ))

    print("\nAGENT RESPONSE:")
    print(manager.record_agent_response(
        session_id=session_id,
        user_id="local_user",
        workspace_id="main_workspace",
        response_text="Here is your full final file.",
        active_agent="VoiceAgent",
        active_route="voice_agent.session_manager",
    ))

    print("\nSUMMARY:")
    print(manager.get_session_summary(
        user_id="local_user",
        workspace_id="main_workspace",
    ))

    print("\nEND:")
    print(manager.end_session(
        session_id=session_id,
        user_id="local_user",
        workspace_id="main_workspace",
    ))

"""
Agent/Module: Voice Agent
File Completed: session_manager.py
Completion: 45.0%
Completed Files: ['voice_agent.py', 'wake_word.py', 'stt_engine.py', 'tts_engine.py', 'language_engine.py', 'device_stream.py', 'interruption.py', 'voice_loop.py', 'session_manager.py']
Remaining Files: ['audio_router.py', 'noise_control.py', 'speaker_recognition.py', 'emotion_detector.py', 'whisper_mode.py', 'voice_profiles.py', 'voice_cloning.py', 'gesture_trigger.py', 'conversation_mode.py', 'voice_memory.py', 'config.py']
Next Recommended File: agents/voice_agent/audio_router.py
FILE COMPLETE
"""