"""
agents/super_agents/call_agent/call_transcriber.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Call Agent - Permission-based call STT/transcription and live note taking.

Purpose:
    Provides safe, permission-based call speech-to-text transcription and live
    note-taking for Call Agent workflows.

Core responsibilities:
    - Start/end transcription sessions for calls.
    - Enforce user_id/workspace_id SaaS isolation.
    - Require explicit transcription permission/consent before handling call audio.
    - Route sensitive transcription activity through Security Agent hooks.
    - Accept text chunks, audio bytes, or provider-ready audio references.
    - Support pluggable STT providers without hardcoding vendor secrets.
    - Maintain live notes, transcript segments, speaker labels, and metadata.
    - Prepare Verification Agent payloads after completed transcription actions.
    - Prepare Memory Agent-compatible payloads without leaking raw audio.
    - Provide dashboard/API-friendly structured results.

Import safety:
    This file uses safe optional imports and fallback stubs so it can be imported
    even before the rest of William/Jarvis is fully implemented.

Important:
    This module does not directly record calls, place calls, send messages,
    access microphones, or invoke external paid STT APIs by default. External
    transcription must be provided through an injected `stt_provider`.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import inspect
import logging
import re
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# =============================================================================
# Optional William/Jarvis imports with safe fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent can provide registry, router,
        telemetry, permission, and lifecycle features. This fallback keeps this
        file import-safe during early module generation.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "call")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s", payload)


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums and data structures
# =============================================================================

class TranscriptionPermissionStatus(str, enum.Enum):
    """Permission state for call transcription."""

    GRANTED = "granted"
    DENIED = "denied"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class TranscriptionSessionStatus(str, enum.Enum):
    """Lifecycle status for a live transcription session."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class TranscriptSourceType(str, enum.Enum):
    """Input type for transcription."""

    TEXT = "text"
    AUDIO_BYTES = "audio_bytes"
    AUDIO_REFERENCE = "audio_reference"


class SpeakerRole(str, enum.Enum):
    """Safe speaker roles used in live notes and transcript segments."""

    AGENT = "agent"
    CUSTOMER = "customer"
    UNKNOWN = "unknown"
    SYSTEM = "system"


class SensitivityLevel(str, enum.Enum):
    """Security sensitivity level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclasses.dataclass
class TranscriptionConfig:
    """
    Configuration for CallTranscriber.

    retain_raw_audio:
        Should remain False by default. This file does not store raw audio unless
        explicitly enabled by the application layer.

    redact_sensitive_data:
        Redacts common sensitive patterns from notes/transcripts.

    require_consent:
        If True, session creation requires explicit consent/permission payload.

    max_segments_per_session:
        Protects memory usage for import-safe in-memory runtime.

    default_language:
        Default STT language hint.

    enable_live_notes:
        Enables live note extraction from transcript chunks.
    """

    retain_raw_audio: bool = False
    redact_sensitive_data: bool = True
    require_consent: bool = True
    max_segments_per_session: int = 2000
    max_notes_per_session: int = 1000
    default_language: str = "en"
    enable_live_notes: bool = True
    min_note_confidence: float = 0.0


@dataclasses.dataclass
class ConsentRecord:
    """
    Permission/consent record for transcription.

    consent_text:
        A statement shown/spoken to the call participant.

    granted_by:
        Person/system granting permission. Example: "customer", "agent", "system".

    jurisdiction:
        Optional region/country/state for dashboard/legal workflow. This module
        does not determine law; it stores provided metadata.
    """

    status: TranscriptionPermissionStatus
    granted_by: Optional[str] = None
    consent_text: Optional[str] = None
    granted_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    jurisdiction: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "granted_by": self.granted_by,
            "consent_text": self.consent_text,
            "granted_at": _dt_to_iso(self.granted_at),
            "revoked_at": _dt_to_iso(self.revoked_at),
            "jurisdiction": self.jurisdiction,
            "metadata": copy.deepcopy(self.metadata),
        }


@dataclasses.dataclass
class TranscriptSegment:
    """One transcript segment or live chunk."""

    segment_id: str
    session_id: str
    call_id: str
    user_id: str
    workspace_id: str
    speaker: SpeakerRole
    text: str
    clean_text: str
    source_type: TranscriptSourceType
    confidence: Optional[float]
    language: str
    started_at_seconds: Optional[float]
    ended_at_seconds: Optional[float]
    created_at: datetime
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "segment_id": self.segment_id,
            "session_id": self.session_id,
            "call_id": self.call_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "speaker": self.speaker.value,
            "text": self.text,
            "clean_text": self.clean_text,
            "source_type": self.source_type.value,
            "confidence": self.confidence,
            "language": self.language,
            "started_at_seconds": self.started_at_seconds,
            "ended_at_seconds": self.ended_at_seconds,
            "created_at": _dt_to_iso(self.created_at),
            "metadata": copy.deepcopy(self.metadata),
        }


@dataclasses.dataclass
class LiveNote:
    """A live note extracted during a call."""

    note_id: str
    session_id: str
    call_id: str
    user_id: str
    workspace_id: str
    note_type: str
    text: str
    speaker: SpeakerRole
    confidence: float
    created_at: datetime
    source_segment_id: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "session_id": self.session_id,
            "call_id": self.call_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "note_type": self.note_type,
            "text": self.text,
            "speaker": self.speaker.value,
            "confidence": self.confidence,
            "created_at": _dt_to_iso(self.created_at),
            "source_segment_id": self.source_segment_id,
            "metadata": copy.deepcopy(self.metadata),
        }


@dataclasses.dataclass
class TranscriptionSession:
    """Live call transcription session."""

    session_id: str
    call_id: str
    user_id: str
    workspace_id: str
    status: TranscriptionSessionStatus
    consent: ConsentRecord
    language: str
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    title: Optional[str] = None
    participants: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    segments: List[TranscriptSegment] = dataclasses.field(default_factory=list)
    notes: List[LiveNote] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(
        self,
        *,
        include_segments: bool = True,
        include_notes: bool = True,
    ) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "call_id": self.call_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": self.status.value,
            "consent": self.consent.to_dict(),
            "language": self.language,
            "created_at": _dt_to_iso(self.created_at),
            "updated_at": _dt_to_iso(self.updated_at),
            "started_at": _dt_to_iso(self.started_at),
            "ended_at": _dt_to_iso(self.ended_at),
            "title": self.title,
            "participants": copy.deepcopy(self.participants),
            "segments": [segment.to_dict() for segment in self.segments] if include_segments else [],
            "notes": [note.to_dict() for note in self.notes] if include_notes else [],
            "metadata": copy.deepcopy(self.metadata),
            "error": self.error,
            "segment_count": len(self.segments),
            "note_count": len(self.notes),
        }


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def _dt_to_iso(value: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO 8601 string."""

    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: Union[str, datetime, None]) -> Optional[datetime]:
    """Parse datetime string/object into UTC-aware datetime."""

    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
    else:
        raise TypeError("Expected datetime, ISO datetime string, or None.")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _safe_deepcopy(value: Any) -> Any:
    """Safely deepcopy values for result payloads."""

    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _hash_bytes(data: bytes) -> str:
    """Return SHA256 hash for audio bytes without storing the raw audio."""

    return hashlib.sha256(data).hexdigest()


def _call_maybe_async_unsafe(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """
    Call a function and run coroutine result when possible.

    If already inside an event loop, the coroutine object is returned. The
    application layer can await it.
    """

    result = func(*args, **kwargs)
    if inspect.isawaitable(result):
        try:
            import asyncio

            try:
                asyncio.get_running_loop()
                return result
            except RuntimeError:
                return asyncio.run(result)
        except Exception:
            return result
    return result


def _normalize_speaker(value: Optional[Union[str, SpeakerRole]]) -> SpeakerRole:
    """Normalize speaker labels."""

    if isinstance(value, SpeakerRole):
        return value

    if not value:
        return SpeakerRole.UNKNOWN

    raw = str(value).strip().lower()
    aliases = {
        "agent": SpeakerRole.AGENT,
        "assistant": SpeakerRole.AGENT,
        "rep": SpeakerRole.AGENT,
        "sales": SpeakerRole.AGENT,
        "customer": SpeakerRole.CUSTOMER,
        "client": SpeakerRole.CUSTOMER,
        "caller": SpeakerRole.CUSTOMER,
        "lead": SpeakerRole.CUSTOMER,
        "system": SpeakerRole.SYSTEM,
    }
    return aliases.get(raw, SpeakerRole.UNKNOWN)


def _safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """Convert value to float safely."""

    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _safe_str(value: Any) -> str:
    """Convert any value to safe string."""

    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


# =============================================================================
# CallTranscriber
# =============================================================================

class CallTranscriber(BaseAgent):
    """
    Permission-based call STT/transcription and live note-taking helper.

    Master Agent connection:
        Master Agent can route call transcription requests to:
            - start_transcription_session()
            - transcribe_audio_chunk()
            - add_text_chunk()
            - add_live_note()
            - end_transcription_session()

    Security Agent connection:
        Starting transcription requires a security/permission check. Sensitive
        call data should be approved by Security Agent before processing.

    Memory Agent connection:
        Completed session summaries and notes are prepared through
        _prepare_memory_payload() without raw audio.

    Verification Agent connection:
        Every completed transcription action prepares a verification payload
        through _prepare_verification_payload().

    Dashboard/API connection:
        Every public method returns structured dict results:
            success, message, data, error, metadata

    Registry/Loader compatibility:
        Required class name: CallTranscriber
        get_agent() factory is provided at the bottom.
    """

    agent_name = "call_transcriber"
    agent_type = "call"
    public_methods = [
        "start_transcription_session",
        "grant_transcription_permission",
        "revoke_transcription_permission",
        "pause_transcription_session",
        "resume_transcription_session",
        "transcribe_audio_chunk",
        "add_text_chunk",
        "add_live_note",
        "get_transcription_session",
        "list_transcription_sessions",
        "get_transcript",
        "get_live_notes",
        "end_transcription_session",
        "cancel_transcription_session",
        "health_check",
    ]

    def __init__(
        self,
        *,
        stt_provider: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        config: Optional[Union[TranscriptionConfig, Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type=self.agent_type, **kwargs)

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        if isinstance(config, TranscriptionConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = TranscriptionConfig(**config)
        else:
            self.config = TranscriptionConfig()

        self.stt_provider = stt_provider
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self._sessions: Dict[str, TranscriptionSession] = {}
        self._call_to_session: Dict[Tuple[str, str, str], str] = {}
        self._lock = threading.RLock()

    # -------------------------------------------------------------------------
    # Public session methods
    # -------------------------------------------------------------------------

    def start_transcription_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        consent: Optional[Union[ConsentRecord, Dict[str, Any]]] = None,
        title: Optional[str] = None,
        participants: Optional[List[Dict[str, Any]]] = None,
        language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Start a permission-based call transcription session.

        A session can only start when:
            - user_id/workspace_id/call_id are valid
            - consent is granted, unless config.require_consent is False
            - Security Agent approves, if required
        """

        try:
            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                call_id=call_id,
            )
            if not context_result["success"]:
                return context_result

            consent_record = self._normalize_consent(consent)

            if self.config.require_consent and consent_record.status != TranscriptionPermissionStatus.GRANTED:
                return self._error_result(
                    message="Transcription permission is required before starting call transcription.",
                    error="transcription_permission_required",
                    data={"consent": consent_record.to_dict()},
                    metadata={"method": "start_transcription_session"},
                )

            now = _utc_now()
            session = TranscriptionSession(
                session_id=str(uuid.uuid4()),
                call_id=call_id.strip(),
                user_id=user_id.strip(),
                workspace_id=workspace_id.strip(),
                status=TranscriptionSessionStatus.ACTIVE,
                consent=consent_record,
                language=language or self.config.default_language,
                created_at=now,
                updated_at=now,
                started_at=now,
                title=title,
                participants=_safe_deepcopy(participants or []),
                metadata=_safe_deepcopy(metadata or {}),
            )

            if require_security_approval or self._requires_security_check(
                action="start_transcription_session",
                session=session,
                sensitivity_level=SensitivityLevel.HIGH,
            ):
                approval = self._request_security_approval(
                    action="start_transcription_session",
                    session=session,
                    reason="Call transcription processes sensitive call audio/text and requires permission approval.",
                    sensitivity_level=SensitivityLevel.HIGH,
                )
                if not approval.get("success"):
                    return self._error_result(
                        message="Security approval denied or unavailable for call transcription.",
                        error=approval.get("error") or "security_approval_failed",
                        data={
                            "security_approval": approval.get("data", {}),
                            "session_preview": session.to_dict(include_segments=False, include_notes=False),
                        },
                        metadata={"method": "start_transcription_session"},
                    )

            with self._lock:
                key = (session.user_id, session.workspace_id, session.call_id)
                existing_id = self._call_to_session.get(key)
                if existing_id:
                    existing = self._sessions.get(existing_id)
                    if existing and existing.status in {
                        TranscriptionSessionStatus.ACTIVE,
                        TranscriptionSessionStatus.PAUSED,
                    }:
                        return self._safe_result(
                            message="An active transcription session already exists for this call.",
                            data={"session": existing.to_dict()},
                            metadata={"method": "start_transcription_session", "existing": True},
                        )

                self._sessions[session.session_id] = session
                self._call_to_session[key] = session.session_id

            self._log_audit_event(
                "call_transcription_session_started",
                session=session,
                extra={"consent_status": consent_record.status.value},
            )
            self._emit_agent_event(
                "call.transcriber.session.started",
                {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "user_id": session.user_id,
                    "workspace_id": session.workspace_id,
                    "language": session.language,
                },
            )

            memory_payload = self._prepare_memory_payload(
                event_type="transcription_session_started",
                session=session,
                segment=None,
                note=None,
                final=False,
            )
            verification_payload = self._prepare_verification_payload(
                event_type="transcription_session_started",
                session=session,
                result={"success": True, "message": "Transcription session started."},
            )

            self._send_to_memory_agent(memory_payload)
            self._send_to_verification_agent(verification_payload)

            return self._safe_result(
                message="Call transcription session started successfully.",
                data={
                    "session": session.to_dict(),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata={"method": "start_transcription_session"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="start_transcription_session")

    def grant_transcription_permission(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        granted_by: str,
        consent_text: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a granted consent record.

        This can be used before calling start_transcription_session().
        """

        try:
            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                call_id=call_id,
            )
            if not context_result["success"]:
                return context_result

            consent = ConsentRecord(
                status=TranscriptionPermissionStatus.GRANTED,
                granted_by=granted_by,
                consent_text=consent_text,
                granted_at=_utc_now(),
                jurisdiction=jurisdiction,
                metadata=_safe_deepcopy(metadata or {}),
            )

            self._emit_agent_event(
                "call.transcriber.permission.granted",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "call_id": call_id,
                    "granted_by": granted_by,
                    "jurisdiction": jurisdiction,
                },
            )
            self._log_audit_event(
                "call_transcription_permission_granted",
                session=None,
                extra={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "call_id": call_id,
                    "granted_by": granted_by,
                    "jurisdiction": jurisdiction,
                },
            )

            return self._safe_result(
                message="Transcription permission granted.",
                data={"consent": consent.to_dict()},
                metadata={"method": "grant_transcription_permission"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="grant_transcription_permission")

    def revoke_transcription_permission(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: Optional[str] = None,
        call_id: Optional[str] = None,
        revoked_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Revoke transcription permission and pause/cancel active session.

        If session_id is not provided, call_id can be used.
        """

        try:
            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                call_id=call_id or session_id or "unknown",
            )
            if not context_result["success"]:
                return context_result

            session = self._find_session(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                call_id=call_id,
            )
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "revoke_transcription_permission"},
                )

            with self._lock:
                session.consent.status = TranscriptionPermissionStatus.REVOKED
                session.consent.revoked_at = _utc_now()
                session.consent.metadata["revoked_by"] = revoked_by
                session.consent.metadata["revoke_reason"] = reason
                if session.status == TranscriptionSessionStatus.ACTIVE:
                    session.status = TranscriptionSessionStatus.PAUSED
                session.updated_at = _utc_now()

            self._log_audit_event(
                "call_transcription_permission_revoked",
                session=session,
                extra={"revoked_by": revoked_by, "reason": reason},
            )
            self._emit_agent_event(
                "call.transcriber.permission.revoked",
                {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "revoked_by": revoked_by,
                },
            )

            return self._safe_result(
                message="Transcription permission revoked. Session paused.",
                data={"session": session.to_dict()},
                metadata={"method": "revoke_transcription_permission"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="revoke_transcription_permission")

    def pause_transcription_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pause an active transcription session."""

        return self._set_session_status(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            status=TranscriptionSessionStatus.PAUSED,
            message="Transcription session paused.",
            event_name="call.transcriber.session.paused",
            method="pause_transcription_session",
            reason=reason,
        )

    def resume_transcription_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
    ) -> Dict[str, Any]:
        """Resume a paused transcription session if permission remains granted."""

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "resume_transcription_session"},
                )

            if session.consent.status != TranscriptionPermissionStatus.GRANTED:
                return self._error_result(
                    message="Cannot resume transcription because permission is not granted.",
                    error="transcription_permission_not_granted",
                    data={"consent": session.consent.to_dict()},
                    metadata={"method": "resume_transcription_session"},
                )

            with self._lock:
                if session.status != TranscriptionSessionStatus.PAUSED:
                    return self._error_result(
                        message=f"Only paused sessions can be resumed. Current status: {session.status.value}",
                        error="invalid_session_status",
                        metadata={"method": "resume_transcription_session"},
                    )
                session.status = TranscriptionSessionStatus.ACTIVE
                session.updated_at = _utc_now()

            self._log_audit_event("call_transcription_session_resumed", session=session)
            self._emit_agent_event(
                "call.transcriber.session.resumed",
                {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

            return self._safe_result(
                message="Transcription session resumed.",
                data={"session": session.to_dict()},
                metadata={"method": "resume_transcription_session"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="resume_transcription_session")

    def end_transcription_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        final_notes: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        End a transcription session and prepare final memory/verification payloads.
        """

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "end_transcription_session"},
                )

            if final_notes:
                for note_payload in final_notes:
                    self._append_live_note(
                        session=session,
                        text=_safe_str(note_payload.get("text")),
                        note_type=_safe_str(note_payload.get("note_type") or "final_note"),
                        speaker=_normalize_speaker(note_payload.get("speaker")),
                        confidence=_safe_float(note_payload.get("confidence"), 1.0) or 1.0,
                        source_segment_id=note_payload.get("source_segment_id"),
                        metadata=note_payload.get("metadata") or {},
                    )

            with self._lock:
                session.status = TranscriptionSessionStatus.COMPLETED
                session.ended_at = _utc_now()
                session.updated_at = _utc_now()
                if metadata:
                    session.metadata.update(_safe_deepcopy(metadata))

            transcript_text = self._build_transcript_text(session)
            summary = self._build_lightweight_summary(session)

            result = {
                "success": True,
                "message": "Transcription session completed.",
                "data": {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "segment_count": len(session.segments),
                    "note_count": len(session.notes),
                    "summary": summary,
                },
            }

            memory_payload = self._prepare_memory_payload(
                event_type="transcription_session_completed",
                session=session,
                segment=None,
                note=None,
                final=True,
                extra={"summary": summary},
            )
            verification_payload = self._prepare_verification_payload(
                event_type="transcription_session_completed",
                session=session,
                result=result,
            )

            self._send_to_memory_agent(memory_payload)
            self._send_to_verification_agent(verification_payload)

            self._log_audit_event("call_transcription_session_completed", session=session)
            self._emit_agent_event(
                "call.transcriber.session.completed",
                {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "segment_count": len(session.segments),
                    "note_count": len(session.notes),
                },
            )

            return self._safe_result(
                message="Transcription session ended successfully.",
                data={
                    "session": session.to_dict(),
                    "transcript_text": transcript_text,
                    "summary": summary,
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata={"method": "end_transcription_session"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="end_transcription_session")

    def cancel_transcription_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a transcription session."""

        return self._set_session_status(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            status=TranscriptionSessionStatus.CANCELLED,
            message="Transcription session cancelled.",
            event_name="call.transcriber.session.cancelled",
            method="cancel_transcription_session",
            reason=reason,
            end_session=True,
        )

    # -------------------------------------------------------------------------
    # Public transcription / note methods
    # -------------------------------------------------------------------------

    def transcribe_audio_chunk(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        audio_bytes: Optional[bytes] = None,
        audio_reference: Optional[str] = None,
        speaker: Optional[Union[str, SpeakerRole]] = None,
        language: Optional[str] = None,
        started_at_seconds: Optional[float] = None,
        ended_at_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Transcribe an audio chunk through an injected STT provider.

        Supported provider interfaces:
            - transcribe(payload)
            - transcribe_audio(payload)
            - speech_to_text(payload)
            - __call__(payload)

        If no provider exists, this returns a safe error and does not attempt
        external STT.
        """

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "transcribe_audio_chunk"},
                )

            active_result = self._ensure_session_can_accept_transcription(session)
            if not active_result["success"]:
                return active_result

            if audio_bytes is None and not audio_reference:
                return self._error_result(
                    message="audio_bytes or audio_reference is required.",
                    error="missing_audio_input",
                    metadata={"method": "transcribe_audio_chunk"},
                )

            if audio_bytes is not None and not isinstance(audio_bytes, (bytes, bytearray)):
                return self._error_result(
                    message="audio_bytes must be bytes or bytearray.",
                    error="invalid_audio_bytes",
                    metadata={"method": "transcribe_audio_chunk"},
                )

            if self._requires_security_check(
                action="transcribe_audio_chunk",
                session=session,
                sensitivity_level=SensitivityLevel.HIGH,
            ):
                approval = self._request_security_approval(
                    action="transcribe_audio_chunk",
                    session=session,
                    reason="Audio transcription chunk contains sensitive call data.",
                    sensitivity_level=SensitivityLevel.HIGH,
                )
                if not approval.get("success"):
                    return self._error_result(
                        message="Security approval denied or unavailable for audio transcription chunk.",
                        error=approval.get("error") or "security_approval_failed",
                        data={"security_approval": approval.get("data", {})},
                        metadata={"method": "transcribe_audio_chunk"},
                    )

            provider_result = self._call_stt_provider(
                audio_bytes=bytes(audio_bytes) if audio_bytes is not None else None,
                audio_reference=audio_reference,
                language=language or session.language,
                metadata=metadata or {},
                session=session,
            )

            if not provider_result.get("success"):
                return provider_result

            transcription_data = provider_result.get("data", {})
            text = _safe_str(transcription_data.get("text") or transcription_data.get("transcript"))
            confidence = _safe_float(transcription_data.get("confidence"), None)

            if not text.strip():
                return self._error_result(
                    message="STT provider returned empty transcript text.",
                    error="empty_transcript",
                    data={"provider_result": provider_result.get("data", {})},
                    metadata={"method": "transcribe_audio_chunk"},
                )

            source_type = TranscriptSourceType.AUDIO_BYTES if audio_bytes is not None else TranscriptSourceType.AUDIO_REFERENCE
            input_metadata = _safe_deepcopy(metadata or {})
            if audio_bytes is not None:
                input_metadata["audio_sha256"] = _hash_bytes(bytes(audio_bytes))
                input_metadata["audio_size_bytes"] = len(audio_bytes)
                if self.config.retain_raw_audio:
                    input_metadata["raw_audio_retained"] = True
                else:
                    input_metadata["raw_audio_retained"] = False

            if audio_reference:
                input_metadata["audio_reference"] = audio_reference

            segment_result = self._append_transcript_segment(
                session=session,
                text=text,
                speaker=_normalize_speaker(speaker),
                source_type=source_type,
                confidence=confidence,
                language=language or session.language,
                started_at_seconds=started_at_seconds,
                ended_at_seconds=ended_at_seconds,
                metadata={
                    **input_metadata,
                    "provider_data": _safe_deepcopy(transcription_data),
                },
            )

            return segment_result

        except Exception as exc:
            return self._exception_result(exc, method="transcribe_audio_chunk")

    def add_text_chunk(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        text: str,
        speaker: Optional[Union[str, SpeakerRole]] = None,
        confidence: Optional[float] = 1.0,
        language: Optional[str] = None,
        started_at_seconds: Optional[float] = None,
        ended_at_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add an already-transcribed text chunk to a live call transcript.

        Useful when Voice Agent, browser-based STT, Twilio media stream, or a
        future telephony provider already produced text.
        """

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "add_text_chunk"},
                )

            active_result = self._ensure_session_can_accept_transcription(session)
            if not active_result["success"]:
                return active_result

            if not isinstance(text, str) or not text.strip():
                return self._error_result(
                    message="text must be a non-empty string.",
                    error="invalid_text_chunk",
                    metadata={"method": "add_text_chunk"},
                )

            return self._append_transcript_segment(
                session=session,
                text=text,
                speaker=_normalize_speaker(speaker),
                source_type=TranscriptSourceType.TEXT,
                confidence=confidence,
                language=language or session.language,
                started_at_seconds=started_at_seconds,
                ended_at_seconds=ended_at_seconds,
                metadata=metadata or {},
            )

        except Exception as exc:
            return self._exception_result(exc, method="add_text_chunk")

    def add_live_note(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        text: str,
        note_type: str = "manual",
        speaker: Optional[Union[str, SpeakerRole]] = None,
        confidence: float = 1.0,
        source_segment_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a manual or external live note to a transcription session."""

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "add_live_note"},
                )

            if session.status not in {TranscriptionSessionStatus.ACTIVE, TranscriptionSessionStatus.PAUSED}:
                return self._error_result(
                    message="Cannot add live note to a completed/cancelled/failed session.",
                    error="invalid_session_status",
                    metadata={"method": "add_live_note", "status": session.status.value},
                )

            if not isinstance(text, str) or not text.strip():
                return self._error_result(
                    message="note text must be a non-empty string.",
                    error="invalid_note_text",
                    metadata={"method": "add_live_note"},
                )

            note = self._append_live_note(
                session=session,
                text=text,
                note_type=note_type,
                speaker=_normalize_speaker(speaker),
                confidence=confidence,
                source_segment_id=source_segment_id,
                metadata=metadata or {},
            )

            self._log_audit_event("call_transcription_live_note_added", session=session)
            self._emit_agent_event(
                "call.transcriber.note.added",
                {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "note_id": note.note_id,
                    "note_type": note.note_type,
                },
            )

            memory_payload = self._prepare_memory_payload(
                event_type="live_note_added",
                session=session,
                segment=None,
                note=note,
                final=False,
            )
            self._send_to_memory_agent(memory_payload)

            return self._safe_result(
                message="Live note added successfully.",
                data={
                    "note": note.to_dict(),
                    "memory_payload": memory_payload,
                },
                metadata={"method": "add_live_note"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="add_live_note")

    # -------------------------------------------------------------------------
    # Public read methods
    # -------------------------------------------------------------------------

    def get_transcription_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        include_segments: bool = True,
        include_notes: bool = True,
    ) -> Dict[str, Any]:
        """Get one transcription session with tenant isolation."""

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "get_transcription_session"},
                )

            return self._safe_result(
                message="Transcription session retrieved successfully.",
                data={
                    "session": session.to_dict(
                        include_segments=include_segments,
                        include_notes=include_notes,
                    )
                },
                metadata={"method": "get_transcription_session"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="get_transcription_session")

    def list_transcription_sessions(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[Union[str, TranscriptionSessionStatus]] = None,
        limit: int = 100,
        offset: int = 0,
        include_segments: bool = False,
        include_notes: bool = False,
    ) -> Dict[str, Any]:
        """List sessions for one user/workspace only."""

        try:
            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                call_id="list",
            )
            if not context_result["success"]:
                return context_result

            normalized_status = None
            if status is not None:
                normalized_status = TranscriptionSessionStatus(
                    status.value if isinstance(status, TranscriptionSessionStatus) else str(status)
                )

            safe_limit = max(min(int(limit), 500), 1)
            safe_offset = max(int(offset), 0)

            with self._lock:
                sessions = [
                    session
                    for session in self._sessions.values()
                    if session.user_id == user_id and session.workspace_id == workspace_id
                ]

                if normalized_status is not None:
                    sessions = [session for session in sessions if session.status == normalized_status]

                sessions.sort(key=lambda item: item.created_at, reverse=True)
                total = len(sessions)
                page = sessions[safe_offset:safe_offset + safe_limit]

            return self._safe_result(
                message="Transcription sessions listed successfully.",
                data={
                    "sessions": [
                        session.to_dict(
                            include_segments=include_segments,
                            include_notes=include_notes,
                        )
                        for session in page
                    ],
                    "total": total,
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
                metadata={"method": "list_transcription_sessions"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="list_transcription_sessions")

    def get_transcript(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        as_text: bool = True,
    ) -> Dict[str, Any]:
        """Return transcript segments or joined plain text."""

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "get_transcript"},
                )

            if as_text:
                transcript = self._build_transcript_text(session)
            else:
                transcript = [segment.to_dict() for segment in session.segments]

            return self._safe_result(
                message="Transcript retrieved successfully.",
                data={
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "transcript": transcript,
                    "segment_count": len(session.segments),
                },
                metadata={"method": "get_transcript"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="get_transcript")

    def get_live_notes(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        note_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return live notes for a transcription session."""

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": "get_live_notes"},
                )

            notes = session.notes
            if note_type:
                notes = [note for note in notes if note.note_type == note_type]

            return self._safe_result(
                message="Live notes retrieved successfully.",
                data={
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "notes": [note.to_dict() for note in notes],
                    "note_count": len(notes),
                },
                metadata={"method": "get_live_notes"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="get_live_notes")

    def health_check(self) -> Dict[str, Any]:
        """Return transcriber health for dashboard/API monitoring."""

        try:
            with self._lock:
                total = len(self._sessions)
                active = sum(1 for s in self._sessions.values() if s.status == TranscriptionSessionStatus.ACTIVE)
                paused = sum(1 for s in self._sessions.values() if s.status == TranscriptionSessionStatus.PAUSED)
                completed = sum(1 for s in self._sessions.values() if s.status == TranscriptionSessionStatus.COMPLETED)
                cancelled = sum(1 for s in self._sessions.values() if s.status == TranscriptionSessionStatus.CANCELLED)
                failed = sum(1 for s in self._sessions.values() if s.status == TranscriptionSessionStatus.FAILED)

            return self._safe_result(
                message="CallTranscriber health check completed.",
                data={
                    "agent_name": self.agent_name,
                    "agent_type": self.agent_type,
                    "total_sessions": total,
                    "active_sessions": active,
                    "paused_sessions": paused,
                    "completed_sessions": completed,
                    "cancelled_sessions": cancelled,
                    "failed_sessions": failed,
                    "stt_provider_configured": self.stt_provider is not None,
                    "security_agent_configured": self.security_agent is not None,
                    "verification_agent_configured": self.verification_agent is not None,
                    "memory_agent_configured": self.memory_agent is not None,
                    "config": dataclasses.asdict(self.config),
                },
                metadata={"method": "health_check"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="health_check")

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every call transcription task must include user_id and workspace_id.
        call_id is required for call-specific operations.
        """

        if not isinstance(user_id, str) or not user_id.strip():
            return self._error_result(
                message="user_id is required for CallTranscriber operations.",
                error="missing_user_id",
                metadata={"hook": "_validate_task_context"},
            )

        if not isinstance(workspace_id, str) or not workspace_id.strip():
            return self._error_result(
                message="workspace_id is required for CallTranscriber operations.",
                error="missing_workspace_id",
                metadata={"hook": "_validate_task_context"},
            )

        if call_id is not None and (not isinstance(call_id, str) or not call_id.strip()):
            return self._error_result(
                message="call_id is required for call transcription operations.",
                error="missing_call_id",
                metadata={"hook": "_validate_task_context"},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id.strip(),
                "workspace_id": workspace_id.strip(),
                "call_id": call_id.strip() if isinstance(call_id, str) else call_id,
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        session: Optional[TranscriptionSession] = None,
        sensitivity_level: Union[str, SensitivityLevel] = SensitivityLevel.HIGH,
        **_: Any,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Call transcription is treated as sensitive because it processes private
        conversations and may contain personal/business information.
        """

        level = SensitivityLevel(
            sensitivity_level.value if isinstance(sensitivity_level, SensitivityLevel) else str(sensitivity_level)
        )

        if action in {
            "start_transcription_session",
            "transcribe_audio_chunk",
            "export_transcript",
            "store_call_notes",
        }:
            return True

        if level in {SensitivityLevel.HIGH, SensitivityLevel.CRITICAL}:
            return True

        if session and session.consent.status != TranscriptionPermissionStatus.GRANTED:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        session: TranscriptionSession,
        reason: str,
        sensitivity_level: SensitivityLevel = SensitivityLevel.HIGH,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Supported Security Agent interfaces:
            - approve_call_transcription(payload)
            - request_approval(payload)
            - validate_action(payload)

        If Security Agent is not configured, this method allows the action only
        when explicit consent is granted. This keeps local development testable
        while still enforcing consent.
        """

        approval_payload = {
            "request_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "reason": reason,
            "sensitivity_level": sensitivity_level.value,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "call_id": session.call_id,
            "session_id": session.session_id,
            "consent": session.consent.to_dict(),
            "requested_at": _dt_to_iso(_utc_now()),
            "metadata": {
                "session_status": session.status.value,
                "language": session.language,
                "participant_count": len(session.participants),
            },
        }

        if self.security_agent is None:
            if session.consent.status == TranscriptionPermissionStatus.GRANTED:
                return self._safe_result(
                    message="Security Agent not configured; explicit consent is granted, so local approval passed.",
                    data={
                        "approved": True,
                        "approval_mode": "local_consent_fallback",
                        "approval_payload": approval_payload,
                    },
                    metadata={"hook": "_request_security_approval"},
                )

            return self._error_result(
                message="Security approval required but no Security Agent is configured and consent is not granted.",
                error="security_agent_unavailable",
                data={
                    "approved": False,
                    "approval_payload": approval_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        try:
            for method_name in ("approve_call_transcription", "request_approval", "validate_action"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    response = _call_maybe_async_unsafe(method, approval_payload)

                    if isinstance(response, dict):
                        approved = bool(
                            response.get("approved")
                            or response.get("success") is True
                            and response.get("data", {}).get("approved", False)
                        )

                        if approved:
                            return self._safe_result(
                                message="Security approval granted.",
                                data={
                                    "approved": True,
                                    "security_response": response,
                                    "approval_payload": approval_payload,
                                },
                                metadata={"hook": "_request_security_approval"},
                            )

                        return self._error_result(
                            message="Security approval denied.",
                            error="security_approval_denied",
                            data={
                                "approved": False,
                                "security_response": response,
                                "approval_payload": approval_payload,
                            },
                            metadata={"hook": "_request_security_approval"},
                        )

                    if response is True:
                        return self._safe_result(
                            message="Security approval granted.",
                            data={
                                "approved": True,
                                "security_response": response,
                                "approval_payload": approval_payload,
                            },
                            metadata={"hook": "_request_security_approval"},
                        )

            return self._error_result(
                message="Configured Security Agent does not expose a supported approval method.",
                error="security_agent_invalid_interface",
                data={
                    "approved": False,
                    "approval_payload": approval_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="_request_security_approval")

    def _prepare_verification_payload(
        self,
        *,
        event_type: str,
        session: TranscriptionSession,
        result: Dict[str, Any],
        segment: Optional[TranscriptSegment] = None,
        note: Optional[LiveNote] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to verify:
            - permission existed
            - transcript segment was appended
            - session completed cleanly
            - transcript count and note count match expected workflow state
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "source": "call_transcriber",
            "event_type": event_type,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "call_id": session.call_id,
            "session_id": session.session_id,
            "session_status": session.status.value,
            "consent_status": session.consent.status.value,
            "success": bool(result.get("success", False)),
            "message": result.get("message"),
            "segment_id": segment.segment_id if segment else None,
            "note_id": note.note_id if note else None,
            "segment_count": len(session.segments),
            "note_count": len(session.notes),
            "created_at": _dt_to_iso(_utc_now()),
            "data": _safe_deepcopy(result.get("data", {})),
            "error": _safe_deepcopy(result.get("error")),
            "metadata": {
                "language": session.language,
                "title": session.title,
                "session_started_at": _dt_to_iso(session.started_at),
                "session_ended_at": _dt_to_iso(session.ended_at),
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        event_type: str,
        session: TranscriptionSession,
        segment: Optional[TranscriptSegment] = None,
        note: Optional[LiveNote] = None,
        final: bool = False,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This payload intentionally does not include raw audio. It includes
        transcript text/notes only after permission checks have passed.
        """

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "source": "call_transcriber",
            "event_type": event_type,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "call_id": session.call_id,
            "session_id": session.session_id,
            "session_status": session.status.value,
            "consent_status": session.consent.status.value,
            "language": session.language,
            "title": session.title,
            "final": final,
            "segment_count": len(session.segments),
            "note_count": len(session.notes),
            "created_at": _dt_to_iso(_utc_now()),
            "metadata": {
                "participants": _safe_deepcopy(session.participants),
                "session_metadata": _safe_deepcopy(session.metadata),
            },
        }

        if segment is not None:
            payload["segment"] = {
                "segment_id": segment.segment_id,
                "speaker": segment.speaker.value,
                "clean_text": segment.clean_text,
                "confidence": segment.confidence,
                "created_at": _dt_to_iso(segment.created_at),
            }

        if note is not None:
            payload["note"] = {
                "note_id": note.note_id,
                "note_type": note.note_type,
                "text": note.text,
                "speaker": note.speaker.value,
                "confidence": note.confidence,
                "created_at": _dt_to_iso(note.created_at),
            }

        if final:
            payload["summary"] = self._build_lightweight_summary(session)
            payload["live_notes"] = [n.to_dict() for n in session.notes[-50:]]

        if extra:
            payload["extra"] = _safe_deepcopy(extra)

        return payload

    def _emit_agent_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Emit events for dashboard/API/realtime monitoring.

        Supports injected event_emitter or BaseAgent emit_event fallback.
        """

        try:
            safe_payload = _safe_deepcopy(payload)
            safe_payload.setdefault("agent", self.agent_name)
            safe_payload.setdefault("emitted_at", _dt_to_iso(_utc_now()))

            if callable(self.event_emitter):
                self.event_emitter(event_type, safe_payload)
                return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_type, safe_payload)
                return

            self.logger.debug("Agent event: %s %s", event_type, safe_payload)

        except Exception as exc:
            self.logger.warning("Failed to emit agent event: %s", exc)

    def _log_audit_event(
        self,
        event_type: str,
        session: Optional[TranscriptionSession] = None,
        *,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event with tenant context.

        Does not leak transcript contents unless explicitly passed by caller.
        """

        try:
            payload = {
                "audit_id": str(uuid.uuid4()),
                "event_type": event_type,
                "agent": self.agent_name,
                "created_at": _dt_to_iso(_utc_now()),
                "extra": _safe_deepcopy(extra or {}),
            }

            if session is not None:
                payload.update({
                    "user_id": session.user_id,
                    "workspace_id": session.workspace_id,
                    "call_id": session.call_id,
                    "session_id": session.session_id,
                    "session_status": session.status.value,
                    "consent_status": session.consent.status.value,
                    "segment_count": len(session.segments),
                    "note_count": len(session.notes),
                })

            if callable(self.audit_logger):
                self.audit_logger(payload)
                return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(payload)
                return

            self.logger.info("Audit event: %s", payload)

        except Exception as exc:
            self.logger.warning("Failed to log audit event: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured success result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Internal session helpers
    # -------------------------------------------------------------------------

    def _normalize_consent(
        self,
        consent: Optional[Union[ConsentRecord, Dict[str, Any]]],
    ) -> ConsentRecord:
        """Normalize consent input into ConsentRecord."""

        if isinstance(consent, ConsentRecord):
            return consent

        if isinstance(consent, dict):
            status_raw = consent.get("status", TranscriptionPermissionStatus.UNKNOWN.value)
            status = TranscriptionPermissionStatus(
                status_raw.value if isinstance(status_raw, TranscriptionPermissionStatus) else str(status_raw)
            )

            granted_at = _parse_datetime(consent.get("granted_at"))
            revoked_at = _parse_datetime(consent.get("revoked_at"))

            if status == TranscriptionPermissionStatus.GRANTED and granted_at is None:
                granted_at = _utc_now()

            return ConsentRecord(
                status=status,
                granted_by=consent.get("granted_by"),
                consent_text=consent.get("consent_text"),
                granted_at=granted_at,
                revoked_at=revoked_at,
                jurisdiction=consent.get("jurisdiction"),
                metadata=_safe_deepcopy(consent.get("metadata") or {}),
            )

        return ConsentRecord(status=TranscriptionPermissionStatus.UNKNOWN)

    def _find_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: Optional[str] = None,
        call_id: Optional[str] = None,
    ) -> Optional[TranscriptionSession]:
        """Find session by session_id or call_id with tenant isolation."""

        with self._lock:
            if session_id:
                return self._get_owned_session_or_none(session_id, user_id, workspace_id)

            if call_id:
                sid = self._call_to_session.get((user_id, workspace_id, call_id))
                if sid:
                    return self._get_owned_session_or_none(sid, user_id, workspace_id)

        return None

    def _get_owned_session_or_none(
        self,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[TranscriptionSession]:
        """Return session only if it belongs to the same user/workspace."""

        with self._lock:
            session = self._sessions.get(session_id)

        if session is None:
            return None

        if session.user_id != user_id or session.workspace_id != workspace_id:
            return None

        return session

    def _ensure_session_can_accept_transcription(self, session: TranscriptionSession) -> Dict[str, Any]:
        """Validate session state before adding transcript data."""

        if session.status != TranscriptionSessionStatus.ACTIVE:
            return self._error_result(
                message=f"Transcription session is not active. Current status: {session.status.value}",
                error="session_not_active",
                metadata={"session_id": session.session_id, "status": session.status.value},
            )

        if session.consent.status != TranscriptionPermissionStatus.GRANTED:
            return self._error_result(
                message="Transcription permission is not granted.",
                error="transcription_permission_not_granted",
                data={"consent": session.consent.to_dict()},
                metadata={"session_id": session.session_id},
            )

        if len(session.segments) >= self.config.max_segments_per_session:
            return self._error_result(
                message="Maximum transcript segments reached for this session.",
                error="max_segments_reached",
                metadata={
                    "session_id": session.session_id,
                    "max_segments": self.config.max_segments_per_session,
                },
            )

        return self._safe_result(
            message="Session can accept transcription.",
            data={"session_id": session.session_id},
            metadata={"method": "_ensure_session_can_accept_transcription"},
        )

    def _set_session_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        status: TranscriptionSessionStatus,
        message: str,
        event_name: str,
        method: str,
        reason: Optional[str] = None,
        end_session: bool = False,
    ) -> Dict[str, Any]:
        """Shared helper for status transitions."""

        try:
            session = self._get_owned_session_or_none(session_id, user_id, workspace_id)
            if session is None:
                return self._error_result(
                    message="Transcription session not found or access denied.",
                    error="session_not_found_or_forbidden",
                    metadata={"method": method},
                )

            with self._lock:
                session.status = status
                session.updated_at = _utc_now()
                if end_session:
                    session.ended_at = _utc_now()
                if reason:
                    session.metadata[f"{status.value}_reason"] = reason

            self._log_audit_event(f"call_transcription_session_{status.value}", session=session, extra={"reason": reason})
            self._emit_agent_event(
                event_name,
                {
                    "session_id": session.session_id,
                    "call_id": session.call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "status": status.value,
                    "reason": reason,
                },
            )

            return self._safe_result(
                message=message,
                data={"session": session.to_dict()},
                metadata={"method": method},
            )

        except Exception as exc:
            return self._exception_result(exc, method=method)

    # -------------------------------------------------------------------------
    # Internal transcription helpers
    # -------------------------------------------------------------------------

    def _call_stt_provider(
        self,
        *,
        audio_bytes: Optional[bytes],
        audio_reference: Optional[str],
        language: str,
        metadata: Dict[str, Any],
        session: TranscriptionSession,
    ) -> Dict[str, Any]:
        """
        Call an injected STT provider.

        No secrets are handled here. The provider should be configured outside
        this file using secure environment/config management.
        """

        if self.stt_provider is None:
            return self._error_result(
                message="No STT provider configured. Cannot transcribe audio.",
                error="stt_provider_unavailable",
                metadata={"method": "_call_stt_provider"},
            )

        payload = {
            "audio_bytes": audio_bytes if self.config.retain_raw_audio else audio_bytes,
            "audio_reference": audio_reference,
            "language": language,
            "metadata": _safe_deepcopy(metadata),
            "context": {
                "user_id": session.user_id,
                "workspace_id": session.workspace_id,
                "call_id": session.call_id,
                "session_id": session.session_id,
                "agent": self.agent_name,
            },
        }

        try:
            provider = self.stt_provider

            if callable(provider) and not any(
                callable(getattr(provider, name, None))
                for name in ("transcribe", "transcribe_audio", "speech_to_text")
            ):
                response = _call_maybe_async_unsafe(provider, payload)
            else:
                response = None
                for method_name in ("transcribe", "transcribe_audio", "speech_to_text"):
                    method = getattr(provider, method_name, None)
                    if callable(method):
                        response = _call_maybe_async_unsafe(method, payload)
                        break

            if response is None:
                return self._error_result(
                    message="Configured STT provider does not expose a supported transcription method.",
                    error="invalid_stt_provider_interface",
                    metadata={"method": "_call_stt_provider"},
                )

            if isinstance(response, dict):
                if "success" in response:
                    return response

                text = response.get("text") or response.get("transcript")
                return self._safe_result(
                    message="STT provider returned transcript.",
                    data={
                        "text": text,
                        "confidence": response.get("confidence"),
                        "language": response.get("language") or language,
                        "provider_response": _safe_deepcopy(response),
                    },
                    metadata={"method": "_call_stt_provider"},
                )

            if isinstance(response, str):
                return self._safe_result(
                    message="STT provider returned transcript text.",
                    data={"text": response, "language": language},
                    metadata={"method": "_call_stt_provider"},
                )

            return self._error_result(
                message="STT provider returned unsupported response type.",
                error="unsupported_stt_response",
                data={"response_type": type(response).__name__},
                metadata={"method": "_call_stt_provider"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="_call_stt_provider")

    def _append_transcript_segment(
        self,
        *,
        session: TranscriptionSession,
        text: str,
        speaker: SpeakerRole,
        source_type: TranscriptSourceType,
        confidence: Optional[float],
        language: str,
        started_at_seconds: Optional[float],
        ended_at_seconds: Optional[float],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Append transcript segment and auto-extract live notes."""

        clean_text = self._clean_transcript_text(text)

        segment = TranscriptSegment(
            segment_id=str(uuid.uuid4()),
            session_id=session.session_id,
            call_id=session.call_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            speaker=speaker,
            text=text,
            clean_text=clean_text,
            source_type=source_type,
            confidence=confidence,
            language=language,
            started_at_seconds=_safe_float(started_at_seconds, None),
            ended_at_seconds=_safe_float(ended_at_seconds, None),
            created_at=_utc_now(),
            metadata=_safe_deepcopy(metadata),
        )

        auto_notes: List[LiveNote] = []

        with self._lock:
            session.segments.append(segment)
            if len(session.segments) > self.config.max_segments_per_session:
                session.segments = session.segments[-self.config.max_segments_per_session:]

            session.updated_at = _utc_now()

            if self.config.enable_live_notes:
                auto_notes = self._extract_live_notes_from_segment(session, segment)
                for note in auto_notes:
                    if len(session.notes) < self.config.max_notes_per_session:
                        session.notes.append(note)
                if len(session.notes) > self.config.max_notes_per_session:
                    session.notes = session.notes[-self.config.max_notes_per_session:]

        result = self._safe_result(
            message="Transcript segment added successfully.",
            data={
                "segment": segment.to_dict(),
                "auto_notes": [note.to_dict() for note in auto_notes],
            },
            metadata={"method": "_append_transcript_segment"},
        )

        memory_payload = self._prepare_memory_payload(
            event_type="transcript_segment_added",
            session=session,
            segment=segment,
            note=None,
            final=False,
        )
        verification_payload = self._prepare_verification_payload(
            event_type="transcript_segment_added",
            session=session,
            result=result,
            segment=segment,
        )

        self._send_to_memory_agent(memory_payload)
        self._send_to_verification_agent(verification_payload)

        self._log_audit_event(
            "call_transcription_segment_added",
            session=session,
            extra={
                "segment_id": segment.segment_id,
                "source_type": source_type.value,
                "speaker": speaker.value,
            },
        )
        self._emit_agent_event(
            "call.transcriber.segment.added",
            {
                "session_id": session.session_id,
                "call_id": session.call_id,
                "user_id": session.user_id,
                "workspace_id": session.workspace_id,
                "segment_id": segment.segment_id,
                "speaker": speaker.value,
                "auto_note_count": len(auto_notes),
            },
        )

        result["data"]["memory_payload"] = memory_payload
        result["data"]["verification_payload"] = verification_payload
        return result

    def _append_live_note(
        self,
        *,
        session: TranscriptionSession,
        text: str,
        note_type: str,
        speaker: SpeakerRole,
        confidence: float,
        source_segment_id: Optional[str],
        metadata: Dict[str, Any],
    ) -> LiveNote:
        """Append a live note to session."""

        clean_text = self._clean_transcript_text(text)

        note = LiveNote(
            note_id=str(uuid.uuid4()),
            session_id=session.session_id,
            call_id=session.call_id,
            user_id=session.user_id,
            workspace_id=session.workspace_id,
            note_type=note_type.strip() or "manual",
            text=clean_text,
            speaker=speaker,
            confidence=max(min(float(confidence), 1.0), 0.0),
            created_at=_utc_now(),
            source_segment_id=source_segment_id,
            metadata=_safe_deepcopy(metadata),
        )

        with self._lock:
            session.notes.append(note)
            if len(session.notes) > self.config.max_notes_per_session:
                session.notes = session.notes[-self.config.max_notes_per_session:]
            session.updated_at = _utc_now()

        return note

    def _extract_live_notes_from_segment(
        self,
        session: TranscriptionSession,
        segment: TranscriptSegment,
    ) -> List[LiveNote]:
        """
        Lightweight live note extraction.

        This is intentionally deterministic and local. Future versions can route
        to Creator Agent, Business Agent, or a summarizer model with approval.
        """

        text = segment.clean_text.strip()
        if not text:
            return []

        notes: List[LiveNote] = []
        lower = text.lower()

        patterns: List[Tuple[str, Iterable[str]]] = [
            ("interest", ["interested", "sounds good", "yes", "i want", "we need", "looking for"]),
            ("objection", ["not interested", "too expensive", "already have", "no budget", "send details"]),
            ("appointment", ["appointment", "meeting", "schedule", "book", "tomorrow", "next week", "call back"]),
            ("budget", ["budget", "price", "cost", "$", "dollar", "fee", "monthly", "one-time"]),
            ("pain_point", ["problem", "issue", "struggling", "need help", "not working", "slow", "no leads"]),
            ("contact_detail", ["email", "phone", "number", "@", "whatsapp"]),
            ("decision_signal", ["owner", "manager", "decision", "approve", "partner", "team"]),
        ]

        for note_type, keywords in patterns:
            if any(keyword in lower for keyword in keywords):
                notes.append(
                    LiveNote(
                        note_id=str(uuid.uuid4()),
                        session_id=session.session_id,
                        call_id=session.call_id,
                        user_id=session.user_id,
                        workspace_id=session.workspace_id,
                        note_type=note_type,
                        text=text,
                        speaker=segment.speaker,
                        confidence=max(float(segment.confidence or 0.75), 0.0),
                        created_at=_utc_now(),
                        source_segment_id=segment.segment_id,
                        metadata={"auto_extracted": True},
                    )
                )

        return notes

    def _clean_transcript_text(self, text: str) -> str:
        """Normalize and optionally redact sensitive text."""

        clean = re.sub(r"\s+", " ", _safe_str(text)).strip()

        if not self.config.redact_sensitive_data:
            return clean

        # Basic defensive redaction for common sensitive patterns.
        clean = re.sub(
            r"\b(?:\d[ -]*?){13,19}\b",
            "[REDACTED_CARD_OR_LONG_NUMBER]",
            clean,
        )
        clean = re.sub(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "[REDACTED_EMAIL]",
            clean,
            flags=re.IGNORECASE,
        )
        clean = re.sub(
            r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b",
            "[REDACTED_PHONE]",
            clean,
        )

        return clean

    def _build_transcript_text(self, session: TranscriptionSession) -> str:
        """Build readable transcript text."""

        lines = []
        for segment in session.segments:
            speaker = segment.speaker.value.upper()
            lines.append(f"{speaker}: {segment.clean_text}")
        return "\n".join(lines)

    def _build_lightweight_summary(self, session: TranscriptionSession) -> Dict[str, Any]:
        """
        Build a small deterministic summary.

        Future call_summarizer.py can replace this with richer model-based logic.
        """

        note_counts: Dict[str, int] = {}
        for note in session.notes:
            note_counts[note.note_type] = note_counts.get(note.note_type, 0) + 1

        latest_notes = [note.to_dict() for note in session.notes[-10:]]

        return {
            "session_id": session.session_id,
            "call_id": session.call_id,
            "status": session.status.value,
            "duration_seconds": self._session_duration_seconds(session),
            "segment_count": len(session.segments),
            "note_count": len(session.notes),
            "note_type_counts": note_counts,
            "latest_notes": latest_notes,
            "started_at": _dt_to_iso(session.started_at),
            "ended_at": _dt_to_iso(session.ended_at),
            "language": session.language,
        }

    @staticmethod
    def _session_duration_seconds(session: TranscriptionSession) -> Optional[float]:
        """Calculate session duration."""

        if not session.started_at:
            return None
        end = session.ended_at or _utc_now()
        return max((end - session.started_at).total_seconds(), 0.0)

    # -------------------------------------------------------------------------
    # Agent integrations
    # -------------------------------------------------------------------------

    def _send_to_verification_agent(self, payload: Dict[str, Any]) -> None:
        """Send payload to Verification Agent if configured."""

        if self.verification_agent is None:
            return

        try:
            for method_name in ("verify", "prepare_verification", "handle_verification_payload", "receive"):
                method = getattr(self.verification_agent, method_name, None)
                if callable(method):
                    _call_maybe_async_unsafe(method, payload)
                    return
        except Exception as exc:
            self.logger.warning("Failed to send payload to Verification Agent: %s", exc)

    def _send_to_memory_agent(self, payload: Dict[str, Any]) -> None:
        """Send payload to Memory Agent if configured."""

        if self.memory_agent is None:
            return

        try:
            for method_name in ("store", "remember", "save_memory", "receive"):
                method = getattr(self.memory_agent, method_name, None)
                if callable(method):
                    _call_maybe_async_unsafe(method, payload)
                    return
        except Exception as exc:
            self.logger.warning("Failed to send payload to Memory Agent: %s", exc)

    # -------------------------------------------------------------------------
    # Error helper
    # -------------------------------------------------------------------------

    def _exception_result(self, exc: Exception, *, method: str) -> Dict[str, Any]:
        """Return structured exception result."""

        self.logger.error("%s failed: %s", method, exc, exc_info=True)
        return self._error_result(
            message=f"{method} failed.",
            error={
                "type": exc.__class__.__name__,
                "detail": str(exc),
                "traceback": traceback.format_exc(),
            },
            metadata={"method": method},
        )


# =============================================================================
# Registry helper
# =============================================================================

def get_agent() -> CallTranscriber:
    """
    Agent Registry / Agent Loader factory.

    Allows dynamic loading:
        module = importlib.import_module("agents.super_agents.call_agent.call_transcriber")
        agent = module.get_agent()
    """

    return CallTranscriber()


__all__ = [
    "CallTranscriber",
    "TranscriptionConfig",
    "ConsentRecord",
    "TranscriptionSession",
    "TranscriptSegment",
    "LiveNote",
    "TranscriptionPermissionStatus",
    "TranscriptionSessionStatus",
    "TranscriptSourceType",
    "SpeakerRole",
    "SensitivityLevel",
    "get_agent",
]