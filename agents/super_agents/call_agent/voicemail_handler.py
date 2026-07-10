"""
agents/super_agents/call_agent/voicemail_handler.py

Voicemail and missed-call handling for the William / Jarvis Call Agent.

Purpose:
    Handles voicemail records, missed-call notes, callback reminders, dashboard
    payloads, memory payloads, and verification payloads.

Safety:
    This module does NOT place calls, send SMS/WhatsApp/email, or execute
    destructive actions directly. Any external communication or callback action
    must be routed through Security Agent approval and later executed by
    approved Call Agent / Workflow Agent components.

SaaS Isolation:
    Every user/workspace-specific operation requires user_id and workspace_id.
    Records are scoped in-memory by workspace and user context to avoid mixing
    voicemail, notes, reminders, audit data, or analytics between tenants.

Compatibility:
    - BaseAgent compatible
    - Agent Registry / Agent Loader compatible
    - Master Agent routing compatible
    - Security Agent approval compatible
    - Memory Agent payload compatible
    - Verification Agent payload compatible
    - Dashboard / FastAPI integration ready
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Import-safe BaseAgent fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the full William/Jarvis framework is
        present. In production, agents.base_agent.BaseAgent should be used.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s", payload)


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

MODULE_NAME = "call_agent"
FILE_NAME = "voicemail_handler.py"
AGENT_NAME = "VoicemailHandler"

DEFAULT_CALLBACK_DELAY_MINUTES = 30
MAX_NOTE_LENGTH = 5000
MAX_TRANSCRIPT_LENGTH = 30000
MAX_CALLER_NAME_LENGTH = 160
MAX_PHONE_LENGTH = 40
MAX_TAGS = 30
MAX_REMINDER_ATTEMPTS = 10
PHONE_SAFE_PATTERN = re.compile(r"^[0-9+().\-\s]{3,40}$")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VoicemailStatus(str, enum.Enum):
    """Voicemail lifecycle status."""

    NEW = "new"
    REVIEWED = "reviewed"
    CALLBACK_SCHEDULED = "callback_scheduled"
    CALLBACK_COMPLETED = "callback_completed"
    ARCHIVED = "archived"
    SPAM = "spam"


class MissedCallStatus(str, enum.Enum):
    """Missed-call note lifecycle status."""

    NEW = "new"
    NOTE_ADDED = "note_added"
    CALLBACK_SCHEDULED = "callback_scheduled"
    CALLBACK_COMPLETED = "callback_completed"
    ARCHIVED = "archived"
    SPAM = "spam"


class CallbackReminderStatus(str, enum.Enum):
    """Callback reminder status."""

    PENDING = "pending"
    READY = "ready"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class CallbackPriority(str, enum.Enum):
    """Callback priority."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class RiskLevel(str, enum.Enum):
    """Risk level used for Security Agent gating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecordType(str, enum.Enum):
    """Supported record types."""

    VOICEMAIL = "voicemail"
    MISSED_CALL = "missed_call"
    CALLBACK_REMINDER = "callback_reminder"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class CallerIdentity:
    """
    Caller identity captured from listener/transcriber/receptionist layers.

    This object is intentionally simple and safe to serialize for dashboard/API.
    """

    phone_number: str
    caller_name: Optional[str] = None
    caller_id: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    country: Optional[str] = None
    timezone_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class VoicemailRecord:
    """Workspace-scoped voicemail record."""

    voicemail_id: str
    user_id: str
    workspace_id: str
    caller: CallerIdentity
    status: str = VoicemailStatus.NEW.value
    transcript: Optional[str] = None
    audio_reference: Optional[str] = None
    duration_seconds: Optional[int] = None
    language: Optional[str] = None
    summary: Optional[str] = None
    intent: Optional[str] = None
    sentiment: Optional[str] = None
    priority: str = CallbackPriority.NORMAL.value
    tags: Optional[List[str]] = None
    callback_requested: bool = False
    callback_time_hint: Optional[str] = None
    source_call_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["caller"] = self.caller.to_dict()
        return data


@dataclasses.dataclass(frozen=True)
class MissedCallNote:
    """Workspace-scoped missed-call note."""

    missed_call_id: str
    user_id: str
    workspace_id: str
    caller: CallerIdentity
    status: str = MissedCallStatus.NEW.value
    note: Optional[str] = None
    reason: Optional[str] = None
    priority: str = CallbackPriority.NORMAL.value
    callback_requested: bool = True
    source_call_id: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["caller"] = self.caller.to_dict()
        return data


@dataclasses.dataclass(frozen=True)
class CallbackReminder:
    """Workspace-scoped callback reminder."""

    reminder_id: str
    user_id: str
    workspace_id: str
    caller: CallerIdentity
    related_record_type: str
    related_record_id: str
    scheduled_for: str
    status: str = CallbackReminderStatus.PENDING.value
    priority: str = CallbackPriority.NORMAL.value
    assigned_to: Optional[str] = None
    callback_script_hint: Optional[str] = None
    attempt_count: int = 0
    max_attempts: int = 3
    reminder_note: Optional[str] = None
    requires_security_approval: bool = True
    security_approval_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["caller"] = self.caller.to_dict()
        return data


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VoicemailHandler(BaseAgent):
    """
    Handles voicemail, missed-call notes, and callback reminder preparation.

    Public methods:
        - record_voicemail()
        - record_missed_call()
        - add_missed_call_note()
        - schedule_callback_reminder()
        - list_voicemails()
        - list_missed_calls()
        - list_callback_reminders()
        - get_record()
        - update_voicemail_status()
        - update_missed_call_status()
        - complete_callback_reminder()
        - cancel_callback_reminder()
        - prepare_callback_payload()
        - build_dashboard_payload()
        - export_records()
        - health_check()

    Integration:
        - Master Agent can route call-related tasks here.
        - Call Listener can create missed-call records here.
        - Call Transcriber can pass voicemail transcript here.
        - Receptionist Mode can request callback reminders here.
        - Security Agent gates any callback/outbound-contact preparation.
        - Memory Agent can store summarized call context using prepared payloads.
        - Verification Agent receives operation verification payloads.
    """

    def __init__(
        self,
        *,
        agent_name: str = AGENT_NAME,
        agent_id: str = "voicemail_handler",
        logger: Optional[logging.Logger] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        initial_store: Optional[Mapping[str, Any]] = None,
        strict_context: bool = True,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logger or logging.getLogger(f"{MODULE_NAME}.{AGENT_NAME}")
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.strict_context = strict_context

        self._voicemails: Dict[str, Dict[str, Any]] = {}
        self._missed_calls: Dict[str, Dict[str, Any]] = {}
        self._callback_reminders: Dict[str, Dict[str, Any]] = {}

        if initial_store:
            self._load_initial_store(initial_store)

        self._emit_agent_event(
            "voicemail_handler.initialized",
            {
                "voicemail_count": len(self._voicemails),
                "missed_call_count": len(self._missed_calls),
                "callback_reminder_count": len(self._callback_reminders),
            },
        )

    # ------------------------------------------------------------------
    # Public API: voicemail
    # ------------------------------------------------------------------

    def record_voicemail(
        self,
        *,
        user_id: str,
        workspace_id: str,
        caller: Union[CallerIdentity, Mapping[str, Any]],
        transcript: Optional[str] = None,
        audio_reference: Optional[str] = None,
        duration_seconds: Optional[int] = None,
        language: Optional[str] = None,
        summary: Optional[str] = None,
        intent: Optional[str] = None,
        sentiment: Optional[str] = None,
        priority: str = CallbackPriority.NORMAL.value,
        callback_requested: bool = False,
        callback_time_hint: Optional[str] = None,
        source_call_id: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a voicemail record from a transcribed or uploaded voicemail.

        This stores only workspace-scoped data and prepares memory/verification
        payloads. It does not call back the caller.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="record_voicemail",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            caller_result = self._normalize_caller(caller)
            if not caller_result["success"]:
                return caller_result

            validation_errors = self._validate_voicemail_fields(
                transcript=transcript,
                audio_reference=audio_reference,
                duration_seconds=duration_seconds,
                priority=priority,
                tags=tags,
            )
            if validation_errors:
                return self._error_result(
                    message="Invalid voicemail payload.",
                    error={"validation_errors": validation_errors},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            voicemail_id = self._generate_record_id(
                prefix="vm",
                user_id=user_id,
                workspace_id=workspace_id,
                source=source_call_id or caller_result["data"]["caller"]["phone_number"],
            )
            now = datetime.now(timezone.utc).isoformat()

            record = VoicemailRecord(
                voicemail_id=voicemail_id,
                user_id=user_id,
                workspace_id=workspace_id,
                caller=CallerIdentity(**caller_result["data"]["caller"]),
                status=VoicemailStatus.NEW.value,
                transcript=self._clean_text(transcript, max_length=MAX_TRANSCRIPT_LENGTH),
                audio_reference=self._clean_text(audio_reference, max_length=1000),
                duration_seconds=duration_seconds,
                language=self._clean_text(language, max_length=40),
                summary=self._clean_text(summary, max_length=MAX_NOTE_LENGTH),
                intent=self._clean_text(intent, max_length=160),
                sentiment=self._clean_text(sentiment, max_length=80),
                priority=self._normalize_enum(priority, CallbackPriority, "priority"),
                tags=self._normalize_tags(tags or []),
                callback_requested=bool(callback_requested),
                callback_time_hint=self._clean_text(callback_time_hint, max_length=500),
                source_call_id=self._clean_text(source_call_id, max_length=160),
                metadata=self._safe_metadata(metadata or {}),
                created_at=now,
                updated_at=now,
            ).to_dict()

            self._voicemails[voicemail_id] = record

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type="call_voicemail_recorded",
                data={
                    "voicemail_id": voicemail_id,
                    "caller": self._redact_caller_for_memory(record["caller"]),
                    "summary": record.get("summary"),
                    "intent": record.get("intent"),
                    "priority": record.get("priority"),
                    "callback_requested": record.get("callback_requested"),
                    "tags": record.get("tags", []),
                },
            )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="record_voicemail",
                data={
                    "voicemail_id": voicemail_id,
                    "source_call_id": source_call_id,
                    "has_transcript": bool(transcript),
                    "has_audio_reference": bool(audio_reference),
                },
            )

            self._emit_agent_event(
                "voicemail.recorded",
                {
                    "voicemail_id": voicemail_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "callback_requested": bool(callback_requested),
                },
            )
            self._log_audit_event(
                event_type="call.voicemail.record",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "voicemail_id": voicemail_id,
                    "source_call_id": source_call_id,
                    "callback_requested": bool(callback_requested),
                    "priority": priority,
                },
            )

            return self._safe_result(
                message="Voicemail recorded successfully.",
                data={
                    "voicemail": copy.deepcopy(record),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to record voicemail.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def update_voicemail_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        voicemail_id: str,
        status: str,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update voicemail status within the same user/workspace scope."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="update_voicemail_status",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            record = self._get_scoped_record(
                store=self._voicemails,
                record_id=voicemail_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not record:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=RecordType.VOICEMAIL.value,
                )

            normalized_status = self._normalize_enum(status, VoicemailStatus, "status")
            updated = copy.deepcopy(record)
            updated["status"] = normalized_status
            updated["updated_at"] = datetime.now(timezone.utc).isoformat()

            if note:
                existing_notes = updated.setdefault("metadata", {}).setdefault("status_notes", [])
                existing_notes.append(
                    {
                        "note": self._clean_text(note, max_length=MAX_NOTE_LENGTH),
                        "status": normalized_status,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )

            self._voicemails[voicemail_id] = updated

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="update_voicemail_status",
                data={"voicemail_id": voicemail_id, "status": normalized_status},
            )

            self._emit_agent_event(
                "voicemail.status_updated",
                {
                    "voicemail_id": voicemail_id,
                    "status": normalized_status,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            self._log_audit_event(
                event_type="call.voicemail.status_update",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"voicemail_id": voicemail_id, "status": normalized_status},
            )

            return self._safe_result(
                message="Voicemail status updated successfully.",
                data={
                    "voicemail": copy.deepcopy(updated),
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to update voicemail status.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def list_voicemails(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        callback_requested: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List workspace-scoped voicemails for dashboard/API usage."""

        return self._list_records(
            store=self._voicemails,
            record_label="voicemails",
            user_id=user_id,
            workspace_id=workspace_id,
            status=status,
            status_enum=VoicemailStatus,
            priority=priority,
            callback_requested=callback_requested,
            limit=limit,
            offset=offset,
            operation="list_voicemails",
        )

    # ------------------------------------------------------------------
    # Public API: missed calls
    # ------------------------------------------------------------------

    def record_missed_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        caller: Union[CallerIdentity, Mapping[str, Any]],
        note: Optional[str] = None,
        reason: Optional[str] = None,
        priority: str = CallbackPriority.NORMAL.value,
        callback_requested: bool = True,
        source_call_id: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a missed call note.

        Typically called by call_listener.py when a call was missed, abandoned,
        disconnected, outside business hours, or not answered.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="record_missed_call",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            caller_result = self._normalize_caller(caller)
            if not caller_result["success"]:
                return caller_result

            validation_errors = self._validate_missed_call_fields(
                note=note,
                reason=reason,
                priority=priority,
                tags=tags,
            )
            if validation_errors:
                return self._error_result(
                    message="Invalid missed-call payload.",
                    error={"validation_errors": validation_errors},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            missed_call_id = self._generate_record_id(
                prefix="mc",
                user_id=user_id,
                workspace_id=workspace_id,
                source=source_call_id or caller_result["data"]["caller"]["phone_number"],
            )
            now = datetime.now(timezone.utc).isoformat()

            record = MissedCallNote(
                missed_call_id=missed_call_id,
                user_id=user_id,
                workspace_id=workspace_id,
                caller=CallerIdentity(**caller_result["data"]["caller"]),
                status=MissedCallStatus.NOTE_ADDED.value if note else MissedCallStatus.NEW.value,
                note=self._clean_text(note, max_length=MAX_NOTE_LENGTH),
                reason=self._clean_text(reason, max_length=500),
                priority=self._normalize_enum(priority, CallbackPriority, "priority"),
                callback_requested=bool(callback_requested),
                source_call_id=self._clean_text(source_call_id, max_length=160),
                tags=self._normalize_tags(tags or []),
                metadata=self._safe_metadata(metadata or {}),
                created_at=now,
                updated_at=now,
            ).to_dict()

            self._missed_calls[missed_call_id] = record

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type="call_missed_call_recorded",
                data={
                    "missed_call_id": missed_call_id,
                    "caller": self._redact_caller_for_memory(record["caller"]),
                    "reason": record.get("reason"),
                    "note": record.get("note"),
                    "priority": record.get("priority"),
                    "callback_requested": record.get("callback_requested"),
                },
            )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="record_missed_call",
                data={
                    "missed_call_id": missed_call_id,
                    "source_call_id": source_call_id,
                    "callback_requested": bool(callback_requested),
                },
            )

            self._emit_agent_event(
                "missed_call.recorded",
                {
                    "missed_call_id": missed_call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "callback_requested": bool(callback_requested),
                },
            )
            self._log_audit_event(
                event_type="call.missed_call.record",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "missed_call_id": missed_call_id,
                    "source_call_id": source_call_id,
                    "callback_requested": bool(callback_requested),
                    "priority": priority,
                },
            )

            return self._safe_result(
                message="Missed call recorded successfully.",
                data={
                    "missed_call": copy.deepcopy(record),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to record missed call.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def add_missed_call_note(
        self,
        *,
        user_id: str,
        workspace_id: str,
        missed_call_id: str,
        note: str,
        append: bool = True,
    ) -> Dict[str, Any]:
        """Add or replace a note on a missed-call record."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="add_missed_call_note",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            if not note or len(note) > MAX_NOTE_LENGTH:
                return self._error_result(
                    message="Invalid missed-call note.",
                    error=f"note is required and must be <= {MAX_NOTE_LENGTH} characters.",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            record = self._get_scoped_record(
                store=self._missed_calls,
                record_id=missed_call_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not record:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=RecordType.MISSED_CALL.value,
                )

            updated = copy.deepcopy(record)
            clean_note = self._clean_text(note, max_length=MAX_NOTE_LENGTH)

            if append and updated.get("note"):
                updated["note"] = f"{updated['note']}\n\n{clean_note}"
            else:
                updated["note"] = clean_note

            updated["status"] = MissedCallStatus.NOTE_ADDED.value
            updated["updated_at"] = datetime.now(timezone.utc).isoformat()

            self._missed_calls[missed_call_id] = updated

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="add_missed_call_note",
                data={"missed_call_id": missed_call_id, "append": append},
            )

            self._emit_agent_event(
                "missed_call.note_added",
                {
                    "missed_call_id": missed_call_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            self._log_audit_event(
                event_type="call.missed_call.note_add",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"missed_call_id": missed_call_id, "append": append},
            )

            return self._safe_result(
                message="Missed-call note saved successfully.",
                data={
                    "missed_call": copy.deepcopy(updated),
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to add missed-call note.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def update_missed_call_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        missed_call_id: str,
        status: str,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update missed-call status within the same user/workspace scope."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="update_missed_call_status",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            record = self._get_scoped_record(
                store=self._missed_calls,
                record_id=missed_call_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not record:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=RecordType.MISSED_CALL.value,
                )

            normalized_status = self._normalize_enum(status, MissedCallStatus, "status")
            updated = copy.deepcopy(record)
            updated["status"] = normalized_status
            updated["updated_at"] = datetime.now(timezone.utc).isoformat()

            if note:
                existing_notes = updated.setdefault("metadata", {}).setdefault("status_notes", [])
                existing_notes.append(
                    {
                        "note": self._clean_text(note, max_length=MAX_NOTE_LENGTH),
                        "status": normalized_status,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )

            self._missed_calls[missed_call_id] = updated

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="update_missed_call_status",
                data={"missed_call_id": missed_call_id, "status": normalized_status},
            )

            self._emit_agent_event(
                "missed_call.status_updated",
                {
                    "missed_call_id": missed_call_id,
                    "status": normalized_status,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            self._log_audit_event(
                event_type="call.missed_call.status_update",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"missed_call_id": missed_call_id, "status": normalized_status},
            )

            return self._safe_result(
                message="Missed-call status updated successfully.",
                data={
                    "missed_call": copy.deepcopy(updated),
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to update missed-call status.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def list_missed_calls(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        callback_requested: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List workspace-scoped missed calls."""

        return self._list_records(
            store=self._missed_calls,
            record_label="missed_calls",
            user_id=user_id,
            workspace_id=workspace_id,
            status=status,
            status_enum=MissedCallStatus,
            priority=priority,
            callback_requested=callback_requested,
            limit=limit,
            offset=offset,
            operation="list_missed_calls",
        )

    # ------------------------------------------------------------------
    # Public API: callback reminders
    # ------------------------------------------------------------------

    def schedule_callback_reminder(
        self,
        *,
        user_id: str,
        workspace_id: str,
        related_record_type: str,
        related_record_id: str,
        scheduled_for: Optional[Union[str, datetime]] = None,
        delay_minutes: Optional[int] = None,
        assigned_to: Optional[str] = None,
        priority: str = CallbackPriority.NORMAL.value,
        callback_script_hint: Optional[str] = None,
        reminder_note: Optional[str] = None,
        max_attempts: int = 3,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Schedule a callback reminder from a voicemail or missed-call record.

        This prepares reminder records only. It does not place a callback.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="schedule_callback_reminder",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            normalized_record_type = self._normalize_enum(
                related_record_type,
                RecordType,
                "related_record_type",
            )
            if normalized_record_type == RecordType.CALLBACK_REMINDER.value:
                return self._error_result(
                    message="Callback reminders cannot be created from callback reminders.",
                    error="invalid_related_record_type",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            related_record = self._find_related_call_record(
                record_type=normalized_record_type,
                record_id=related_record_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not related_record:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=normalized_record_type,
                )

            if max_attempts < 1 or max_attempts > MAX_REMINDER_ATTEMPTS:
                return self._error_result(
                    message="Invalid max_attempts value.",
                    error=f"max_attempts must be between 1 and {MAX_REMINDER_ATTEMPTS}.",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            scheduled_iso = self._resolve_schedule_time(
                scheduled_for=scheduled_for,
                delay_minutes=delay_minutes,
            )

            reminder_id = self._generate_record_id(
                prefix="cb",
                user_id=user_id,
                workspace_id=workspace_id,
                source=f"{normalized_record_type}:{related_record_id}:{scheduled_iso}",
            )

            caller_data = related_record["caller"]
            now = datetime.now(timezone.utc).isoformat()

            reminder = CallbackReminder(
                reminder_id=reminder_id,
                user_id=user_id,
                workspace_id=workspace_id,
                caller=CallerIdentity(**caller_data),
                related_record_type=normalized_record_type,
                related_record_id=related_record_id,
                scheduled_for=scheduled_iso,
                status=CallbackReminderStatus.PENDING.value,
                priority=self._normalize_enum(priority, CallbackPriority, "priority"),
                assigned_to=self._clean_text(assigned_to, max_length=160),
                callback_script_hint=self._clean_text(callback_script_hint, max_length=MAX_NOTE_LENGTH),
                attempt_count=0,
                max_attempts=max_attempts,
                reminder_note=self._clean_text(reminder_note, max_length=MAX_NOTE_LENGTH),
                requires_security_approval=True,
                security_approval_id=None,
                metadata=self._safe_metadata(metadata or {}),
                created_at=now,
                updated_at=now,
            ).to_dict()

            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="schedule_callback_reminder",
                payload={
                    "reminder_id": reminder_id,
                    "related_record_type": normalized_record_type,
                    "related_record_id": related_record_id,
                    "scheduled_for": scheduled_iso,
                    "priority": priority,
                    "risk_level": RiskLevel.HIGH.value,
                },
            )

            if approval.get("approved", False):
                reminder["security_approval_id"] = approval.get("approval_id") or approval.get("request", {}).get("request_id")
            else:
                reminder.setdefault("metadata", {})["security_approval"] = approval

            self._callback_reminders[reminder_id] = reminder

            self._mark_related_record_callback_scheduled(
                record_type=normalized_record_type,
                record_id=related_record_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type="call_callback_reminder_scheduled",
                data={
                    "reminder_id": reminder_id,
                    "related_record_type": normalized_record_type,
                    "related_record_id": related_record_id,
                    "scheduled_for": scheduled_iso,
                    "priority": priority,
                    "assigned_to": assigned_to,
                },
            )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="schedule_callback_reminder",
                data={
                    "reminder_id": reminder_id,
                    "related_record_type": normalized_record_type,
                    "related_record_id": related_record_id,
                    "security_approval_requested": True,
                    "security_approved": bool(approval.get("approved", False)),
                },
            )

            self._emit_agent_event(
                "callback_reminder.scheduled",
                {
                    "reminder_id": reminder_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "scheduled_for": scheduled_iso,
                    "security_approved": bool(approval.get("approved", False)),
                },
            )
            self._log_audit_event(
                event_type="call.callback_reminder.schedule",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "reminder_id": reminder_id,
                    "related_record_type": normalized_record_type,
                    "related_record_id": related_record_id,
                    "scheduled_for": scheduled_iso,
                    "security_approved": bool(approval.get("approved", False)),
                },
            )

            return self._safe_result(
                message="Callback reminder scheduled successfully.",
                data={
                    "callback_reminder": copy.deepcopy(reminder),
                    "security_approval": approval,
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to schedule callback reminder.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def list_callback_reminders(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        due_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List workspace-scoped callback reminders."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="list_callback_reminders",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            normalized_status = (
                self._normalize_enum(status, CallbackReminderStatus, "status")
                if status
                else None
            )
            normalized_priority = (
                self._normalize_enum(priority, CallbackPriority, "priority")
                if priority
                else None
            )

            now = datetime.now(timezone.utc)
            records = []

            for record in self._callback_reminders.values():
                if record.get("user_id") != user_id or record.get("workspace_id") != workspace_id:
                    continue
                if normalized_status and record.get("status") != normalized_status:
                    continue
                if normalized_priority and record.get("priority") != normalized_priority:
                    continue
                if due_only:
                    scheduled = self._parse_datetime(record.get("scheduled_for"))
                    if not scheduled or scheduled > now:
                        continue
                records.append(copy.deepcopy(record))

            records.sort(key=lambda item: item.get("scheduled_for") or "")
            total = len(records)
            page = records[max(0, offset): max(0, offset) + max(1, min(limit, 200))]

            self._log_audit_event(
                event_type="call.callback_reminder.list",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "count": len(page),
                    "total": total,
                    "status": normalized_status,
                    "due_only": due_only,
                },
            )

            return self._safe_result(
                message="Callback reminders listed successfully.",
                data={
                    "callback_reminders": page,
                    "count": len(page),
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "due_only": due_only,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to list callback reminders.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def prepare_callback_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        reminder_id: str,
        mark_ready: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare a callback action payload for the Call Agent.

        This method does NOT place the call. It creates a security-aware payload
        that appointment_booker/contact_router/call_agent can later use after
        permissions and business rules are verified.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="prepare_callback_payload",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            reminder = self._get_scoped_record(
                store=self._callback_reminders,
                record_id=reminder_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not reminder:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=RecordType.CALLBACK_REMINDER.value,
                )

            if reminder.get("status") in {
                CallbackReminderStatus.CANCELLED.value,
                CallbackReminderStatus.COMPLETED.value,
                CallbackReminderStatus.EXPIRED.value,
            }:
                return self._error_result(
                    message="Callback reminder is not actionable.",
                    error="reminder_not_actionable",
                    data={"status": reminder.get("status")},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            if int(reminder.get("attempt_count", 0)) >= int(reminder.get("max_attempts", 3)):
                updated = copy.deepcopy(reminder)
                updated["status"] = CallbackReminderStatus.EXPIRED.value
                updated["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._callback_reminders[reminder_id] = updated
                return self._error_result(
                    message="Callback reminder exceeded maximum attempts.",
                    error="max_attempts_exceeded",
                    data={"callback_reminder": updated},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="prepare_callback_payload",
                payload={
                    "reminder_id": reminder_id,
                    "phone_number": reminder.get("caller", {}).get("phone_number"),
                    "risk_level": RiskLevel.HIGH.value,
                    "reason": "Preparing outbound callback payload.",
                },
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval required before preparing callback payload.",
                    error="security_approval_required",
                    data={"security_approval": approval},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            callback_payload = {
                "callback_payload_id": f"call_cb_{uuid.uuid4().hex}",
                "source_agent": self.agent_name,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "reminder_id": reminder_id,
                "caller": copy.deepcopy(reminder.get("caller", {})),
                "assigned_to": reminder.get("assigned_to"),
                "priority": reminder.get("priority"),
                "related_record_type": reminder.get("related_record_type"),
                "related_record_id": reminder.get("related_record_id"),
                "script_hint": reminder.get("callback_script_hint"),
                "reminder_note": reminder.get("reminder_note"),
                "security_approval": approval,
                "mode": "prepare_only",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            updated = copy.deepcopy(reminder)
            if mark_ready:
                updated["status"] = CallbackReminderStatus.READY.value
            updated["security_approval_id"] = (
                approval.get("approval_id")
                or approval.get("request", {}).get("request_id")
                or updated.get("security_approval_id")
            )
            updated["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._callback_reminders[reminder_id] = updated

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="prepare_callback_payload",
                data={
                    "reminder_id": reminder_id,
                    "callback_payload_id": callback_payload["callback_payload_id"],
                    "security_approved": True,
                },
            )

            self._emit_agent_event(
                "callback_payload.prepared",
                {
                    "reminder_id": reminder_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            self._log_audit_event(
                event_type="call.callback_payload.prepare",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "reminder_id": reminder_id,
                    "callback_payload_id": callback_payload["callback_payload_id"],
                    "security_approved": True,
                },
            )

            return self._safe_result(
                message="Callback payload prepared successfully.",
                data={
                    "callback_payload": callback_payload,
                    "callback_reminder": copy.deepcopy(updated),
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to prepare callback payload.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def complete_callback_reminder(
        self,
        *,
        user_id: str,
        workspace_id: str,
        reminder_id: str,
        outcome: Optional[str] = None,
        note: Optional[str] = None,
        increment_attempt: bool = True,
    ) -> Dict[str, Any]:
        """Mark a callback reminder completed after an approved call flow."""

        return self._finalize_callback_reminder(
            user_id=user_id,
            workspace_id=workspace_id,
            reminder_id=reminder_id,
            status=CallbackReminderStatus.COMPLETED.value,
            outcome=outcome,
            note=note,
            increment_attempt=increment_attempt,
            operation="complete_callback_reminder",
        )

    def cancel_callback_reminder(
        self,
        *,
        user_id: str,
        workspace_id: str,
        reminder_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a callback reminder without deleting history."""

        return self._finalize_callback_reminder(
            user_id=user_id,
            workspace_id=workspace_id,
            reminder_id=reminder_id,
            status=CallbackReminderStatus.CANCELLED.value,
            outcome="cancelled",
            note=reason,
            increment_attempt=False,
            operation="cancel_callback_reminder",
        )

    # ------------------------------------------------------------------
    # Public API: retrieval, dashboard, export
    # ------------------------------------------------------------------

    def get_record(
        self,
        *,
        user_id: str,
        workspace_id: str,
        record_type: str,
        record_id: str,
    ) -> Dict[str, Any]:
        """Get a scoped voicemail, missed call, or callback reminder."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="get_record",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            normalized_type = self._normalize_enum(record_type, RecordType, "record_type")
            store = self._store_for_record_type(normalized_type)
            record = self._get_scoped_record(
                store=store,
                record_id=record_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            if not record:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=normalized_type,
                )

            self._log_audit_event(
                event_type="call.voicemail_handler.get_record",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"record_type": normalized_type, "record_id": record_id},
            )

            return self._safe_result(
                message="Record loaded successfully.",
                data={"record_type": normalized_type, "record": copy.deepcopy(record)},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to get record.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def build_dashboard_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """
        Build dashboard/API summary payload.

        Designed for Call Agent dashboard cards, notification panels, and
        workspace analytics.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="build_dashboard_payload",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            scoped_voicemails = self._scoped_records(self._voicemails, user_id, workspace_id)
            scoped_missed = self._scoped_records(self._missed_calls, user_id, workspace_id)
            scoped_reminders = self._scoped_records(self._callback_reminders, user_id, workspace_id)

            now = datetime.now(timezone.utc)
            due_reminders = [
                reminder for reminder in scoped_reminders
                if reminder.get("status") in {
                    CallbackReminderStatus.PENDING.value,
                    CallbackReminderStatus.READY.value,
                }
                and self._parse_datetime(reminder.get("scheduled_for"))
                and self._parse_datetime(reminder.get("scheduled_for")) <= now
            ]

            payload = {
                "summary": {
                    "voicemails_total": len(scoped_voicemails),
                    "voicemails_new": self._count_by_status(scoped_voicemails, VoicemailStatus.NEW.value),
                    "missed_calls_total": len(scoped_missed),
                    "missed_calls_new": self._count_by_status(scoped_missed, MissedCallStatus.NEW.value),
                    "callback_reminders_total": len(scoped_reminders),
                    "callback_reminders_due": len(due_reminders),
                    "urgent_callbacks": len(
                        [
                            reminder for reminder in scoped_reminders
                            if reminder.get("priority") == CallbackPriority.URGENT.value
                            and reminder.get("status") in {
                                CallbackReminderStatus.PENDING.value,
                                CallbackReminderStatus.READY.value,
                            }
                        ]
                    ),
                },
                "latest_voicemails": sorted(
                    scoped_voicemails,
                    key=lambda item: item.get("created_at") or "",
                    reverse=True,
                )[:10],
                "latest_missed_calls": sorted(
                    scoped_missed,
                    key=lambda item: item.get("created_at") or "",
                    reverse=True,
                )[:10],
                "due_callback_reminders": sorted(
                    due_reminders,
                    key=lambda item: item.get("scheduled_for") or "",
                )[:10],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            return self._safe_result(
                message="Voicemail dashboard payload prepared successfully.",
                data=payload,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build voicemail dashboard payload.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def export_records(
        self,
        *,
        user_id: str,
        workspace_id: str,
        record_type: Optional[str] = None,
        export_format: str = "dict",
    ) -> Dict[str, Any]:
        """Export scoped records as dict or JSON for dashboard/API backup."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="export_records",
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            export_format = export_format.strip().lower()
            if export_format not in {"dict", "json"}:
                return self._error_result(
                    message="Unsupported export format.",
                    error="export_format must be 'dict' or 'json'.",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            payload: Dict[str, Any] = {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "exported_at": datetime.now(timezone.utc).isoformat(),
            }

            if record_type:
                normalized_type = self._normalize_enum(record_type, RecordType, "record_type")
                store = self._store_for_record_type(normalized_type)
                payload[normalized_type] = self._scoped_records(store, user_id, workspace_id)
            else:
                payload["voicemails"] = self._scoped_records(self._voicemails, user_id, workspace_id)
                payload["missed_calls"] = self._scoped_records(self._missed_calls, user_id, workspace_id)
                payload["callback_reminders"] = self._scoped_records(
                    self._callback_reminders,
                    user_id,
                    workspace_id,
                )

            exported: Union[Dict[str, Any], str]
            exported = json.dumps(payload, indent=2, sort_keys=True) if export_format == "json" else payload

            self._log_audit_event(
                event_type="call.voicemail_handler.export",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"record_type": record_type, "export_format": export_format},
            )

            return self._safe_result(
                message="Records exported successfully.",
                data={"export_format": export_format, "export": exported},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to export records.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def health_check(self) -> Dict[str, Any]:
        """Agent Registry / Loader compatible health check."""

        try:
            return self._safe_result(
                message="VoicemailHandler health check passed.",
                data={
                    "healthy": True,
                    "voicemail_count": len(self._voicemails),
                    "missed_call_count": len(self._missed_calls),
                    "callback_reminder_count": len(self._callback_reminders),
                    "safe_to_import": True,
                    "executes_external_actions": False,
                },
                metadata=self._base_metadata(),
            )
        except Exception as exc:
            return self._error_result(
                message="VoicemailHandler health check failed.",
                error=exc,
                metadata=self._base_metadata(),
            )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        operation: str,
        require_context: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        All runtime records must be scoped by user_id and workspace_id.
        """

        errors: List[str] = []

        if require_context:
            if not self._is_safe_identifier(user_id):
                errors.append("A valid user_id is required.")
            if not self._is_safe_identifier(workspace_id):
                errors.append("A valid workspace_id is required.")

        if errors:
            return self._error_result(
                message="Invalid Call Agent task context.",
                error={"context_errors": errors},
                data={"operation": operation},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

        return self._safe_result(
            message="Call Agent task context validated.",
            data={
                "operation": operation,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "context_required": require_context,
            },
            metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
        )

    def _requires_security_check(self, payload: Mapping[str, Any]) -> bool:
        """
        Decide whether Security Agent approval is required.

        Any callback preparation, outbound call intent, external message action,
        or high-risk operation must be security-gated.
        """

        action = str(payload.get("action") or "").lower()
        risk_level = str(payload.get("risk_level") or RiskLevel.LOW.value).lower()

        if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
            return True

        sensitive_actions = {
            "schedule_callback_reminder",
            "prepare_callback_payload",
            "outbound_callback",
            "send_sms",
            "send_whatsapp",
            "send_email",
            "make_call",
            "delete_record",
            "export_records",
        }

        if action in sensitive_actions:
            return True

        if payload.get("phone_number"):
            return True

        return False

    def _request_security_approval(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        action: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a security client is injected, it is used. Otherwise fallback approval
        grants low/medium-risk internal record actions but blocks high/critical
        outbound-contact preparation.
        """

        request = {
            "request_id": f"sec_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": self._redact_value(copy.deepcopy(dict(payload))),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.security_client and hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(request)
                if isinstance(response, Mapping):
                    return dict(response)

            requires_approval = self._requires_security_check(
                {
                    "action": action,
                    **dict(payload),
                }
            )
            risk_level = str(payload.get("risk_level") or RiskLevel.LOW.value).lower()

            approved = not (
                requires_approval and risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}
            )

            return {
                "approved": approved,
                "approval_required": not approved,
                "mode": "fallback",
                "request": request,
                "message": (
                    "Fallback security approval granted."
                    if approved
                    else "Security approval required for outbound or high-risk call action."
                ),
            }
        except Exception as exc:
            self.logger.exception("Security approval request failed: %s", exc)
            return {
                "approved": False,
                "approval_required": True,
                "mode": "error",
                "request": request,
                "error": str(exc),
            }

    def _prepare_verification_payload(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        action: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This payload verifies SaaS isolation, permission gating, and record
        preparation after voicemail/missed-call/reminder operations.
        """

        payload = {
            "verification_id": f"ver_{uuid.uuid4().hex}",
            "source_agent": self.agent_name,
            "source_agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": self._redact_value(copy.deepcopy(dict(data))),
            "checks": [
                "user_workspace_context_validated",
                "record_scope_enforced",
                "security_gate_considered",
                "no_direct_outbound_action_executed",
                "memory_payload_prepared_when_relevant",
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.verification_client and hasattr(self.verification_client, "prepare"):
                response = self.verification_client.prepare(payload)
                if isinstance(response, Mapping):
                    return dict(response)
        except Exception as exc:
            self.logger.warning("Verification client failed: %s", exc)

        return payload

    def _prepare_memory_payload(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        memory_type: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not force-write memory. It prepares a clean payload for
        call_memory.py or Memory Agent to store later.
        """

        payload = {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "source_agent": self.agent_name,
            "source_agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "memory_type": memory_type,
            "privacy_scope": "workspace",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": self._redact_value(copy.deepcopy(dict(data))),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.memory_client and hasattr(self.memory_client, "prepare_memory"):
                response = self.memory_client.prepare_memory(payload)
                if isinstance(response, Mapping):
                    return dict(response)
        except Exception as exc:
            self.logger.warning("Memory client failed: %s", exc)

        return payload

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit Agent Registry / dashboard-compatible event.

        This is non-fatal by design.
        """

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "payload": self._redact_value(copy.deepcopy(dict(payload))),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event_name, event)
                return
            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, event)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.debug("Agent event emitted: %s | %s", event_name, event)
        except Exception as exc:
            self.logger.warning("Failed to emit agent event: %s", exc)

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Audit entries preserve tenant boundaries and redact sensitive values.
        """

        audit = {
            "audit_id": f"aud_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "details": self._redact_value(copy.deepcopy(dict(details or {}))),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit)
                return
            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(audit)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.info("Audit event: %s", audit)
        except Exception as exc:
            self.logger.warning("Failed to log audit event: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Return structured success result."""

        return {
            "success": bool(success),
            "message": message,
            "data": copy.deepcopy(dict(data or {})),
            "error": error,
            "metadata": copy.deepcopy(dict(metadata or self._base_metadata())),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured error result."""

        if isinstance(error, Exception):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": copy.deepcopy(dict(data or {})),
            "error": error_payload,
            "metadata": copy.deepcopy(dict(metadata or self._base_metadata())),
        }

    # ------------------------------------------------------------------
    # Internal workflow helpers
    # ------------------------------------------------------------------

    def _finalize_callback_reminder(
        self,
        *,
        user_id: str,
        workspace_id: str,
        reminder_id: str,
        status: str,
        outcome: Optional[str],
        note: Optional[str],
        increment_attempt: bool,
        operation: str,
    ) -> Dict[str, Any]:
        """Shared completion/cancellation logic for callback reminders."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation=operation,
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            reminder = self._get_scoped_record(
                store=self._callback_reminders,
                record_id=reminder_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not reminder:
                return self._not_found_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_type=RecordType.CALLBACK_REMINDER.value,
                )

            normalized_status = self._normalize_enum(status, CallbackReminderStatus, "status")
            updated = copy.deepcopy(reminder)
            updated["status"] = normalized_status
            updated["updated_at"] = datetime.now(timezone.utc).isoformat()

            if increment_attempt:
                updated["attempt_count"] = int(updated.get("attempt_count", 0)) + 1

            history = updated.setdefault("metadata", {}).setdefault("history", [])
            history.append(
                {
                    "operation": operation,
                    "status": normalized_status,
                    "outcome": self._clean_text(outcome, max_length=500),
                    "note": self._clean_text(note, max_length=MAX_NOTE_LENGTH),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )

            self._callback_reminders[reminder_id] = updated
            self._mark_related_record_callback_finalized(updated)

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type=f"call_callback_reminder_{normalized_status}",
                data={
                    "reminder_id": reminder_id,
                    "related_record_type": updated.get("related_record_type"),
                    "related_record_id": updated.get("related_record_id"),
                    "outcome": outcome,
                    "note": note,
                },
            )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action=operation,
                data={
                    "reminder_id": reminder_id,
                    "status": normalized_status,
                    "attempt_count": updated.get("attempt_count"),
                },
            )

            self._emit_agent_event(
                f"callback_reminder.{normalized_status}",
                {
                    "reminder_id": reminder_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "status": normalized_status,
                },
            )
            self._log_audit_event(
                event_type=f"call.callback_reminder.{normalized_status}",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "reminder_id": reminder_id,
                    "status": normalized_status,
                    "outcome": outcome,
                },
            )

            return self._safe_result(
                message=f"Callback reminder marked as {normalized_status}.",
                data={
                    "callback_reminder": copy.deepcopy(updated),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to finalize callback reminder.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def _mark_related_record_callback_scheduled(
        self,
        *,
        record_type: str,
        record_id: str,
        user_id: str,
        workspace_id: str,
    ) -> None:
        """Update related voicemail/missed-call status after scheduling callback."""

        if record_type == RecordType.VOICEMAIL.value:
            store = self._voicemails
            status = VoicemailStatus.CALLBACK_SCHEDULED.value
        elif record_type == RecordType.MISSED_CALL.value:
            store = self._missed_calls
            status = MissedCallStatus.CALLBACK_SCHEDULED.value
        else:
            return

        record = self._get_scoped_record(
            store=store,
            record_id=record_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not record:
            return

        updated = copy.deepcopy(record)
        updated["status"] = status
        updated["callback_requested"] = True
        updated["updated_at"] = datetime.now(timezone.utc).isoformat()
        store[record_id] = updated

    def _mark_related_record_callback_finalized(self, reminder: Mapping[str, Any]) -> None:
        """Update related voicemail/missed-call after callback completion."""

        related_type = reminder.get("related_record_type")
        related_id = reminder.get("related_record_id")
        user_id = reminder.get("user_id")
        workspace_id = reminder.get("workspace_id")

        if not related_type or not related_id or not user_id or not workspace_id:
            return

        if reminder.get("status") != CallbackReminderStatus.COMPLETED.value:
            return

        if related_type == RecordType.VOICEMAIL.value:
            store = self._voicemails
            status = VoicemailStatus.CALLBACK_COMPLETED.value
        elif related_type == RecordType.MISSED_CALL.value:
            store = self._missed_calls
            status = MissedCallStatus.CALLBACK_COMPLETED.value
        else:
            return

        record = self._get_scoped_record(
            store=store,
            record_id=str(related_id),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
        )
        if not record:
            return

        updated = copy.deepcopy(record)
        updated["status"] = status
        updated["updated_at"] = datetime.now(timezone.utc).isoformat()
        store[str(related_id)] = updated

    # ------------------------------------------------------------------
    # Store and list helpers
    # ------------------------------------------------------------------

    def _load_initial_store(self, initial_store: Mapping[str, Any]) -> None:
        """Load optional initial store safely."""

        for key, target in (
            ("voicemails", self._voicemails),
            ("missed_calls", self._missed_calls),
            ("callback_reminders", self._callback_reminders),
        ):
            raw_records = initial_store.get(key, {})
            if isinstance(raw_records, Mapping):
                for record_id, record in raw_records.items():
                    if isinstance(record, Mapping):
                        target[str(record_id)] = copy.deepcopy(dict(record))

    def _store_for_record_type(self, record_type: str) -> Dict[str, Dict[str, Any]]:
        """Return internal store for record type."""

        if record_type == RecordType.VOICEMAIL.value:
            return self._voicemails
        if record_type == RecordType.MISSED_CALL.value:
            return self._missed_calls
        if record_type == RecordType.CALLBACK_REMINDER.value:
            return self._callback_reminders
        raise ValueError(f"Unsupported record_type: {record_type}")

    def _find_related_call_record(
        self,
        *,
        record_type: str,
        record_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Find a voicemail or missed-call related record."""

        store = self._store_for_record_type(record_type)
        return self._get_scoped_record(
            store=store,
            record_id=record_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )

    def _get_scoped_record(
        self,
        *,
        store: Mapping[str, Dict[str, Any]],
        record_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Return record only if it belongs to the user/workspace."""

        record = store.get(str(record_id))
        if not record:
            return None
        if record.get("user_id") != user_id or record.get("workspace_id") != workspace_id:
            return None
        return copy.deepcopy(record)

    def _scoped_records(
        self,
        store: Mapping[str, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
    ) -> List[Dict[str, Any]]:
        """Return all records scoped to the user/workspace."""

        return [
            copy.deepcopy(record)
            for record in store.values()
            if record.get("user_id") == user_id and record.get("workspace_id") == workspace_id
        ]

    def _list_records(
        self,
        *,
        store: Mapping[str, Dict[str, Any]],
        record_label: str,
        user_id: str,
        workspace_id: str,
        status: Optional[str],
        status_enum: Any,
        priority: Optional[str],
        callback_requested: Optional[bool],
        limit: int,
        offset: int,
        operation: str,
    ) -> Dict[str, Any]:
        """Shared list logic for voicemails and missed calls."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation=operation,
            require_context=True,
        )
        if not context["success"]:
            return context

        try:
            normalized_status = self._normalize_enum(status, status_enum, "status") if status else None
            normalized_priority = self._normalize_enum(priority, CallbackPriority, "priority") if priority else None

            records = []
            for record in store.values():
                if record.get("user_id") != user_id or record.get("workspace_id") != workspace_id:
                    continue
                if normalized_status and record.get("status") != normalized_status:
                    continue
                if normalized_priority and record.get("priority") != normalized_priority:
                    continue
                if callback_requested is not None and bool(record.get("callback_requested")) != bool(callback_requested):
                    continue
                records.append(copy.deepcopy(record))

            records.sort(key=lambda item: item.get("created_at") or "", reverse=True)
            total = len(records)
            safe_limit = max(1, min(limit, 200))
            safe_offset = max(0, offset)
            page = records[safe_offset: safe_offset + safe_limit]

            self._log_audit_event(
                event_type=f"call.{record_label}.list",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "count": len(page),
                    "total": total,
                    "status": normalized_status,
                    "priority": normalized_priority,
                    "callback_requested": callback_requested,
                },
            )

            return self._safe_result(
                message=f"{record_label.replace('_', ' ').title()} listed successfully.",
                data={
                    record_label: page,
                    "count": len(page),
                    "total": total,
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message=f"Failed to list {record_label}.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def _not_found_result(
        self,
        *,
        user_id: str,
        workspace_id: str,
        record_type: str,
    ) -> Dict[str, Any]:
        """Standard not-found result."""

        return self._error_result(
            message="Record not found or not accessible in this workspace.",
            error="record_not_found",
            data={"record_type": record_type},
            metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
        )

    # ------------------------------------------------------------------
    # Validation and normalization helpers
    # ------------------------------------------------------------------

    def _normalize_caller(
        self,
        caller: Union[CallerIdentity, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Normalize and validate caller identity."""

        try:
            data = caller.to_dict() if isinstance(caller, CallerIdentity) else copy.deepcopy(dict(caller))
            phone_number = self._clean_text(data.get("phone_number"), max_length=MAX_PHONE_LENGTH)

            if not phone_number:
                return self._error_result(
                    message="Caller phone_number is required.",
                    error="missing_phone_number",
                    metadata=self._base_metadata(),
                )

            if not PHONE_SAFE_PATTERN.match(phone_number):
                return self._error_result(
                    message="Caller phone_number has invalid format.",
                    error="invalid_phone_number",
                    metadata=self._base_metadata(),
                )

            normalized = {
                "phone_number": phone_number,
                "caller_name": self._clean_text(data.get("caller_name"), max_length=MAX_CALLER_NAME_LENGTH),
                "caller_id": self._clean_text(data.get("caller_id"), max_length=160),
                "company": self._clean_text(data.get("company"), max_length=160),
                "email": self._clean_text(data.get("email"), max_length=255),
                "country": self._clean_text(data.get("country"), max_length=80),
                "timezone_hint": self._clean_text(data.get("timezone_hint"), max_length=100),
            }

            return self._safe_result(
                message="Caller normalized successfully.",
                data={"caller": normalized},
                metadata=self._base_metadata(),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to normalize caller.",
                error=exc,
                metadata=self._base_metadata(),
            )

    def _validate_voicemail_fields(
        self,
        *,
        transcript: Optional[str],
        audio_reference: Optional[str],
        duration_seconds: Optional[int],
        priority: str,
        tags: Optional[Sequence[str]],
    ) -> List[str]:
        """Validate voicemail-specific fields."""

        errors: List[str] = []

        if not transcript and not audio_reference:
            errors.append("Either transcript or audio_reference is required.")

        if transcript and len(transcript) > MAX_TRANSCRIPT_LENGTH:
            errors.append(f"transcript must be <= {MAX_TRANSCRIPT_LENGTH} characters.")

        if duration_seconds is not None and duration_seconds < 0:
            errors.append("duration_seconds cannot be negative.")

        try:
            self._normalize_enum(priority, CallbackPriority, "priority")
        except ValueError as exc:
            errors.append(str(exc))

        if tags and len(tags) > MAX_TAGS:
            errors.append(f"tags must be <= {MAX_TAGS}.")

        return errors

    def _validate_missed_call_fields(
        self,
        *,
        note: Optional[str],
        reason: Optional[str],
        priority: str,
        tags: Optional[Sequence[str]],
    ) -> List[str]:
        """Validate missed-call fields."""

        errors: List[str] = []

        if note and len(note) > MAX_NOTE_LENGTH:
            errors.append(f"note must be <= {MAX_NOTE_LENGTH} characters.")

        if reason and len(reason) > 500:
            errors.append("reason must be <= 500 characters.")

        try:
            self._normalize_enum(priority, CallbackPriority, "priority")
        except ValueError as exc:
            errors.append(str(exc))

        if tags and len(tags) > MAX_TAGS:
            errors.append(f"tags must be <= {MAX_TAGS}.")

        return errors

    def _resolve_schedule_time(
        self,
        *,
        scheduled_for: Optional[Union[str, datetime]],
        delay_minutes: Optional[int],
    ) -> str:
        """Resolve callback reminder scheduled time to UTC ISO string."""

        if scheduled_for:
            if isinstance(scheduled_for, datetime):
                dt = scheduled_for
            else:
                dt = self._parse_datetime(str(scheduled_for))
                if not dt:
                    raise ValueError("scheduled_for must be a valid ISO datetime string.")

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()

        minutes = delay_minutes if delay_minutes is not None else DEFAULT_CALLBACK_DELAY_MINUTES
        if minutes < 0:
            raise ValueError("delay_minutes cannot be negative.")

        return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()

    def _parse_datetime(self, value: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime safely."""

        if not value:
            return None

        try:
            normalized = str(value).replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    def _normalize_enum(self, value: Optional[str], enum_cls: Any, field_name: str) -> str:
        """Normalize enum value or raise ValueError."""

        normalized = str(value or "").strip().lower()
        allowed = {item.value for item in enum_cls}
        if normalized not in allowed:
            raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}.")
        return normalized

    def _normalize_tags(self, tags: Sequence[str]) -> List[str]:
        """Normalize tag list."""

        normalized: List[str] = []
        seen = set()

        for tag in tags:
            clean = re.sub(r"\s+", "-", str(tag).strip().lower())
            clean = re.sub(r"[^a-z0-9_.-]", "", clean)
            if not clean or clean in seen:
                continue
            seen.add(clean)
            normalized.append(clean)

        return normalized[:MAX_TAGS]

    def _safe_metadata(self, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        """Return redacted JSON-safe metadata."""

        try:
            safe = json.loads(json.dumps(dict(metadata), default=str))
        except Exception:
            safe = {"raw_metadata": str(metadata)}
        return self._redact_value(safe)

    def _clean_text(self, value: Any, *, max_length: int) -> Optional[str]:
        """Normalize text fields safely."""

        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return text[:max_length]

    def _is_safe_identifier(self, value: Optional[str]) -> bool:
        """Validate tenant/user identifier."""

        if not value or not isinstance(value, str):
            return False
        if len(value) > 160:
            return False
        return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.:@-]*$", value))

    def _generate_record_id(
        self,
        *,
        prefix: str,
        user_id: str,
        workspace_id: str,
        source: str,
    ) -> str:
        """Generate collision-resistant record ID."""

        seed = f"{prefix}:{user_id}:{workspace_id}:{source}:{time.time()}:{uuid.uuid4().hex}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:18]
        return f"{prefix}_{digest}"

    def _count_by_status(self, records: Sequence[Mapping[str, Any]], status: str) -> int:
        """Count records by status."""

        return len([record for record in records if record.get("status") == status])

    def _base_metadata(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return common metadata."""

        return {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Redaction helpers
    # ------------------------------------------------------------------

    def _redact_caller_for_memory(self, caller: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Redact caller details for memory payload while preserving useful context.

        Phone is partially masked because memory should not expose full PII unless
        a dedicated Memory Agent policy allows it.
        """

        phone = str(caller.get("phone_number") or "")
        masked_phone = self._mask_phone(phone)

        return {
            "phone_number_masked": masked_phone,
            "caller_name": caller.get("caller_name"),
            "company": caller.get("company"),
            "country": caller.get("country"),
            "timezone_hint": caller.get("timezone_hint"),
        }

    def _mask_phone(self, phone: str) -> str:
        """Mask phone number for memory/audit summaries."""

        digits = re.sub(r"\D", "", phone)
        if len(digits) <= 4:
            return "***"
        return f"***{digits[-4:]}"

    def _redact_value(self, value: Any) -> Any:
        """Recursively redact sensitive values."""

        if isinstance(value, Mapping):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                key_str = str(key)
                if self._looks_sensitive_key(key_str):
                    redacted[key_str] = "***REDACTED***"
                elif key_str.lower() in {"phone", "phone_number", "caller_phone"}:
                    redacted[key_str] = self._mask_phone(str(item))
                else:
                    redacted[key_str] = self._redact_value(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_value(item) for item in value]

        return value

    def _looks_sensitive_key(self, key: str) -> bool:
        """Detect sensitive metadata keys."""

        lowered = key.lower()
        sensitive_fragments = [
            "secret",
            "token",
            "password",
            "api_key",
            "apikey",
            "private_key",
            "auth",
            "credential",
            "access_key",
            "refresh",
        ]
        return any(fragment in lowered for fragment in sensitive_fragments)


# ---------------------------------------------------------------------------
# Agent Loader / Registry hooks
# ---------------------------------------------------------------------------

def get_agent() -> VoicemailHandler:
    """
    Agent Loader compatible factory.

    Allows dynamic loading by Agent Registry without knowing constructor args.
    """

    return VoicemailHandler()


def get_module_metadata() -> Dict[str, Any]:
    """
    Agent Registry metadata.

    Used by Master Agent, dashboard, health checks, and plugin discovery.
    """

    return {
        "module": MODULE_NAME,
        "file": FILE_NAME,
        "class_name": AGENT_NAME,
        "agent_id": "voicemail_handler",
        "purpose": "Handles voicemail, missed-call notes, callback reminders.",
        "safe_to_import": True,
        "executes_external_actions": False,
        "requires_user_workspace_context": True,
        "compatible_with": [
            "BaseAgent",
            "AgentRegistry",
            "AgentLoader",
            "AgentRouter",
            "MasterAgent",
            "SecurityAgent",
            "VerificationAgent",
            "MemoryAgent",
            "CallAgent",
            "CallListener",
            "CallTranscriber",
            "ReceptionistMode",
            "DashboardAPI",
            "FastAPI",
        ],
        "public_methods": [
            "record_voicemail",
            "record_missed_call",
            "add_missed_call_note",
            "schedule_callback_reminder",
            "list_voicemails",
            "list_missed_calls",
            "list_callback_reminders",
            "get_record",
            "update_voicemail_status",
            "update_missed_call_status",
            "complete_callback_reminder",
            "cancel_callback_reminder",
            "prepare_callback_payload",
            "build_dashboard_payload",
            "export_records",
            "health_check",
        ],
        "record_types": [item.value for item in RecordType],
        "statuses": {
            "voicemail": [item.value for item in VoicemailStatus],
            "missed_call": [item.value for item in MissedCallStatus],
            "callback_reminder": [item.value for item in CallbackReminderStatus],
        },
        "completion": {
            "agent_module": "Call Agent",
            "file_completed": "voicemail_handler.py",
            "completion_percent": 58.3,
        },
    }


__all__ = [
    "VoicemailHandler",
    "CallerIdentity",
    "VoicemailRecord",
    "MissedCallNote",
    "CallbackReminder",
    "VoicemailStatus",
    "MissedCallStatus",
    "CallbackReminderStatus",
    "CallbackPriority",
    "RiskLevel",
    "RecordType",
    "get_agent",
    "get_module_metadata",
]