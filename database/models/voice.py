"""
database/models/voice.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 9 — User-Based Admin Voice Agent + Wake Word + Voice Identity + Multilingual
MasterAgent Handoff.

Purpose:
- Per-workspace voice runtime settings (mode, wake word, requires-approval state).
- Trusted voice identity/permission profiles -- who is allowed to speak commands
  into this workspace and what they're allowed to do. This is a DIFFERENT concept
  from agents/voice_agent/voice_profiles.py's VoiceProfile (which stores HOW a
  user's voice sounds/behaves -- persona, TTS voice, speed/pitch). This module's
  VoiceIdentityProfile stores WHO is allowed to speak and WHAT they may access
  (role, allowed/blocked agents and capabilities, finance/system/code/private-memory
  gates) -- an access-control identity, not a preference bundle. A profile here
  does not need its own dashboard user_id; the owner can enroll a trusted friend
  or employee's voice without creating them a full account.
- Durable (DB-persisted) voice sessions and voice events, since
  agents/voice_agent/session_manager.py's VoiceSession is in-memory only and does
  not survive an API worker restart.

SaaS isolation: every row is scoped by workspace_id (and, where applicable,
created_by_user_id / linked_user_id). Cross-workspace access must always be
denied at the query layer -- callers must filter by workspace_id explicitly.

Security:
- No raw audio is ever stored by any model in this file (see VoiceIdentityProfile's
  voiceprint_reference_id -- a provider-side reference id only, never audio bytes).
- Default voice_settings.mode is "disabled" for every workspace.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Index,
        String,
        Text,
        UniqueConstraint,
    )
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/voice.py. "
        "Install it with: pip install sqlalchemy"
    ) from exc

try:
    from database.db import Base
except Exception:  # pragma: no cover
    try:
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()
    except Exception as exc:
        raise ImportError(
            "Could not import SQLAlchemy Base. Ensure database/db.py exists "
            "or SQLAlchemy is installed correctly."
        ) from exc


logger = logging.getLogger("william.database.models.voice")
if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


UTC = timezone.utc

DEFAULT_SYSTEM_USER_ID = "system"
DEFAULT_SYSTEM_WORKSPACE_ID = "system"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else [], ensure_ascii=False)
    except TypeError:
        return json.dumps([str(item) for item in (value or [])], ensure_ascii=False)


def _json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# =============================================================================
# Enums (plain string constants, matching this codebase's Text-column-with-
# validated-choices convention rather than native SQL enum types, for the same
# cross-dialect-portability reasons already established elsewhere in
# database/models/*.py)
# =============================================================================

VOICE_MODE_DISABLED = "disabled"
VOICE_MODE_PUSH_TO_TALK = "push_to_talk"
VOICE_MODE_WAKE_WORD_ADMIN = "wake_word_admin"
VOICE_MODE_WAKE_WORD_TRUSTED_USERS = "wake_word_trusted_users"
VOICE_MODE_CONTINUOUS_CONVERSATION = "continuous_conversation"
VOICE_MODE_STANDBY = "standby"

VALID_VOICE_MODES = {
    VOICE_MODE_DISABLED,
    VOICE_MODE_PUSH_TO_TALK,
    VOICE_MODE_WAKE_WORD_ADMIN,
    VOICE_MODE_WAKE_WORD_TRUSTED_USERS,
    VOICE_MODE_CONTINUOUS_CONVERSATION,
    VOICE_MODE_STANDBY,
}

# Modes the worker gates on local wake-word detection before contacting the
# API at all (apps/worker_nodes/voice/voice_worker.py::WAKE_WORD_GATED_MODES
# mirrors this set). standby is included: the worker keeps listening
# locally, but only a detected wake word is allowed to reach
# /voice/command while standby is active (see voice_service.route_voice_
# command_to_master_agent's standby gate).
WAKE_WORD_GATED_MODES = {
    VOICE_MODE_WAKE_WORD_ADMIN,
    VOICE_MODE_WAKE_WORD_TRUSTED_USERS,
    VOICE_MODE_STANDBY,
}

# Modes that always require Security Agent approval to enable per the mission
# spec ("Requires SecurityAgent approval" for wake_word_admin; "Blocked unless
# admin explicitly approves" for continuous_conversation).
VOICE_MODES_REQUIRING_APPROVAL = {
    VOICE_MODE_WAKE_WORD_ADMIN,
    VOICE_MODE_WAKE_WORD_TRUSTED_USERS,
    VOICE_MODE_CONTINUOUS_CONVERSATION,
}

VOICEPRINT_STATUS_ENROLLED = "enrolled"
VOICEPRINT_STATUS_PENDING = "pending"
VOICEPRINT_STATUS_EXTERNAL_DEPENDENCY_REQUIRED = "external_dependency_required"
VOICEPRINT_STATUS_DISABLED = "disabled"

VALID_VOICEPRINT_STATUSES = {
    VOICEPRINT_STATUS_ENROLLED,
    VOICEPRINT_STATUS_PENDING,
    VOICEPRINT_STATUS_EXTERNAL_DEPENDENCY_REQUIRED,
    VOICEPRINT_STATUS_DISABLED,
}

PROFILE_STATUS_ACTIVE = "active"
PROFILE_STATUS_DISABLED = "disabled"
PROFILE_STATUS_REVOKED = "revoked"

VALID_PROFILE_STATUSES = {PROFILE_STATUS_ACTIVE, PROFILE_STATUS_DISABLED, PROFILE_STATUS_REVOKED}

REPLY_LANGUAGE_MODE_SAME_AS_SPEAKER = "same_as_speaker"
REPLY_LANGUAGE_MODE_FIXED_LANGUAGE = "fixed_language"
REPLY_LANGUAGE_MODE_TEXT_ONLY = "text_only"

VALID_REPLY_LANGUAGE_MODES = {
    REPLY_LANGUAGE_MODE_SAME_AS_SPEAKER,
    REPLY_LANGUAGE_MODE_FIXED_LANGUAGE,
    REPLY_LANGUAGE_MODE_TEXT_ONLY,
}

# database/models/workspace.py::WorkspaceMemberRole / role_permission.py::
# BuiltInRoleKey is the canonical 5-value DB role vocabulary (owner/admin/
# manager/member/viewer). Voice identity profiles use this same vocabulary
# plus the mission's named example tiers as free-text roles for capability
# gating (trusted_developer/trusted_manager/trusted_assistant/guest) --
# these are NOT DB membership roles, they only affect voice command
# permission checks, so they are intentionally not constrained to the
# 5-value enum (a trusted profile need not have any WorkspaceMembership row
# at all -- that's the whole point of "add a friend's voice without giving
# them a login").
VOICE_ROLE_OWNER = "owner"
VOICE_ROLE_ADMIN = "admin"
VOICE_ROLE_TRUSTED_DEVELOPER = "trusted_developer"
VOICE_ROLE_TRUSTED_MANAGER = "trusted_manager"
VOICE_ROLE_TRUSTED_ASSISTANT = "trusted_assistant"
VOICE_ROLE_GUEST = "guest"

VALID_VOICE_ROLES = {
    VOICE_ROLE_OWNER,
    VOICE_ROLE_ADMIN,
    VOICE_ROLE_TRUSTED_DEVELOPER,
    VOICE_ROLE_TRUSTED_MANAGER,
    VOICE_ROLE_TRUSTED_ASSISTANT,
    VOICE_ROLE_GUEST,
}

SESSION_STATUS_ACTIVE = "active"
SESSION_STATUS_ENDED = "ended"
SESSION_STATUS_ERROR = "error"

VOICE_EVENT_WAKE_DETECTED = "wake_detected"
VOICE_EVENT_SPEAKER_VERIFIED = "speaker_verified"
VOICE_EVENT_SPEAKER_DENIED = "speaker_denied"
VOICE_EVENT_COMMAND_RECEIVED = "command_received"
VOICE_EVENT_COMMAND_ROUTED = "command_routed"
VOICE_EVENT_RESPONSE_GENERATED = "response_generated"
VOICE_EVENT_ENROLLMENT_STARTED = "enrollment_started"
VOICE_EVENT_ENROLLMENT_COMPLETED = "enrollment_completed"
VOICE_EVENT_CONFIG_CHANGED = "config_changed"
VOICE_EVENT_ERROR = "error"


# =============================================================================
# VoiceSettings -- one row per workspace
# =============================================================================

class VoiceSettings(Base):
    """
    Per-workspace voice runtime configuration.

    Default mode is always "disabled" for every workspace -- there is no
    global always-on voice listening. Only an owner/admin can change this
    (enforced at the API layer, not here).
    """

    __tablename__ = "voice_settings"

    id = Column(String(80), primary_key=True, default=lambda: _new_id("voicecfg"))

    workspace_id = Column(String(80), nullable=False, unique=True, index=True)
    created_by_user_id = Column(String(80), nullable=False, default=DEFAULT_SYSTEM_USER_ID)
    updated_by_user_id = Column(String(80), nullable=True)

    mode = Column(String(40), nullable=False, default=VOICE_MODE_DISABLED)
    wake_word = Column(String(60), nullable=False, default="william")
    requires_security_approval = Column(Boolean, nullable=False, default=True)
    pending_approval_id = Column(String(80), nullable=True)

    # Cached dependency status (wake_word_engine/audio_input_worker/stt_provider/
    # tts_provider/speaker_recognition_provider), refreshed on GET /voice/status
    # rather than tracked live -- see apps/api/routes/voice.py.
    dependency_status_json = Column(Text, nullable=False, default="{}")

    voice_worker_connected = Column(Boolean, nullable=False, default=False)
    voice_worker_last_seen_at = Column(DateTime(timezone=True), nullable=True)

    last_wake_event_at = Column(DateTime(timezone=True), nullable=True)
    last_recognized_speaker_profile_id = Column(String(80), nullable=True)
    last_speaker_display_name = Column(String(160), nullable=True)
    last_detected_language = Column(String(20), nullable=True)
    last_command_transcript = Column(Text, nullable=True)
    last_routed_agent = Column(String(80), nullable=True)
    last_response_text = Column(Text, nullable=True)

    # Cleared on the next successful command -- reflects the CURRENT problem
    # state for a live status dashboard, not a permanent error history (the
    # voice_events table already keeps the full error event history).
    last_error_message = Column(Text, nullable=True)
    last_error_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    __table_args__ = (
        Index("ix_voice_settings_workspace", "workspace_id"),
    )

    @property
    def dependency_status(self) -> Dict[str, str]:
        return _json_loads(self.dependency_status_json, {})

    @dependency_status.setter
    def dependency_status(self, value: Dict[str, str]) -> None:
        self.dependency_status_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "created_by_user_id": self.created_by_user_id,
            "updated_by_user_id": self.updated_by_user_id,
            "mode": self.mode,
            "wake_word": self.wake_word,
            "requires_security_approval": bool(self.requires_security_approval),
            "pending_approval_id": self.pending_approval_id,
            "dependency_status": self.dependency_status,
            "voice_worker_connected": bool(self.voice_worker_connected),
            "voice_worker_last_seen_at": self.voice_worker_last_seen_at.isoformat() if self.voice_worker_last_seen_at else None,
            "last_wake_event_at": self.last_wake_event_at.isoformat() if self.last_wake_event_at else None,
            "last_recognized_speaker_profile_id": self.last_recognized_speaker_profile_id,
            "last_speaker_display_name": self.last_speaker_display_name,
            "last_detected_language": self.last_detected_language,
            "last_command_transcript": self.last_command_transcript,
            "last_routed_agent": self.last_routed_agent,
            "last_response_text": self.last_response_text,
            "last_error_message": self.last_error_message,
            "last_error_at": self.last_error_at.isoformat() if self.last_error_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# =============================================================================
# VoiceIdentityProfile -- trusted speaker identity + permission profile
# =============================================================================

class VoiceIdentityProfile(Base):
    """
    A trusted voice identity: who is allowed to speak commands into this
    workspace, and what they're allowed to do. Enrolled by the owner/admin.

    linked_user_id is optional -- a trusted profile does not require its own
    dashboard account (e.g. the owner's friend/employee can be voice-enrolled
    without ever logging into the dashboard).

    voiceprint_reference_id is a provider-side reference id only (e.g. an
    opaque id returned by a real speaker-recognition provider after
    enrollment) -- raw audio is never stored in this or any other column.
    """

    __tablename__ = "voice_identity_profiles"

    id = Column(String(80), primary_key=True, default=lambda: _new_id("voiceprofile"))

    workspace_id = Column(String(80), nullable=False, index=True)
    created_by_user_id = Column(String(80), nullable=False)
    linked_user_id = Column(String(80), nullable=True, index=True)

    display_name = Column(String(160), nullable=False)
    role = Column(String(40), nullable=False, default=VOICE_ROLE_GUEST)

    allowed_agents_json = Column(Text, nullable=False, default="[]")
    blocked_agents_json = Column(Text, nullable=False, default="[]")
    allowed_capabilities_json = Column(Text, nullable=False, default="[]")
    blocked_capabilities_json = Column(Text, nullable=False, default="[]")

    can_use_voice = Column(Boolean, nullable=False, default=False)
    can_use_wake_word = Column(Boolean, nullable=False, default=False)
    can_access_private_memory = Column(Boolean, nullable=False, default=False)
    can_access_finance = Column(Boolean, nullable=False, default=False)
    can_access_system_agent = Column(Boolean, nullable=False, default=False)
    can_run_code_agent = Column(Boolean, nullable=False, default=False)
    requires_approval_for_risky_actions = Column(Boolean, nullable=False, default=True)

    preferred_language = Column(String(20), nullable=False, default="en")
    reply_language_mode = Column(String(40), nullable=False, default=REPLY_LANGUAGE_MODE_SAME_AS_SPEAKER)

    voiceprint_status = Column(String(40), nullable=False, default=VOICEPRINT_STATUS_PENDING)
    voiceprint_reference_id = Column(String(160), nullable=True)

    status = Column(String(20), nullable=False, default=PROFILE_STATUS_ACTIVE, index=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)
    last_used_at = Column(DateTime(timezone=True), nullable=True, index=True)

    __table_args__ = (
        Index("ix_voice_identity_profiles_workspace_status", "workspace_id", "status"),
        Index("ix_voice_identity_profiles_linked_user", "linked_user_id"),
        Index("ix_voice_identity_profiles_last_used", "last_used_at"),
        Index("ix_voice_identity_profiles_created", "created_at"),
    )

    @property
    def allowed_agents(self) -> List[str]:
        return _json_loads(self.allowed_agents_json, [])

    @allowed_agents.setter
    def allowed_agents(self, value: List[str]) -> None:
        self.allowed_agents_json = _json_dumps(value)

    @property
    def blocked_agents(self) -> List[str]:
        return _json_loads(self.blocked_agents_json, [])

    @blocked_agents.setter
    def blocked_agents(self, value: List[str]) -> None:
        self.blocked_agents_json = _json_dumps(value)

    @property
    def allowed_capabilities(self) -> List[str]:
        return _json_loads(self.allowed_capabilities_json, [])

    @allowed_capabilities.setter
    def allowed_capabilities(self, value: List[str]) -> None:
        self.allowed_capabilities_json = _json_dumps(value)

    @property
    def blocked_capabilities(self) -> List[str]:
        return _json_loads(self.blocked_capabilities_json, [])

    @blocked_capabilities.setter
    def blocked_capabilities(self, value: List[str]) -> None:
        self.blocked_capabilities_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "created_by_user_id": self.created_by_user_id,
            "linked_user_id": self.linked_user_id,
            "display_name": self.display_name,
            "role": self.role,
            "allowed_agents": self.allowed_agents,
            "blocked_agents": self.blocked_agents,
            "allowed_capabilities": self.allowed_capabilities,
            "blocked_capabilities": self.blocked_capabilities,
            "can_use_voice": bool(self.can_use_voice),
            "can_use_wake_word": bool(self.can_use_wake_word),
            "can_access_private_memory": bool(self.can_access_private_memory),
            "can_access_finance": bool(self.can_access_finance),
            "can_access_system_agent": bool(self.can_access_system_agent),
            "can_run_code_agent": bool(self.can_run_code_agent),
            "requires_approval_for_risky_actions": bool(self.requires_approval_for_risky_actions),
            "preferred_language": self.preferred_language,
            "reply_language_mode": self.reply_language_mode,
            "voiceprint_status": self.voiceprint_status,
            "voiceprint_reference_id": self.voiceprint_reference_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }


# =============================================================================
# VoiceSession -- durable record of a voice interaction session
# =============================================================================

class VoiceSession(Base):
    """
    Durable (DB-persisted) voice session record. Complements the in-memory
    agents/voice_agent/session_manager.py::VoiceSessionManager (which stays
    the source of truth for live in-process session state); this table
    exists so dashboard history/audit views survive an API worker restart.
    """

    __tablename__ = "voice_sessions"

    id = Column(String(80), primary_key=True, default=lambda: _new_id("voicesession"))

    session_id = Column(String(80), nullable=False, unique=True, index=True)
    workspace_id = Column(String(80), nullable=False, index=True)
    user_id = Column(String(80), nullable=True)
    profile_id = Column(String(80), nullable=True, index=True)

    input_mode = Column(String(20), nullable=False, default="voice")
    wake_word = Column(String(60), nullable=True)
    detected_language = Column(String(20), nullable=True)
    reply_language = Column(String(20), nullable=True)

    status = Column(String(20), nullable=False, default=SESSION_STATUS_ACTIVE, index=True)

    started_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    last_activity_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    ended_at = Column(DateTime(timezone=True), nullable=True)

    # NOTE: named session_metadata_json/session_metadata, not metadata/
    # metadata_json -- SQLAlchemy declarative Base classes reserve the bare
    # "metadata" attribute name for the real MetaData object; a same-named
    # property here silently shadows it and crashes table construction
    # ("AttributeError: 'property' object has no attribute 'schema'"),
    # the same class of reserved-attribute bug documented in CLAUDE.md's
    # project history for earlier models in this codebase.
    session_metadata_json = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        Index("ix_voice_sessions_workspace_status", "workspace_id", "status"),
        Index("ix_voice_sessions_profile", "profile_id"),
    )

    @property
    def session_metadata(self) -> Dict[str, Any]:
        return _json_loads(self.session_metadata_json, {})

    @session_metadata.setter
    def session_metadata(self, value: Dict[str, Any]) -> None:
        self.session_metadata_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "workspace_id": self.workspace_id,
            "user_id": self.user_id,
            "profile_id": self.profile_id,
            "input_mode": self.input_mode,
            "wake_word": self.wake_word,
            "detected_language": self.detected_language,
            "reply_language": self.reply_language,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "last_activity_at": self.last_activity_at.isoformat() if self.last_activity_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "metadata": self.session_metadata,
        }


# =============================================================================
# VoiceEvent -- voice-specific event/audit stream
# =============================================================================

class VoiceEvent(Base):
    """
    Voice-specific event stream (wake detected, speaker verified/denied,
    command received/routed, response generated, enrollment, config change,
    error). Every voice command/enrollment/config-change also writes a
    standard database.models.security.AuditLogModel row for the main audit
    trail -- this table is additive, giving the dashboard a richer,
    voice-native event feed (last wake event, last recognized speaker, etc.)
    without overloading the generic audit log's schema.
    """

    __tablename__ = "voice_events"

    id = Column(String(80), primary_key=True, default=lambda: _new_id("voiceevent"))

    workspace_id = Column(String(80), nullable=False, index=True)
    session_id = Column(String(80), nullable=True, index=True)
    profile_id = Column(String(80), nullable=True, index=True)
    user_id = Column(String(80), nullable=True)

    event_type = Column(String(60), nullable=False, index=True)
    payload_json = Column(Text, nullable=False, default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)

    __table_args__ = (
        Index("ix_voice_events_workspace_type", "workspace_id", "event_type"),
        Index("ix_voice_events_created", "created_at"),
    )

    @property
    def payload(self) -> Dict[str, Any]:
        return _json_loads(self.payload_json, {})

    @payload.setter
    def payload(self, value: Dict[str, Any]) -> None:
        self.payload_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "session_id": self.session_id,
            "profile_id": self.profile_id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


__all__ = [
    "VoiceSettings",
    "VoiceIdentityProfile",
    "VoiceSession",
    "VoiceEvent",
    "VOICE_MODE_DISABLED",
    "VOICE_MODE_PUSH_TO_TALK",
    "VOICE_MODE_WAKE_WORD_ADMIN",
    "VOICE_MODE_WAKE_WORD_TRUSTED_USERS",
    "VOICE_MODE_CONTINUOUS_CONVERSATION",
    "VOICE_MODE_STANDBY",
    "VALID_VOICE_MODES",
    "WAKE_WORD_GATED_MODES",
    "VOICE_MODES_REQUIRING_APPROVAL",
    "VOICEPRINT_STATUS_ENROLLED",
    "VOICEPRINT_STATUS_PENDING",
    "VOICEPRINT_STATUS_EXTERNAL_DEPENDENCY_REQUIRED",
    "VOICEPRINT_STATUS_DISABLED",
    "VALID_VOICEPRINT_STATUSES",
    "PROFILE_STATUS_ACTIVE",
    "PROFILE_STATUS_DISABLED",
    "PROFILE_STATUS_REVOKED",
    "VALID_PROFILE_STATUSES",
    "REPLY_LANGUAGE_MODE_SAME_AS_SPEAKER",
    "REPLY_LANGUAGE_MODE_FIXED_LANGUAGE",
    "REPLY_LANGUAGE_MODE_TEXT_ONLY",
    "VALID_REPLY_LANGUAGE_MODES",
    "VOICE_ROLE_OWNER",
    "VOICE_ROLE_ADMIN",
    "VOICE_ROLE_TRUSTED_DEVELOPER",
    "VOICE_ROLE_TRUSTED_MANAGER",
    "VOICE_ROLE_TRUSTED_ASSISTANT",
    "VOICE_ROLE_GUEST",
    "VALID_VOICE_ROLES",
    "SESSION_STATUS_ACTIVE",
    "SESSION_STATUS_ENDED",
    "SESSION_STATUS_ERROR",
    "VOICE_EVENT_WAKE_DETECTED",
    "VOICE_EVENT_SPEAKER_VERIFIED",
    "VOICE_EVENT_SPEAKER_DENIED",
    "VOICE_EVENT_COMMAND_RECEIVED",
    "VOICE_EVENT_COMMAND_ROUTED",
    "VOICE_EVENT_RESPONSE_GENERATED",
    "VOICE_EVENT_ENROLLMENT_STARTED",
    "VOICE_EVENT_ENROLLMENT_COMPLETED",
    "VOICE_EVENT_CONFIG_CHANGED",
    "VOICE_EVENT_ERROR",
]
