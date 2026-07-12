"""
apps/api/services/voice_service.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 9 -- Voice identity/permission service + MasterAgent voice handoff.

This module owns:
- VoiceSettings / VoiceIdentityProfile CRUD (database/models/voice.py), always
  scoped by workspace_id.
- Permission enforcement: a trusted voice profile's allowed_agents/
  blocked_agents/can_access_* flags are checked BEFORE a voice command is
  forwarded to MasterAgent (defense layer 1), and the profile's role +
  allowed-agent permission strings ("agents.<key>.use") are also threaded
  into the MasterAgent payload so the real SecurityAgent per-step check
  provides defense-in-depth for whichever agent the Planner actually routes
  to (defense layer 2) -- see core/master_agent.py's _process_step(), which
  already reads request.metadata.get("role") and request.permissions with
  zero structural change required (confirmed by direct inspection).
- Building the MasterAgent-compatible task payload for a voice-originated
  command (input_mode="voice", speaker identity, detected_language, wake
  word) and calling the real, already-fixed
  apps.api.services.master_agent_bridge.MasterAgentBridge.execute().
- Voice event + audit logging (both a rich VoiceEvent row and a standard
  AuditLogModel row per real command/enrollment/config-change).

Nothing here executes real STT/TTS/wake-word/speaker-recognition -- those
live in agents/voice_agent/*. This module is the orchestration/permission
layer between the API routes, those engines, and MasterAgent.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("william.api.services.voice_service")

UTC = timezone.utc


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


# =============================================================================
# Canonical agent keys (matches agents/capability_manifest.py::AGENT_CAPABILITY_KEYS)
# =============================================================================

ALL_AGENT_KEYS = [
    "voice", "system", "browser", "code", "memory", "security", "verification",
    "visual", "workflow", "hologram", "call", "business", "finance", "creator",
]

# Agents every non-owner trusted profile is blocked from by default, per the
# mission's explicit examples (finance/private-memory/security/risky system
# actions require an explicit opt-in flag on the profile).
DEFAULT_BLOCKED_FOR_NON_OWNER = {"finance", "security"}

UNAUTHORIZED_SPEAKER_MESSAGE = "You are not authorized to use this William workspace."


# =============================================================================
# Keyword-based agent intent inference (a real, local heuristic -- not a
# replacement for MasterAgent's own Planner, only a pre-routing permission
# guard so a blocked agent can be refused BEFORE calling MasterAgent at all,
# per the mission's "Voice profile permissions must be enforced before
# MasterAgent routes to any agent" requirement).
# =============================================================================

_AGENT_KEYWORDS: Dict[str, List[str]] = {
    "finance": ["invoice", "payment", "budget", "expense", "bill", "transfer", "finance", "money", "receipt", "refund", "subscription cost"],
    "system": ["shutdown", "restart", "reboot", "delete file", "terminal", "shell command", "install", "system command", "cpu", "ram", "disk", "device", "power off"],
    "code": ["code", "function", "bug", "deploy", "repository", "repo", "git commit", "debug", "refactor", "script", "pull request", "unit test"],
    "creator": ["video ad", "veo prompt", "script for", "caption", "thumbnail", "content calendar", "ad copy", "campaign creative"],
    "business": ["crm", "lead", "client", "pipeline", "deal", "business report", "proposal"],
    "browser": ["search the web", "research", "website", "competitor", "browse to"],
    "workflow": ["workflow", "automation", "webhook", "n8n", "trigger", "pipeline for"],
    "call": ["receptionist", "voicemail", "phone call", "call script"],
    "memory": ["remember that", "recall", "forget that", "my preference"],
    "security": ["security setting", "approval request", "audit log", "permission change"],
    "visual": ["screenshot", "this image", "analyze the screen"],
    "hologram": ["ar overlay", "hologram"],
}


def infer_target_agent(text: str) -> Optional[str]:
    """
    Best-effort keyword guess at which agent a voice command is likely
    headed for -- used only as a pre-routing permission guard, never as the
    real routing decision (MasterAgent's Planner remains authoritative for
    that). Returns None if no keyword matches (ambiguous / general request).
    """
    lowered = (text or "").lower()
    for agent_key, keywords in _AGENT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in lowered:
                return agent_key
    return None


# =============================================================================
# Effective profile resolution (owner has full access without needing a
# VoiceIdentityProfile row of their own -- enrollment is about voiceprint
# capture, not permission bootstrapping)
# =============================================================================

def authenticated_user_virtual_profile(workspace_id: str, user_id: str, role: str) -> Dict[str, Any]:
    """
    A synthetic profile representing the ALREADY-JWT-AUTHENTICATED dashboard
    user themselves, used for push-to-talk (safe fallback) mode -- no
    separate voice enrollment is needed since the caller is already a real,
    logged-in identity. Access follows their REAL workspace role, not a
    hardcoded owner grant; non-owner/admin roles keep the same
    finance/system default-blocked posture as any other trusted profile.
    """
    is_owner_or_admin = role in ("owner", "admin")
    return {
        "id": None,
        "workspace_id": workspace_id,
        "linked_user_id": user_id,
        "display_name": "Dashboard User",
        "role": "owner" if role == "owner" else ("admin" if role == "admin" else "trusted_manager"),
        "allowed_agents": list(ALL_AGENT_KEYS) if is_owner_or_admin else [a for a in ALL_AGENT_KEYS if a not in DEFAULT_BLOCKED_FOR_NON_OWNER],
        "blocked_agents": [] if is_owner_or_admin else sorted(DEFAULT_BLOCKED_FOR_NON_OWNER),
        "allowed_capabilities": [],
        "blocked_capabilities": [],
        "can_use_voice": True,
        "can_use_wake_word": False,
        "can_access_private_memory": is_owner_or_admin,
        "can_access_finance": is_owner_or_admin,
        "can_access_system_agent": is_owner_or_admin,
        "can_run_code_agent": True,
        "requires_approval_for_risky_actions": True,
        "preferred_language": "en",
        "reply_language_mode": "same_as_speaker",
        "status": "active",
        "is_owner_virtual_profile": is_owner_or_admin,
    }


def owner_virtual_profile(workspace_id: str, user_id: str) -> Dict[str, Any]:
    """A synthetic full-access profile for the resolved workspace owner/admin.

    Does not correspond to a VoiceIdentityProfile DB row -- the owner always
    has full voice access (subject to the SAME SecurityAgent risk-based
    approval every other pipeline already enforces for risky actions; this
    virtual profile does not bypass that, only the voice-layer allow-list).
    """
    return {
        "id": None,
        "workspace_id": workspace_id,
        "linked_user_id": user_id,
        "display_name": "Owner",
        "role": "owner",
        "allowed_agents": list(ALL_AGENT_KEYS),
        "blocked_agents": [],
        "allowed_capabilities": [],
        "blocked_capabilities": [],
        "can_use_voice": True,
        "can_use_wake_word": True,
        "can_access_private_memory": True,
        "can_access_finance": True,
        "can_access_system_agent": True,
        "can_run_code_agent": True,
        "requires_approval_for_risky_actions": True,
        "preferred_language": "en",
        "reply_language_mode": "same_as_speaker",
        "status": "active",
        "is_owner_virtual_profile": True,
    }


# =============================================================================
# VoiceSettings
# =============================================================================

def get_or_create_settings(db, workspace_id: str, created_by_user_id: str = "system") -> Dict[str, Any]:
    from database.seeders.seed_voice_defaults import get_or_create_voice_settings

    settings, _created = get_or_create_voice_settings(db, workspace_id=workspace_id, created_by_user_id=created_by_user_id)
    return settings.to_dict()


def update_settings(
    db,
    workspace_id: str,
    *,
    mode: Optional[str] = None,
    wake_word: Optional[str] = None,
    updated_by_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    from database.models.voice import VoiceSettings, VALID_VOICE_MODES

    settings = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == workspace_id).first()
    if settings is None:
        settings, _ = _get_or_create_settings_row(db, workspace_id, updated_by_user_id or "system")

    if mode is not None:
        if mode not in VALID_VOICE_MODES:
            raise ValueError(f"Invalid voice mode: {mode}")
        settings.mode = mode

    if wake_word:
        settings.wake_word = wake_word[:60]

    if updated_by_user_id:
        settings.updated_by_user_id = updated_by_user_id

    settings.updated_at = _utc_now()
    db.flush()
    return settings.to_dict()


def _get_or_create_settings_row(db, workspace_id: str, created_by_user_id: str):
    from database.seeders.seed_voice_defaults import get_or_create_voice_settings

    return get_or_create_voice_settings(db, workspace_id=workspace_id, created_by_user_id=created_by_user_id)


def record_dependency_status(db, workspace_id: str, dependency_status: Dict[str, str]) -> Dict[str, Any]:
    from database.models.voice import VoiceSettings

    settings = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == workspace_id).first()
    if settings is None:
        settings, _ = _get_or_create_settings_row(db, workspace_id, "system")

    settings.dependency_status = dependency_status
    db.flush()
    return settings.to_dict()


# =============================================================================
# VoiceIdentityProfile CRUD
# =============================================================================

def list_profiles(db, workspace_id: str) -> List[Dict[str, Any]]:
    from database.models.voice import VoiceIdentityProfile

    rows = (
        db.query(VoiceIdentityProfile)
        .filter(VoiceIdentityProfile.workspace_id == workspace_id)
        .order_by(VoiceIdentityProfile.created_at.desc())
        .all()
    )
    return [row.to_dict() for row in rows]


def get_profile(db, workspace_id: str, profile_id: str):
    from database.models.voice import VoiceIdentityProfile

    return (
        db.query(VoiceIdentityProfile)
        .filter(VoiceIdentityProfile.workspace_id == workspace_id, VoiceIdentityProfile.id == profile_id)
        .first()
    )


def create_profile(
    db,
    *,
    workspace_id: str,
    created_by_user_id: str,
    display_name: str,
    role: str = "guest",
    linked_user_id: Optional[str] = None,
    allowed_agents: Optional[List[str]] = None,
    blocked_agents: Optional[List[str]] = None,
    allowed_capabilities: Optional[List[str]] = None,
    blocked_capabilities: Optional[List[str]] = None,
    can_use_voice: bool = True,
    can_use_wake_word: bool = False,
    can_access_private_memory: bool = False,
    can_access_finance: bool = False,
    can_access_system_agent: bool = False,
    can_run_code_agent: bool = False,
    requires_approval_for_risky_actions: bool = True,
    preferred_language: str = "en",
    reply_language_mode: str = "same_as_speaker",
) -> Dict[str, Any]:
    from database.models.voice import VoiceIdentityProfile, VALID_VOICE_ROLES

    if role not in VALID_VOICE_ROLES:
        raise ValueError(f"Invalid voice role: {role}")

    resolved_blocked_agents = set(blocked_agents or [])
    if role != "owner" and not can_access_finance:
        resolved_blocked_agents.add("finance")
    if not can_access_system_agent:
        resolved_blocked_agents.add("system")

    profile = VoiceIdentityProfile(
        workspace_id=workspace_id,
        created_by_user_id=created_by_user_id,
        linked_user_id=linked_user_id,
        display_name=display_name[:160],
        role=role,
        can_use_voice=can_use_voice,
        can_use_wake_word=can_use_wake_word,
        can_access_private_memory=can_access_private_memory,
        can_access_finance=can_access_finance,
        can_access_system_agent=can_access_system_agent,
        can_run_code_agent=can_run_code_agent,
        requires_approval_for_risky_actions=requires_approval_for_risky_actions,
        preferred_language=preferred_language,
        reply_language_mode=reply_language_mode,
        voiceprint_status="pending",
    )
    profile.allowed_agents = allowed_agents or []
    profile.blocked_agents = sorted(resolved_blocked_agents)
    profile.allowed_capabilities = allowed_capabilities or []
    profile.blocked_capabilities = blocked_capabilities or []

    db.add(profile)
    db.flush()
    return profile.to_dict()


def update_profile(db, workspace_id: str, profile_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from database.models.voice import VALID_VOICE_ROLES, VALID_PROFILE_STATUSES

    profile = get_profile(db, workspace_id, profile_id)
    if profile is None:
        return None

    if "display_name" in updates and updates["display_name"]:
        profile.display_name = str(updates["display_name"])[:160]
    if "role" in updates and updates["role"]:
        if updates["role"] not in VALID_VOICE_ROLES:
            raise ValueError(f"Invalid voice role: {updates['role']}")
        profile.role = updates["role"]
    if "allowed_agents" in updates and isinstance(updates["allowed_agents"], list):
        profile.allowed_agents = updates["allowed_agents"]
    if "blocked_agents" in updates and isinstance(updates["blocked_agents"], list):
        profile.blocked_agents = updates["blocked_agents"]
    if "allowed_capabilities" in updates and isinstance(updates["allowed_capabilities"], list):
        profile.allowed_capabilities = updates["allowed_capabilities"]
    if "blocked_capabilities" in updates and isinstance(updates["blocked_capabilities"], list):
        profile.blocked_capabilities = updates["blocked_capabilities"]
    for bool_field in (
        "can_use_voice", "can_use_wake_word", "can_access_private_memory",
        "can_access_finance", "can_access_system_agent", "can_run_code_agent",
        "requires_approval_for_risky_actions",
    ):
        if bool_field in updates and updates[bool_field] is not None:
            setattr(profile, bool_field, bool(updates[bool_field]))
    if "preferred_language" in updates and updates["preferred_language"]:
        profile.preferred_language = updates["preferred_language"]
    if "reply_language_mode" in updates and updates["reply_language_mode"]:
        profile.reply_language_mode = updates["reply_language_mode"]
    if "status" in updates and updates["status"]:
        if updates["status"] not in VALID_PROFILE_STATUSES:
            raise ValueError(f"Invalid profile status: {updates['status']}")
        profile.status = updates["status"]

    profile.updated_at = _utc_now()
    db.flush()
    return profile.to_dict()


def revoke_profile(db, workspace_id: str, profile_id: str, *, hard_delete: bool = False) -> Optional[Dict[str, Any]]:
    from database.models.voice import PROFILE_STATUS_REVOKED

    profile = get_profile(db, workspace_id, profile_id)
    if profile is None:
        return None

    if hard_delete:
        data = profile.to_dict()
        db.delete(profile)
        db.flush()
        return data

    profile.status = PROFILE_STATUS_REVOKED
    profile.updated_at = _utc_now()
    db.flush()
    return profile.to_dict()


# =============================================================================
# Permission enforcement
# =============================================================================

def voice_permission_strings(profile: Dict[str, Any]) -> List[str]:
    """Map a profile's allowed_agents into SecurityAgent-recognized
    permission strings ("agents.<key>.use"), the exact convention already
    seeded in database/seeders/default_plans.py's PERMISSIONS list."""
    allowed = profile.get("allowed_agents") or []
    if profile.get("role") == "owner" or profile.get("is_owner_virtual_profile"):
        allowed = ALL_AGENT_KEYS
    return sorted({f"agents.{agent_key}.use" for agent_key in allowed if agent_key in ALL_AGENT_KEYS})


def check_profile_permission(
    profile: Dict[str, Any],
    transcript: str,
) -> Tuple[bool, str, Optional[str]]:
    """
    Pre-routing permission guard. Returns (allowed, reason, inferred_agent).

    This is defense layer 1 (before MasterAgent is even called). Defense
    layer 2 is the real SecurityAgent per-step check that happens naturally
    inside MasterAgent's own pipeline once role/permissions are threaded
    through (see build_master_agent_payload below) -- this function cannot
    catch every case (the Planner may route somewhere this keyword guess
    didn't anticipate), so layer 2 remains the authoritative enforcement for
    sensitive agents.
    """
    if profile.get("status") not in (None, "active"):
        return False, "This voice profile has been disabled or revoked.", None

    if not profile.get("can_use_voice", False):
        return False, "This voice profile is not permitted to use voice commands.", None

    if profile.get("role") == "owner" or profile.get("is_owner_virtual_profile"):
        return True, "Owner has full voice access.", None

    inferred_agent = infer_target_agent(transcript)
    if inferred_agent is None:
        return True, "No specific sensitive agent detected; proceeding to MasterAgent.", None

    blocked_agents = set(profile.get("blocked_agents") or [])
    allowed_agents = set(profile.get("allowed_agents") or [])

    if inferred_agent in blocked_agents:
        return False, f"This voice profile is not allowed to use the {inferred_agent} agent.", inferred_agent

    if allowed_agents and inferred_agent not in allowed_agents:
        return False, f"This voice profile is not allowed to use the {inferred_agent} agent.", inferred_agent

    if inferred_agent == "finance" and not profile.get("can_access_finance", False):
        return False, "This voice profile cannot access the Finance Agent.", inferred_agent

    if inferred_agent == "system" and not profile.get("can_access_system_agent", False):
        return False, "This voice profile cannot run System Agent actions.", inferred_agent

    if inferred_agent == "code" and not profile.get("can_run_code_agent", False):
        return False, "This voice profile cannot run Code Agent actions.", inferred_agent

    return True, "Allowed.", inferred_agent


# =============================================================================
# MasterAgent voice handoff
# =============================================================================

def build_master_agent_payload(
    *,
    workspace_id: str,
    user_id: str,
    profile: Dict[str, Any],
    transcript: str,
    detected_language: str,
    session_id: str,
    request_id: str,
    wake_word: Optional[str],
) -> Dict[str, Any]:
    """
    Build the exact dict apps.api.services.master_agent_bridge.
    MasterAgentBridge.execute() (and, underneath it, core.master_agent.
    MasterAgent.execute()) expects. Speaker identity/voice metadata is
    threaded into `metadata` (arbitrary keys there pass through the full
    pipeline untouched, confirmed by direct inspection of
    core/master_agent.py -- no structural change to MasterAgent required).
    `permissions` and `metadata["role"]` are the two fields MasterAgent's
    real per-step SecurityAgent check already reads.
    """
    return {
        "message": transcript,
        "user_id": user_id,
        "workspace_id": workspace_id,
        "action": "general_request",
        "preferred_agent": None,
        "input_data": {},
        "permissions": voice_permission_strings(profile),
        "metadata": {
            "role": profile.get("role", "guest"),
            "subscription_plan": None,
            "input_mode": "voice",
            "wake_word": wake_word,
            "detected_language": detected_language,
            "voice_session_id": session_id,
            "request_id": request_id,
            "speaker_identity": {
                "profile_id": profile.get("id"),
                "display_name": profile.get("display_name"),
                "role": profile.get("role"),
                "linked_user_id": profile.get("linked_user_id"),
                "allowed_agents": profile.get("allowed_agents"),
                "blocked_agents": profile.get("blocked_agents"),
                "can_access_private_memory": profile.get("can_access_private_memory", False),
            },
        },
    }


async def route_voice_command_to_master_agent(
    *,
    db,
    workspace_id: str,
    user_id: str,
    profile: Dict[str, Any],
    transcript: str,
    detected_language: str,
    session_id: str,
    request_id: Optional[str] = None,
    wake_word: Optional[str] = None,
    tts_available: bool = False,
) -> Dict[str, Any]:
    """
    The full voice command handoff: permission pre-check -> MasterAgent ->
    normalized voice-response envelope (with reply_language +
    speech_output_status, never claiming spoken output happened without a
    real TTS provider).
    """
    request_id = request_id or _new_id("req")

    allowed, reason, inferred_agent = check_profile_permission(profile, transcript)

    record_voice_event(
        db, workspace_id=workspace_id, session_id=session_id, profile_id=profile.get("id"),
        user_id=user_id, event_type="command_received",
        payload={"transcript": transcript, "detected_language": detected_language, "inferred_agent": inferred_agent},
    )

    if not allowed:
        record_voice_event(
            db, workspace_id=workspace_id, session_id=session_id, profile_id=profile.get("id"),
            user_id=user_id, event_type="speaker_denied",
            payload={"reason": reason, "inferred_agent": inferred_agent},
        )
        write_voice_audit(
            db, user_id=user_id, workspace_id=workspace_id, action="voice.command.blocked",
            status="denied", metadata={"reason": reason, "inferred_agent": inferred_agent, "profile_id": profile.get("id")},
        )
        return _voice_response_envelope(
            success=False,
            message=reason,
            response_text=reason,
            reply_language=_resolve_reply_language(profile, detected_language),
            tts_available=tts_available,
            master_result=None,
            request_id=request_id,
        )

    from apps.api.services.master_agent_bridge import MasterAgentBridge

    payload = build_master_agent_payload(
        workspace_id=workspace_id, user_id=user_id, profile=profile, transcript=transcript,
        detected_language=detected_language, session_id=session_id, request_id=request_id, wake_word=wake_word,
    )

    bridge = MasterAgentBridge()
    master_result = await bridge.execute(payload)

    record_voice_event(
        db, workspace_id=workspace_id, session_id=session_id, profile_id=profile.get("id"),
        user_id=user_id, event_type="command_routed",
        payload={"success": master_result.get("success"), "inferred_agent": inferred_agent},
    )
    write_voice_audit(
        db, user_id=user_id, workspace_id=workspace_id, action="voice.command.routed",
        status="success" if master_result.get("success") else "failed",
        metadata={"inferred_agent": inferred_agent, "profile_id": profile.get("id")},
    )

    response_text = _extract_response_text(master_result)
    reply_language = _resolve_reply_language(profile, detected_language)

    record_voice_event(
        db, workspace_id=workspace_id, session_id=session_id, profile_id=profile.get("id"),
        user_id=user_id, event_type="response_generated",
        payload={"response_text": response_text, "reply_language": reply_language},
    )

    envelope = _voice_response_envelope(
        success=bool(master_result.get("success")),
        message=master_result.get("message", ""),
        response_text=response_text,
        reply_language=reply_language,
        tts_available=tts_available,
        master_result=master_result,
        request_id=request_id,
    )

    _update_settings_last_command(db, workspace_id, profile, transcript, detected_language, response_text)
    return envelope


def _resolve_reply_language(profile: Dict[str, Any], detected_language: str) -> str:
    mode = profile.get("reply_language_mode", "same_as_speaker")
    if mode == "fixed_language":
        return profile.get("preferred_language", "en")
    if mode == "text_only":
        return detected_language or "en"
    return detected_language or profile.get("preferred_language", "en")


def _extract_response_text(master_result: Optional[Dict[str, Any]]) -> str:
    if not master_result:
        return ""
    if master_result.get("message"):
        return str(master_result["message"])
    data = master_result.get("data") or {}
    if isinstance(data, dict):
        summary = data.get("summary") or data.get("message")
        if summary:
            return str(summary)
    return "Task processed." if master_result.get("success") else "The task could not be completed."


def _voice_response_envelope(
    *,
    success: bool,
    message: str,
    response_text: str,
    reply_language: str,
    tts_available: bool,
    master_result: Optional[Dict[str, Any]],
    request_id: str,
) -> Dict[str, Any]:
    """
    Never claims spoken output happened without a real TTS provider --
    speech_output_status is "available" only when tts_available=True was
    passed in (the caller -- apps/api/routes/voice.py -- determines this
    from the real TTS engine's own provider-configured check, not a guess).
    """
    return {
        "success": success,
        "message": message,
        "response_text": response_text,
        "reply_language": reply_language,
        "speech_output_status": "available" if tts_available else "external_dependency_required",
        "master_result": master_result,
        "request_id": request_id,
    }


def _update_settings_last_command(db, workspace_id: str, profile: Dict[str, Any], transcript: str, detected_language: str, response_text: str) -> None:
    from database.models.voice import VoiceSettings

    settings = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == workspace_id).first()
    if settings is None:
        return
    settings.last_command_transcript = transcript[:2000]
    settings.last_detected_language = detected_language
    settings.last_response_text = (response_text or "")[:2000]
    settings.last_recognized_speaker_profile_id = profile.get("id")
    settings.updated_at = _utc_now()
    db.flush()


# =============================================================================
# Events + Audit
# =============================================================================

def record_voice_event(
    db,
    *,
    workspace_id: str,
    session_id: Optional[str],
    profile_id: Optional[str],
    user_id: Optional[str],
    event_type: str,
    payload: Dict[str, Any],
) -> None:
    from database.models.voice import VoiceEvent

    event = VoiceEvent(
        workspace_id=workspace_id,
        session_id=session_id,
        profile_id=profile_id,
        user_id=user_id,
        event_type=event_type,
    )
    event.payload = payload
    db.add(event)
    db.flush()


def write_voice_audit(
    db,
    *,
    user_id: Optional[str],
    workspace_id: str,
    action: str,
    status: str = "success",
    resource_id: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        from database.models.security import AuditLogModel

        audit = AuditLogModel(
            user_id=user_id or "unknown",
            workspace_id=workspace_id,
            action=action,
            resource_type="voice",
            resource_id=resource_id,
            agent_key="voice",
            actor=user_id or "unknown",
            status=status,
            ip_address="",
            user_agent="",
        )
        audit.extra_metadata = metadata or {}
        db.add(audit)
        db.flush()
    except Exception as exc:  # noqa: BLE001 -- audit logging must never break the voice pipeline
        logger.warning("write_voice_audit failed: %s", exc)
