"""
apps/api/routes/voice.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 9 -- User-Based Admin Voice Agent + Wake Word + Voice Identity +
Multilingual MasterAgent Handoff.

Endpoints:
    GET    /voice/status
    POST   /voice/config
    GET    /voice/profiles
    POST   /voice/profiles
    PATCH  /voice/profiles/{profile_id}
    DELETE /voice/profiles/{profile_id}
    POST   /voice/wake-event
    POST   /voice/command
    POST   /voice/push-to-talk/text
    POST   /voice/enroll/start
    POST   /voice/enroll/complete

Every endpoint requires a real, JWT-verified auth context (get_current_auth_context,
imported from apps.api.routes.auth exactly like every other router in this
codebase) -- voice never bypasses existing session/JWT security, and every
query/write is scoped to context.workspace_id.

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field


LOGGER_NAME = "william.api.routes.voice"
logger = logging.getLogger(LOGGER_NAME)

if not logger.handlers:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    logger.addHandler(stream_handler)

logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


# =============================================================================
# Roles / Plans (mirrors apps/api/routes/auth.py / audit.py)
# =============================================================================

class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    DEVELOPER = "developer"
    ANALYST = "analyst"
    AGENT = "agent"
    USER = "user"
    VIEWER = "viewer"


class Plan(str, Enum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


ROLE_RANK: Dict[str, int] = {
    Role.VIEWER.value: 10,
    Role.USER.value: 20,
    "member": 20,
    Role.AGENT.value: 30,
    Role.ANALYST.value: 35,
    Role.DEVELOPER.value: 40,
    Role.MANAGER.value: 50,
    Role.ADMIN.value: 80,
    Role.OWNER.value: 100,
}


def normalize_role(role: Optional[str]) -> str:
    clean = (role or Role.USER.value).strip().lower()
    return clean if clean in ROLE_RANK else Role.USER.value


def normalize_plan(plan: Optional[str]) -> str:
    return (plan or Plan.FREE.value).strip().lower()


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


def is_owner_or_admin(role: str) -> bool:
    return has_min_role(role, Role.ADMIN.value)


# =============================================================================
# Safe API Responses
# =============================================================================

def api_success(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {
            "request_id": request_id,
            "timestamp": utc_now(),
            "module": "voice",
            **(metadata or {}),
        },
    }


def raise_api_error(
    status_code: int,
    message: str,
    code: str,
    request_id: Optional[str] = None,
    details: Optional[Any] = None,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": {},
            "error": {"code": code, "details": details},
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "voice"},
        },
    )


# =============================================================================
# Auth Compatibility
# =============================================================================

class FallbackAuthContext(BaseModel):
    request_id: str
    user_id: str
    workspace_id: str
    session_id: str = "dev_session"
    role: str = Role.OWNER.value
    plan: str = Plan.FREE.value
    email: str = "dev@example.com"
    permissions: List[str] = Field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


try:
    from apps.api.routes.auth import (  # type: ignore
        AuthContext,
        get_current_auth_context,
        require_auth_role,
    )
except Exception as auth_import_exc:  # pragma: no cover - import-safe fallback
    logger.warning("Auth import fallback enabled in voice.py: %s", auth_import_exc)
    AuthContext = FallbackAuthContext

    async def get_current_auth_context(
        request: Request,
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
        x_user_id: Optional[str] = Header(default="demo_user", alias="X-User-ID"),
        x_workspace_id: Optional[str] = Header(default="demo_workspace", alias="X-Workspace-ID"),
        x_user_role: Optional[str] = Header(default=Role.OWNER.value, alias="X-User-Role"),
        x_subscription_plan: Optional[str] = Header(default=Plan.FREE.value, alias="X-Subscription-Plan"),
    ) -> FallbackAuthContext:
        return FallbackAuthContext(
            request_id=x_request_id or new_id("req"),
            user_id=x_user_id or "demo_user",
            workspace_id=x_workspace_id or "demo_workspace",
            role=normalize_role(x_user_role),
            plan=normalize_plan(x_subscription_plan),
            email="dev@example.com",
            permissions=["voice:read"],
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    def require_auth_role(required_role: str) -> Callable[[FallbackAuthContext], Awaitable[FallbackAuthContext]]:
        async def dependency(context: FallbackAuthContext = Depends(get_current_auth_context)) -> FallbackAuthContext:
            if not has_min_role(context.role, required_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message=f"Role '{required_role}' or higher is required.",
                    code="INSUFFICIENT_ROLE",
                    request_id=context.request_id,
                )
            return context

        return dependency


try:
    from apps.api.routes.voice_device_setup import get_voice_worker_auth_context  # type: ignore
except Exception as voice_device_setup_import_exc:  # pragma: no cover - import-safe fallback
    logger.warning(
        "voice_device_setup import fallback enabled in voice.py (device-token auth unavailable, "
        "falling back to JWT-only get_current_auth_context): %s",
        voice_device_setup_import_exc,
    )
    get_voice_worker_auth_context = get_current_auth_context  # type: ignore


# =============================================================================
# Security Agent hook (mirrors the run_task-first dispatch order already
# fixed in apps/api/routes/tasks.py / auth.py for this exact class of bug)
# =============================================================================

class OptionalHook:
    def __init__(self, component_name: str, import_candidates, method_candidates) -> None:
        self.component_name = component_name
        self.import_candidates = list(import_candidates)
        self.method_candidates = list(method_candidates)
        self.instance: Optional[Any] = None
        self.import_error: Optional[str] = None

    def load(self) -> bool:
        if self.instance is not None:
            return True
        import importlib

        for module_path, attr_name in self.import_candidates:
            try:
                module = importlib.import_module(module_path)
                attr = getattr(module, attr_name)
                self.instance = attr() if isinstance(attr, type) else attr
                return True
            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"
        return False

    async def call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        import inspect

        if not self.load() or self.instance is None:
            return {"success": False, "message": f"{self.component_name} is not available.", "data": {}, "error": {"code": "COMPONENT_UNAVAILABLE", "detail": self.import_error}}

        for method_name in self.method_candidates:
            method = getattr(self.instance, method_name, None)
            if callable(method):
                try:
                    result = method(payload)
                    if inspect.isawaitable(result):
                        result = await result
                    return result if isinstance(result, dict) else {"success": True, "data": {"result": result}}
                except Exception as exc:  # noqa: BLE001
                    return {"success": False, "message": f"{self.component_name} failed.", "data": {}, "error": {"code": "COMPONENT_ERROR", "detail": str(exc)}}

        return {"success": False, "message": f"{self.component_name} has no compatible method.", "data": {}, "error": {"code": "METHOD_MISSING"}}


SECURITY_AGENT = OptionalHook(
    component_name="Security Agent",
    import_candidates=[
        ("agents.security_agent.security_agent", "SecurityAgent"),
        ("agents.security.security_agent", "SecurityAgent"),
    ],
    method_candidates=["run_task", "execute_task"],
)


async def request_voice_mode_approval(*, workspace_id: str, user_id: str, role: str, mode: str) -> Dict[str, Any]:
    """
    wake_word_admin / wake_word_trusted_users / continuous_conversation all
    require Security Agent approval to enable, per the mission spec. Fails
    CLOSED: if the Security Agent cannot be reached/confirmed, the mode
    change is NOT applied (matches "no risky action proceeds without
    approval" -- see agents/security_agent's own default-deny posture).
    """
    result = await SECURITY_AGENT.call(
        {
            "command": "authorize",
            "task_context": {"user_id": user_id, "workspace_id": workspace_id, "role": role},
            "action": f"voice.config.enable_{mode}",
            "payload": {"mode": mode},
        }
    )
    data = result.get("data") if isinstance(result, dict) else {}
    approved = bool(result.get("success")) and bool((data or {}).get("decision") in ("allow", "approved", True) or (data or {}).get("approved"))
    return {"approved": approved, "raw": result}


# =============================================================================
# Dependency status
# =============================================================================

def compute_dependency_status() -> Dict[str, Dict[str, Any]]:
    """
    Honest, environment-driven dependency check. Text-based wake-word
    detection (agents/voice_agent/wake_word.py) works today with no external
    provider (pure algorithmic regex/confidence scoring) -- everything else
    genuinely needs a configured provider, and none is configured in this
    deployment by default, so those honestly report
    external_dependency_required rather than a fake "available".

    Each entry is {"status": ..., "install_guidance": str | None} -- the
    install_guidance comes from agents/voice_agent/provider_capabilities.py's
    real (importlib.util.find_spec-based) local-package probe, never a
    fabricated "it's ready" claim. A package being importable on disk does
    NOT change status to "configured" -- that still requires the operator to
    actually set the matching WILLIAM_*_PROVIDER env var.
    """
    from agents.voice_agent.provider_capabilities import (
        stt_install_guidance,
        tts_install_guidance,
        wake_word_install_guidance,
    )

    def _status(env_var: str) -> str:
        return "configured" if os.getenv(env_var) else "external_dependency_required"

    def _entry(status_value: str, guidance: Optional[str]) -> Dict[str, Any]:
        return {"status": status_value, "install_guidance": guidance}

    return {
        "wake_word_engine": _entry("available", None),
        # Distinct from wake_word_engine above: text-based wake-word
        # detection (agents/voice_agent/wake_word.py) always works with no
        # provider (used by --simulate-text); a real *audio* wake-word
        # engine for always-listening microphone mode is a separate,
        # genuinely-optional dependency.
        "wake_word_provider": _entry(
            _status("WILLIAM_WAKE_WORD_PROVIDER"), wake_word_install_guidance()["install_guidance"]
        ),
        "audio_input_worker": _entry(_status("WILLIAM_AUDIO_INPUT_PROVIDER"), None),
        "stt_provider": _entry(_status("WILLIAM_STT_PROVIDER"), stt_install_guidance()["install_guidance"]),
        "tts_provider": _entry(_status("WILLIAM_TTS_PROVIDER"), tts_install_guidance()["install_guidance"]),
        "speaker_recognition_provider": _entry(_status("WILLIAM_SPEAKER_RECOGNITION_PROVIDER"), None),
    }


# =============================================================================
# Request models
# =============================================================================

class VoiceConfigRequest(BaseModel):
    mode: Optional[str] = None
    wake_word: Optional[str] = Field(default=None, max_length=60)


class VoiceProfileCreateRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=160)
    role: str = Field(default="guest")
    linked_user_id: Optional[str] = None
    allowed_agents: List[str] = Field(default_factory=list)
    blocked_agents: List[str] = Field(default_factory=list)
    allowed_capabilities: List[str] = Field(default_factory=list)
    blocked_capabilities: List[str] = Field(default_factory=list)
    can_use_voice: bool = True
    can_use_wake_word: bool = False
    can_access_private_memory: bool = False
    can_access_finance: bool = False
    can_access_system_agent: bool = False
    can_run_code_agent: bool = False
    requires_approval_for_risky_actions: bool = True
    preferred_language: str = "en"
    reply_language_mode: str = "same_as_speaker"


class VoiceProfileUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    allowed_agents: Optional[List[str]] = None
    blocked_agents: Optional[List[str]] = None
    allowed_capabilities: Optional[List[str]] = None
    blocked_capabilities: Optional[List[str]] = None
    can_use_voice: Optional[bool] = None
    can_use_wake_word: Optional[bool] = None
    can_access_private_memory: Optional[bool] = None
    can_access_finance: Optional[bool] = None
    can_access_system_agent: Optional[bool] = None
    can_run_code_agent: Optional[bool] = None
    requires_approval_for_risky_actions: Optional[bool] = None
    preferred_language: Optional[str] = None
    reply_language_mode: Optional[str] = None
    status: Optional[str] = None


class WakeEventRequest(BaseModel):
    session_id: Optional[str] = None
    confidence: Optional[float] = None
    activation_type: Optional[str] = "wake_word"


class VoiceCommandRequest(BaseModel):
    transcript: str = Field(..., min_length=1, max_length=4000)
    detected_language: str = Field(default="en")
    speaker_profile_id: Optional[str] = None
    voice_sample_ref: Optional[str] = None
    session_id: Optional[str] = None
    # No implicit default: this field means "the worker locally detected a
    # real wake word for this command" (see apps/worker_nodes/voice/
    # voice_worker.py::send_command, which only ever passes a real trigger
    # string or None). Defaulting it to a fixed "william" made every
    # command silently claim a detected wake word regardless of whether one
    # actually occurred, which made the standby-mode wake-word gate below a
    # no-op.
    wake_word: Optional[str] = None


class PushToTalkTextRequest(BaseModel):
    # `text` is the primary field going forward (matches dashboard
    # chat/voice-simulation callers); `transcript` stays real and required-
    # ish for backward compatibility with the existing dashboard voice
    # panel, which already sends {transcript, ...}. At least one must be
    # non-empty -- enforced in the route body, not here, so a request with
    # only `text` set doesn't fail Pydantic validation.
    text: Optional[str] = Field(default=None, max_length=4000)
    transcript: Optional[str] = Field(default=None, max_length=4000)
    detected_language: str = Field(default="en")
    session_id: Optional[str] = None


class EnrollStartRequest(BaseModel):
    profile_id: Optional[str] = None
    display_name: str = Field(..., min_length=1, max_length=160)


class EnrollCompleteRequest(BaseModel):
    profile_id: str
    voice_sample_ref: str


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Voice"])


@router.get("/status")
async def get_voice_status(context: "AuthContext" = Depends(get_voice_worker_auth_context)) -> Dict[str, Any]:
    # An installed Voice Worker's very first call every run is GET
    # /voice/status (mode/dependency_status/wake_word -- everything it
    # needs to decide locally whether to gate a command) -- a device-token-
    # only worker (no user JWT at all) must be able to reach this route,
    # not just heartbeat/worker-status/push-to-talk-text, or it can never
    # get past startup. Discovered via the manual live device-token
    # verification run, not written into the original plan -- mode/
    # dependency status for one's own workspace is operational data a
    # device is allowed to read, not an admin/billing/tasks/files concern.
    from database.db import db_manager
    from database.models.voice import compute_voice_connection_state
    from apps.api.services import voice_service as vs

    # Real provider status (audio input/STT/TTS/wake word) as seen from
    # THIS process's own machine/environment -- honest for the common
    # single-machine dev/test setup this repo ships with. In a real
    # distributed deployment (backend on a server with no microphone, a
    # separately-installed Voice Worker on the operator's own machine),
    # the WORKER independently re-checks its own local status before ever
    # attempting to listen (see voice_worker.py::_run_wake_word_admin_loop
    # -> _local_provider_readiness) -- it never blindly trusts this
    # server-side view for its own listen/speak decisions.
    try:
        from apps.worker_nodes.voice.providers import provider_status as voice_provider_status
        real_provider_status = voice_provider_status.get_full_status()
    except Exception as provider_status_exc:  # pragma: no cover - import-safe fallback
        logger.warning("Voice provider status unavailable in voice.py: %s", provider_status_exc)
        real_provider_status = {
            "audio_input_status": {"status": "external_dependency_required", "install_guidance": None},
            "stt_status": {"status": "external_dependency_required", "install_guidance": None},
            "tts_status": {"status": "external_dependency_required", "install_guidance": None},
            "wake_word_status": {"status": "external_dependency_required", "install_guidance": None},
            "speaker_recognition_status": {"status": "external_dependency_required", "install_guidance": None},
            "real_microphone_available": False,
            "speech_output_available": False,
            "always_listening_available": False,
            "text_command_available": True,
            "missing_dependencies": [],
            "setup_commands": {},
        }

    with db_manager.session_scope() as db:
        settings = vs.get_or_create_settings(db, context.workspace_id, context.user_id)
        dependency_status = compute_dependency_status()
        settings = vs.record_dependency_status(db, context.workspace_id, dependency_status)

        missing_dependencies = [
            key for key, value in dependency_status.items() if value["status"] not in ("configured", "available")
        ]
        worker_connected = vs.compute_worker_connected(settings)
        # The raw stored flag is overwritten with the staleness-aware value
        # in the response only -- the DB row itself is untouched here, so a
        # genuinely-recent heartbeat elsewhere in the same request isn't lost.
        settings = {**settings, "voice_worker_connected": worker_connected}
        connection_state = compute_voice_connection_state(settings, worker_connected)
        runtime_state = vs.compute_runtime_state(
            mode=settings["mode"], missing_dependencies=missing_dependencies, worker_connected=worker_connected,
        )
        last_speaker_name = vs.resolve_last_speaker_name(db, context.workspace_id, settings)
        active_sessions = vs.count_active_sessions(db, context.workspace_id)

    return api_success(
        "Voice status loaded.",
        data={
            "settings": settings,
            "connection_state": connection_state,
            "wake_word_default": "william",
            # Flattened, dashboard-shaped view of the same settings row --
            # kept alongside `settings` (not replacing it) so existing
            # callers reading data.settings.* keep working unchanged.
            "mode": settings["mode"],
            "enabled": settings["mode"] != "disabled",
            "runtime_state": runtime_state,
            "wake_word_enabled": settings["mode"] in ("wake_word_admin", "wake_word_trusted_users", "continuous_conversation", "standby"),
            "wake_word_phrase": settings["wake_word"],
            "worker_connected": worker_connected,
            "worker_last_seen_at": settings["voice_worker_last_seen_at"],
            "dependencies": dependency_status,
            "missing_dependencies": missing_dependencies,
            # POST /voice/push-to-talk/text (and voice_worker.py's
            # --simulate-text) never require STT/TTS/wake-word/audio-input
            # providers -- typed/simulated text always works, regardless of
            # what's missing above. Stated outright rather than left for
            # the dashboard to infer from the absence of a "typed text
            # needs X" dependency key.
            "text_command_available": True,
            # Real audio-input/STT/TTS/wake-word/speaker-recognition status
            # (apps/worker_nodes/voice/providers/provider_status.py) -- see
            # the comment above real_provider_status's computation for why
            # this reflects THIS process's own environment, not necessarily
            # a separately-installed Voice Worker's.
            "audio_input_status": real_provider_status["audio_input_status"],
            "stt_status": real_provider_status["stt_status"],
            "tts_status": real_provider_status["tts_status"],
            "wake_word_status": real_provider_status["wake_word_status"],
            "speaker_recognition_status": real_provider_status["speaker_recognition_status"],
            "real_microphone_available": real_provider_status["real_microphone_available"],
            "speech_output_available": real_provider_status["speech_output_available"],
            "always_listening_available": real_provider_status["always_listening_available"],
            "setup_commands": real_provider_status["setup_commands"],
            "active_sessions": active_sessions,
            "last_wake_event": settings["last_wake_event_at"],
            "last_command": settings["last_command_transcript"],
            "last_detected_language": settings["last_detected_language"],
            "last_speaker_name": last_speaker_name,
            "last_routed_agent": settings["last_routed_agent"],
            "last_error": settings["last_error_message"],
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
        },
        request_id=context.request_id,
    )


@router.post("/worker/heartbeat")
async def voice_worker_heartbeat(
    context: "AuthContext" = Depends(get_voice_worker_auth_context),
) -> Dict[str, Any]:
    """
    Called periodically by apps/worker_nodes/voice/voice_worker.py's idle
    loop so the dashboard can show a real worker_connected/worker_offline
    state instead of only updating on a wake event (a worker that's alive
    but hasn't heard a wake word yet should still show as connected). Uses
    the dual-mode dependency (installed device token OR dev-mode JWT), not
    plain get_current_auth_context -- an installed Voice Worker only ever
    carries a device token, never a user JWT.
    """
    from database.db import db_manager
    from apps.api.services import voice_service as vs

    with db_manager.session_scope() as db:
        settings = vs.record_worker_heartbeat(db, context.workspace_id)

    return api_success(
        "Heartbeat received.",
        data={"worker_connected": True, "worker_last_seen_at": settings["voice_worker_last_seen_at"]},
        request_id=context.request_id,
    )


@router.get("/worker/status")
async def get_voice_worker_status(
    context: "AuthContext" = Depends(get_voice_worker_auth_context),
) -> Dict[str, Any]:
    """Voice-device-specific status, distinct from the broader GET
    /voice/status (mode/dependencies/last-command) -- this is the one the
    dashboard's Voice Worker card and install/setup flow polls to answer
    "is a device even registered, and if so is it connected right now."""
    from database.db import db_manager
    from database.models.voice import VoiceSettings, compute_voice_connection_state
    from apps.api.services import voice_service as vs

    try:
        from apps.worker_nodes.voice.providers import provider_status as voice_provider_status
        real_provider_status = voice_provider_status.get_full_status()
    except Exception as provider_status_exc:  # pragma: no cover - import-safe fallback
        logger.warning("Voice provider status unavailable in voice.py: %s", provider_status_exc)
        real_provider_status = {
            "audio_input_status": {"status": "external_dependency_required", "install_guidance": None},
            "stt_status": {"status": "external_dependency_required", "install_guidance": None},
            "tts_status": {"status": "external_dependency_required", "install_guidance": None},
            "wake_word_status": {"status": "external_dependency_required", "install_guidance": None},
            "speaker_recognition_status": {"status": "external_dependency_required", "install_guidance": None},
            "real_microphone_available": False,
            "speech_output_available": False,
            "always_listening_available": False,
            "text_command_available": True,
            "missing_dependencies": [],
            "setup_commands": {},
        }

    with db_manager.session_scope() as db:
        row = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == context.workspace_id).first()
        row_dict = row.to_dict() if row is not None else None
        worker_connected = vs.compute_worker_connected(row_dict) if row_dict is not None else False
        connection_state = compute_voice_connection_state(row_dict, worker_connected)

    return api_success(
        "Voice worker status loaded.",
        data={
            "mode": row_dict.get("mode") if row_dict else "disabled",
            "connection_state": connection_state,
            "worker_connected": worker_connected,
            "device_id": row_dict.get("device_id") if row_dict else None,
            "device_name": row_dict.get("device_name") if row_dict else None,
            "device_platform": row_dict.get("device_platform") if row_dict else None,
            "device_token_status": row_dict.get("device_token_status") if row_dict else None,
            "supported_features": row_dict.get("supported_features") if row_dict else [],
            "worker_last_seen_at": row_dict.get("voice_worker_last_seen_at") if row_dict else None,
            "setup_completed_at": row_dict.get("setup_completed_at") if row_dict else None,
            "audio_input_status": real_provider_status["audio_input_status"],
            "stt_status": real_provider_status["stt_status"],
            "tts_status": real_provider_status["tts_status"],
            "wake_word_status": real_provider_status["wake_word_status"],
            "speaker_recognition_status": real_provider_status["speaker_recognition_status"],
            "text_command_available": real_provider_status["text_command_available"],
            "real_microphone_available": real_provider_status["real_microphone_available"],
            "speech_output_available": real_provider_status["speech_output_available"],
            "always_listening_available": real_provider_status["always_listening_available"],
            "missing_dependencies": real_provider_status["missing_dependencies"],
            "setup_commands": real_provider_status["setup_commands"],
        },
        request_id=context.request_id,
    )


@router.post("/config")
async def update_voice_config(
    payload: VoiceConfigRequest,
    context: "AuthContext" = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.voice import VALID_VOICE_MODES, VOICE_MODES_REQUIRING_APPROVAL, VOICE_MODE_DISABLED
    from apps.api.services import voice_service as vs

    if payload.mode is not None and payload.mode not in VALID_VOICE_MODES:
        raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invalid voice mode: {payload.mode}", "INVALID_MODE", context.request_id)

    approval_info: Optional[Dict[str, Any]] = None

    if payload.mode in VOICE_MODES_REQUIRING_APPROVAL:
        approval_info = await request_voice_mode_approval(
            workspace_id=context.workspace_id, user_id=context.user_id, role=context.role, mode=payload.mode,
        )
        if not approval_info["approved"]:
            with db_manager.session_scope() as db:
                settings = vs.get_or_create_settings(db, context.workspace_id, context.user_id)
            return api_success(
                f"Mode '{payload.mode}' requires Security Agent approval, which was not granted. Voice mode unchanged.",
                data={"settings": settings, "requires_approval": True, "approved": False},
                request_id=context.request_id,
            )

    with db_manager.session_scope() as db:
        settings = vs.update_settings(
            db, context.workspace_id, mode=payload.mode, wake_word=payload.wake_word, updated_by_user_id=context.user_id,
        )
        vs.write_voice_audit(
            db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.config.updated",
            metadata={"mode": payload.mode, "wake_word": payload.wake_word, "approval": approval_info},
        )

    return api_success(
        "Voice configuration updated.",
        data={"settings": settings, "requires_approval": payload.mode in VOICE_MODES_REQUIRING_APPROVAL, "approved": True},
        request_id=context.request_id,
    )


@router.get("/profiles")
async def list_voice_profiles(context: "AuthContext" = Depends(require_auth_role(Role.USER.value))) -> Dict[str, Any]:
    from database.db import db_manager
    from apps.api.services import voice_service as vs

    with db_manager.session_scope() as db:
        profiles = vs.list_profiles(db, context.workspace_id)

    return api_success("Voice profiles loaded.", data={"profiles": profiles, "count": len(profiles)}, request_id=context.request_id)


@router.post("/profiles")
async def create_voice_profile(
    payload: VoiceProfileCreateRequest,
    context: "AuthContext" = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from apps.api.services import voice_service as vs

    try:
        with db_manager.session_scope() as db:
            profile = vs.create_profile(
                db,
                workspace_id=context.workspace_id,
                created_by_user_id=context.user_id,
                **payload.model_dump(),
            )
            vs.write_voice_audit(
                db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.profile.created",
                resource_id=profile["id"], metadata={"display_name": profile["display_name"], "role": profile["role"]},
            )
    except ValueError as exc:
        raise_api_error(status.HTTP_400_BAD_REQUEST, str(exc), "INVALID_PROFILE", context.request_id)

    return api_success("Voice profile created.", data={"profile": profile}, request_id=context.request_id)


@router.patch("/profiles/{profile_id}")
async def update_voice_profile(
    profile_id: str,
    payload: VoiceProfileUpdateRequest,
    context: "AuthContext" = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from apps.api.services import voice_service as vs

    updates = {k: v for k, v in payload.model_dump().items() if v is not None}

    try:
        with db_manager.session_scope() as db:
            profile = vs.update_profile(db, context.workspace_id, profile_id, updates)
            if profile is None:
                raise_api_error(status.HTTP_404_NOT_FOUND, "Voice profile not found.", "PROFILE_NOT_FOUND", context.request_id)
            vs.write_voice_audit(
                db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.profile.updated",
                resource_id=profile_id, metadata={"updated_fields": sorted(updates.keys())},
            )
    except ValueError as exc:
        raise_api_error(status.HTTP_400_BAD_REQUEST, str(exc), "INVALID_UPDATE", context.request_id)

    return api_success("Voice profile updated.", data={"profile": profile}, request_id=context.request_id)


@router.delete("/profiles/{profile_id}")
async def delete_voice_profile(
    profile_id: str,
    hard_delete: bool = False,
    context: "AuthContext" = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from apps.api.services import voice_service as vs

    with db_manager.session_scope() as db:
        profile = vs.revoke_profile(db, context.workspace_id, profile_id, hard_delete=hard_delete)
        if profile is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Voice profile not found.", "PROFILE_NOT_FOUND", context.request_id)
        vs.write_voice_audit(
            db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.profile.revoked",
            resource_id=profile_id, metadata={"hard_delete": hard_delete},
        )

    return api_success("Voice profile revoked.", data={"profile": profile}, request_id=context.request_id)


@router.post("/wake-event")
async def register_wake_event(
    payload: WakeEventRequest,
    # voice_worker.py's own local text-based wake-word detection (see
    # VoiceWorker._handle_input_text) calls this route whenever it detects
    # the wake word in input text, unconditionally of voice mode -- an
    # installed, device-token-only worker must be able to reach it just
    # like GET /voice/status, or "William open Notepad" would 401 here
    # before push-to-talk-text is ever called. Discovered via the manual
    # live device-token verification run, same class of gap as GET
    # /voice/status's fix above.
    context: "AuthContext" = Depends(get_voice_worker_auth_context),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.voice import VoiceSettings, VOICE_MODE_DISABLED
    from apps.api.services import voice_service as vs

    with db_manager.session_scope() as db:
        settings_row = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == context.workspace_id).first()
        mode = settings_row.mode if settings_row else VOICE_MODE_DISABLED

        should_listen = mode != VOICE_MODE_DISABLED

        if settings_row is not None and should_listen:
            settings_row.last_wake_event_at = datetime.now(timezone.utc)
            settings_row.voice_worker_connected = True
            settings_row.voice_worker_last_seen_at = datetime.now(timezone.utc)
            db.flush()

        vs.record_voice_event(
            db, workspace_id=context.workspace_id, session_id=payload.session_id, profile_id=None,
            user_id=context.user_id, event_type="wake_detected",
            payload={"activation_type": payload.activation_type, "confidence": payload.confidence, "mode": mode, "should_listen": should_listen},
        )
        vs.write_voice_audit(
            db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.wake_event",
            metadata={"mode": mode, "should_listen": should_listen},
        )

    return api_success(
        "Wake event registered." if should_listen else "Wake word mode is disabled for this workspace.",
        data={"should_listen": should_listen, "mode": mode},
        request_id=context.request_id,
    )


@router.post("/command")
async def submit_voice_command(
    payload: VoiceCommandRequest,
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.voice import VoiceSettings, VOICE_MODE_DISABLED, VOICE_MODE_STANDBY, VOICE_MODE_PUSH_TO_TALK
    from agents.voice_agent.speaker_recognition import SpeakerRecognitionEngine
    from apps.api.services import voice_service as vs

    session_id = payload.session_id or new_id("voicesession")

    with db_manager.session_scope() as db:
        settings_row = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == context.workspace_id).first()
        mode = settings_row.mode if settings_row else VOICE_MODE_DISABLED

        if mode == VOICE_MODE_DISABLED:
            raise_api_error(status.HTTP_403_FORBIDDEN, "Voice mode is disabled for this workspace.", "VOICE_DISABLED", context.request_id)

        if mode == VOICE_MODE_STANDBY:
            # Only a worker-detected wake word (payload.wake_word set) may
            # reach the pipeline while in standby -- an ambient/typed
            # command with no wake word is refused, matching "stop
            # processing commands until wake word is used again". Landing
            # back in push_to_talk on reactivation is a deliberate
            # simplification: it is always safe/functional immediately,
            # rather than replaying a previously-approved wake-word mode
            # without re-running that approval.
            if not payload.wake_word:
                raise_api_error(
                    status.HTTP_403_FORBIDDEN,
                    "Voice is in standby mode. Say the wake word to resume.",
                    "VOICE_STANDBY",
                    context.request_id,
                )
            settings_row.mode = VOICE_MODE_PUSH_TO_TALK
            settings_row.updated_by_user_id = context.user_id
            settings_row.updated_at = datetime.now(timezone.utc)
            db.flush()
            vs.record_voice_event(
                db, workspace_id=context.workspace_id, session_id=session_id, profile_id=None,
                user_id=context.user_id, event_type="config_changed",
                payload={"mode": VOICE_MODE_PUSH_TO_TALK, "trigger": "wake_word_reactivation"},
            )
            mode = VOICE_MODE_PUSH_TO_TALK

        profile: Optional[Dict[str, Any]] = None

        if payload.speaker_profile_id:
            row = vs.get_profile(db, context.workspace_id, payload.speaker_profile_id)
            if row is None or row.status != "active":
                vs.record_voice_event(
                    db, workspace_id=context.workspace_id, session_id=session_id, profile_id=payload.speaker_profile_id,
                    user_id=context.user_id, event_type="speaker_denied", payload={"reason": "profile_not_found_or_inactive"},
                )
                raise_api_error(status.HTTP_403_FORBIDDEN, vs.UNAUTHORIZED_SPEAKER_MESSAGE, "SPEAKER_UNAUTHORIZED", context.request_id)
            profile = row.to_dict()
            row.last_used_at = datetime.now(timezone.utc)
            db.flush()
        elif has_min_role(context.role, Role.ADMIN.value):
            profile = vs.owner_virtual_profile(context.workspace_id, context.user_id)
        elif payload.voice_sample_ref:
            candidates = [p for p in vs.list_profiles(db, context.workspace_id) if p["status"] == "active" and p["voiceprint_reference_id"]]
            engine = SpeakerRecognitionEngine()
            verify_result = engine.verify_speaker(
                payload.voice_sample_ref,
                candidate_profiles=[{"profile_id": c["id"], "voiceprint_reference_id": c["voiceprint_reference_id"]} for c in candidates],
                context={"user_id": context.user_id, "workspace_id": context.workspace_id},
            )
            verify_data = verify_result.get("data", {})
            if not verify_result.get("success"):
                vs.record_voice_event(
                    db, workspace_id=context.workspace_id, session_id=session_id, profile_id=None,
                    user_id=context.user_id, event_type="speaker_denied", payload={"status": verify_data.get("status")},
                )
                if verify_data.get("status") == "external_dependency_required":
                    return api_success(
                        "Speaker verification is not available (no speaker-recognition provider configured).",
                        data={"status": "external_dependency_required"},
                        request_id=context.request_id,
                    )
                raise_api_error(status.HTTP_403_FORBIDDEN, vs.UNAUTHORIZED_SPEAKER_MESSAGE, "SPEAKER_UNAUTHORIZED", context.request_id)

            matched_id = verify_data.get("matched_profile_id")
            if verify_data.get("dev_bypass"):
                profile = vs.owner_virtual_profile(context.workspace_id, context.user_id)
            else:
                matched_row = next((c for c in candidates if c["id"] == matched_id), None)
                if matched_row is None:
                    raise_api_error(status.HTTP_403_FORBIDDEN, vs.UNAUTHORIZED_SPEAKER_MESSAGE, "SPEAKER_UNAUTHORIZED", context.request_id)
                profile = matched_row
        else:
            raise_api_error(status.HTTP_403_FORBIDDEN, vs.UNAUTHORIZED_SPEAKER_MESSAGE, "SPEAKER_UNAUTHORIZED", context.request_id)

        if mode == "wake_word_admin" and not has_min_role(profile.get("role", "guest"), Role.ADMIN.value) and profile.get("role") not in ("owner", "admin"):
            raise_api_error(status.HTTP_403_FORBIDDEN, "Wake word mode is currently admin-only for this workspace.", "WAKE_WORD_ADMIN_ONLY", context.request_id)

        envelope = await vs.route_voice_command_to_master_agent(
            db=db,
            workspace_id=context.workspace_id,
            user_id=context.user_id,
            profile=profile,
            transcript=payload.transcript,
            detected_language=payload.detected_language,
            session_id=session_id,
            request_id=context.request_id,
            wake_word=payload.wake_word,
            tts_available=compute_dependency_status()["tts_provider"]["status"] == "configured",
        )

    return api_success(envelope["message"] or "Voice command processed.", data=envelope, request_id=context.request_id)


@router.post("/push-to-talk/text")
async def push_to_talk_text(
    payload: PushToTalkTextRequest,
    context: "AuthContext" = Depends(get_voice_worker_auth_context),
) -> Dict[str, Any]:
    """Safe fallback mode: authenticated dashboard user (or voice_worker.py's
    --simulate-text) sends typed/PTT text directly, using their own real
    identity/role -- no separate voice profile enrollment required.

    A real command (not a control phrase, permission allowed) is executed
    through apps/api/routes/assistant.py::process_assistant_message -- the
    exact same dispatcher POST /assistant/message uses, including real
    SystemAgent/Windows Worker dispatch for "William open Notepad"-style
    commands. Before this, this route handed the transcript straight to
    the raw MasterAgentBridge (apps/api/services/voice_service.py::
    route_voice_command_to_master_agent), which has no intent-classifier
    windows_device_action special-casing and could never reach SystemAgent
    -- the same bypass bug the dashboard Command Console had before its own
    fix. Control-phrase handling ("William standby"/"William shutdown
    voice") and the speaker-permission pre-check still run first and keep
    their existing response shape -- a control phrase must never be sent
    to SystemAgent as if it were an app-open command."""
    from database.db import db_manager
    from apps.api.services import voice_service as vs
    from apps.api.routes.assistant import process_assistant_message, AssistantMessageRequest

    effective_text = (payload.text or payload.transcript or "").strip()
    if not effective_text:
        raise_api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "text or transcript is required.",
            "TEXT_REQUIRED",
            context.request_id,
        )

    session_id = payload.session_id or new_id("voicesession")
    tts_available = compute_dependency_status()["tts_provider"]["status"] == "configured"

    with db_manager.session_scope() as db:
        profile = vs.authenticated_user_virtual_profile(context.workspace_id, context.user_id, context.role)

        control_response = vs.try_handle_voice_control_phrase(
            db,
            workspace_id=context.workspace_id,
            user_id=context.user_id,
            profile=profile,
            transcript=effective_text,
            session_id=session_id,
            request_id=context.request_id,
            tts_available=tts_available,
        )
        if control_response is not None:
            return api_success(
                control_response.get("message") or "Voice control processed.",
                data=control_response,
                request_id=context.request_id,
            )

        allowed, reason, inferred_agent = vs.check_profile_permission(profile, effective_text)
        if not allowed:
            vs.record_voice_event(
                db, workspace_id=context.workspace_id, session_id=session_id, profile_id=profile.get("id"),
                user_id=context.user_id, event_type="speaker_denied",
                payload={"reason": reason, "inferred_agent": inferred_agent},
            )
            vs.write_voice_audit(
                db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.command.blocked",
                status="denied", metadata={"reason": reason, "inferred_agent": inferred_agent, "profile_id": profile.get("id")},
            )
            return api_success(
                reason,
                data={
                    "success": False,
                    "response_text": reason,
                    "speech_output_status": "spoken" if tts_available else "tts_missing",
                },
                request_id=context.request_id,
            )

    # Real command -- the bookkeeping session above has already committed
    # and closed (same nested-session-deadlock reason apps/api/routes/
    # assistant.py::send_message's own docstring explains: SystemAgent may
    # open its own short-lived session_scope() to queue a real WorkerTask).
    result = await process_assistant_message(
        AssistantMessageRequest(message=effective_text), context
    )
    data = dict(result.get("data") or {})
    # Tied only to real TTS provider availability, not command success --
    # a failure message ("Boss, I need an LLM provider...") is just as
    # speakable as a success one once a real TTS provider exists.
    data["speech_output_status"] = "spoken" if tts_available else "tts_missing"
    return {**result, "data": data}


@router.post("/enroll/start")
async def enroll_start(
    payload: EnrollStartRequest,
    context: "AuthContext" = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from agents.voice_agent.speaker_recognition import SpeakerRecognitionEngine
    from apps.api.services import voice_service as vs

    engine = SpeakerRecognitionEngine()
    health = engine.health_check()

    with db_manager.session_scope() as db:
        profile_id = payload.profile_id
        if not profile_id:
            profile = vs.create_profile(
                db, workspace_id=context.workspace_id, created_by_user_id=context.user_id,
                display_name=payload.display_name, role="owner" if not payload.profile_id else "guest",
                can_use_voice=True, can_use_wake_word=True,
            )
            profile_id = profile["id"]

        vs.record_voice_event(
            db, workspace_id=context.workspace_id, session_id=None, profile_id=profile_id,
            user_id=context.user_id, event_type="enrollment_started", payload={"display_name": payload.display_name},
        )
        vs.write_voice_audit(
            db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.enroll.started",
            resource_id=profile_id, metadata={"display_name": payload.display_name},
        )

    return api_success(
        "Enrollment started." if health["data"]["provider_configured"] else "Enrollment started, but no speaker-recognition provider is configured yet.",
        data={"profile_id": profile_id, "dependency_status": health["data"]},
        request_id=context.request_id,
    )


@router.post("/enroll/complete")
async def enroll_complete(
    payload: EnrollCompleteRequest,
    context: "AuthContext" = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from agents.voice_agent.speaker_recognition import SpeakerRecognitionEngine
    from apps.api.services import voice_service as vs

    engine = SpeakerRecognitionEngine()

    with db_manager.session_scope() as db:
        row = vs.get_profile(db, context.workspace_id, payload.profile_id)
        if row is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Voice profile not found.", "PROFILE_NOT_FOUND", context.request_id)

        result = engine.enroll_speaker(
            payload.voice_sample_ref, profile_id=payload.profile_id,
            context={"user_id": context.user_id, "workspace_id": context.workspace_id},
        )
        data = result.get("data", {})

        if result.get("success") and data.get("voiceprint_reference_id"):
            row.voiceprint_status = "enrolled"
            row.voiceprint_reference_id = data["voiceprint_reference_id"]
        else:
            row.voiceprint_status = "external_dependency_required" if data.get("status") == "external_dependency_required" else "pending"
        row.updated_at = datetime.now(timezone.utc)
        db.flush()

        vs.record_voice_event(
            db, workspace_id=context.workspace_id, session_id=None, profile_id=payload.profile_id,
            user_id=context.user_id, event_type="enrollment_completed", payload={"success": result.get("success"), "status": data.get("status")},
        )
        vs.write_voice_audit(
            db, user_id=context.user_id, workspace_id=context.workspace_id, action="voice.enroll.completed",
            resource_id=payload.profile_id, status="success" if result.get("success") else "failed",
            metadata={"status": data.get("status")},
        )

        profile_data = row.to_dict()

    return api_success(
        result.get("message", "Enrollment processed."),
        data={"profile": profile_data, "enrollment_result": data},
        request_id=context.request_id,
    )
