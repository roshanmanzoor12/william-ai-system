"""
apps/api/routes/voice_device_setup.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real SaaS device-connector onboarding for the Voice Worker -- the exact
voice-side mirror of apps/api/routes/device_setup.py's Windows Worker flow:
a logged-in dashboard user requests a short-lived, one-time setup token
(POST /voice/device/setup-token); a brand-new, not-yet-authenticated Voice
Worker process redeems it exactly once (POST /voice/device/register) to
receive a durable, workspace-scoped device token; the dashboard can revoke
that device token at any time (POST /voice/device/disable) without
touching the user's own session.

This intentionally does NOT let a browser click magically start a local
microphone -- see get_voice_worker_auth_context()'s docstring and
apps/worker_nodes/voice/voice_worker.py for the actual worker process that
must be installed/running locally to ever go from "enabled" to "connected".
A registered voice device token also does not, by itself, change voice
mode -- mode (disabled/push_to_talk/wake_word_admin/...) stays a separate,
explicit choice made via POST /voice/config (see apps/api/routes/voice.py).

Device tokens are opaque secrets (secrets.token_urlsafe), never JWTs --
only their SHA-256 hash is ever persisted (database/models/voice.py::
VoiceSettings.device_token_hash), so revocation is a real, durable DB flag
flip, not dependent on any JWT blocklist.

Reuses database/models/device_setup_token.py::DeviceSetupToken/
DeviceSetupTokenService as-is (device_type="voice") -- that model was built
generically for exactly this kind of second device type, not Windows-only.

Mounted at /api/v1/voice/device/* (same /voice prefix as voice.py -- a
separate router, no path collision since voice.py has no /device/* routes
of its own).

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

LOGGER_NAME = "william.api.routes.voice_device_setup"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())

SETUP_TOKEN_TTL_SECONDS = int(os.getenv("WILLIAM_VOICE_DEVICE_SETUP_TOKEN_TTL_SECONDS", "900"))

from apps.api.routes.auth import AuthContext, get_current_auth_context, new_id  # type: ignore
from apps.api.routes._voice_worker_shared import (  # type: ignore
    VOICE_WORKER_SUPPORTED_FEATURES,
    api_success,
    raise_api_error,
    utc_now,
)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _build_setup_command(*, api_base_url: str, setup_token: str, device_name: str) -> str:
    return (
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\install_voice_worker.ps1 "
        f'-ApiBaseUrl "{api_base_url}" -SetupToken "{setup_token}" -DeviceName "{device_name}"'
    )


router = APIRouter(tags=["Voice Device Setup"])


class CreateVoiceSetupTokenPayload(BaseModel):
    device_name: str = Field(default="Voice Worker", max_length=140)


@router.post("/device/setup-token")
async def create_voice_setup_token(
    payload: CreateVoiceSetupTokenPayload = CreateVoiceSetupTokenPayload(),
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    """Only a real, already-authenticated dashboard user can mint one of
    these. The token is deliberately narrow: short-lived, single-use, and
    only ever redeemable for POST /voice/device/register -- it cannot
    itself heartbeat, submit commands, or reach any other route. Minting a
    setup token does NOT enable voice mode by itself -- that remains a
    separate POST /voice/config call the dashboard's Voice Control UI
    already makes."""
    from database.db import db_manager
    from database.models.device_setup_token import DeviceSetupTokenService

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    with db_manager.session_scope() as db:
        row = DeviceSetupTokenService.create(
            db,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            token_hash=token_hash,
            device_type="voice",
            allowed_actions=sorted(VOICE_WORKER_SUPPORTED_FEATURES),
            ttl_seconds=SETUP_TOKEN_TTL_SECONDS,
        )
        expires_at = row.expires_at.isoformat() if row.expires_at else None

    api_base_url = os.getenv("WILLIAM_PUBLIC_API_BASE_URL", "http://localhost:8001/api/v1")

    return api_success(
        "Voice device setup token created.",
        data={
            "setup_token": raw_token,
            "expires_at": expires_at,
            "expires_in_seconds": SETUP_TOKEN_TTL_SECONDS,
            "api_base_url": api_base_url,
            "setup_command": _build_setup_command(
                api_base_url=api_base_url, setup_token=raw_token, device_name=payload.device_name
            ),
            "install_script_url": "/voice/device/install-script",
        },
        request_id=context.request_id,
    )


class RegisterVoiceDevicePayload(BaseModel):
    setup_token: str
    device_name: str = Field(default="Voice Worker", max_length=140)
    device_platform: str = Field(default="windows", max_length=20)
    supported_features: List[str] = Field(default_factory=list)


@router.post("/device/register")
async def register_voice_device(payload: RegisterVoiceDevicePayload, request: Request) -> Dict[str, Any]:
    """No JWT here -- a brand-new voice worker process has no session yet.
    The ONLY thing that can ever reach this route successfully is a
    genuine, unexpired, not-yet-consumed device_type="voice" setup token
    minted by create_voice_setup_token() above. Never claims a device is
    registered without a real, validated token; never invents a
    workspace_id from the request; a Windows-Worker setup token (same
    shared table, device_type="windows") is explicitly rejected here even
    though the hash lookup itself doesn't filter by device_type, since the
    two device types must never be interchangeable."""
    request_id = request.headers.get("X-Request-ID") or new_id("req")

    from database.db import db_manager
    from database.models.device_setup_token import DeviceSetupTokenService
    from database.models.voice import VoiceSettings

    token_hash = _hash_token(payload.setup_token)

    with db_manager.session_scope() as db:
        setup_row = DeviceSetupTokenService.find_valid_by_hash(db, token_hash)
        if setup_row is None or setup_row.device_type != "voice":
            raise_api_error(
                401,
                "Setup token is invalid, already used, expired, or not a voice-device token.",
                "SETUP_TOKEN_INVALID",
                request_id,
            )

        device_id = new_id("voicedevice")
        device_token = secrets.token_urlsafe(32)
        device_token_hash = _hash_token(device_token)

        clean_features = [f for f in payload.supported_features if f in VOICE_WORKER_SUPPORTED_FEATURES] or [
            "push_to_talk_text"
        ]

        settings_row = (
            db.query(VoiceSettings)
            .filter(VoiceSettings.workspace_id == setup_row.workspace_id)
            .first()
        )
        if settings_row is None:
            from database.seeders.seed_voice_defaults import get_or_create_voice_settings

            settings_row, _created = get_or_create_voice_settings(
                db, workspace_id=setup_row.workspace_id, created_by_user_id=setup_row.user_id
            )

        settings_row.device_owner_user_id = setup_row.user_id
        settings_row.device_id = device_id
        settings_row.device_token_hash = device_token_hash
        settings_row.device_token_status = "active"
        settings_row.device_name = payload.device_name
        settings_row.device_platform = payload.device_platform
        settings_row.supported_features = clean_features
        settings_row.setup_completed_at = utc_now()
        settings_row.voice_worker_connected = True
        settings_row.voice_worker_last_seen_at = utc_now()

        DeviceSetupTokenService.mark_consumed(db, setup_row)
        db.flush()

        workspace_id = setup_row.workspace_id
        user_id = setup_row.user_id
        supported_features = settings_row.supported_features

    return api_success(
        "Voice device registered.",
        data={
            "device_id": device_id,
            "device_token": device_token,
            "workspace_id": workspace_id,
            "user_id": user_id,
            "supported_features": supported_features,
        },
        request_id=request_id,
    )


@router.post("/device/disable")
async def disable_voice_device(context: AuthContext = Depends(get_current_auth_context)) -> Dict[str, Any]:
    """Revokes the workspace's voice device token immediately and durably
    (a DB flag flip, checked on every voice-worker request via
    get_voice_worker_auth_context() below) -- idempotent, so disabling an
    already-disabled or never-set-up workspace is not an error. Does NOT
    change voice mode -- a revoked device simply can no longer authenticate
    as a device; the workspace's mode setting is untouched."""
    from database.db import db_manager
    from database.models.voice import VoiceSettings

    with db_manager.session_scope() as db:
        row = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == context.workspace_id).first()
        if row is not None:
            row.device_token_status = "revoked"
            row.voice_worker_connected = False
            db.add(row)
            db.flush()

    return api_success("Voice Worker disabled.", data={}, request_id=context.request_id)


@router.get("/device/install-script")
async def download_voice_install_script() -> PlainTextResponse:
    """Static, non-sensitive content -- no auth required. Serves the real
    scripts/windows/install_voice_worker.ps1 file directly so the
    dashboard never carries a second, driftable copy."""
    from pathlib import Path

    script_path = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "install_voice_worker.ps1"
    try:
        content = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read install_voice_worker.ps1: %s", exc)
        raise_api_error(404, "Install script is not available.", "INSTALL_SCRIPT_MISSING")
        return PlainTextResponse("")  # unreachable, satisfies type checkers

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=install_voice_worker.ps1"},
    )


async def get_voice_worker_auth_context(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
) -> AuthContext:
    """Dual-mode auth for the voice-worker-facing routes only (POST
    /voice/worker/heartbeat, GET /voice/worker/status, POST
    /voice/push-to-talk/text) -- every other voice route
    (/voice/config, /voice/profiles/*, /voice/enroll/*, etc.) still
    requires a real user JWT via the unmodified get_current_auth_context
    and never imports this function at all. This is what makes "a voice
    device token cannot reach admin/billing/tasks/files" true by
    construction.

    Tries a device-token hash lookup first (recognizes ONLY tokens minted
    by /voice/device/register); a revoked match fails fast with a specific
    error. A hash miss falls back to the existing, unmodified
    get_current_auth_context for the pre-existing dev-mode "paste a real
    user JWT" path -- that path keeps working completely unchanged, which
    is what lets tests/worker_tests/test_voice_worker.py's existing
    JWT-based fixtures keep passing unmodified."""
    request_id = x_request_id or getattr(request.state, "request_id", None) or new_id("req")

    if not authorization or not authorization.lower().startswith("bearer "):
        raise_api_error(401, "Bearer token required.", "ACCESS_TOKEN_REQUIRED", request_id)

    token = authorization.split(" ", 1)[1].strip()
    token_hash = _hash_token(token)

    from database.db import db_manager
    from database.models.voice import VoiceSettings

    with db_manager.session_scope() as db:
        row = db.query(VoiceSettings).filter(VoiceSettings.device_token_hash == token_hash).first()
        if row is not None:
            if row.device_token_status == "revoked":
                raise_api_error(
                    401,
                    "Device token revoked. Re-enable worker from dashboard.",
                    "DEVICE_TOKEN_REVOKED",
                    request_id,
                )
            device_context = AuthContext(
                request_id=request_id,
                user_id=row.device_owner_user_id or "device_owner_unknown",
                workspace_id=row.workspace_id,
                session_id=f"voicedevice_{row.device_id or 'unknown'}",
                role="device",
                plan="free",
                email="device@worker.local",
                permissions=[],
                is_platform_admin=False,
            )
            return device_context

    return await get_current_auth_context(request, authorization=authorization, x_request_id=x_request_id)


__all__ = ["router", "get_voice_worker_auth_context"]
