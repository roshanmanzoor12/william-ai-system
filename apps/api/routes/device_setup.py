"""
apps/api/routes/device_setup.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real SaaS device-connector onboarding: a logged-in dashboard user requests a
short-lived, one-time setup token (POST /device/setup-token); a brand-new,
not-yet-authenticated Windows Worker process redeems it exactly once
(POST /device/register) to receive a durable, workspace-scoped device
token; the dashboard can revoke that device token at any time
(POST /device/disable) without touching the user's own session.

This intentionally does NOT let a browser click magically start a local
process -- see get_worker_auth_context()'s docstring and
apps/worker_nodes/windows/windows_worker.py for the actual worker process
that must be installed/running locally to ever go from "enabled" to
"connected".

Device tokens are opaque secrets (secrets.token_urlsafe), never JWTs --
only their SHA-256 hash is ever persisted (database/models/system_worker.py
::SystemWorkerStatus.device_token_hash), so revocation is a real, durable
DB flag flip, not dependent on the JWT jti-blocklist apps/api/routes/
auth.py's own comments already document as in-memory/non-durable.

Mounted at /api/v1/system/device/* (same /system prefix as
system_worker.py/capabilities.py -- separate router, no path collision).

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

LOGGER_NAME = "william.api.routes.device_setup"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())

SETUP_TOKEN_TTL_SECONDS = int(os.getenv("WILLIAM_DEVICE_SETUP_TOKEN_TTL_SECONDS", "900"))

from apps.api.routes.auth import AuthContext, get_current_auth_context, new_id  # type: ignore
from apps.api.routes._worker_shared import (  # type: ignore
    WORKER_MVP_ACTIONS,
    api_success,
    raise_api_error,
    utc_now,
)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _build_setup_command(*, api_base_url: str, setup_token: str, device_name: str) -> str:
    return (
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\windows\\install_windows_worker.ps1 "
        f'-ApiBaseUrl "{api_base_url}" -SetupToken "{setup_token}" -DeviceName "{device_name}"'
    )


router = APIRouter(tags=["Device Setup"])


class CreateSetupTokenPayload(BaseModel):
    device_name: str = Field(default="Windows Laptop", max_length=140)


@router.post("/device/setup-token")
async def create_setup_token(
    payload: CreateSetupTokenPayload = CreateSetupTokenPayload(),
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    """Only a real, already-authenticated dashboard user can mint one of
    these -- this is the one and only place a user's own JWT is ever
    involved in the device-setup flow. The token this returns is
    deliberately narrow: short-lived, single-use, and only ever redeemable
    for POST /device/register -- it cannot itself poll tasks, heartbeat,
    or reach any other route."""
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
            device_type="windows",
            allowed_actions=sorted(WORKER_MVP_ACTIONS),
            ttl_seconds=SETUP_TOKEN_TTL_SECONDS,
        )
        expires_at = row.expires_at.isoformat() if row.expires_at else None

    api_base_url = os.getenv("WILLIAM_PUBLIC_API_BASE_URL", "http://localhost:8001/api/v1")

    return api_success(
        "Device setup token created.",
        data={
            "setup_token": raw_token,
            "expires_at": expires_at,
            "expires_in_seconds": SETUP_TOKEN_TTL_SECONDS,
            "api_base_url": api_base_url,
            "setup_command": _build_setup_command(
                api_base_url=api_base_url, setup_token=raw_token, device_name=payload.device_name
            ),
            # Relative to API_BASE_URL, matching every other path this API
            # returns (e.g. generated_files[].download_url elsewhere) --
            # the dashboard prefixes it with its own NEXT_PUBLIC_API_BASE_URL.
            "install_script_url": "/system/device/install-script",
        },
        request_id=context.request_id,
    )


class RegisterDevicePayload(BaseModel):
    setup_token: str
    device_name: str = Field(default="Windows Laptop", max_length=140)
    supported_actions: List[str] = Field(default_factory=list)


@router.post("/device/register")
async def register_device(payload: RegisterDevicePayload, request: Request) -> Dict[str, Any]:
    """No JWT here -- a brand-new worker process has no session yet. The
    ONLY thing that can ever reach this route successfully is a genuine,
    unexpired, not-yet-consumed setup token minted by create_setup_token()
    above. Never claims a device is registered without a real, validated
    token; never invents a workspace_id from the request."""
    request_id = request.headers.get("X-Request-ID") or new_id("req")

    from database.db import db_manager
    from database.models.device_setup_token import DeviceSetupTokenService
    from database.models.system_worker import SystemWorkerStatus, VALID_PLATFORMS

    token_hash = _hash_token(payload.setup_token)

    with db_manager.session_scope() as db:
        setup_row = DeviceSetupTokenService.find_valid_by_hash(db, token_hash)
        if setup_row is None:
            raise_api_error(
                401,
                "Setup token is invalid, already used, or expired.",
                "SETUP_TOKEN_INVALID",
                request_id,
            )

        device_id = new_id("device")
        device_token = secrets.token_urlsafe(32)
        device_token_hash = _hash_token(device_token)

        clean_platform = "windows" if "windows" in VALID_PLATFORMS else "windows"
        status_row = (
            db.query(SystemWorkerStatus)
            .filter(SystemWorkerStatus.workspace_id == setup_row.workspace_id)
            .first()
        )
        if status_row is None:
            status_row = SystemWorkerStatus(workspace_id=setup_row.workspace_id, platform=clean_platform)
            db.add(status_row)

        status_row.platform = clean_platform
        status_row.owner_user_id = setup_row.user_id
        status_row.device_id = device_id
        status_row.device_token_hash = device_token_hash
        status_row.device_token_status = "active"
        status_row.device_name = payload.device_name
        if payload.supported_actions:
            status_row.supported_actions = payload.supported_actions
        status_row.setup_completed_at = utc_now()
        status_row.worker_connected = True
        status_row.worker_last_seen_at = utc_now()

        DeviceSetupTokenService.mark_consumed(db, setup_row)
        db.flush()

        workspace_id = setup_row.workspace_id
        user_id = setup_row.user_id
        supported_actions = status_row.supported_actions

    return api_success(
        "Device registered.",
        data={
            "device_id": device_id,
            "device_token": device_token,
            "workspace_id": workspace_id,
            "user_id": user_id,
            "supported_actions": supported_actions,
        },
        request_id=request_id,
    )


@router.post("/device/disable")
async def disable_device(context: AuthContext = Depends(get_current_auth_context)) -> Dict[str, Any]:
    """Revokes the workspace's device token immediately and durably (a DB
    flag flip, checked on every worker request via
    get_worker_auth_context() below) -- idempotent, so disabling an
    already-disabled or never-set-up workspace is not an error."""
    from database.db import db_manager
    from database.models.system_worker import SystemWorkerStatus

    with db_manager.session_scope() as db:
        row = (
            db.query(SystemWorkerStatus)
            .filter(SystemWorkerStatus.workspace_id == context.workspace_id)
            .first()
        )
        if row is not None:
            row.device_token_status = "revoked"
            row.worker_connected = False
            db.add(row)
            db.flush()

    return api_success("Windows Worker disabled.", data={}, request_id=context.request_id)


@router.get("/device/install-script")
async def download_install_script() -> PlainTextResponse:
    """Static, non-sensitive content -- no auth required. Serves the real
    scripts/windows/install_windows_worker.ps1 file directly so the
    dashboard never carries a second, driftable copy."""
    from pathlib import Path

    script_path = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "install_windows_worker.ps1"
    try:
        content = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read install_windows_worker.ps1: %s", exc)
        raise_api_error(404, "Install script is not available.", "INSTALL_SCRIPT_MISSING")
        return PlainTextResponse("")  # unreachable, satisfies type checkers

    return PlainTextResponse(
        content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=install_windows_worker.ps1"},
    )


async def get_worker_auth_context(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
) -> AuthContext:
    """Dual-mode auth for the 4 worker routes (heartbeat/tasks/tasks-result/
    status) only -- every other route in this codebase still requires a
    real user JWT via the unmodified get_current_auth_context. This is
    what makes "a device token cannot reach admin/billing/memory/etc.
    routes" true by construction: those routes never import or use this
    function at all.

    Tries a device-token hash lookup first (a cheap, deliberate DB read
    that recognizes ONLY tokens minted by /device/register); a revoked
    match fails fast with a specific error rather than falling through to
    JWT parsing (which would just fail with the generic "invalid token"
    message and hide the real reason). A hash miss falls back to the
    existing, unmodified get_current_auth_context for the pre-existing
    dev-mode "paste a real user JWT" path -- that path keeps working
    completely unchanged."""
    request_id = x_request_id or getattr(request.state, "request_id", None) or new_id("req")

    if not authorization or not authorization.lower().startswith("bearer "):
        raise_api_error(401, "Bearer token required.", "ACCESS_TOKEN_REQUIRED", request_id)

    token = authorization.split(" ", 1)[1].strip()
    token_hash = _hash_token(token)

    from database.db import db_manager
    from database.models.system_worker import SystemWorkerStatus

    with db_manager.session_scope() as db:
        row = (
            db.query(SystemWorkerStatus)
            .filter(SystemWorkerStatus.device_token_hash == token_hash)
            .first()
        )
        if row is not None:
            if row.device_token_status == "revoked":
                raise_api_error(
                    401,
                    "Device token has been revoked. Re-enable Windows Worker from Settings.",
                    "DEVICE_TOKEN_REVOKED",
                    request_id,
                )
            device_context = AuthContext(
                request_id=request_id,
                user_id=row.owner_user_id or "device_owner_unknown",
                workspace_id=row.workspace_id,
                session_id=f"device_{row.device_id or 'unknown'}",
                role="device",
                plan="free",
                email="device@worker.local",
                permissions=[],
                is_platform_admin=False,
            )
            return device_context

    return await get_current_auth_context(request, authorization=authorization, x_request_id=x_request_id)


__all__ = ["router", "get_worker_auth_context"]
