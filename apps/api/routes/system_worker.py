"""
apps/api/routes/system_worker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, honest presence tracking for a Windows/Mac device worker
(apps/worker_nodes/windows/windows_worker.py, apps/worker_nodes/mac/
mac_worker.py). Mirrors apps/api/routes/voice.py's worker heartbeat
endpoint exactly -- same problem, same fix.

This does NOT implement real remote task dispatch (poll/report) yet -- see
agents/system_agent/system_agent.py's open_app()/close_app(), which read
this status but stay honest about that gap (worker_connected=True does not
mean a command can actually be sent to it yet).

Mounted at /api/v1/system/worker/* (apps/api/main.py already owns
/api/v1/system/config and /api/v1/system/audit as separate, non-colliding
sub-paths under the same prefix).

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends

LOGGER_NAME = "william.api.routes.system_worker"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())

WORKER_STALE_AFTER_SECONDS = 90


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def api_success(message: str, data: Optional[Dict[str, Any]] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "system_worker"},
    }


from apps.api.routes.auth import AuthContext, get_current_auth_context  # type: ignore


def compute_worker_connected(status_row: Dict[str, Any]) -> bool:
    """Staleness-aware read, same pattern as apps/api/services/
    voice_service.py::compute_worker_connected -- a worker that hasn't
    heartbeated recently is honestly reported as disconnected even if the
    stored flag was never explicitly cleared."""
    if not status_row.get("worker_connected"):
        return False
    last_seen = status_row.get("worker_last_seen_at")
    if not last_seen:
        return False
    try:
        last_seen_dt = datetime.fromisoformat(last_seen)
    except (TypeError, ValueError):
        return False
    if last_seen_dt.tzinfo is None:
        last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
    return (utc_now() - last_seen_dt).total_seconds() <= WORKER_STALE_AFTER_SECONDS


def get_system_worker_status(workspace_id: str) -> Dict[str, Any]:
    """Real DB read, safe to call from agents/system_agent/system_agent.py
    (or anywhere else) without going through HTTP -- honest
    external_dependency_required-shaped default when no worker has ever
    checked in for this workspace."""
    from database.db import db_manager
    from database.models.system_worker import SystemWorkerStatus

    with db_manager.session_scope() as db:
        row = db.query(SystemWorkerStatus).filter(SystemWorkerStatus.workspace_id == workspace_id).first()
        if row is None:
            return {
                "workspace_id": workspace_id,
                "platform": None,
                "worker_connected": False,
                "worker_last_seen_at": None,
            }
        data = row.to_dict()
        data["worker_connected"] = compute_worker_connected(data)
        return data


router = APIRouter(tags=["System Worker"])


@router.get("/worker/status")
async def get_worker_status(context: AuthContext = Depends(get_current_auth_context)) -> Dict[str, Any]:
    status_data = get_system_worker_status(context.workspace_id)
    return api_success("System worker status loaded.", data=status_data, request_id=context.request_id)


@router.post("/worker/heartbeat")
async def worker_heartbeat(
    platform: str = "windows",
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.system_worker import SystemWorkerStatus, VALID_PLATFORMS

    clean_platform = platform if platform in VALID_PLATFORMS else "windows"

    with db_manager.session_scope() as db:
        row = db.query(SystemWorkerStatus).filter(SystemWorkerStatus.workspace_id == context.workspace_id).first()
        if row is None:
            row = SystemWorkerStatus(workspace_id=context.workspace_id, platform=clean_platform)
            db.add(row)
        row.platform = clean_platform
        row.worker_connected = True
        row.worker_last_seen_at = utc_now()
        db.flush()
        data = row.to_dict()

    return api_success(
        "Heartbeat received.",
        data={"worker_connected": True, "worker_last_seen_at": data["worker_last_seen_at"]},
        request_id=context.request_id,
    )
