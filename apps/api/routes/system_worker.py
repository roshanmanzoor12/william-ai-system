"""
apps/api/routes/system_worker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real presence tracking AND real task dispatch for a Windows/Mac device
worker (apps/worker_nodes/windows/windows_worker.py, apps/worker_nodes/mac/
mac_worker.py). Presence (GET /worker/status, POST /worker/heartbeat) mirrors
apps/api/routes/voice.py's worker heartbeat pattern -- same problem, same
fix. Task dispatch (GET /worker/tasks, POST /worker/tasks/{id}/result) is the
real queue agents/system_agent/system_agent.py's open_app()/close_app() now
use once a worker is connected -- before this, worker_connected=True still
meant "no command can actually be sent to it yet" (external_dependency_required).

Every action is validated server-side against a fixed allowlist
(WORKER_MVP_ACTIONS/WORKER_RISKY_ACTIONS) -- never trust the worker (or the
caller) to decide what's safe. A risky action is never silently queued: it
always comes back "requires_approval" from classify_worker_action() (see
that function's docstring for why the shared security_review() helper is
still called, for audit purposes, but its verdict is deliberately not
trusted to auto-allow -- no real per-task human-approval workflow exists
yet to make that verdict meaningful for a specific risky action).

Mounted at /api/v1/system/worker/* (apps/api/main.py already owns
/api/v1/system/config and /api/v1/system/audit as separate, non-colliding
sub-paths under the same prefix).

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

LOGGER_NAME = "william.api.routes.system_worker"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())

WORKER_STALE_AFTER_SECONDS = 90

# Server-side allowlist -- the single source of truth for what a worker is
# ever allowed to be asked to do. Anything outside both sets is rejected
# outright by classify_worker_action(), regardless of what a caller asks
# for; nothing here ever gets queued just because a payload claims it.
WORKER_MVP_ACTIONS = {
    "open_microsoft_store",
    "open_chrome",
    "open_vscode",
    "open_notepad",
    "open_explorer",
    "open_folder",
    "open_file",
    "download_generated_file_to_downloads",
    "open_downloads_folder",
    "show_system_info",
}

# Matches the user-facing risky-action list (delete/shutdown/install/shell/
# messages/calls/financial/passwords) -- none of these are reachable via the
# Phase 1 assistant's windows_device_action flow today (only the MVP set
# above is), but the classification/approval machinery exists now so a
# future phase can add a risky action without inventing this gate from
# scratch.
WORKER_RISKY_ACTIONS = {
    "delete_file",
    "shutdown",
    "restart",
    "install_software",
    "run_shell_command",
    "send_message",
    "place_call",
    "financial_action",
    "enter_password",
    "browser_login_form",
}


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
            "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "system_worker"},
        },
    )


from apps.api.routes.auth import AuthContext, get_current_auth_context  # type: ignore

try:
    from apps.api.routes.agents import security_review  # type: ignore
except Exception as security_import_exc:  # pragma: no cover
    logger.warning("Could not import security_review in system_worker.py: %s", security_import_exc)

    async def security_review(payload: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore
        return {"success": False, "message": "Security Agent hook unavailable.", "data": {}, "error": {"code": "SECURITY_HOOK_UNAVAILABLE"}}


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
                "device_name": None,
                "supported_actions": [],
                "last_command": None,
                "last_result": None,
            }
        data = row.to_dict()
        data["worker_connected"] = compute_worker_connected(data)
        return data


async def classify_worker_action(
    action_type: str,
    *,
    context: AuthContext,
) -> str:
    """Returns "allowed" | "requires_approval" | "rejected". Never trusts
    the caller -- an action_type outside both known sets is rejected
    outright, no matter what a worker or an agent claims about it.

    Risky actions are ALWAYS "requires_approval", never delegated to
    security_review()/security_approved(): that shared helper (the same
    one apps/api/routes/agents.py uses for agent_enable/disable) calls
    SecurityAgent.check_permission(), which is a ROLE/permission check --
    for an owner/admin role with no specific required_permissions passed,
    it grants unconditionally regardless of the action name. There is no
    real per-task human-approval-granting workflow built yet (no endpoint
    to approve/deny a specific pending WorkerTask), so treating that
    trivial grant as "Security Agent approved this delete" would be a
    fake approval, not a real one. Hardcoding "requires_approval" here is
    the honest behavior until a real approval workflow exists."""
    if action_type in WORKER_MVP_ACTIONS:
        return "allowed"

    if action_type in WORKER_RISKY_ACTIONS:
        await security_review(
            {
                "type": "worker_task_dispatch",
                "actor_user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "action_type": action_type,
                "request_id": context.request_id,
                "created_at": utc_now().isoformat(),
            }
        )
        return "requires_approval"

    return "rejected"


router = APIRouter(tags=["System Worker"])


@router.get("/worker/status")
async def get_worker_status(context: AuthContext = Depends(get_current_auth_context)) -> Dict[str, Any]:
    status_data = get_system_worker_status(context.workspace_id)
    return api_success("System worker status loaded.", data=status_data, request_id=context.request_id)


class WorkerHeartbeatPayload(BaseModel):
    platform: str = "windows"
    device_name: Optional[str] = None
    supported_actions: List[str] = Field(default_factory=list)


@router.post("/worker/heartbeat")
async def worker_heartbeat(
    payload: WorkerHeartbeatPayload,
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    """A worker's first heartbeat IS its registration -- this upsert
    creates the row if none exists yet, so there is no separate
    /worker/register route (one wouldn't do anything this doesn't already
    do)."""
    from database.db import db_manager
    from database.models.system_worker import SystemWorkerStatus, VALID_PLATFORMS

    clean_platform = payload.platform if payload.platform in VALID_PLATFORMS else "windows"

    with db_manager.session_scope() as db:
        row = db.query(SystemWorkerStatus).filter(SystemWorkerStatus.workspace_id == context.workspace_id).first()
        if row is None:
            row = SystemWorkerStatus(workspace_id=context.workspace_id, platform=clean_platform)
            db.add(row)
        row.platform = clean_platform
        row.worker_connected = True
        row.worker_last_seen_at = utc_now()
        if payload.device_name:
            row.device_name = payload.device_name
        if payload.supported_actions:
            row.supported_actions = payload.supported_actions
        db.flush()
        data = row.to_dict()

    return api_success(
        "Heartbeat received.",
        data={
            "worker_connected": True,
            "worker_last_seen_at": data["worker_last_seen_at"],
            "device_name": data["device_name"],
            "supported_actions": data["supported_actions"],
        },
        request_id=context.request_id,
    )


@router.get("/worker/tasks")
async def poll_worker_tasks(
    limit: int = 5,
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    """Worker polls for its own workspace's queued tasks only -- real
    per-workspace isolation via the same JWT-derived AuthContext every
    other route in this file already uses; there is no way to pass a
    different workspace_id in and see another tenant's queue."""
    from database.db import db_manager
    from database.models.worker_task import WorkerTaskService

    with db_manager.session_scope() as db:
        tasks = WorkerTaskService.list_queued_for_workspace(
            db, workspace_id=context.workspace_id, limit=max(1, min(limit, 20))
        )
        task_dicts = [task.to_dict() for task in tasks]

    return api_success("Queued tasks loaded.", data={"tasks": task_dicts}, request_id=context.request_id)


class WorkerTaskResultPayload(BaseModel):
    status: str  # "completed" | "failed"
    result_message: Optional[str] = None
    error_code: Optional[str] = None
    error_details: Optional[str] = None
    device_id: Optional[str] = None


@router.post("/worker/tasks/{task_id}/result")
async def report_worker_task_result(
    task_id: str,
    payload: WorkerTaskResultPayload,
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.system_worker import SystemWorkerStatus
    from database.models.worker_task import TASK_COMPLETED, TASK_FAILED, WorkerTaskService

    with db_manager.session_scope() as db:
        task = WorkerTaskService.get_for_workspace(db, task_id=task_id, workspace_id=context.workspace_id)
        if task is None:
            # Deliberately 404, not 403 -- do not confirm or deny whether a
            # task_id exists in ANY other workspace; a task belonging to a
            # different tenant must look identical to a task that never
            # existed at all.
            raise_api_error(
                status.HTTP_404_NOT_FOUND,
                "Worker task not found.",
                "WORKER_TASK_NOT_FOUND",
                context.request_id,
            )

        if payload.status == TASK_COMPLETED:
            WorkerTaskService.mark_completed(
                db, task, result_message=payload.result_message, device_id=payload.device_id
            )
        else:
            WorkerTaskService.mark_failed(
                db, task,
                error_code=payload.error_code or "WORKER_TASK_FAILED",
                error_details=payload.error_details,
                device_id=payload.device_id,
            )

        summary = payload.result_message or payload.error_details or payload.status
        status_row = db.query(SystemWorkerStatus).filter(SystemWorkerStatus.workspace_id == context.workspace_id).first()
        if status_row is not None:
            status_row.last_command = task.action_type
            status_row.last_result = summary
            db.add(status_row)
            db.flush()

        result_data = task.to_dict()

    return api_success("Task result recorded.", data=result_data, request_id=context.request_id)
