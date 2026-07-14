"""
apps/api/routes/capabilities.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase H -- a thin, read-only route exposing core/capability_roadmap.py's 50
advanced-function manifest via the API, so it's inspectable at runtime
instead of only living in a doc that can silently drift from reality.

Kept separate from apps/api/routes/system_worker.py (which owns real worker
presence/task-dispatch) so that file stays scoped to its own concern.

Mounted at /api/v1/system/capabilities (same /system prefix as
system_worker.py -- two separate router objects sharing one prefix is a
normal FastAPI pattern, no collision since the sub-paths differ).

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict

from fastapi import APIRouter, Depends

LOGGER_NAME = "william.api.routes.capabilities"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())

try:
    from apps.api.routes.auth import AuthContext, get_current_auth_context
except Exception as import_exc:  # pragma: no cover
    logger.warning("Could not import real AuthContext in capabilities.py: %s", import_exc)
    from pydantic import BaseModel
    from fastapi import Header
    from typing import Optional

    class AuthContext(BaseModel):  # type: ignore
        user_id: str
        workspace_id: str
        request_id: str = "unknown"

    async def get_current_auth_context(  # type: ignore
        x_user_id: Optional[str] = Header(default="demo_user", alias="X-User-ID"),
        x_workspace_id: Optional[str] = Header(default="demo_workspace", alias="X-Workspace-ID"),
    ) -> AuthContext:
        return AuthContext(user_id=x_user_id or "demo_user", workspace_id=x_workspace_id or "demo_workspace")

try:
    from apps.api.routes.system_worker import api_success
except Exception:  # pragma: no cover
    def api_success(message: str, *, data: Any = None, request_id: str = "unknown") -> Dict[str, Any]:  # type: ignore
        return {"success": True, "message": message, "data": data or {}, "error": None, "metadata": {"request_id": request_id}}

from core.capability_roadmap import capability_roadmap_as_dicts

router = APIRouter(tags=["Capability Roadmap"])


@router.get("/capabilities")
async def get_capability_roadmap(
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    entries = capability_roadmap_as_dicts()
    status_counts: Dict[str, int] = {}
    for entry in entries:
        status_counts[entry["current_status"]] = status_counts.get(entry["current_status"], 0) + 1

    return api_success(
        "Capability roadmap loaded.",
        data={
            "capabilities": entries,
            "count": len(entries),
            "status_breakdown": status_counts,
        },
        request_id=context.request_id,
    )
