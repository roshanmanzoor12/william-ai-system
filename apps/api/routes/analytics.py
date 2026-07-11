"""
apps/api/routes/analytics.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Workspace analytics, aggregated from real persisted rows only (agent
tasks, agent events, audit log). No invented/placeholder metrics --
every number here is a real COUNT()/aggregate against the database.

Purpose:
- Workspace-scoped summary counters for the dashboard analytics page
- Task status breakdown
- Audit activity breakdown

This file did not exist before -- apps/api/main.py referenced
apps.api.routes.analytics in OPTIONAL_ROUTERS but the module was never
created (ModuleNotFoundError, caught, silently unmounted).

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field


LOGGER_NAME = "william.api.routes.analytics"
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
# Roles / Plans (mirrors apps/api/routes/auth.py)
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
            "module": "analytics",
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
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "analytics"},
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
    logger.warning("Auth import fallback enabled in analytics.py: %s", auth_import_exc)
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
            permissions=["analytics:read"],
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


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Analytics"])


@router.get("/summary")
async def analytics_summary(
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    from sqlalchemy import func
    from database.db import db_manager
    from database.models.agent_task import AgentTask
    from database.models.agent_event import AgentEvent
    from database.models.security import AuditLogModel

    workspace_id = context.workspace_id
    since_7d = datetime.now(timezone.utc) - timedelta(days=7)

    with db_manager.session_scope() as session:
        total_tasks = (
            session.query(func.count(AgentTask.id))
            .filter(AgentTask.workspace_id == workspace_id)
            .scalar()
            or 0
        )

        tasks_by_status_rows = (
            session.query(AgentTask.status, func.count(AgentTask.id))
            .filter(AgentTask.workspace_id == workspace_id)
            .group_by(AgentTask.status)
            .all()
        )
        tasks_by_status = {status_value: count for status_value, count in tasks_by_status_rows}

        total_agent_events = (
            session.query(func.count(AgentEvent.id))
            .filter(AgentEvent.workspace_id == workspace_id)
            .scalar()
            or 0
        )

        audit_events_7d = (
            session.query(func.count(AuditLogModel.id))
            .filter(
                AuditLogModel.workspace_id == workspace_id,
                AuditLogModel.timestamp >= since_7d,
            )
            .scalar()
            or 0
        )

        audit_by_status_rows = (
            session.query(AuditLogModel.status, func.count(AuditLogModel.id))
            .filter(AuditLogModel.workspace_id == workspace_id, AuditLogModel.timestamp >= since_7d)
            .group_by(AuditLogModel.status)
            .all()
        )
        audit_by_status = {status_value: count for status_value, count in audit_by_status_rows}

    return api_success(
        "Analytics summary generated.",
        data={
            "workspace_id": workspace_id,
            "tasks": {"total": total_tasks, "by_status": tasks_by_status},
            "agent_events": {"total": total_agent_events},
            "audit": {"last_7_days_total": audit_events_7d, "by_status": audit_by_status},
            "generated_at": utc_now(),
        },
        request_id=context.request_id,
    )


@router.get("/health/status")
async def analytics_health() -> Dict[str, Any]:
    return api_success("Analytics service healthy.")
