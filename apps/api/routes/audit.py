"""
apps/api/routes/audit.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Audit log routes, reading from database.models.security.AuditLogModel
(the real persisted audit trail wired up in Phase 4's auth rewrite and
reused by every other route file's audit hooks).

Purpose:
- List/search audit events for the caller's workspace
- Read a single audit event
- Workspace isolation: never return another workspace's events

This file did not exist before -- apps/api/main.py referenced
apps.api.routes.audit in OPTIONAL_ROUTERS but the module was never
created (ModuleNotFoundError, caught, silently unmounted).

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


LOGGER_NAME = "william.api.routes.audit"
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


def parse_int(value: Optional[str], default: int, minimum: int = 1, maximum: int = 500) -> int:
    try:
        parsed = int(value) if value is not None else default
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


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
            "module": "audit",
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
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "audit"},
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
    logger.warning("Auth import fallback enabled in audit.py: %s", auth_import_exc)
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
            permissions=["audit:read"],
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

router = APIRouter(tags=["Audit"])


@router.get("")
async def list_audit_events(
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    status_filter: Optional[str] = None,
    limit: Optional[str] = None,
    context: "AuthContext" = Depends(require_auth_role(Role.MANAGER.value)),
) -> Dict[str, Any]:
    """Manager role or higher: full workspace audit trail (matches
    security/policies/default_policy.json's "blocked_actions/override
    rules hidden from non-admin" visibility intent)."""
    from database.db import db_manager
    from database.models.security import AuditLogModel

    safe_limit = parse_int(limit, default=100)

    with db_manager.session_scope() as session:
        query = session.query(AuditLogModel).filter(AuditLogModel.workspace_id == context.workspace_id)

        if action:
            query = query.filter(AuditLogModel.action == action)
        if resource_type:
            query = query.filter(AuditLogModel.resource_type == resource_type)
        if status_filter:
            query = query.filter(AuditLogModel.status == status_filter)

        rows = query.order_by(AuditLogModel.timestamp.desc()).limit(safe_limit).all()
        events = [row.to_dict(include_internal=has_min_role(context.role, Role.ADMIN.value)) for row in rows]

    return api_success(
        "Audit events loaded.",
        data={"events": events, "count": len(events)},
        request_id=context.request_id,
    )


@router.get("/{event_id}")
async def get_audit_event(
    event_id: str,
    context: "AuthContext" = Depends(require_auth_role(Role.MANAGER.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.security import AuditLogModel

    with db_manager.session_scope() as session:
        row = session.get(AuditLogModel, event_id)

        if not row or row.workspace_id != context.workspace_id:
            raise_api_error(
                status.HTTP_404_NOT_FOUND,
                "Audit event not found.",
                "AUDIT_EVENT_NOT_FOUND",
                request_id=context.request_id,
            )

        payload = row.to_dict(include_internal=has_min_role(context.role, Role.ADMIN.value))

    return api_success("Audit event loaded.", data={"event": payload}, request_id=context.request_id)


@router.get("/health/status")
async def audit_health() -> Dict[str, Any]:
    return api_success("Audit service healthy.")
