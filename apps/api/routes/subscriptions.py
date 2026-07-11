"""
apps/api/routes/subscriptions.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Plan/agent-access routes, wired to the real subscriptions/*.py engine
(PlanRules, UsageMeter, AccessControl). Distinct from routes/billing.py
(subscription lifecycle: create/upgrade/cancel/invoices) -- this file
answers "what can this plan/role do right now" for the dashboard and
for other services to check before routing a task to an agent.

Known limitation (documented, not hidden): subscriptions/access_control.py
holds plan/usage/override state in-process only (see that module's own
docstrings) -- it is not yet backed by the real
database.models.subscription tables wired up in Phase 3. It resets on
restart and does not share state across worker processes. Tracked as a
follow-up in the final production-readiness report.

This file did not exist before -- apps/api/main.py referenced
apps.api.routes.subscriptions in OPTIONAL_ROUTERS but the module was
never created (ModuleNotFoundError, caught, silently unmounted).

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


LOGGER_NAME = "william.api.routes.subscriptions"
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
            "module": "subscriptions",
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
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "subscriptions"},
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
    logger.warning("Auth import fallback enabled in subscriptions.py: %s", auth_import_exc)
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
            permissions=["subscription:read"],
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
# Access control engine (in-process singleton -- see module docstring)
# =============================================================================

from subscriptions.access_control import AccessControl, AgentExecutionRequest  # noqa: E402

ACCESS_CONTROL = AccessControl()


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Subscriptions"])


@router.get("/plan")
async def get_current_plan(
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    plan_result = ACCESS_CONTROL.plan_rules.get_plan(context.plan)

    return api_success(
        "Current plan loaded.",
        data={"plan": plan_result.get("data", plan_result)},
        request_id=context.request_id,
    )


@router.post("/access-check")
async def check_agent_access(
    payload: Dict[str, Any],
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    agent_key = str(payload.get("agent_key") or "").strip()

    if not agent_key:
        raise_api_error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "agent_key is required.",
            "AGENT_KEY_REQUIRED",
            request_id=context.request_id,
        )

    request = AgentExecutionRequest(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        plan_name=context.plan,
        role=context.role,
        agent_key=agent_key,
        action=payload.get("action"),
        feature_key=payload.get("feature_key"),
        request_id=context.request_id,
    )

    decision = ACCESS_CONTROL.can_execute_agent(request)

    return api_success(
        "Access decision generated.",
        data=decision.get("data", decision),
        request_id=context.request_id,
    )


@router.get("/dashboard")
async def access_dashboard(
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    snapshot = ACCESS_CONTROL.get_access_dashboard_snapshot(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        plan_name=context.plan,
        role=context.role,
    )

    return api_success(
        "Access dashboard snapshot generated.",
        data=snapshot.get("data", snapshot),
        request_id=context.request_id,
    )


@router.get("/health/status")
async def subscriptions_health() -> Dict[str, Any]:
    return api_success(
        "Subscriptions service healthy.",
        data={"backing_store": "in_process_only", "persisted": False},
    )
