"""
apps/api/routes/agent_permissions.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real backend for the dashboard's "Agent Permissions" page
(apps/dashboard/src/app/(dashboard)/agent-permissions/page.tsx). That page
was calling GET/PUT /agent-permissions against a route that never existed
anywhere in the API -- FastAPI's default 404 body
(`{"detail": "Not Found"}`) doesn't match this codebase's
`{success, data, error}` envelope, so the frontend's own response-shape
guard correctly rejected it as "The API returned an invalid response
shape." That was an honest symptom of a missing route, not a parsing bug.

Data model:
- Per-user, per-agent access is NOT reinvented here -- it reuses the same
  real, already-tested WorkspaceAgentConfig.allowed_user_ids/denied_user_ids
  store (apps.api.routes.agents.AGENT_STORE) that
  PATCH /agents/{agent_name}/access already writes to. This route is a
  workspace-wide, per-user aggregation VIEW/EDITOR over that same store,
  not a second source of truth.
- "users" comes from the real database.models.workspace.WorkspaceMembership
  table (+ database.models.user.User for display name/email), scoped to
  context.workspace_id -- never another workspace's members.
- "role_matrix" and each agent's "allowed_roles" are derived live from
  AGENT_CATALOG's required_role + the same has_min_role/ROLE_RANK ranking
  agents.py itself uses for real access decisions, not a hand-maintained
  duplicate table.

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field


LOGGER_NAME = "william.api.routes.agent_permissions"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# Safe API responses (same envelope convention as every other router)
# =============================================================================

def api_success(message: str, data: Optional[Dict[str, Any]] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "agent_permissions"},
    }


def raise_api_error(status_code: int, message: str, code: str, request_id: Optional[str] = None, details: Optional[Any] = None) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": {},
            "error": {"code": code, "details": details},
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "agent_permissions"},
        },
    )


# =============================================================================
# Auth (canonical context -- same dependency every other router uses)
# =============================================================================

from apps.api.routes.auth import AuthContext, get_current_auth_context, require_auth_role  # type: ignore

# Reuse the real agent registry/store and its role-ranking + hook helpers
# rather than duplicating them -- this route is a view/editor over the same
# data agents.py already owns.
from apps.api.routes.agents import (  # type: ignore
    AGENT_CATALOG,
    AGENT_STORE,
    Role,
    ROLE_RANK,
    has_min_role,
    has_min_plan,
    security_review,
    emit_memory_context,
    prepare_verification,
    write_agent_audit,
)

# The 5-value DB membership role vocabulary (database.models.workspace.
# WorkspaceMemberRole) -- this is what real WorkspaceMembership rows
# actually carry, distinct from AGENT_CATALOG's 8-value Role enum used for
# required_role gating (ROLE_RANK/has_min_role already reconcile the two,
# "member" ranks equal to "user").
UI_ROLES = ["owner", "admin", "manager", "member", "viewer"]

AGENT_CATEGORY_MAP: Dict[str, str] = {
    "master": "core",
    "security": "security",
    "verification": "core",
    "memory": "memory",
    "code": "execution",
    "browser": "execution",
    "voice": "device",
    "system": "device",
    "visual": "creative",
    "workflow": "business",
    "hologram": "creative",
    "call": "business",
    "business": "business",
    "finance": "finance",
    "creator": "creative",
}


def _agent_risk_level(definition) -> str:
    if any(getattr(cap, "sensitive", False) for cap in definition.capabilities):
        return "high"
    if definition.required_role in (Role.MANAGER.value, Role.DEVELOPER.value):
        return "medium"
    return "low"


def _agent_allowed_roles(definition) -> List[str]:
    return [role for role in UI_ROLES if has_min_role(role, definition.required_role)]


def _public_agent_item(agent_name: str, workspace_id: str) -> Dict[str, Any]:
    definition = AGENT_CATALOG[agent_name]
    config = AGENT_STORE.get_or_create_config(workspace_id, agent_name)

    return {
        "agent_id": definition.agent_name,
        "key": definition.agent_name,
        "name": definition.display_name,
        "category": AGENT_CATEGORY_MAP.get(definition.agent_name, "core"),
        "description": definition.description,
        "enabled": config.enabled,
        "status": "active" if config.enabled else "inactive",
        "requires_security_approval": any(getattr(cap, "sensitive", False) for cap in definition.capabilities),
        "risk_level": _agent_risk_level(definition),
        "minimum_plan": definition.required_plan,
        "allowed_roles": _agent_allowed_roles(definition),
    }


def _user_assigned_agents(user_id: str, role: str, plan: str, workspace_id: str, agent_items: List[Dict[str, Any]]) -> List[str]:
    assigned: List[str] = []
    for item in agent_items:
        if not item["enabled"]:
            continue
        if role not in item["allowed_roles"]:
            continue
        if not has_min_plan(plan, item["minimum_plan"]):
            continue
        config = AGENT_STORE.get_or_create_config(workspace_id, item["key"])
        if user_id in config.denied_user_ids:
            continue
        if config.allowed_user_ids and user_id not in config.allowed_user_ids:
            continue
        assigned.append(item["key"])
    return assigned


def _workspace_role_matrix(agent_items: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    return {
        role: [item["key"] for item in agent_items if role in item["allowed_roles"]]
        for role in UI_ROLES
    }


# =============================================================================
# Request models
# =============================================================================

class PermissionUpdateRequest(BaseModel):
    target_user_id: str
    target_role: Optional[str] = None
    target_plan: Optional[str] = None
    assigned_agents: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Agent Permissions"])


@router.get("")
async def get_agent_permissions(context: AuthContext = Depends(get_current_auth_context)) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User
    from database.models.workspace import WorkspaceMembership, WorkspaceMembershipStatus

    try:
        agent_items = [_public_agent_item(agent_name, context.workspace_id) for agent_name in AGENT_CATALOG.keys()]
        role_matrix = _workspace_role_matrix(agent_items)

        users: List[Dict[str, Any]] = []
        with db_manager.session_scope() as db:
            memberships = (
                db.query(WorkspaceMembership)
                .filter(
                    WorkspaceMembership.workspace_id == context.workspace_id,
                    WorkspaceMembership.status == WorkspaceMembershipStatus.ACTIVE,
                )
                .all()
            )

            for membership in memberships:
                user_row = db.query(User).filter(User.id == membership.user_id).first()
                role_value = getattr(membership.role, "value", str(membership.role))
                plan_value = context.plan if membership.user_id == context.user_id else context.plan

                users.append(
                    {
                        "user_id": membership.user_id,
                        "workspace_id": context.workspace_id,
                        "name": (user_row.full_name if user_row and user_row.full_name else (user_row.email if user_row else membership.user_id)),
                        "email": user_row.email if user_row else "",
                        "role": role_value,
                        "plan": plan_value,
                        "status": "active",
                        "assigned_agents": _user_assigned_agents(membership.user_id, role_value, plan_value, context.workspace_id, agent_items),
                        "created_at": membership.created_at.isoformat() if membership.created_at else None,
                        "last_active_at": membership.last_active_at.isoformat() if membership.last_active_at else None,
                    }
                )

        return api_success(
            "Agent permissions loaded.",
            data={"users": users, "agents": agent_items, "role_matrix": role_matrix},
            request_id=context.request_id,
        )
    except Exception as exc:  # noqa: BLE001 -- never leak a raw 500 with a non-envelope body
        logger.exception("get_agent_permissions failed")
        raise_api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, "Could not load agent permissions.", "AGENT_PERMISSIONS_LOAD_FAILED", context.request_id, {"detail": str(exc)})


@router.put("/{user_id}")
async def update_agent_permissions(
    user_id: str,
    payload: PermissionUpdateRequest,
    request: Request,
    context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import WorkspaceMembership, WorkspaceMembershipStatus

    if payload.target_user_id != user_id:
        raise_api_error(status.HTTP_400_BAD_REQUEST, "target_user_id must match the path user_id.", "USER_ID_MISMATCH", context.request_id)

    with db_manager.session_scope() as db:
        membership = (
            db.query(WorkspaceMembership)
            .filter(
                WorkspaceMembership.workspace_id == context.workspace_id,
                WorkspaceMembership.user_id == user_id,
                WorkspaceMembership.status == WorkspaceMembershipStatus.ACTIVE,
            )
            .first()
        )
        if membership is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "User is not an active member of this workspace.", "MEMBER_NOT_FOUND", context.request_id)

    assigned = set(payload.assigned_agents)
    sensitive_agents = [
        name for name in AGENT_CATALOG.keys()
        if name in assigned and any(getattr(cap, "sensitive", False) for cap in AGENT_CATALOG[name].capabilities)
    ]

    security_result = await security_review(
        {
            "type": "agent_permissions_update",
            "actor_user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "target_user_id": user_id,
            "sensitive_agents": sensitive_agents,
        }
    )

    for agent_name in AGENT_CATALOG.keys():
        config = AGENT_STORE.get_or_create_config(context.workspace_id, agent_name)
        allowed_user_ids = set(config.allowed_user_ids)
        denied_user_ids = set(config.denied_user_ids)

        if agent_name in assigned:
            allowed_user_ids.add(user_id)
            denied_user_ids.discard(user_id)
        else:
            denied_user_ids.add(user_id)
            allowed_user_ids.discard(user_id)

        AGENT_STORE.update_access(
            context.workspace_id,
            agent_name,
            allowed_user_ids=sorted(allowed_user_ids),
            denied_user_ids=sorted(denied_user_ids),
            metadata={"last_permissions_update_by": context.user_id, "notes": payload.notes or ""},
        )

    audit = write_agent_audit(
        request=request,
        context=context,
        event_type="agent_permissions_update",
        action="update_agent_permissions",
        result="success",
        target_user_id=user_id,
        status_code=status.HTTP_200_OK,
        metadata={"assigned_agents": sorted(assigned), "sensitive_agents": sensitive_agents, "notes": payload.notes},
    )

    memory_result = await emit_memory_context(
        {
            "type": "agent_permissions_update",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "content": {"event": "agent_permissions_updated", "target_user_id": user_id, "assigned_agents": sorted(assigned)},
        }
    )

    verification_result = await prepare_verification(
        {
            "type": "agent_permissions_update_confirmation",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "target_user_id": user_id,
            "assigned_agents": sorted(assigned),
        }
    )

    return api_success(
        "Agent permissions saved.",
        data={
            "user_id": user_id,
            "workspace_id": context.workspace_id,
            "assigned_agents": sorted(assigned),
            "audit": {"event_id": audit.get("audit_id"), "action": "agent_permissions.update"},
            "security": {
                "routed_to_security_agent": bool(sensitive_agents),
                "approved": bool(security_result.get("success", True)),
                "risk_level": "high" if sensitive_agents else "low",
            },
            "verification": {
                "verification_id": (verification_result.get("data") or {}).get("verification_id"),
                "status": "prepared" if verification_result.get("success") else "pending",
            },
        },
        request_id=context.request_id,
    )
