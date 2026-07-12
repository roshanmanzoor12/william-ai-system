"""
apps/api/routes/admin.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Platform Admin Control Center backend. Every endpoint here is gated on
`AuthContext.is_platform_admin` -- a real, DB-driven flag
(database.models.user.User.is_platform_admin), never a hardcoded email
check in route code (see require_platform_admin below). This is a
cross-workspace capability, distinct from any single workspace's
owner/admin role -- a workspace owner without is_platform_admin cannot
reach any route in this file, and normal users can never change their own
plan/role because the whole surface requires platform-admin first.

This file does not reinvent user/workspace/membership/invite persistence:
it queries and writes the same real SQLAlchemy models
(database.models.user.User, database.models.workspace.{Workspace,
WorkspaceMembership, WorkspaceInvitation}) that apps/api/routes/auth.py and
apps/api/routes/workspaces.py already use, and reuses the same
SecurityAgent/MemoryAgent/VerificationAgent hook helpers
(security_review/emit_memory_context/prepare_verification/write_agent_audit)
already established in apps/api/routes/agents.py for sensitive-change
audit metadata, rather than duplicating that plumbing a third time.

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field


LOGGER_NAME = "william.api.routes.admin"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())

# workspace_id used on audit rows for actions that are genuinely
# cross-workspace (e.g. listing all users) rather than scoped to one real
# workspace -- AuditLogModel.workspace_id is NOT NULL, and "platform" is an
# honest sentinel rather than an arbitrary/misleading real workspace id.
PLATFORM_AUDIT_WORKSPACE = "platform"

INVITE_DEFAULT_EXPIRY_HOURS = 168  # 7 days


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# =============================================================================
# Safe API responses
# =============================================================================

def api_success(message: str, data: Optional[Dict[str, Any]] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "admin"},
    }


def raise_api_error(status_code: int, message: str, code: str, request_id: Optional[str] = None, details: Optional[Any] = None) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": {},
            "error": {"code": code, "details": details},
            "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "admin"},
        },
    )


# =============================================================================
# Auth (canonical context) + platform-admin gate
# =============================================================================

from apps.api.routes.auth import (  # type: ignore
    AuthContext,
    get_current_auth_context,
    normalize_email,
    hash_password,
)

# Reuse the real SecurityAgent/MemoryAgent/VerificationAgent hooks and audit
# helper already built and tested in agents.py rather than duplicating them.
from apps.api.routes.agents import (  # type: ignore
    security_review,
    emit_memory_context,
    prepare_verification,
    write_agent_audit,
)


async def require_platform_admin(context: AuthContext = Depends(get_current_auth_context)) -> AuthContext:
    if not context.is_platform_admin:
        raise_api_error(
            status.HTTP_403_FORBIDDEN,
            "Platform admin access required.",
            "PLATFORM_ADMIN_REQUIRED",
            context.request_id,
        )
    return context


def _write_admin_audit(
    db,
    *,
    actor: AuthContext,
    action: str,
    resource_type: str,
    resource_id: str = "",
    workspace_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    status_value: str = "success",
):
    from database.models.security import AuditLogModel

    row = AuditLogModel(
        user_id=actor.user_id,
        workspace_id=workspace_id or PLATFORM_AUDIT_WORKSPACE,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        agent_key="admin",
        actor=actor.email,
        status=status_value,
    )
    row.extra_metadata = metadata or {}
    db.add(row)
    db.flush()
    return row


def _safe_membership(m) -> Dict[str, Any]:
    from database.models.workspace import enum_value as _ev

    return {
        "membership_id": m.id,
        "user_id": m.user_id,
        "workspace_id": m.workspace_id,
        "role": _ev(m.role),
        "status": _ev(m.status),
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


def _safe_workspace(w) -> Dict[str, Any]:
    from database.models.workspace import enum_value as _ev

    return {
        "workspace_id": w.id,
        "name": w.name,
        "slug": w.slug,
        "owner_user_id": w.owner_user_id,
        "plan": _ev(w.plan),
        "status": _ev(w.status),
        "subscription_status": _ev(w.subscription_status),
        "max_members": w.max_members,
        "max_agents": w.max_agents,
        "is_suspended": w.is_suspended,
        "created_at": w.created_at.isoformat() if w.created_at else None,
        "updated_at": w.updated_at.isoformat() if w.updated_at else None,
    }


def _safe_invitation(inv) -> Dict[str, Any]:
    from database.models.workspace import enum_value as _ev

    return {
        "invite_id": inv.id,
        "workspace_id": inv.workspace_id,
        "invited_email": inv.invited_email,
        "role": _ev(inv.role),
        "status": _ev(inv.status),
        "invited_by": inv.invited_by,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "expires_at": inv.expires_at.isoformat() if inv.expires_at else None,
        "accepted_at": inv.accepted_at.isoformat() if inv.accepted_at else None,
    }


# =============================================================================
# Request models
# =============================================================================

class AdminCreateUserRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=8, max_length=256)
    full_name: str = Field(..., min_length=1, max_length=180)
    workspace_id: Optional[str] = None
    role: str = "member"


class AdminUpdateUserRequest(BaseModel):
    is_active: Optional[bool] = None
    workspace_id: Optional[str] = None
    role: Optional[str] = None
    reset_role: bool = False


class AdminCreateWorkspaceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=180)
    owner_user_id: str
    plan: str = "free"


class AdminUpdateWorkspacePlanRequest(BaseModel):
    plan: str


class AdminUpdateWorkspaceOwnerRequest(BaseModel):
    new_owner_user_id: str


class AdminCreateInviteRequest(BaseModel):
    email: str
    workspace_id: str
    role: str = "member"
    plan: Optional[str] = None
    message: Optional[str] = None


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Admin"])


@router.get("/overview")
async def get_overview(context: AuthContext = Depends(require_platform_admin)) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User
    from database.models.workspace import Workspace, WorkspaceInvitation, WorkspaceInvitationStatus, enum_value
    from database.models.security import AuditLogModel
    from apps.api.routes.agents import AGENT_STORE

    with db_manager.session_scope() as db:
        users_count = db.query(User).count()
        workspaces_count = db.query(Workspace).count()

        plans_breakdown: Dict[str, int] = {}
        for workspace in db.query(Workspace).all():
            key = enum_value(workspace.plan)
            plans_breakdown[key] = plans_breakdown.get(key, 0) + 1

        pending_invites = (
            db.query(WorkspaceInvitation)
            .filter(WorkspaceInvitation.status == WorkspaceInvitationStatus.PENDING)
            .count()
        )

        enabled_agent_configs = sum(1 for cfg in AGENT_STORE.configs.values() if cfg.enabled)
        total_agent_configs = len(AGENT_STORE.configs)

        recent_rows = (
            db.query(AuditLogModel)
            .filter(AuditLogModel.agent_key == "admin")
            .order_by(AuditLogModel.created_at.desc())
            .limit(20)
            .all()
        )
        recent_actions = [row.to_dict() for row in recent_rows]

    return api_success(
        "Admin overview loaded.",
        data={
            "users_count": users_count,
            "workspaces_count": workspaces_count,
            "active_plans": plans_breakdown,
            "pending_invites": pending_invites,
            "agent_usage_summary": {
                "enabled_configs": enabled_agent_configs,
                "total_configs": total_agent_configs,
            },
            "recent_admin_actions": recent_actions,
        },
        request_id=context.request_id,
    )


@router.get("/users")
async def list_users(
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User
    from database.models.workspace import WorkspaceMembership

    with db_manager.session_scope() as db:
        query = db.query(User)

        if search:
            needle = f"%{search.strip().lower()}%"
            query = query.filter(
                (User.email.ilike(needle)) | (User.full_name.ilike(needle))
            )

        total = query.count()
        rows = query.order_by(User.created_at.desc()).offset(max(offset, 0)).limit(min(max(limit, 1), 200)).all()

        users: List[Dict[str, Any]] = []
        for user_row in rows:
            memberships = (
                db.query(WorkspaceMembership)
                .filter(WorkspaceMembership.user_id == user_row.id)
                .all()
            )
            users.append(
                {
                    **user_row.safe_dict(),
                    "memberships": [_safe_membership(m) for m in memberships],
                }
            )

    return api_success(
        "Users loaded.",
        data={"users": users, "count": total, "limit": limit, "offset": offset},
        request_id=context.request_id,
    )


@router.post("/users")
async def create_user(
    payload: AdminCreateUserRequest,
    request: Request,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User, UserStatus
    from database.models.workspace import Workspace, WorkspaceMembership, WorkspaceMemberRole

    email = normalize_email(payload.email)

    try:
        role_enum = WorkspaceMemberRole(payload.role) if payload.workspace_id else None
    except ValueError:
        raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invalid role: {payload.role}", "INVALID_ROLE", context.request_id)

    try:
        with db_manager.session_scope() as db:
            existing = db.query(User).filter(User.email == email).first()
            if existing is not None:
                raise_api_error(status.HTTP_409_CONFLICT, "Email is already registered.", "EMAIL_ALREADY_REGISTERED", context.request_id)

            if payload.workspace_id:
                workspace = db.query(Workspace).filter(Workspace.id == payload.workspace_id).first()
                if workspace is None:
                    raise_api_error(status.HTTP_404_NOT_FOUND, "Workspace not found.", "WORKSPACE_NOT_FOUND", context.request_id)

            combined_hash = hash_password(payload.password)
            _, _, salt_component, _ = combined_hash.split("$", 3)

            user = User(
                email=email,
                full_name=payload.full_name.strip(),
                password_hash=combined_hash,
                password_salt=salt_component,
                password_algorithm="pbkdf2_sha256",
                status=UserStatus.ACTIVE,
                is_active=True,
            )
            db.add(user)
            db.flush()

            membership_data = None
            if payload.workspace_id and role_enum is not None:
                membership = WorkspaceMembership.create_member(
                    workspace_id=payload.workspace_id,
                    user_id=user.id,
                    role=role_enum,
                    invited_by=context.user_id,
                )
                db.add(membership)
                db.flush()
                membership_data = _safe_membership(membership)

            _write_admin_audit(
                db, actor=context, action="admin.user.created", resource_type="user", resource_id=user.id,
                workspace_id=payload.workspace_id, metadata={"email": email, "workspace_id": payload.workspace_id, "role": payload.role},
            )

            user_data = user.safe_dict()
    except ValueError as exc:
        raise_api_error(status.HTTP_400_BAD_REQUEST, str(exc), "INVALID_PASSWORD", context.request_id)

    security_result = await security_review(
        {"type": "admin_user_created", "actor_user_id": context.user_id, "target_email": email}
    )

    return api_success(
        "User created.",
        data={"user": user_data, "membership": membership_data, "security": {"approved": bool(security_result.get("success", True))}},
        request_id=context.request_id,
    )


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    payload: AdminUpdateUserRequest,
    request: Request,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User, UserStatus
    from database.models.workspace import Workspace, WorkspaceMembership, WorkspaceMemberRole

    with db_manager.session_scope() as db:
        user_row = db.query(User).filter(User.id == user_id).first()
        if user_row is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "User not found.", "USER_NOT_FOUND", context.request_id)

        changes: Dict[str, Any] = {}

        if payload.is_active is not None:
            user_row.is_active = payload.is_active
            user_row.status = UserStatus.ACTIVE if payload.is_active else UserStatus.SUSPENDED
            changes["is_active"] = payload.is_active

        membership_data = None
        if payload.workspace_id and (payload.role or payload.reset_role):
            workspace = db.query(Workspace).filter(Workspace.id == payload.workspace_id).first()
            if workspace is None:
                raise_api_error(status.HTTP_404_NOT_FOUND, "Workspace not found.", "WORKSPACE_NOT_FOUND", context.request_id)

            effective_role = "member" if payload.reset_role else payload.role
            try:
                role_enum = WorkspaceMemberRole(effective_role)
            except ValueError:
                raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invalid role: {effective_role}", "INVALID_ROLE", context.request_id)

            membership = (
                db.query(WorkspaceMembership)
                .filter(WorkspaceMembership.workspace_id == payload.workspace_id, WorkspaceMembership.user_id == user_id)
                .first()
            )
            if membership is None:
                membership = WorkspaceMembership.create_member(
                    workspace_id=payload.workspace_id, user_id=user_id, role=role_enum, invited_by=context.user_id,
                )
                db.add(membership)
            else:
                membership.role = role_enum
                membership.updated_at = utc_now()

            db.flush()
            membership_data = _safe_membership(membership)
            changes["workspace_id"] = payload.workspace_id
            changes["role"] = effective_role
            changes["reset_role"] = payload.reset_role

        _write_admin_audit(
            db, actor=context, action="admin.user.updated", resource_type="user", resource_id=user_id,
            workspace_id=payload.workspace_id, metadata=changes,
        )

        user_data = user_row.safe_dict()

    security_result = await security_review(
        {"type": "admin_user_updated", "actor_user_id": context.user_id, "target_user_id": user_id, "changes": changes}
    )

    return api_success(
        "User updated.",
        data={"user": user_data, "membership": membership_data, "security": {"approved": bool(security_result.get("success", True))}},
        request_id=context.request_id,
    )


@router.get("/workspaces")
async def list_workspaces(context: AuthContext = Depends(require_platform_admin)) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import Workspace, WorkspaceMembership

    with db_manager.session_scope() as db:
        rows = db.query(Workspace).order_by(Workspace.created_at.desc()).limit(500).all()
        workspaces = []
        for w in rows:
            member_count = db.query(WorkspaceMembership).filter(WorkspaceMembership.workspace_id == w.id).count()
            workspaces.append({**_safe_workspace(w), "member_count": member_count})

    return api_success("Workspaces loaded.", data={"workspaces": workspaces, "count": len(workspaces)}, request_id=context.request_id)


@router.get("/workspaces/{workspace_id}/members")
async def get_workspace_members(workspace_id: str, context: AuthContext = Depends(require_platform_admin)) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import Workspace, WorkspaceMembership
    from database.models.user import User

    with db_manager.session_scope() as db:
        workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
        if workspace is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Workspace not found.", "WORKSPACE_NOT_FOUND", context.request_id)

        memberships = db.query(WorkspaceMembership).filter(WorkspaceMembership.workspace_id == workspace_id).all()
        members = []
        for m in memberships:
            user_row = db.query(User).filter(User.id == m.user_id).first()
            members.append({**_safe_membership(m), "email": user_row.email if user_row else None, "full_name": user_row.full_name if user_row else None})

    return api_success(
        "Workspace members loaded.",
        data={"workspace": _safe_workspace(workspace), "members": members},
        request_id=context.request_id,
    )


@router.post("/workspaces")
async def create_workspace(
    payload: AdminCreateWorkspaceRequest,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User
    from database.models.workspace import Workspace, WorkspaceMembership, WorkspacePlan

    try:
        plan_enum = WorkspacePlan(payload.plan)
    except ValueError:
        raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invalid plan: {payload.plan}", "INVALID_PLAN", context.request_id)

    with db_manager.session_scope() as db:
        owner = db.query(User).filter(User.id == payload.owner_user_id).first()
        if owner is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Owner user not found.", "USER_NOT_FOUND", context.request_id)

        workspace = Workspace.create(
            owner_user_id=payload.owner_user_id, name=payload.name, plan=plan_enum, created_by=context.user_id,
        )
        db.add(workspace)
        db.flush()

        membership = WorkspaceMembership.create_owner(workspace_id=workspace.id, user_id=payload.owner_user_id)
        db.add(membership)
        db.flush()

        _write_admin_audit(
            db, actor=context, action="admin.workspace.created", resource_type="workspace", resource_id=workspace.id,
            workspace_id=workspace.id, metadata={"name": payload.name, "plan": payload.plan, "owner_user_id": payload.owner_user_id},
        )

        workspace_data = _safe_workspace(workspace)

    return api_success("Workspace created.", data={"workspace": workspace_data}, request_id=context.request_id)


@router.patch("/workspaces/{workspace_id}/plan")
async def update_workspace_plan(
    workspace_id: str,
    payload: AdminUpdateWorkspacePlanRequest,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import Workspace, WorkspacePlan, plan_member_limit, plan_agent_limit

    try:
        plan_enum = WorkspacePlan(payload.plan)
    except ValueError:
        raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invalid plan: {payload.plan}", "INVALID_PLAN", context.request_id)

    security_result = await security_review(
        {"type": "admin_workspace_plan_change", "actor_user_id": context.user_id, "workspace_id": workspace_id, "new_plan": payload.plan}
    )

    with db_manager.session_scope() as db:
        workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
        if workspace is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Workspace not found.", "WORKSPACE_NOT_FOUND", context.request_id)

        previous_plan = workspace.plan.value if hasattr(workspace.plan, "value") else str(workspace.plan)
        workspace.plan = plan_enum
        workspace.max_members = plan_member_limit(plan_enum)
        workspace.max_agents = plan_agent_limit(plan_enum)
        workspace.updated_at = utc_now()
        workspace.updated_by = context.user_id
        db.flush()

        audit = _write_admin_audit(
            db, actor=context, action="admin.workspace.plan_changed", resource_type="workspace", resource_id=workspace_id,
            workspace_id=workspace_id, metadata={"previous_plan": previous_plan, "new_plan": payload.plan, "security_approved": bool(security_result.get("success", True))},
        )

        workspace_data = _safe_workspace(workspace)

    return api_success(
        "Workspace plan updated.",
        data={"workspace": workspace_data, "audit_id": audit.id, "security": {"approved": bool(security_result.get("success", True))}},
        request_id=context.request_id,
    )


@router.patch("/workspaces/{workspace_id}/owner")
async def update_workspace_owner(
    workspace_id: str,
    payload: AdminUpdateWorkspaceOwnerRequest,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.user import User
    from database.models.workspace import Workspace, WorkspaceMembership, WorkspaceMemberRole

    security_result = await security_review(
        {"type": "admin_workspace_owner_change", "actor_user_id": context.user_id, "workspace_id": workspace_id, "new_owner_user_id": payload.new_owner_user_id}
    )

    with db_manager.session_scope() as db:
        workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
        if workspace is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Workspace not found.", "WORKSPACE_NOT_FOUND", context.request_id)

        new_owner = db.query(User).filter(User.id == payload.new_owner_user_id).first()
        if new_owner is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "New owner user not found.", "USER_NOT_FOUND", context.request_id)

        previous_owner_id = workspace.owner_user_id
        workspace.owner_user_id = payload.new_owner_user_id
        workspace.owner_id = payload.new_owner_user_id
        workspace.updated_at = utc_now()
        workspace.updated_by = context.user_id

        new_owner_membership = (
            db.query(WorkspaceMembership)
            .filter(WorkspaceMembership.workspace_id == workspace_id, WorkspaceMembership.user_id == payload.new_owner_user_id)
            .first()
        )
        if new_owner_membership is None:
            new_owner_membership = WorkspaceMembership.create_owner(workspace_id=workspace_id, user_id=payload.new_owner_user_id)
            db.add(new_owner_membership)
        else:
            new_owner_membership.role = WorkspaceMemberRole.OWNER

        previous_owner_membership = (
            db.query(WorkspaceMembership)
            .filter(WorkspaceMembership.workspace_id == workspace_id, WorkspaceMembership.user_id == previous_owner_id)
            .first()
        )
        if previous_owner_membership is not None:
            previous_owner_membership.role = WorkspaceMemberRole.ADMIN

        db.flush()

        _write_admin_audit(
            db, actor=context, action="admin.workspace.owner_changed", resource_type="workspace", resource_id=workspace_id,
            workspace_id=workspace_id, metadata={"previous_owner_user_id": previous_owner_id, "new_owner_user_id": payload.new_owner_user_id, "security_approved": bool(security_result.get("success", True))},
        )

        workspace_data = _safe_workspace(workspace)

    return api_success(
        "Workspace owner updated.",
        data={"workspace": workspace_data, "security": {"approved": bool(security_result.get("success", True))}},
        request_id=context.request_id,
    )


@router.post("/invites")
async def create_invite(
    payload: AdminCreateInviteRequest,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import Workspace, WorkspaceInvitation, WorkspaceMemberRole
    from apps.api.services import email_service

    try:
        role_enum = WorkspaceMemberRole(payload.role)
    except ValueError:
        raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invalid role: {payload.role}", "INVALID_ROLE", context.request_id)

    email = normalize_email(payload.email)
    token = new_token()
    token_hash = hash_token(token)
    expires_at = utc_now() + timedelta(hours=INVITE_DEFAULT_EXPIRY_HOURS)

    with db_manager.session_scope() as db:
        workspace = db.query(Workspace).filter(Workspace.id == payload.workspace_id).first()
        if workspace is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Workspace not found.", "WORKSPACE_NOT_FOUND", context.request_id)

        invitation = WorkspaceInvitation.create(
            workspace_id=payload.workspace_id,
            invited_email=email,
            role=role_enum,
            invited_by=context.user_id,
            token_hash=token_hash,
            message=payload.message,
            expires_at=expires_at,
            metadata={"plan_hint": payload.plan} if payload.plan else {},
        )
        db.add(invitation)
        db.flush()

        _write_admin_audit(
            db, actor=context, action="admin.invite.created", resource_type="invite", resource_id=invitation.id,
            workspace_id=payload.workspace_id, metadata={"invited_email": email, "role": payload.role},
        )

        invite_data = _safe_invitation(invitation)

    invite_link = f"{os.getenv('WILLIAM_DASHBOARD_URL', 'http://localhost:3000')}/invite/accept?token={token}"

    email_result = email_service.send_email(
        to_email=email,
        subject=f"You're invited to {workspace.name} on William/Jarvis",
        body_text=f"You've been invited to join {workspace.name} as {payload.role}.\n\nAccept your invite: {invite_link}",
    )

    return api_success(
        "Invite created.",
        data={
            "invite": invite_data,
            "invite_link": invite_link,
            "email_status": email_result.get("status"),
        },
        request_id=context.request_id,
    )


@router.get("/invites")
async def list_invites(
    workspace_id: Optional[str] = None,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import WorkspaceInvitation

    with db_manager.session_scope() as db:
        query = db.query(WorkspaceInvitation)
        if workspace_id:
            query = query.filter(WorkspaceInvitation.workspace_id == workspace_id)
        rows = query.order_by(WorkspaceInvitation.created_at.desc()).limit(200).all()
        invites = [_safe_invitation(inv) for inv in rows]

    return api_success("Invites loaded.", data={"invites": invites, "count": len(invites)}, request_id=context.request_id)


@router.post("/invites/{token}/accept")
async def accept_invite(
    token: str,
    context: AuthContext = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    """
    Deliberately NOT gated by require_platform_admin -- the person accepting
    an invite is, by definition, usually not a platform admin. Any
    authenticated user may accept, but only for the workspace/email the
    invite was actually issued to (their JWT-verified email must match).
    """
    from database.db import db_manager
    from database.models.workspace import WorkspaceInvitation, WorkspaceInvitationStatus, WorkspaceMembership

    token_hash = hash_token(token)

    with db_manager.session_scope() as db:
        invitation = db.query(WorkspaceInvitation).filter(WorkspaceInvitation.token_hash == token_hash).first()
        if invitation is None:
            raise_api_error(status.HTTP_404_NOT_FOUND, "Invite not found.", "INVITE_NOT_FOUND", context.request_id)

        if invitation.status != WorkspaceInvitationStatus.PENDING:
            raise_api_error(status.HTTP_400_BAD_REQUEST, f"Invite is already {invitation.status.value}.", "INVITE_NOT_PENDING", context.request_id)

        if invitation.is_expired:
            invitation.status = WorkspaceInvitationStatus.EXPIRED
            db.flush()
            raise_api_error(status.HTTP_400_BAD_REQUEST, "Invite has expired.", "INVITE_EXPIRED", context.request_id)

        if normalize_email(invitation.invited_email) != normalize_email(context.email):
            raise_api_error(status.HTTP_403_FORBIDDEN, "This invite was issued to a different email address.", "INVITE_EMAIL_MISMATCH", context.request_id)

        invitation.accept(accepted_by=context.user_id)

        membership = (
            db.query(WorkspaceMembership)
            .filter(WorkspaceMembership.workspace_id == invitation.workspace_id, WorkspaceMembership.user_id == context.user_id)
            .first()
        )
        if membership is None:
            membership = WorkspaceMembership.create_member(
                workspace_id=invitation.workspace_id, user_id=context.user_id, role=invitation.role, invited_by=invitation.invited_by,
            )
            db.add(membership)
        else:
            membership.role = invitation.role

        db.flush()

        _write_admin_audit(
            db, actor=context, action="admin.invite.accepted", resource_type="invite", resource_id=invitation.id,
            workspace_id=invitation.workspace_id, metadata={"accepted_by": context.user_id},
        )

        invite_data = _safe_invitation(invitation)
        membership_data = _safe_membership(membership)

    return api_success("Invite accepted.", data={"invite": invite_data, "membership": membership_data}, request_id=context.request_id)


@router.get("/audit")
async def get_admin_audit(
    limit: int = 100,
    action: Optional[str] = None,
    context: AuthContext = Depends(require_platform_admin),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.security import AuditLogModel

    with db_manager.session_scope() as db:
        query = db.query(AuditLogModel).filter(
            (AuditLogModel.agent_key == "admin") | (AuditLogModel.action.like("admin.%")) | (AuditLogModel.action.like("voice.%")) | (AuditLogModel.action.like("agent_permissions.%"))
        )
        if action:
            query = query.filter(AuditLogModel.action == action)
        rows = query.order_by(AuditLogModel.created_at.desc()).limit(min(max(limit, 1), 500)).all()
        entries = [row.to_dict() for row in rows]

    return api_success("Admin audit loaded.", data={"entries": entries, "count": len(entries)}, request_id=context.request_id)
