"""
database/models/workspace.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: Database Prompt Bible
Purpose: Workspace and membership models

This file is intentionally import-safe:
- It depends only on database.db Base and scope helpers.
- It uses string-based relationships where possible.
- It does not hardcode secrets.
- It keeps workspace isolation as the central SaaS boundary.
- It includes compatibility aliases for older code using WorkspaceModel.
- It supports workspace ownership, memberships, roles, permissions, invitations,
  subscription status, plan limits, agent access, audit-ready methods, and
  Memory/Verification payload helpers.

Critical SaaS rule:
Never mix users, workspaces, memberships, memory, files, logs, tasks, analytics,
billing, or agent access between workspaces.
"""

from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    from sqlalchemy import (
        Boolean,
        DateTime,
        Enum,
        ForeignKey,
        Index,
        Integer,
        String,
        Text,
        UniqueConstraint,
        event,
    )
    from sqlalchemy.orm import Mapped, mapped_column, relationship
    from sqlalchemy.types import JSON
except Exception as exc:  # pragma: no cover - import-safe fallback
    Boolean = DateTime = Enum = ForeignKey = Index = Integer = String = Text = UniqueConstraint = JSON = object  # type: ignore

    def event_listens_for_fallback(*args: Any, **kwargs: Any):
        def decorator(fn: Any) -> Any:
            return fn
        return decorator

    class _EventFallback:
        listens_for = staticmethod(event_listens_for_fallback)

    event = _EventFallback()  # type: ignore

    class Mapped:  # type: ignore
        def __class_getitem__(cls, item: Any) -> Any:
            return Any

    def mapped_column(*args: Any, **kwargs: Any) -> Any:
        return None

    def relationship(*args: Any, **kwargs: Any) -> Any:
        return None

try:
    from database.db import Base, DbScope, validate_scope_id
except Exception:  # pragma: no cover - emergency import-safe fallback
    class Base:  # type: ignore
        pass

    class DbScope:  # type: ignore
        def __init__(self, user_id: str, workspace_id: str) -> None:
            self.user_id = user_id
            self.workspace_id = workspace_id

        def as_filter_kwargs(self) -> Dict[str, str]:
            return {"user_id": self.user_id, "workspace_id": self.workspace_id}

    def validate_scope_id(value: str, field_name: str) -> str:
        cleaned = str(value).strip()
        if not cleaned:
            raise ValueError(f"{field_name} is required.")
        if len(cleaned) > 140:
            raise ValueError(f"{field_name} is too long.")
        if not re.match(r"^[a-zA-Z0-9_\\-:.@]+$", cleaned):
            raise ValueError(f"{field_name} contains unsafe characters.")
        return cleaned


# =============================================================================
# Time / ID helpers
# =============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_id(prefix: str) -> str:
    cleaned_prefix = re.sub(r"[^a-zA-Z0-9_]", "", str(prefix)).lower()
    cleaned_prefix = cleaned_prefix or "id"
    return f"{cleaned_prefix}_{uuid.uuid4().hex}"


def normalize_slug(value: str) -> str:
    cleaned = str(value or "").strip().lower()
    # These were double-escaped raw-string regexes (r"\\s" is a literal
    # backslash + "s", not whitespace) -- the first line silently dropped
    # every space instead of preserving it for the second line to convert
    # to a hyphen, so "My Workspace" normalized to "myworkspace" instead of
    # the intended "my-workspace" for every workspace ever created.
    cleaned = re.sub(r"[^a-z0-9\s\-]", "", cleaned)
    cleaned = re.sub(r"\s+", "-", cleaned)
    cleaned = re.sub(r"-+", "-", cleaned)
    cleaned = cleaned.strip("-")
    return cleaned[:80] or f"workspace-{uuid.uuid4().hex[:8]}"


def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()


def enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


# =============================================================================
# Enums
# =============================================================================

class WorkspaceStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    DELETED = "deleted"


class WorkspacePlan(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class WorkspaceSubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELLED = "cancelled"
    INACTIVE = "inactive"


class WorkspaceMemberRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"


class WorkspaceMembershipStatus(str, enum.Enum):
    ACTIVE = "active"
    INVITED = "invited"
    SUSPENDED = "suspended"
    REMOVED = "removed"


class WorkspaceInvitationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REVOKED = "revoked"
    EXPIRED = "expired"


# =============================================================================
# Permission / plan helpers
# =============================================================================

ROLE_RANK: Dict[WorkspaceMemberRole, int] = {
    WorkspaceMemberRole.VIEWER: 10,
    WorkspaceMemberRole.MEMBER: 20,
    WorkspaceMemberRole.MANAGER: 30,
    WorkspaceMemberRole.ADMIN: 40,
    WorkspaceMemberRole.OWNER: 50,
}


def role_rank(role: WorkspaceMemberRole) -> int:
    return ROLE_RANK.get(role, 0)


def role_at_least(role: WorkspaceMemberRole, minimum: WorkspaceMemberRole) -> bool:
    return role_rank(role) >= role_rank(minimum)


def can_manage_workspace(role: WorkspaceMemberRole) -> bool:
    return role in {WorkspaceMemberRole.OWNER, WorkspaceMemberRole.ADMIN}


def can_manage_members(role: WorkspaceMemberRole) -> bool:
    return role in {WorkspaceMemberRole.OWNER, WorkspaceMemberRole.ADMIN, WorkspaceMemberRole.MANAGER}


def can_manage_billing(role: WorkspaceMemberRole) -> bool:
    return role in {WorkspaceMemberRole.OWNER, WorkspaceMemberRole.ADMIN}


def can_run_agents(role: WorkspaceMemberRole) -> bool:
    return role in {
        WorkspaceMemberRole.OWNER,
        WorkspaceMemberRole.ADMIN,
        WorkspaceMemberRole.MANAGER,
        WorkspaceMemberRole.MEMBER,
    }


def can_view_dashboard(role: WorkspaceMemberRole) -> bool:
    return role in {
        WorkspaceMemberRole.OWNER,
        WorkspaceMemberRole.ADMIN,
        WorkspaceMemberRole.MANAGER,
        WorkspaceMemberRole.MEMBER,
        WorkspaceMemberRole.VIEWER,
    }


def can_access_audit_logs(role: WorkspaceMemberRole) -> bool:
    return role in {WorkspaceMemberRole.OWNER, WorkspaceMemberRole.ADMIN, WorkspaceMemberRole.MANAGER}


def can_approve_sensitive_actions(role: WorkspaceMemberRole) -> bool:
    return role in {WorkspaceMemberRole.OWNER, WorkspaceMemberRole.ADMIN}


def plan_member_limit(plan: WorkspacePlan) -> int:
    limits = {
        WorkspacePlan.FREE: 1,
        WorkspacePlan.PRO: 5,
        WorkspacePlan.BUSINESS: 25,
        WorkspacePlan.ENTERPRISE: 1000,
    }
    return limits.get(plan, 1)


def plan_agent_limit(plan: WorkspacePlan) -> int:
    limits = {
        WorkspacePlan.FREE: 3,
        WorkspacePlan.PRO: 14,
        WorkspacePlan.BUSINESS: 14,
        WorkspacePlan.ENTERPRISE: 14,
    }
    return limits.get(plan, 3)


def plan_allows_team_members(plan: WorkspacePlan, requested_count: int) -> bool:
    return requested_count <= plan_member_limit(plan)


def workspace_plan_rank(plan: WorkspacePlan) -> int:
    ranks = {
        WorkspacePlan.FREE: 1,
        WorkspacePlan.PRO: 2,
        WorkspacePlan.BUSINESS: 3,
        WorkspacePlan.ENTERPRISE: 4,
    }
    return ranks.get(plan, 0)


# =============================================================================
# Default settings
# =============================================================================

def default_security_settings() -> Dict[str, Any]:
    return {
        "require_security_agent_for_sensitive_actions": True,
        "require_verification_agent_after_completion": True,
        "allow_external_tool_actions": False,
        "allow_device_worker_actions": False,
        "audit_all_state_changes": True,
        "approval_required_for": [
            "billing_changes",
            "member_role_changes",
            "workspace_delete",
            "memory_export",
            "file_delete",
            "system_actions",
            "browser_purchases",
        ],
    }


def all_agent_names() -> List[str]:
    return [
        "master",
        "voice",
        "system",
        "browser",
        "code",
        "memory",
        "security",
        "verification",
        "visual",
        "workflow",
        "hologram",
        "call",
        "business",
        "finance",
        "creator",
    ]


def default_agent_access(plan: WorkspacePlan) -> Dict[str, Any]:
    agents = all_agent_names()
    free_agents = ["master", "memory", "verification"]

    if plan == WorkspacePlan.FREE:
        return {
            "all_agents_enabled": False,
            "enabled_agents": free_agents,
            "disabled_agents": [agent for agent in agents if agent not in free_agents],
        }

    return {
        "all_agents_enabled": True,
        "enabled_agents": agents,
        "disabled_agents": [],
    }


def default_member_agent_access(role: WorkspaceMemberRole) -> Dict[str, Any]:
    agents = all_agent_names()

    if role == WorkspaceMemberRole.VIEWER:
        return {
            "all_agents_enabled": False,
            "enabled_agents": [],
            "disabled_agents": agents,
        }

    if role == WorkspaceMemberRole.MEMBER:
        enabled = ["master", "memory", "verification", "business", "creator"]
        return {
            "all_agents_enabled": False,
            "enabled_agents": enabled,
            "disabled_agents": [agent for agent in agents if agent not in enabled],
        }

    return {
        "all_agents_enabled": True,
        "enabled_agents": agents,
        "disabled_agents": [],
    }


def default_role_permissions(role: WorkspaceMemberRole) -> Dict[str, bool]:
    if role == WorkspaceMemberRole.OWNER:
        return {"*": True}

    if role == WorkspaceMemberRole.ADMIN:
        return {
            "workspace.view": True,
            "workspace.update": True,
            "members.view": True,
            "members.invite": True,
            "members.update": True,
            "members.remove": True,
            "billing.view": True,
            "billing.manage": True,
            "agents.run": True,
            "agents.manage": True,
            "memory.view": True,
            "memory.write": True,
            "memory.delete": True,
            "memory.export": True,
            "files.view": True,
            "files.write": True,
            "files.delete": True,
            "audit.view": True,
            "security.approve": True,
            "workflows.manage": True,
            "workflows.run": True,
        }

    if role == WorkspaceMemberRole.MANAGER:
        return {
            "workspace.view": True,
            "members.view": True,
            "members.invite": True,
            "billing.view": True,
            "agents.run": True,
            "memory.view": True,
            "memory.write": True,
            "files.view": True,
            "files.write": True,
            "audit.view": True,
            "workflows.manage": True,
            "workflows.run": True,
        }

    if role == WorkspaceMemberRole.MEMBER:
        return {
            "workspace.view": True,
            "agents.run": True,
            "memory.view": True,
            "memory.write": True,
            "files.view": True,
            "files.write": True,
            "workflows.run": True,
        }

    return {
        "workspace.view": True,
        "members.view": False,
        "billing.view": False,
        "agents.run": False,
        "memory.view": True,
        "files.view": True,
        "audit.view": False,
        "workflows.run": False,
    }


# =============================================================================
# Models
# =============================================================================

class Workspace(Base):
    """
    Workspace tenant model.

    A workspace is the main SaaS isolation boundary.
    Every user-owned or client-owned resource should attach to workspace_id.

    Required component name: Workspace
    """

    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("ws"))

    owner_user_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[WorkspaceStatus] = mapped_column(
        Enum(WorkspaceStatus, name="workspace_status"),
        nullable=False,
        default=WorkspaceStatus.ACTIVE,
        index=True,
    )

    plan: Mapped[WorkspacePlan] = mapped_column(
        Enum(WorkspacePlan, name="workspace_plan"),
        nullable=False,
        default=WorkspacePlan.FREE,
        index=True,
    )

    subscription_status: Mapped[WorkspaceSubscriptionStatus] = mapped_column(
        Enum(WorkspaceSubscriptionStatus, name="workspace_subscription_status"),
        nullable=False,
        default=WorkspaceSubscriptionStatus.ACTIVE,
        index=True,
    )

    billing_customer_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    billing_subscription_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    default_language: Mapped[str] = mapped_column(String(20), nullable=False, default="en")
    timezone: Mapped[str] = mapped_column(String(80), nullable=False, default="UTC")
    region: Mapped[str] = mapped_column(String(100), nullable=False, default="global")
    data_isolation_level: Mapped[str] = mapped_column(String(50), nullable=False, default="strict")

    max_members: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_agents: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    settings: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    security_settings: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    agent_access: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    is_personal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_suspended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_security_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by: Mapped[str] = mapped_column(String(140), nullable=False)
    updated_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True)
    archived_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True)
    deleted_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    memberships: Mapped[List["WorkspaceMembership"]] = relationship(
        "WorkspaceMembership",
        back_populates="workspace",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    invitations: Mapped[List["WorkspaceInvitation"]] = relationship(
        "WorkspaceInvitation",
        back_populates="workspace",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    # Membership (who belongs to this workspace, with what role) is modeled
    # through WorkspaceMembership.user_id below -- a user can belong to more
    # than one workspace, so this is intentionally not a direct 1:N
    # relationship to a single "owning" User row. Query memberships to get
    # workspace members, and database.models.user.User.get_by_id per member.

    __table_args__ = (
        Index("ix_workspaces_owner_status", "owner_user_id", "status"),
        Index("ix_workspaces_owner_id_status", "owner_id", "status"),
        Index("ix_workspaces_plan_subscription", "plan", "subscription_status"),
        Index("ix_workspaces_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"Workspace(id={self.id!r}, slug={self.slug!r}, status={enum_value(self.status)!r})"

    @classmethod
    def create(
        cls,
        owner_user_id: str,
        name: str,
        slug: Optional[str] = None,
        plan: WorkspacePlan = WorkspacePlan.FREE,
        description: Optional[str] = None,
        is_personal: bool = False,
        timezone: str = "UTC",
        region: str = "global",
        created_by: Optional[str] = None,
        settings: Optional[Dict[str, Any]] = None,
        security_settings: Optional[Dict[str, Any]] = None,
        agent_access: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Workspace":
        safe_owner_id = validate_scope_id(owner_user_id, "owner_user_id")
        safe_name = str(name or "").strip()

        if not safe_name:
            raise ValueError("Workspace name is required.")

        workspace_plan = plan
        safe_slug = normalize_slug(slug or safe_name)

        return cls(
            owner_user_id=safe_owner_id,
            owner_id=safe_owner_id,
            name=safe_name[:180],
            slug=safe_slug,
            description=description,
            status=WorkspaceStatus.ACTIVE,
            plan=workspace_plan,
            subscription_status=WorkspaceSubscriptionStatus.ACTIVE,
            max_members=plan_member_limit(workspace_plan),
            max_agents=plan_agent_limit(workspace_plan),
            is_personal=is_personal,
            is_suspended=False,
            timezone=timezone or "UTC",
            region=region or "global",
            data_isolation_level="strict",
            created_by=created_by or safe_owner_id,
            settings=settings or {},
            security_settings=security_settings or default_security_settings(),
            agent_access=agent_access or default_agent_access(workspace_plan),
            metadata_json=metadata or {},
        )

    @property
    def workspace_id(self) -> str:
        return self.id

    @property
    def user_id(self) -> str:
        return self.owner_user_id

    @property
    def is_active(self) -> bool:
        return (
            self.status == WorkspaceStatus.ACTIVE
            and self.deleted_at is None
            and self.is_suspended is False
        )

    @is_active.setter
    def is_active(self, value: bool) -> None:
        self.status = WorkspaceStatus.ACTIVE if value else WorkspaceStatus.SUSPENDED
        self.is_suspended = not value
        self.updated_at = utc_now()

    @property
    def subscription_active(self) -> bool:
        return self.subscription_status in {
            WorkspaceSubscriptionStatus.ACTIVE,
            WorkspaceSubscriptionStatus.TRIALING,
        }

    @property
    def is_billable(self) -> bool:
        return self.plan != WorkspacePlan.FREE

    def scope(self) -> DbScope:
        return DbScope(user_id=self.owner_user_id, workspace_id=self.id)

    def has_plan_at_least(self, required_plan: WorkspacePlan) -> bool:
        return workspace_plan_rank(self.plan) >= workspace_plan_rank(required_plan)

    def can_add_member(self, current_member_count: int) -> bool:
        return self.is_active and self.subscription_active and current_member_count < self.max_members

    def can_use_agent(self, agent_name: str) -> bool:
        if not self.is_active or not self.subscription_active:
            return False

        normalized = str(agent_name or "").strip().lower()
        if not normalized:
            return False

        access = self.agent_access or {}

        if access.get("all_agents_enabled") is True:
            return normalized not in set(access.get("disabled_agents", []))

        enabled_agents = set(access.get("enabled_agents", []))
        disabled_agents = set(access.get("disabled_agents", []))

        if normalized in disabled_agents:
            return False

        return normalized in enabled_agents

    def is_access_allowed(self, user_id: str) -> bool:
        validate_scope_id(user_id, "user_id")
        return self.is_active and self.subscription_active and self.data_isolation_level == "strict"

    def update_settings(self, new_settings: Dict[str, Any]) -> None:
        if not isinstance(new_settings, dict):
            raise ValueError("new_settings must be a dictionary.")

        if not isinstance(self.settings, dict):
            self.settings = {}

        self.settings.update(new_settings)
        self.updated_at = utc_now()

    def update_plan(self, plan: WorkspacePlan, updated_by: str) -> None:
        self.plan = plan
        self.max_members = plan_member_limit(plan)
        self.max_agents = plan_agent_limit(plan)
        self.agent_access = default_agent_access(plan)
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def suspend(self, updated_by: Optional[str] = None, reason: Optional[str] = None) -> None:
        self.status = WorkspaceStatus.SUSPENDED
        self.is_suspended = True
        if updated_by:
            self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()
        self.metadata_json = {
            **(self.metadata_json or {}),
            "suspension_reason": reason,
            "suspended_at": utc_now().isoformat(),
        }

    def activate(self, updated_by: Optional[str] = None) -> None:
        self.status = WorkspaceStatus.ACTIVE
        self.is_suspended = False
        if updated_by:
            self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def reactivate(self, updated_by: Optional[str] = None) -> None:
        self.activate(updated_by=updated_by)

    def archive(self, archived_by: str) -> None:
        self.status = WorkspaceStatus.ARCHIVED
        self.archived_by = validate_scope_id(archived_by, "archived_by")
        self.archived_at = utc_now()
        self.updated_by = self.archived_by
        self.updated_at = utc_now()

    def soft_delete(self, deleted_by: str) -> None:
        self.status = WorkspaceStatus.DELETED
        self.deleted_by = validate_scope_id(deleted_by, "deleted_by")
        self.deleted_at = utc_now()
        self.updated_by = self.deleted_by
        self.updated_at = utc_now()

    def safe_dict(self, include_settings: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "workspace_id": self.id,
            "owner_user_id": self.owner_user_id,
            "owner_id": self.owner_id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "status": enum_value(self.status),
            "plan": enum_value(self.plan),
            "subscription_status": enum_value(self.subscription_status),
            "default_language": self.default_language,
            "timezone": self.timezone,
            "region": self.region,
            "data_isolation_level": self.data_isolation_level,
            "max_members": self.max_members,
            "max_agents": self.max_agents,
            "is_personal": self.is_personal,
            "is_active": self.is_active,
            "is_suspended": self.is_suspended,
            "requires_security_approval": self.requires_security_approval,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "archived_by": self.archived_by,
            "deleted_by": self.deleted_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

        if include_settings:
            data["settings"] = self.settings or {}
            data["security_settings"] = self.security_settings or {}
            data["agent_access"] = self.agent_access or {}
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_settings=True)

    def _prepare_memory_payload(self) -> Dict[str, Any]:
        return {
            "workspace_id": self.id,
            "owner_user_id": self.owner_user_id,
            "name": self.name,
            "plan": enum_value(self.plan),
            "region": self.region,
            "data_isolation_level": self.data_isolation_level,
        }

    def _prepare_verification_payload(self) -> Dict[str, Any]:
        return {
            "entity": "workspace",
            "workspace_id": self.id,
            "owner_user_id": self.owner_user_id,
            "status": enum_value(self.status),
            "timestamp": utc_now().isoformat(),
        }

    def _log_audit_event(self, action: str, actor_user_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "action": action,
            "workspace_id": self.id,
            "actor_user_id": actor_user_id,
            "timestamp": utc_now().isoformat(),
        }


class WorkspaceMembership(Base):
    """
    Workspace membership model.

    Connects users to workspaces and defines dashboard/API access.
    """

    __tablename__ = "workspace_memberships"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("wsm"))

    workspace_id: Mapped[str] = mapped_column(
        String(140),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    role: Mapped[WorkspaceMemberRole] = mapped_column(
        Enum(WorkspaceMemberRole, name="workspace_member_role"),
        nullable=False,
        default=WorkspaceMemberRole.MEMBER,
        index=True,
    )

    status: Mapped[WorkspaceMembershipStatus] = mapped_column(
        Enum(WorkspaceMembershipStatus, name="workspace_membership_status"),
        nullable=False,
        default=WorkspaceMembershipStatus.ACTIVE,
        index=True,
    )

    title: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    invited_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    removed_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    permissions: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    agent_access: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    last_active_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped["Workspace"] = relationship(
        "Workspace",
        back_populates="memberships",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_workspace_membership_workspace_user"),
        Index("ix_workspace_memberships_user_status", "user_id", "status"),
        Index("ix_workspace_memberships_workspace_role", "workspace_id", "role"),
        Index("ix_workspace_memberships_workspace_status", "workspace_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"WorkspaceMembership(id={self.id!r}, "
            f"workspace_id={self.workspace_id!r}, user_id={self.user_id!r}, role={enum_value(self.role)!r})"
        )

    @classmethod
    def create_owner(
        cls,
        workspace_id: str,
        user_id: str,
        permissions: Optional[Dict[str, Any]] = None,
    ) -> "WorkspaceMembership":
        return cls(
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            user_id=validate_scope_id(user_id, "user_id"),
            role=WorkspaceMemberRole.OWNER,
            status=WorkspaceMembershipStatus.ACTIVE,
            permissions=permissions or default_role_permissions(WorkspaceMemberRole.OWNER),
            agent_access=default_member_agent_access(WorkspaceMemberRole.OWNER),
        )

    @classmethod
    def create_member(
        cls,
        workspace_id: str,
        user_id: str,
        role: WorkspaceMemberRole = WorkspaceMemberRole.MEMBER,
        invited_by: Optional[str] = None,
        title: Optional[str] = None,
        permissions: Optional[Dict[str, Any]] = None,
        agent_access: Optional[Dict[str, Any]] = None,
    ) -> "WorkspaceMembership":
        return cls(
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            user_id=validate_scope_id(user_id, "user_id"),
            role=role,
            status=WorkspaceMembershipStatus.ACTIVE,
            invited_by=validate_scope_id(invited_by, "invited_by") if invited_by else None,
            title=title,
            permissions=permissions or default_role_permissions(role),
            agent_access=agent_access or default_member_agent_access(role),
        )

    @property
    def is_active(self) -> bool:
        return self.status == WorkspaceMembershipStatus.ACTIVE and self.removed_at is None

    @property
    def is_owner(self) -> bool:
        return self.role == WorkspaceMemberRole.OWNER

    @property
    def is_admin(self) -> bool:
        return self.role == WorkspaceMemberRole.ADMIN

    def scope(self) -> DbScope:
        return DbScope(user_id=self.user_id, workspace_id=self.workspace_id)

    def has_role_at_least(self, minimum: WorkspaceMemberRole) -> bool:
        return role_at_least(self.role, minimum)

    def has_permission(self, permission_key: str) -> bool:
        if not self.is_active:
            return False

        normalized = str(permission_key or "").strip()
        if not normalized:
            return False

        permissions = self.permissions or {}

        if permissions.get("*") is True:
            return True

        return bool(permissions.get(normalized, False))

    def can_manage_workspace(self) -> bool:
        return self.is_active and can_manage_workspace(self.role)

    def can_manage_members(self) -> bool:
        return self.is_active and can_manage_members(self.role)

    def can_manage_billing(self) -> bool:
        return self.is_active and can_manage_billing(self.role)

    def can_run_agents(self) -> bool:
        return self.is_active and can_run_agents(self.role)

    def can_view_dashboard(self) -> bool:
        return self.is_active and can_view_dashboard(self.role)

    def can_access_audit_logs(self) -> bool:
        return self.is_active and can_access_audit_logs(self.role)

    def can_approve_sensitive_actions(self) -> bool:
        return self.is_active and can_approve_sensitive_actions(self.role)

    def can_use_agent(self, agent_name: str) -> bool:
        if not self.can_run_agents():
            return False

        normalized = str(agent_name or "").strip().lower()
        if not normalized:
            return False

        access = self.agent_access or {}

        if access.get("all_agents_enabled") is True:
            return normalized not in set(access.get("disabled_agents", []))

        disabled = set(access.get("disabled_agents", []))
        if normalized in disabled:
            return False

        enabled = set(access.get("enabled_agents", []))
        return normalized in enabled

    def touch_activity(self) -> None:
        self.last_active_at = utc_now()
        self.updated_at = utc_now()

    def change_role(self, role: WorkspaceMemberRole, updated_by: str) -> None:
        self.role = role
        self.permissions = default_role_permissions(role)
        self.agent_access = default_member_agent_access(role)
        self.approved_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def suspend(self, updated_by: str, reason: Optional[str] = None) -> None:
        self.status = WorkspaceMembershipStatus.SUSPENDED
        self.approved_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()
        self.metadata_json = {
            **(self.metadata_json or {}),
            "suspension_reason": reason,
            "suspended_at": utc_now().isoformat(),
        }

    def reactivate(self, updated_by: str) -> None:
        self.status = WorkspaceMembershipStatus.ACTIVE
        self.approved_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def remove(self, removed_by: str, reason: Optional[str] = None) -> None:
        self.status = WorkspaceMembershipStatus.REMOVED
        self.removed_by = validate_scope_id(removed_by, "removed_by")
        self.removed_at = utc_now()
        self.updated_at = utc_now()
        self.metadata_json = {
            **(self.metadata_json or {}),
            "removal_reason": reason,
            "removed_at": self.removed_at.isoformat(),
        }

    def safe_dict(self, include_permissions: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "user_id": self.user_id,
            "role": enum_value(self.role),
            "status": enum_value(self.status),
            "title": self.title,
            "invited_by": self.invited_by,
            "approved_by": self.approved_by,
            "removed_by": self.removed_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_active_at": self.last_active_at.isoformat() if self.last_active_at else None,
            "removed_at": self.removed_at.isoformat() if self.removed_at else None,
        }

        if include_permissions:
            data["permissions"] = self.permissions or {}
            data["agent_access"] = self.agent_access or {}
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_permissions=True)


class WorkspaceInvitation(Base):
    """
    Workspace invitation model.

    Used for team invites without requiring user account existence yet.
    """

    __tablename__ = "workspace_invitations"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("wsi"))

    workspace_id: Mapped[str] = mapped_column(
        String(140),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    invited_email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    invited_user_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    role: Mapped[WorkspaceMemberRole] = mapped_column(
        Enum(WorkspaceMemberRole, name="workspace_invitation_role"),
        nullable=False,
        default=WorkspaceMemberRole.MEMBER,
    )

    status: Mapped[WorkspaceInvitationStatus] = mapped_column(
        Enum(WorkspaceInvitationStatus, name="workspace_invitation_status"),
        nullable=False,
        default=WorkspaceInvitationStatus.PENDING,
        index=True,
    )

    token_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    invited_by: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    accepted_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped["Workspace"] = relationship(
        "Workspace",
        back_populates="invitations",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_workspace_invitations_email_status", "invited_email", "status"),
        Index("ix_workspace_invitations_workspace_status", "workspace_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"WorkspaceInvitation(id={self.id!r}, "
            f"workspace_id={self.workspace_id!r}, invited_email={self.invited_email!r}, "
            f"status={enum_value(self.status)!r})"
        )

    @classmethod
    def create(
        cls,
        workspace_id: str,
        invited_email: str,
        role: WorkspaceMemberRole,
        invited_by: str,
        token_hash: Optional[str] = None,
        message: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "WorkspaceInvitation":
        safe_email = normalize_email(invited_email)

        if "@" not in safe_email or len(safe_email) > 320:
            raise ValueError("A valid invited_email is required.")

        return cls(
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            invited_email=safe_email,
            role=role,
            invited_by=validate_scope_id(invited_by, "invited_by"),
            token_hash=token_hash,
            message=message,
            expires_at=expires_at,
            metadata_json=metadata or {},
        )

    @property
    def is_pending(self) -> bool:
        return self.status == WorkspaceInvitationStatus.PENDING

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return utc_now() > self.expires_at

    def accept(self, accepted_by: str) -> None:
        if self.status != WorkspaceInvitationStatus.PENDING:
            raise ValueError("Only pending invitations can be accepted.")

        if self.is_expired:
            self.status = WorkspaceInvitationStatus.EXPIRED
            self.updated_at = utc_now()
            raise ValueError("Invitation has expired.")

        self.status = WorkspaceInvitationStatus.ACCEPTED
        self.accepted_by = validate_scope_id(accepted_by, "accepted_by")
        self.invited_user_id = self.accepted_by
        self.accepted_at = utc_now()
        self.updated_at = utc_now()

    def revoke(self, revoked_by: str, reason: Optional[str] = None) -> None:
        if self.status not in {WorkspaceInvitationStatus.PENDING, WorkspaceInvitationStatus.EXPIRED}:
            raise ValueError("Only pending or expired invitations can be revoked.")

        self.status = WorkspaceInvitationStatus.REVOKED
        self.revoked_by = validate_scope_id(revoked_by, "revoked_by")
        self.revoked_at = utc_now()
        self.updated_at = utc_now()
        self.metadata_json = {
            **(self.metadata_json or {}),
            "revocation_reason": reason,
            "revoked_at": self.revoked_at.isoformat(),
        }

    def mark_expired(self) -> None:
        self.status = WorkspaceInvitationStatus.EXPIRED
        self.updated_at = utc_now()

    def safe_dict(self, include_token_hash: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "invited_email": self.invited_email,
            "invited_user_id": self.invited_user_id,
            "role": enum_value(self.role),
            "status": enum_value(self.status),
            "message": self.message,
            "invited_by": self.invited_by,
            "accepted_by": self.accepted_by,
            "revoked_by": self.revoked_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "accepted_at": self.accepted_at.isoformat() if self.accepted_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "metadata": self.metadata_json or {},
        }

        if include_token_hash:
            data["token_hash"] = self.token_hash

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_token_hash=False)


# =============================================================================
# Validation / query helper functions
# =============================================================================

def require_workspace_active(workspace: Workspace) -> Workspace:
    if workspace.status != WorkspaceStatus.ACTIVE or workspace.deleted_at is not None or workspace.is_suspended:
        raise PermissionError("Workspace is not active.")
    return workspace


def require_subscription_active(workspace: Workspace) -> Workspace:
    if not workspace.subscription_active:
        raise PermissionError("Workspace subscription is not active.")
    return workspace


def require_membership_active(membership: WorkspaceMembership) -> WorkspaceMembership:
    if not membership.is_active:
        raise PermissionError("Workspace membership is not active.")
    return membership


def require_workspace_member(
    memberships: Iterable[WorkspaceMembership],
    user_id: str,
    workspace_id: str,
) -> WorkspaceMembership:
    safe_user_id = validate_scope_id(user_id, "user_id")
    safe_workspace_id = validate_scope_id(workspace_id, "workspace_id")

    for membership in memberships:
        if (
            membership.user_id == safe_user_id
            and membership.workspace_id == safe_workspace_id
            and membership.is_active
        ):
            return membership

    raise PermissionError("User is not an active member of this workspace.")


def require_role(
    membership: WorkspaceMembership,
    minimum_role: WorkspaceMemberRole,
) -> WorkspaceMembership:
    require_membership_active(membership)

    if not membership.has_role_at_least(minimum_role):
        raise PermissionError(f"Role {minimum_role.value} or higher is required.")

    return membership


def require_permission(
    membership: WorkspaceMembership,
    permission_key: str,
) -> WorkspaceMembership:
    require_membership_active(membership)

    if not membership.has_permission(permission_key):
        raise PermissionError(f"Permission denied: {permission_key}")

    return membership


def workspace_scope_filter(workspace_id: str) -> Dict[str, str]:
    return {"workspace_id": validate_scope_id(workspace_id, "workspace_id")}


def user_workspace_scope_filter(user_id: str, workspace_id: str) -> Dict[str, str]:
    return {
        "user_id": validate_scope_id(user_id, "user_id"),
        "workspace_id": validate_scope_id(workspace_id, "workspace_id"),
    }


# =============================================================================
# SQLAlchemy events
# =============================================================================

@event.listens_for(Workspace, "before_insert")
def workspace_before_insert(mapper: Any, connection: Any, target: Workspace) -> None:
    if not target.id:
        target.id = generate_id("ws")

    target.owner_user_id = validate_scope_id(target.owner_user_id, "owner_user_id")
    target.owner_id = validate_scope_id(target.owner_id or target.owner_user_id, "owner_id")
    target.created_by = validate_scope_id(target.created_by or target.owner_user_id, "created_by")

    if not target.slug:
        target.slug = normalize_slug(target.name)

    target.slug = normalize_slug(target.slug)
    target.max_members = target.max_members or plan_member_limit(target.plan)
    target.max_agents = target.max_agents or plan_agent_limit(target.plan)

    if target.settings is None:
        target.settings = {}

    if target.security_settings is None:
        target.security_settings = default_security_settings()

    if target.agent_access is None:
        target.agent_access = default_agent_access(target.plan)

    if target.metadata_json is None:
        target.metadata_json = {}

    if not target.region:
        target.region = "global"

    if not target.data_isolation_level:
        target.data_isolation_level = "strict"

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(Workspace, "before_update")
def workspace_before_update(mapper: Any, connection: Any, target: Workspace) -> None:
    target.updated_at = utc_now()

    if target.slug:
        target.slug = normalize_slug(target.slug)

    if target.max_members <= 0:
        target.max_members = plan_member_limit(target.plan)

    if target.max_agents <= 0:
        target.max_agents = plan_agent_limit(target.plan)

    target.is_suspended = target.status == WorkspaceStatus.SUSPENDED


@event.listens_for(WorkspaceMembership, "before_insert")
def membership_before_insert(mapper: Any, connection: Any, target: WorkspaceMembership) -> None:
    if not target.id:
        target.id = generate_id("wsm")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.user_id = validate_scope_id(target.user_id, "user_id")

    if target.permissions is None:
        target.permissions = default_role_permissions(target.role)

    if target.agent_access is None:
        target.agent_access = default_member_agent_access(target.role)

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(WorkspaceMembership, "before_update")
def membership_before_update(mapper: Any, connection: Any, target: WorkspaceMembership) -> None:
    target.updated_at = utc_now()


@event.listens_for(WorkspaceInvitation, "before_insert")
def invitation_before_insert(mapper: Any, connection: Any, target: WorkspaceInvitation) -> None:
    if not target.id:
        target.id = generate_id("wsi")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.invited_email = normalize_email(target.invited_email)
    target.invited_by = validate_scope_id(target.invited_by, "invited_by")

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(WorkspaceInvitation, "before_update")
def invitation_before_update(mapper: Any, connection: Any, target: WorkspaceInvitation) -> None:
    target.updated_at = utc_now()

    if target.status == WorkspaceInvitationStatus.PENDING and target.is_expired:
        target.status = WorkspaceInvitationStatus.EXPIRED


# =============================================================================
# Backward compatibility aliases
# =============================================================================

WorkspaceModel = Workspace
WorkspaceMembershipModel = WorkspaceMembership
WorkspaceInvitationModel = WorkspaceInvitation


__all__ = [
    "Workspace",
    "WorkspaceModel",
    "WorkspaceMembership",
    "WorkspaceMembershipModel",
    "WorkspaceInvitation",
    "WorkspaceInvitationModel",
    "WorkspaceStatus",
    "WorkspacePlan",
    "WorkspaceSubscriptionStatus",
    "WorkspaceMemberRole",
    "WorkspaceMembershipStatus",
    "WorkspaceInvitationStatus",
    "role_rank",
    "role_at_least",
    "can_manage_workspace",
    "can_manage_members",
    "can_manage_billing",
    "can_run_agents",
    "can_view_dashboard",
    "can_access_audit_logs",
    "can_approve_sensitive_actions",
    "plan_allows_team_members",
    "plan_member_limit",
    "plan_agent_limit",
    "default_security_settings",
    "default_agent_access",
    "default_member_agent_access",
    "default_role_permissions",
    "require_workspace_active",
    "require_subscription_active",
    "require_membership_active",
    "require_workspace_member",
    "require_role",
    "require_permission",
    "workspace_scope_filter",
    "user_workspace_scope_filter",
]