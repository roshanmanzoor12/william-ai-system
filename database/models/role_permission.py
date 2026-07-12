"""
database/models/role_permission.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: Database Prompt Bible
Purpose: roles, permissions, user role mappings

This file is intentionally import-safe:
- It depends only on database.db Base and scope helpers.
- It does not hardcode secrets.
- It keeps user_id and workspace_id isolation as first-class fields.
- It supports workspace-scoped RBAC with roles, permissions, role-permission
  links, and user-role assignments.
- It includes compatibility helpers for API routes, Security Agent approval,
  dashboard access control, audit logs, Memory Agent payloads, and
  Verification Agent payloads.

Critical SaaS rule:
Never mix roles, permissions, users, memory, files, logs, tasks, billing,
analytics, or agent access between workspaces.
"""

from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

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
except Exception:  # pragma: no cover - import-safe fallback
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


def normalize_key(value: str, field_name: str = "key") -> str:
    cleaned = str(value or "").strip().lower()
    cleaned = cleaned.replace(" ", ".")
    cleaned = re.sub(r"[^a-z0-9_.:\\-]", "", cleaned)
    cleaned = re.sub(r"\\.+", ".", cleaned)
    cleaned = cleaned.strip(".:-_")

    if not cleaned:
        raise ValueError(f"{field_name} is required.")

    if len(cleaned) > 160:
        raise ValueError(f"{field_name} is too long.")

    return cleaned


def normalize_name(value: str, field_name: str = "name") -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        raise ValueError(f"{field_name} is required.")
    return cleaned[:180]


def enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


# =============================================================================
# Enums
# =============================================================================

class RoleStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"
    DELETED = "deleted"


class PermissionStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class RoleScope(str, enum.Enum):
    SYSTEM = "system"
    WORKSPACE = "workspace"
    CUSTOM = "custom"


class PermissionCategory(str, enum.Enum):
    WORKSPACE = "workspace"
    MEMBERS = "members"
    BILLING = "billing"
    AGENTS = "agents"
    MEMORY = "memory"
    FILES = "files"
    TASKS = "tasks"
    WORKFLOWS = "workflows"
    AUDIT = "audit"
    SECURITY = "security"
    ANALYTICS = "analytics"
    DASHBOARD = "dashboard"
    DEVICE = "device"
    SYSTEM = "system"
    API = "api"
    # database/seeders/default_plans.py seeds "integrations.manage" and
    # "plugins.manage" permissions with these two category strings; they had
    # no matching enum member, so the SQLAlchemy Enum(PermissionCategory)
    # column raised LookupError on SELECT for any row already inserted with
    # this category (INSERT succeeds since SQLite doesn't enforce it, but
    # the ORM-side read/lookup back does not) -- including inside
    # _find_existing()'s duplicate check, which silently treated the lookup
    # failure as "not found" and re-attempted an INSERT on every re-run.
    INTEGRATIONS = "integrations"
    PLUGINS = "plugins"


class PermissionEffect(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


class UserRoleAssignmentStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class BuiltInRoleKey(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"


# =============================================================================
# Default permissions
# =============================================================================

OWNER_PERMISSIONS = {"*"}

ADMIN_PERMISSIONS = {
    "workspace.view",
    "workspace.update",
    "workspace.settings.manage",
    "members.view",
    "members.invite",
    "members.update",
    "members.remove",
    "roles.view",
    "roles.manage",
    "billing.view",
    "billing.manage",
    "agents.view",
    "agents.run",
    "agents.manage",
    "memory.view",
    "memory.write",
    "memory.delete",
    "memory.export",
    "files.view",
    "files.write",
    "files.delete",
    "tasks.view",
    "tasks.create",
    "tasks.cancel",
    "workflows.view",
    "workflows.run",
    "workflows.manage",
    "audit.view",
    "security.view",
    "security.approve",
    "analytics.view",
    "dashboard.view",
    "api.use",
}

MANAGER_PERMISSIONS = {
    "workspace.view",
    "members.view",
    "members.invite",
    "roles.view",
    "billing.view",
    "agents.view",
    "agents.run",
    "memory.view",
    "memory.write",
    "files.view",
    "files.write",
    "tasks.view",
    "tasks.create",
    "tasks.cancel",
    "workflows.view",
    "workflows.run",
    "workflows.manage",
    "audit.view",
    "analytics.view",
    "dashboard.view",
    "api.use",
}

MEMBER_PERMISSIONS = {
    "workspace.view",
    "agents.view",
    "agents.run",
    "memory.view",
    "memory.write",
    "files.view",
    "files.write",
    "tasks.view",
    "tasks.create",
    "workflows.view",
    "workflows.run",
    "dashboard.view",
    "api.use",
}

VIEWER_PERMISSIONS = {
    "workspace.view",
    "agents.view",
    "memory.view",
    "files.view",
    "tasks.view",
    "workflows.view",
    "dashboard.view",
}


ROLE_RANK: Dict[str, int] = {
    BuiltInRoleKey.VIEWER.value: 10,
    BuiltInRoleKey.MEMBER.value: 20,
    BuiltInRoleKey.MANAGER.value: 30,
    BuiltInRoleKey.ADMIN.value: 40,
    BuiltInRoleKey.OWNER.value: 50,
}


def default_permissions_for_role(role_key: str) -> Set[str]:
    key = normalize_key(role_key, "role_key")

    if key == BuiltInRoleKey.OWNER.value:
        return set(OWNER_PERMISSIONS)

    if key == BuiltInRoleKey.ADMIN.value:
        return set(ADMIN_PERMISSIONS)

    if key == BuiltInRoleKey.MANAGER.value:
        return set(MANAGER_PERMISSIONS)

    if key == BuiltInRoleKey.MEMBER.value:
        return set(MEMBER_PERMISSIONS)

    if key == BuiltInRoleKey.VIEWER.value:
        return set(VIEWER_PERMISSIONS)

    return set()


def default_role_rank(role_key: str) -> int:
    return ROLE_RANK.get(normalize_key(role_key, "role_key"), 0)


def role_at_least(role_key: str, minimum_role_key: str) -> bool:
    return default_role_rank(role_key) >= default_role_rank(minimum_role_key)


def permission_category_from_key(permission_key: str) -> PermissionCategory:
    key = normalize_key(permission_key, "permission_key")
    prefix = key.split(".", 1)[0]

    mapping = {
        "workspace": PermissionCategory.WORKSPACE,
        "members": PermissionCategory.MEMBERS,
        "billing": PermissionCategory.BILLING,
        "agents": PermissionCategory.AGENTS,
        "agent": PermissionCategory.AGENTS,
        "memory": PermissionCategory.MEMORY,
        "files": PermissionCategory.FILES,
        "file": PermissionCategory.FILES,
        "tasks": PermissionCategory.TASKS,
        "task": PermissionCategory.TASKS,
        "workflows": PermissionCategory.WORKFLOWS,
        "workflow": PermissionCategory.WORKFLOWS,
        "audit": PermissionCategory.AUDIT,
        "security": PermissionCategory.SECURITY,
        "analytics": PermissionCategory.ANALYTICS,
        "dashboard": PermissionCategory.DASHBOARD,
        "device": PermissionCategory.DEVICE,
        "system": PermissionCategory.SYSTEM,
        "api": PermissionCategory.API,
    }

    return mapping.get(prefix, PermissionCategory.API)


def all_default_permission_keys() -> List[str]:
    permissions = set()
    permissions.update(ADMIN_PERMISSIONS)
    permissions.update(MANAGER_PERMISSIONS)
    permissions.update(MEMBER_PERMISSIONS)
    permissions.update(VIEWER_PERMISSIONS)
    return sorted(permissions)


# =============================================================================
# Required component
# =============================================================================

class RolePermission:
    """
    Required class/component name: RolePermission

    Utility component for evaluating role and permission mappings without
    requiring service/API layers.

    This class is safe to use in repositories, FastAPI dependencies,
    Security Agent checks, dashboard visibility logic, and tests.
    """

    @staticmethod
    def normalize_permission(permission_key: str) -> str:
        return normalize_key(permission_key, "permission_key")

    @staticmethod
    def normalize_role(role_key: str) -> str:
        return normalize_key(role_key, "role_key")

    @staticmethod
    def default_permissions(role_key: str) -> Set[str]:
        return default_permissions_for_role(role_key)

    @staticmethod
    def role_rank(role_key: str) -> int:
        return default_role_rank(role_key)

    @staticmethod
    def role_at_least(role_key: str, minimum_role_key: str) -> bool:
        return role_at_least(role_key, minimum_role_key)

    @staticmethod
    def has_permission(permission_keys: Iterable[str], required_permission: str) -> bool:
        required = normalize_key(required_permission, "required_permission")
        normalized_permissions = {normalize_key(item, "permission_key") for item in permission_keys}

        if "*" in normalized_permissions:
            return True

        if required in normalized_permissions:
            return True

        required_prefix = required.split(".", 1)[0]
        wildcard = f"{required_prefix}.*"

        return wildcard in normalized_permissions

    @staticmethod
    def denied_by(permission_keys: Iterable[str], required_permission: str) -> bool:
        required = normalize_key(required_permission, "required_permission")
        deny_key = f"!{required}"

        raw_permissions = {str(item).strip().lower() for item in permission_keys}
        return deny_key in raw_permissions or "!*" in raw_permissions

    @staticmethod
    def evaluate(
        allowed_permissions: Iterable[str],
        denied_permissions: Iterable[str],
        required_permission: str,
    ) -> bool:
        if RolePermission.denied_by(denied_permissions, required_permission):
            return False

        return RolePermission.has_permission(allowed_permissions, required_permission)

    @staticmethod
    def safe_error(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            },
        }


# =============================================================================
# Models
# =============================================================================

class Role(Base):
    """
    Workspace-scoped role model.

    Built-in roles can exist per workspace for clean customization while still
    retaining SaaS isolation.
    """

    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("role"))

    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    key: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scope: Mapped[RoleScope] = mapped_column(
        Enum(RoleScope, name="role_scope"),
        nullable=False,
        default=RoleScope.WORKSPACE,
        index=True,
    )

    status: Mapped[RoleStatus] = mapped_column(
        Enum(RoleStatus, name="role_status"),
        nullable=False,
        default=RoleStatus.ACTIVE,
        index=True,
    )

    rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_system_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_security_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    role_permissions: Mapped[List["RolePermissionLink"]] = relationship(
        "RolePermissionLink",
        back_populates="role",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    user_roles: Mapped[List["UserRoleMapping"]] = relationship(
        "UserRoleMapping",
        back_populates="role",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "key", name="uq_roles_workspace_key"),
        Index("ix_roles_workspace_status", "workspace_id", "status"),
        Index("ix_roles_workspace_rank", "workspace_id", "rank"),
    )

    def __repr__(self) -> str:
        return f"Role(id={self.id!r}, workspace_id={self.workspace_id!r}, key={self.key!r})"

    @classmethod
    def create(
        cls,
        workspace_id: str,
        key: str,
        name: str,
        created_by: Optional[str] = None,
        description: Optional[str] = None,
        scope: RoleScope = RoleScope.WORKSPACE,
        rank: Optional[int] = None,
        is_builtin: bool = False,
        is_system_locked: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Role":
        safe_workspace_id = validate_scope_id(workspace_id, "workspace_id")
        safe_key = normalize_key(key, "role_key")

        return cls(
            workspace_id=safe_workspace_id,
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
            key=safe_key,
            name=normalize_name(name, "role_name"),
            description=description,
            scope=scope,
            status=RoleStatus.ACTIVE,
            rank=rank if rank is not None else default_role_rank(safe_key),
            is_builtin=is_builtin,
            is_system_locked=is_system_locked,
            requires_security_approval=True,
            metadata_json=metadata or {},
        )

    @property
    def workspace_scope(self) -> Dict[str, str]:
        return {"workspace_id": self.workspace_id}

    @property
    def is_active(self) -> bool:
        return self.status == RoleStatus.ACTIVE and self.deleted_at is None

    @property
    def is_owner_role(self) -> bool:
        return self.key == BuiltInRoleKey.OWNER.value

    def archive(self, updated_by: str) -> None:
        if self.is_system_locked:
            raise PermissionError("System locked roles cannot be archived.")

        self.status = RoleStatus.ARCHIVED
        self.archived_at = utc_now()
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def soft_delete(self, updated_by: str) -> None:
        if self.is_system_locked:
            raise PermissionError("System locked roles cannot be deleted.")

        self.status = RoleStatus.DELETED
        self.deleted_at = utc_now()
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def update_details(
        self,
        updated_by: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        rank: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self.is_system_locked and self.is_builtin:
            allowed_fields = {"description", "metadata"}
            requested_fields = {
                key
                for key, value in {
                    "name": name,
                    "description": description,
                    "rank": rank,
                    "metadata": metadata,
                }.items()
                if value is not None
            }
            if requested_fields - allowed_fields:
                raise PermissionError("System locked built-in roles cannot change name or rank.")

        if name is not None:
            self.name = normalize_name(name, "role_name")
        if description is not None:
            self.description = description
        if rank is not None:
            self.rank = int(rank)
        if metadata is not None:
            self.metadata_json = metadata

        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "scope": enum_value(self.scope),
            "status": enum_value(self.status),
            "rank": self.rank,
            "is_builtin": self.is_builtin,
            "is_system_locked": self.is_system_locked,
            "requires_security_approval": self.requires_security_approval,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)

    def _prepare_memory_payload(self) -> Dict[str, Any]:
        return {
            "entity": "role",
            "role_id": self.id,
            "workspace_id": self.workspace_id,
            "key": self.key,
            "name": self.name,
            "rank": self.rank,
        }

    def _prepare_verification_payload(self) -> Dict[str, Any]:
        return {
            "entity": "role",
            "role_id": self.id,
            "workspace_id": self.workspace_id,
            "status": enum_value(self.status),
            "timestamp": utc_now().isoformat(),
        }

    def _log_audit_event(self, action: str, actor_user_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "action": action,
            "entity": "role",
            "role_id": self.id,
            "workspace_id": self.workspace_id,
            "actor_user_id": actor_user_id,
            "timestamp": utc_now().isoformat(),
        }


class Permission(Base):
    """
    Permission definition model.

    Permissions are workspace-scoped by default, but can also represent system
    seeded permission definitions when workspace_id is set to "system".
    """

    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("perm"))

    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True, default="system")
    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    key: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    category: Mapped[PermissionCategory] = mapped_column(
        Enum(PermissionCategory, name="permission_category"),
        nullable=False,
        default=PermissionCategory.API,
        index=True,
    )

    status: Mapped[PermissionStatus] = mapped_column(
        Enum(PermissionStatus, name="permission_status"),
        nullable=False,
        default=PermissionStatus.ACTIVE,
        index=True,
    )

    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_security_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    role_permissions: Mapped[List["RolePermissionLink"]] = relationship(
        "RolePermissionLink",
        back_populates="permission",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "key", name="uq_permissions_workspace_key"),
        Index("ix_permissions_workspace_status", "workspace_id", "status"),
        Index("ix_permissions_category_status", "category", "status"),
    )

    def __repr__(self) -> str:
        return f"Permission(id={self.id!r}, workspace_id={self.workspace_id!r}, key={self.key!r})"

    @classmethod
    def create(
        cls,
        key: str,
        name: Optional[str] = None,
        workspace_id: str = "system",
        created_by: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[PermissionCategory] = None,
        is_sensitive: bool = False,
        requires_security_approval: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Permission":
        safe_key = normalize_key(key, "permission_key")

        return cls(
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
            key=safe_key,
            name=normalize_name(name or safe_key.replace(".", " ").title(), "permission_name"),
            description=description,
            category=category or permission_category_from_key(safe_key),
            status=PermissionStatus.ACTIVE,
            is_sensitive=is_sensitive,
            requires_security_approval=requires_security_approval if requires_security_approval is not None else is_sensitive,
            metadata_json=metadata or {},
        )

    @property
    def is_active(self) -> bool:
        return self.status == PermissionStatus.ACTIVE

    def disable(self, updated_by: str) -> None:
        self.status = PermissionStatus.DISABLED
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def enable(self, updated_by: str) -> None:
        self.status = PermissionStatus.ACTIVE
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "category": enum_value(self.category),
            "status": enum_value(self.status),
            "is_sensitive": self.is_sensitive,
            "requires_security_approval": self.requires_security_approval,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)


class RolePermissionLink(Base):
    """
    Role to permission mapping model.

    A DENY effect overrides ALLOW during permission evaluation.
    """

    __tablename__ = "role_permission_links"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("rpl"))

    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    role_id: Mapped[str] = mapped_column(
        String(140),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    permission_id: Mapped[str] = mapped_column(
        String(140),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    effect: Mapped[PermissionEffect] = mapped_column(
        Enum(PermissionEffect, name="permission_effect"),
        nullable=False,
        default=PermissionEffect.ALLOW,
        index=True,
    )

    conditions: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    role: Mapped["Role"] = relationship("Role", back_populates="role_permissions", lazy="selectin")
    permission: Mapped["Permission"] = relationship("Permission", back_populates="role_permissions", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("workspace_id", "role_id", "permission_id", "effect", name="uq_role_permission_effect"),
        Index("ix_role_permission_workspace_role", "workspace_id", "role_id"),
        Index("ix_role_permission_workspace_permission", "workspace_id", "permission_id"),
    )

    def __repr__(self) -> str:
        return (
            f"RolePermissionLink(id={self.id!r}, workspace_id={self.workspace_id!r}, "
            f"role_id={self.role_id!r}, permission_id={self.permission_id!r}, effect={enum_value(self.effect)!r})"
        )

    @classmethod
    def create(
        cls,
        workspace_id: str,
        role_id: str,
        permission_id: str,
        effect: PermissionEffect = PermissionEffect.ALLOW,
        created_by: Optional[str] = None,
        conditions: Optional[Dict[str, Any]] = None,
    ) -> "RolePermissionLink":
        return cls(
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            role_id=validate_scope_id(role_id, "role_id"),
            permission_id=validate_scope_id(permission_id, "permission_id"),
            effect=effect,
            conditions=conditions or {},
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
        )

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "role_id": self.role_id,
            "permission_id": self.permission_id,
            "effect": enum_value(self.effect),
            "conditions": self.conditions or {},
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict()


class UserRoleMapping(Base):
    """
    User to role assignment model.

    Every assignment is scoped to a single user_id + workspace_id.
    """

    __tablename__ = "user_role_mappings"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("urm"))

    user_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    role_id: Mapped[str] = mapped_column(
        String(140),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[UserRoleAssignmentStatus] = mapped_column(
        Enum(UserRoleAssignmentStatus, name="user_role_assignment_status"),
        nullable=False,
        default=UserRoleAssignmentStatus.ACTIVE,
        index=True,
    )

    assigned_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    role: Mapped["Role"] = relationship("Role", back_populates="user_roles", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("user_id", "workspace_id", "role_id", name="uq_user_workspace_role"),
        Index("ix_user_roles_workspace_status", "workspace_id", "status"),
        Index("ix_user_roles_user_workspace", "user_id", "workspace_id"),
    )

    def __repr__(self) -> str:
        return (
            f"UserRoleMapping(id={self.id!r}, user_id={self.user_id!r}, "
            f"workspace_id={self.workspace_id!r}, role_id={self.role_id!r})"
        )

    @classmethod
    def create(
        cls,
        user_id: str,
        workspace_id: str,
        role_id: str,
        assigned_by: Optional[str] = None,
        reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UserRoleMapping":
        return cls(
            user_id=validate_scope_id(user_id, "user_id"),
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            role_id=validate_scope_id(role_id, "role_id"),
            status=UserRoleAssignmentStatus.ACTIVE,
            assigned_by=validate_scope_id(assigned_by, "assigned_by") if assigned_by else None,
            reason=reason,
            expires_at=expires_at,
            metadata_json=metadata or {},
        )

    @property
    def is_active(self) -> bool:
        if self.status != UserRoleAssignmentStatus.ACTIVE:
            return False

        if self.expires_at and utc_now() > self.expires_at:
            return False

        return self.revoked_at is None

    def scope(self) -> DbScope:
        return DbScope(user_id=self.user_id, workspace_id=self.workspace_id)

    def revoke(self, revoked_by: str, reason: Optional[str] = None) -> None:
        self.status = UserRoleAssignmentStatus.REVOKED
        self.revoked_by = validate_scope_id(revoked_by, "revoked_by")
        self.revoked_at = utc_now()
        self.updated_at = utc_now()
        self.reason = reason or self.reason

    def suspend(self, updated_by: str, reason: Optional[str] = None) -> None:
        self.status = UserRoleAssignmentStatus.SUSPENDED
        self.updated_at = utc_now()
        self.reason = reason or self.reason
        self.metadata_json = {
            **(self.metadata_json or {}),
            "suspended_by": validate_scope_id(updated_by, "updated_by"),
            "suspended_at": utc_now().isoformat(),
        }

    def activate(self, updated_by: str) -> None:
        self.status = UserRoleAssignmentStatus.ACTIVE
        self.updated_at = utc_now()
        self.metadata_json = {
            **(self.metadata_json or {}),
            "activated_by": validate_scope_id(updated_by, "updated_by"),
            "activated_at": utc_now().isoformat(),
        }

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role_id": self.role_id,
            "status": enum_value(self.status),
            "assigned_by": self.assigned_by,
            "revoked_by": self.revoked_by,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)

    def _prepare_memory_payload(self) -> Dict[str, Any]:
        return {
            "entity": "user_role_mapping",
            "mapping_id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role_id": self.role_id,
            "status": enum_value(self.status),
        }

    def _prepare_verification_payload(self) -> Dict[str, Any]:
        return {
            "entity": "user_role_mapping",
            "mapping_id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": enum_value(self.status),
            "timestamp": utc_now().isoformat(),
        }

    def _log_audit_event(self, action: str, actor_user_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "action": action,
            "entity": "user_role_mapping",
            "mapping_id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "actor_user_id": actor_user_id,
            "timestamp": utc_now().isoformat(),
        }


# =============================================================================
# Permission evaluation helpers
# =============================================================================

def role_permission_keys(
    role: Role,
    links: Iterable[RolePermissionLink],
) -> Dict[str, Set[str]]:
    allowed: Set[str] = set()
    denied: Set[str] = set()

    if role.key == BuiltInRoleKey.OWNER.value:
        allowed.add("*")

    for link in links:
        if link.role_id != role.id:
            continue

        permission = getattr(link, "permission", None)
        if permission is None:
            continue

        if not getattr(permission, "is_active", False):
            continue

        permission_key = normalize_key(permission.key, "permission_key")

        if link.effect == PermissionEffect.DENY:
            denied.add(permission_key)
        else:
            allowed.add(permission_key)

    if not allowed and role.is_builtin:
        allowed.update(default_permissions_for_role(role.key))

    return {"allow": allowed, "deny": denied}


def user_effective_permissions(
    user_id: str,
    workspace_id: str,
    mappings: Iterable[UserRoleMapping],
    role_links: Iterable[RolePermissionLink],
) -> Dict[str, Set[str]]:
    safe_user_id = validate_scope_id(user_id, "user_id")
    safe_workspace_id = validate_scope_id(workspace_id, "workspace_id")

    allowed: Set[str] = set()
    denied: Set[str] = set()

    for mapping in mappings:
        if mapping.user_id != safe_user_id or mapping.workspace_id != safe_workspace_id:
            continue

        if not mapping.is_active:
            continue

        role = getattr(mapping, "role", None)
        if role is None or not getattr(role, "is_active", False):
            continue

        result = role_permission_keys(role, role_links)
        allowed.update(result["allow"])
        denied.update(result["deny"])

    return {"allow": allowed, "deny": denied}


def user_has_permission(
    user_id: str,
    workspace_id: str,
    required_permission: str,
    mappings: Iterable[UserRoleMapping],
    role_links: Iterable[RolePermissionLink],
) -> bool:
    effective = user_effective_permissions(user_id, workspace_id, mappings, role_links)
    return RolePermission.evaluate(
        allowed_permissions=effective["allow"],
        denied_permissions=effective["deny"],
        required_permission=required_permission,
    )


def require_user_permission(
    user_id: str,
    workspace_id: str,
    required_permission: str,
    mappings: Iterable[UserRoleMapping],
    role_links: Iterable[RolePermissionLink],
) -> bool:
    if not user_has_permission(user_id, workspace_id, required_permission, mappings, role_links):
        raise PermissionError(f"Permission denied: {required_permission}")
    return True


def role_scope_filter(workspace_id: str) -> Dict[str, str]:
    return {"workspace_id": validate_scope_id(workspace_id, "workspace_id")}


def user_role_scope_filter(user_id: str, workspace_id: str) -> Dict[str, str]:
    return {
        "user_id": validate_scope_id(user_id, "user_id"),
        "workspace_id": validate_scope_id(workspace_id, "workspace_id"),
    }


# =============================================================================
# Seed helpers
# =============================================================================

def build_default_permission_models(workspace_id: str = "system", created_by: Optional[str] = None) -> List[Permission]:
    return [
        Permission.create(
            workspace_id=workspace_id,
            key=permission_key,
            created_by=created_by,
            is_sensitive=permission_key in {
                "billing.manage",
                "security.approve",
                "memory.export",
                "memory.delete",
                "files.delete",
                "members.remove",
                "roles.manage",
            },
        )
        for permission_key in all_default_permission_keys()
    ]


def build_default_role_models(workspace_id: str, created_by: Optional[str] = None) -> List[Role]:
    return [
        Role.create(
            workspace_id=workspace_id,
            key=BuiltInRoleKey.OWNER.value,
            name="Owner",
            created_by=created_by,
            description="Full workspace ownership and all permissions.",
            scope=RoleScope.WORKSPACE,
            is_builtin=True,
            is_system_locked=True,
        ),
        Role.create(
            workspace_id=workspace_id,
            key=BuiltInRoleKey.ADMIN.value,
            name="Admin",
            created_by=created_by,
            description="Manage workspace, billing, members, agents, and security approvals.",
            scope=RoleScope.WORKSPACE,
            is_builtin=True,
            is_system_locked=True,
        ),
        Role.create(
            workspace_id=workspace_id,
            key=BuiltInRoleKey.MANAGER.value,
            name="Manager",
            created_by=created_by,
            description="Manage daily workspace operations and workflows.",
            scope=RoleScope.WORKSPACE,
            is_builtin=True,
            is_system_locked=True,
        ),
        Role.create(
            workspace_id=workspace_id,
            key=BuiltInRoleKey.MEMBER.value,
            name="Member",
            created_by=created_by,
            description="Run agents, create tasks, and use workspace resources.",
            scope=RoleScope.WORKSPACE,
            is_builtin=True,
            is_system_locked=True,
        ),
        Role.create(
            workspace_id=workspace_id,
            key=BuiltInRoleKey.VIEWER.value,
            name="Viewer",
            created_by=created_by,
            description="Read-only workspace dashboard access.",
            scope=RoleScope.WORKSPACE,
            is_builtin=True,
            is_system_locked=True,
        ),
    ]


# =============================================================================
# SQLAlchemy events
# =============================================================================

@event.listens_for(Role, "before_insert")
def role_before_insert(mapper: Any, connection: Any, target: Role) -> None:
    if not target.id:
        target.id = generate_id("role")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.key = normalize_key(target.key, "role_key")
    target.name = normalize_name(target.name, "role_name")

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.updated_by:
        target.updated_by = validate_scope_id(target.updated_by, "updated_by")

    if target.rank is None:
        target.rank = default_role_rank(target.key)

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(Role, "before_update")
def role_before_update(mapper: Any, connection: Any, target: Role) -> None:
    target.key = normalize_key(target.key, "role_key")
    target.name = normalize_name(target.name, "role_name")
    target.updated_at = utc_now()


@event.listens_for(Permission, "before_insert")
def permission_before_insert(mapper: Any, connection: Any, target: Permission) -> None:
    if not target.id:
        target.id = generate_id("perm")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.key = normalize_key(target.key, "permission_key")
    target.name = normalize_name(target.name, "permission_name")

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.updated_by:
        target.updated_by = validate_scope_id(target.updated_by, "updated_by")

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(Permission, "before_update")
def permission_before_update(mapper: Any, connection: Any, target: Permission) -> None:
    target.key = normalize_key(target.key, "permission_key")
    target.name = normalize_name(target.name, "permission_name")
    target.updated_at = utc_now()


@event.listens_for(RolePermissionLink, "before_insert")
def role_permission_link_before_insert(mapper: Any, connection: Any, target: RolePermissionLink) -> None:
    if not target.id:
        target.id = generate_id("rpl")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.role_id = validate_scope_id(target.role_id, "role_id")
    target.permission_id = validate_scope_id(target.permission_id, "permission_id")

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.conditions is None:
        target.conditions = {}

    target.created_at = target.created_at or utc_now()


@event.listens_for(UserRoleMapping, "before_insert")
def user_role_mapping_before_insert(mapper: Any, connection: Any, target: UserRoleMapping) -> None:
    if not target.id:
        target.id = generate_id("urm")

    target.user_id = validate_scope_id(target.user_id, "user_id")
    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.role_id = validate_scope_id(target.role_id, "role_id")

    if target.assigned_by:
        target.assigned_by = validate_scope_id(target.assigned_by, "assigned_by")

    if target.revoked_by:
        target.revoked_by = validate_scope_id(target.revoked_by, "revoked_by")

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(UserRoleMapping, "before_update")
def user_role_mapping_before_update(mapper: Any, connection: Any, target: UserRoleMapping) -> None:
    target.updated_at = utc_now()

    if target.status == UserRoleAssignmentStatus.ACTIVE and target.expires_at and utc_now() > target.expires_at:
        target.status = UserRoleAssignmentStatus.EXPIRED


# =============================================================================
# Backward compatibility aliases
# =============================================================================

RoleModel = Role
PermissionModel = Permission
RolePermissionModel = RolePermissionLink
UserRoleMappingModel = UserRoleMapping


__all__ = [
    "RolePermission",
    "Role",
    "RoleModel",
    "Permission",
    "PermissionModel",
    "RolePermissionLink",
    "RolePermissionModel",
    "UserRoleMapping",
    "UserRoleMappingModel",
    "RoleStatus",
    "PermissionStatus",
    "RoleScope",
    "PermissionCategory",
    "PermissionEffect",
    "UserRoleAssignmentStatus",
    "BuiltInRoleKey",
    "OWNER_PERMISSIONS",
    "ADMIN_PERMISSIONS",
    "MANAGER_PERMISSIONS",
    "MEMBER_PERMISSIONS",
    "VIEWER_PERMISSIONS",
    "default_permissions_for_role",
    "default_role_rank",
    "role_at_least",
    "permission_category_from_key",
    "all_default_permission_keys",
    "role_permission_keys",
    "user_effective_permissions",
    "user_has_permission",
    "require_user_permission",
    "role_scope_filter",
    "user_role_scope_filter",
    "build_default_permission_models",
    "build_default_role_models",
]