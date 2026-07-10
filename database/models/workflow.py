"""
database/models/workflow.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Workflows, workflow runs, nodes, logs, and failures.

This file is designed for:
    - SaaS-safe user/workspace isolation
    - Master Agent workflow orchestration
    - Security Agent approval routing for sensitive workflow actions
    - Verification Agent payload preparation after completed runs/nodes
    - Memory Agent compatible workflow context snapshots
    - Audit-friendly logs and failure records
    - Dashboard/API-safe structured responses

The file avoids importing future project modules directly so it can import safely
even when the rest of the system is still being built.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Dict, Iterable, Mapping, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

try:
    from sqlalchemy.dialects.postgresql import JSONB
except Exception:  # pragma: no cover
    JSONB = None

try:
    from sqlalchemy import JSON
except Exception as exc:  # pragma: no cover
    raise RuntimeError("SQLAlchemy JSON support is required for workflow.py") from exc

try:
    from database.base import Base
except Exception:
    try:
        from database.models.base import Base
    except Exception:
        from sqlalchemy.orm import DeclarativeBase

        class Base(DeclarativeBase):
            """Fallback base so this model can import before project Base exists."""


JsonColumn = JSONB if JSONB is not None and os.getenv("WILLIAM_DB_DIALECT", "").lower() == "postgresql" else JSON


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a string UUID for cross-service compatibility."""
    return str(uuid.uuid4())


class WorkflowStatus(str, Enum):
    """Workflow definition lifecycle status."""

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"
    DELETED = "deleted"


class WorkflowRunStatus(str, Enum):
    """Workflow run lifecycle status."""

    QUEUED = "queued"
    WAITING_SECURITY = "waiting_security"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class WorkflowNodeStatus(str, Enum):
    """Workflow node execution lifecycle status."""

    PENDING = "pending"
    WAITING_DEPENDENCY = "waiting_dependency"
    WAITING_SECURITY = "waiting_security"
    RUNNING = "running"
    SKIPPED = "skipped"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class WorkflowNodeType(str, Enum):
    """Supported node categories for agentic workflows."""

    START = "start"
    END = "end"
    AGENT = "agent"
    MASTER_AGENT = "master_agent"
    SECURITY_AGENT = "security_agent"
    VERIFICATION_AGENT = "verification_agent"
    MEMORY_AGENT = "memory_agent"
    TOOL = "tool"
    CONDITION = "condition"
    DELAY = "delay"
    HUMAN_APPROVAL = "human_approval"
    WEBHOOK = "webhook"
    API_CALL = "api_call"
    FILE_ACTION = "file_action"
    SYSTEM_ACTION = "system_action"


class WorkflowTriggerType(str, Enum):
    """Workflow trigger categories."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"
    API = "api"
    EVENT = "event"
    AGENT = "agent"
    SYSTEM = "system"


class WorkflowLogLevel(str, Enum):
    """Log severity for workflow execution events."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class WorkflowVisibility(str, Enum):
    """Visibility scope for workflow dashboards and APIs."""

    PRIVATE = "private"
    WORKSPACE = "workspace"
    ADMIN_ONLY = "admin_only"
    SECURITY_ONLY = "security_only"


class WorkflowFailureType(str, Enum):
    """Failure categories for workflow run/node failures."""

    VALIDATION = "validation"
    SECURITY_REJECTED = "security_rejected"
    PERMISSION_DENIED = "permission_denied"
    SUBSCRIPTION_LIMIT = "subscription_limit"
    AGENT_ERROR = "agent_error"
    TOOL_ERROR = "tool_error"
    TIMEOUT = "timeout"
    DEPENDENCY_FAILED = "dependency_failed"
    SYSTEM_ERROR = "system_error"
    UNKNOWN = "unknown"


class WorkflowActorType(str, Enum):
    """Actor responsible for creating or changing workflow state."""

    USER = "user"
    AGENT = "agent"
    MASTER_AGENT = "master_agent"
    SECURITY_AGENT = "security_agent"
    VERIFICATION_AGENT = "verification_agent"
    MEMORY_AGENT = "memory_agent"
    SYSTEM = "system"
    API = "api"
    WORKER = "worker"


class WorkflowAccessDecision(str, Enum):
    """Simple access decision values for dashboard/API helpers."""

    ALLOW = "allow"
    DENY = "deny"
    SECURITY_REVIEW = "security_review"
    SUBSCRIPTION_REQUIRED = "subscription_required"


class WorkflowMixin:
    """
    Shared helpers for workflow-related models.

    This mixin intentionally contains no SQLAlchemy fields so it can be used safely
    by multiple mapped classes.
    """

    SECRET_REDACTION: ClassVar[str] = "[REDACTED]"
    DEFAULT_PAYLOAD_LIMIT: ClassVar[int] = 96_000

    SENSITIVE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "token",
            "authorization",
            "auth",
            "cookie",
            "session",
            "private_key",
            "client_secret",
            "stripe_secret",
            "openai_api_key",
            "database_url",
            "dsn",
            "connection_string",
            "webhook_secret",
        }
    )

    @staticmethod
    def clean_identifier(value: Any, field_name: str = "identifier", max_length: int = 128) -> str:
        if value is None:
            return ""
        cleaned = str(value).strip()
        if not cleaned:
            return ""
        if len(cleaned) > max_length:
            raise ValueError(f"{field_name} is too long.")
        return cleaned

    @classmethod
    def enum_value(cls, value: Any) -> Any:
        return value.value if isinstance(value, Enum) else value

    @classmethod
    def coerce_enum(cls, value: Any, enum_cls: type[Enum]) -> Enum:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            normalized = value.strip()
            for item in enum_cls:
                if item.value == normalized or item.name.lower() == normalized.lower():
                    return item
        raise ValueError(f"Invalid {enum_cls.__name__}: {value!r}")

    @classmethod
    def safe_json_value(cls, value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "[MAX_DEPTH_REACHED]"

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, datetime):
            return value.isoformat()

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, Mapping):
            safe_dict: Dict[str, Any] = {}
            for raw_key, raw_value in value.items():
                key = str(raw_key)
                normalized_key = key.lower().replace("-", "_").replace(" ", "_")
                if normalized_key in cls.SENSITIVE_KEYS or any(
                    sensitive in normalized_key for sensitive in cls.SENSITIVE_KEYS
                ):
                    safe_dict[key] = cls.SECRET_REDACTION
                else:
                    safe_dict[key] = cls.safe_json_value(raw_value, depth + 1)
            return safe_dict

        if isinstance(value, (list, tuple, set, frozenset)):
            return [cls.safe_json_value(item, depth + 1) for item in value]

        return str(value)

    @classmethod
    def sanitize_payload(cls, payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Return JSON-safe payload with secrets redacted."""
        if not payload:
            return {}

        safe_payload = cls.safe_json_value(dict(payload))
        serialized = json.dumps(safe_payload, sort_keys=True, default=str)

        max_size = int(os.getenv("WILLIAM_WORKFLOW_PAYLOAD_LIMIT", cls.DEFAULT_PAYLOAD_LIMIT))
        size_bytes = len(serialized.encode("utf-8"))

        if size_bytes > max_size:
            return {
                "payload_truncated": True,
                "payload_size_bytes": size_bytes,
                "payload_preview": serialized[: max_size // 2],
            }

        return safe_payload

    @classmethod
    def compute_hash(cls, payload: Optional[Mapping[str, Any]]) -> str:
        safe_payload = cls.sanitize_payload(payload)
        serialized = json.dumps(safe_payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def build_scope_key(cls, user_id: str, workspace_id: str) -> str:
        safe_user_id = cls.clean_identifier(user_id, "user_id")
        safe_workspace_id = cls.clean_identifier(workspace_id, "workspace_id")
        if not safe_user_id or not safe_workspace_id:
            raise ValueError("Both user_id and workspace_id are required.")
        return f"{safe_workspace_id}:{safe_user_id}"

    @staticmethod
    def calculate_progress_percent(current: int, total: int) -> int:
        safe_total = max(int(total or 100), 1)
        safe_current = max(int(current or 0), 0)
        return min(int(round((safe_current / safe_total) * 100)), 100)

    @classmethod
    def safe_error_response(
        cls,
        *,
        code: str,
        message: str,
        correlation_id: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": str(code),
                "message": str(message),
                "correlation_id": correlation_id,
                "resource_id": resource_id,
            },
        }

    @classmethod
    def success_response(
        cls,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "ok": True,
            "message": message,
            "data": cls.sanitize_payload(data or {}),
        }


class Workflow(Base, WorkflowMixin):
    """
    Workflow definition model.

    Stores reusable workflow templates/definitions. Actual executions are stored
    in WorkflowRun. Nodes are stored in WorkflowNode.

    Required isolation:
        - user_id
        - workspace_id

    Dashboard/API layers should enforce role, plan, and subscription checks before
    exposing or mutating records. This model stores enough context and provides
    helpers to support those checks safely.
    """

    __tablename__ = "workflows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    workflow_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"wf_{uuid.uuid4().hex}",
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    slug: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[WorkflowStatus] = mapped_column(
        SAEnum(WorkflowStatus, name="workflow_status"),
        nullable=False,
        default=WorkflowStatus.DRAFT,
        index=True,
    )

    visibility: Mapped[WorkflowVisibility] = mapped_column(
        SAEnum(WorkflowVisibility, name="workflow_visibility"),
        nullable=False,
        default=WorkflowVisibility.PRIVATE,
        index=True,
    )

    trigger_type: Mapped[WorkflowTriggerType] = mapped_column(
        SAEnum(WorkflowTriggerType, name="workflow_trigger_type"),
        nullable=False,
        default=WorkflowTriggerType.MANUAL,
        index=True,
    )

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_template: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    is_system_workflow: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    created_by_actor_type: Mapped[WorkflowActorType] = mapped_column(
        SAEnum(WorkflowActorType, name="workflow_created_by_actor_type"),
        nullable=False,
        default=WorkflowActorType.USER,
        index=True,
    )
    created_by_actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    owner_role: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    subscription_plan: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)

    definition: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    trigger_config: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    variables: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    permissions: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    requires_security_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    security_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    last_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    definition_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    runs: Mapped[list["WorkflowRun"]] = relationship(
        "WorkflowRun",
        back_populates="workflow",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    nodes: Mapped[list["WorkflowNode"]] = relationship(
        "WorkflowNode",
        back_populates="workflow",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    logs: Mapped[list["WorkflowLog"]] = relationship(
        "WorkflowLog",
        back_populates="workflow",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    failures: Mapped[list["WorkflowFailure"]] = relationship(
        "WorkflowFailure",
        back_populates="workflow",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "workflow_uid", name="uq_workflows_workspace_uid"),
        UniqueConstraint("workspace_id", "slug", name="uq_workflows_workspace_slug"),
        Index("ix_workflows_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_workflows_scope_trigger", "workspace_id", "user_id", "trigger_type"),
        Index("ix_workflows_security_queue", "workspace_id", "requires_security_review", "security_reviewed"),
    )

    def __repr__(self) -> str:
        return (
            "Workflow("
            f"id={self.id!r}, workflow_uid={self.workflow_uid!r}, "
            f"user_id={self.user_id!r}, workspace_id={self.workspace_id!r}, "
            f"name={self.name!r}, status={self.status.value!r})"
        )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for Workflow isolation.")
        return cleaned

    @validates("name")
    def validate_name(self, key: str, value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("Workflow name is required.")
        if len(cleaned) > 180:
            raise ValueError("Workflow name is too long.")
        return cleaned

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        name: str,
        description: Optional[str] = None,
        slug: Optional[str] = None,
        trigger_type: WorkflowTriggerType | str = WorkflowTriggerType.MANUAL,
        definition: Optional[Mapping[str, Any]] = None,
        trigger_config: Optional[Mapping[str, Any]] = None,
        variables: Optional[Mapping[str, Any]] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        created_by_actor_type: WorkflowActorType | str = WorkflowActorType.USER,
        created_by_actor_id: Optional[str] = None,
        owner_role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        visibility: WorkflowVisibility | str = WorkflowVisibility.PRIVATE,
        is_template: bool = False,
        is_system_workflow: bool = False,
        requires_security_review: bool = False,
    ) -> "Workflow":
        safe_definition = cls.sanitize_payload(definition)
        safe_trigger_config = cls.sanitize_payload(trigger_config)
        safe_variables = cls.sanitize_payload(variables)
        safe_permissions = cls.sanitize_payload(permissions)
        safe_metadata = cls.sanitize_payload(metadata)

        workflow = cls(
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            name=name,
            slug=str(slug).strip()[:200] if slug else None,
            description=description,
            trigger_type=cls.coerce_enum(trigger_type, WorkflowTriggerType),
            visibility=cls.coerce_enum(visibility, WorkflowVisibility),
            created_by_actor_type=cls.coerce_enum(created_by_actor_type, WorkflowActorType),
            created_by_actor_id=str(created_by_actor_id)[:120] if created_by_actor_id else None,
            owner_role=str(owner_role)[:80] if owner_role else None,
            subscription_plan=str(subscription_plan)[:80] if subscription_plan else None,
            definition=safe_definition,
            trigger_config=safe_trigger_config,
            variables=safe_variables,
            permissions=safe_permissions,
            metadata_json={
                **safe_metadata,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "Workflow",
            },
            is_template=bool(is_template),
            is_system_workflow=bool(is_system_workflow),
            requires_security_review=bool(requires_security_review),
            status=WorkflowStatus.DRAFT,
        )
        workflow.definition_hash = cls.compute_hash(
            {
                "definition": workflow.definition,
                "trigger_config": workflow.trigger_config,
                "variables": workflow.variables,
                "permissions": workflow.permissions,
            }
        )
        return workflow

    @property
    def scope_key(self) -> str:
        return self.build_scope_key(self.user_id, self.workspace_id)

    @property
    def is_active(self) -> bool:
        return self.status == WorkflowStatus.ACTIVE

    @property
    def is_deleted(self) -> bool:
        return self.status == WorkflowStatus.DELETED or self.deleted_at is not None

    @property
    def needs_security_agent(self) -> bool:
        return self.requires_security_review and not self.security_reviewed

    def assert_same_scope(self, *, user_id: str, workspace_id: str) -> None:
        if self.user_id != str(user_id).strip() or self.workspace_id != str(workspace_id).strip():
            raise PermissionError("Workflow access denied for this user/workspace scope.")

    def activate(self) -> None:
        if self.needs_security_agent:
            self.status = WorkflowStatus.PAUSED
            raise PermissionError("Workflow requires Security Agent approval before activation.")
        self.status = WorkflowStatus.ACTIVE
        self.activated_at = utc_now()
        self.updated_at = utc_now()

    def pause(self) -> None:
        self.status = WorkflowStatus.PAUSED
        self.updated_at = utc_now()

    def archive(self) -> None:
        self.status = WorkflowStatus.ARCHIVED
        self.archived_at = utc_now()
        self.updated_at = utc_now()

    def soft_delete(self) -> None:
        self.status = WorkflowStatus.DELETED
        self.deleted_at = utc_now()
        self.updated_at = utc_now()

    def mark_security_decision(self, *, approved: bool, reason: Optional[str] = None) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.security_reason = reason
        self.status = WorkflowStatus.ACTIVE if approved else WorkflowStatus.PAUSED
        self.updated_at = utc_now()

    def update_definition(
        self,
        *,
        definition: Optional[Mapping[str, Any]] = None,
        trigger_config: Optional[Mapping[str, Any]] = None,
        variables: Optional[Mapping[str, Any]] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        requires_security_review: Optional[bool] = None,
    ) -> None:
        if definition is not None:
            self.definition = self.sanitize_payload(definition)
        if trigger_config is not None:
            self.trigger_config = self.sanitize_payload(trigger_config)
        if variables is not None:
            self.variables = self.sanitize_payload(variables)
        if permissions is not None:
            self.permissions = self.sanitize_payload(permissions)
        if requires_security_review is not None:
            self.requires_security_review = bool(requires_security_review)
            self.security_reviewed = False
            self.security_approved = None

        self.version += 1
        self.definition_hash = self.compute_hash(
            {
                "definition": self.definition,
                "trigger_config": self.trigger_config,
                "variables": self.variables,
                "permissions": self.permissions,
            }
        )
        self.updated_at = utc_now()

    def prepare_memory_context(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "type": "workflow_definition",
                "workflow_uid": self.workflow_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "name": self.name,
                "description": self.description,
                "status": self.status.value,
                "trigger_type": self.trigger_type.value,
                "version": self.version,
                "definition_summary": self.definition,
                "scope_key": self.scope_key,
                "updated_at": self.updated_at,
            }
        )

    def prepare_verification_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "verification_id": f"ver_{uuid.uuid4().hex}",
                "type": "workflow_definition",
                "workflow_uid": self.workflow_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "name": self.name,
                "status": self.status.value,
                "version": self.version,
                "definition_hash": self.definition_hash,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "prepared_at": utc_now(),
            }
        )

    def can_be_seen_by_role(self, role: Optional[str]) -> bool:
        normalized = (role or "").lower().strip()

        if self.visibility == WorkflowVisibility.PRIVATE:
            return normalized in {"owner", "admin", "member", "user"}

        if self.visibility == WorkflowVisibility.WORKSPACE:
            return normalized in {"owner", "admin", "member", "viewer", "user"}

        if self.visibility == WorkflowVisibility.ADMIN_ONLY:
            return normalized in {"owner", "admin", "super_admin"}

        if self.visibility == WorkflowVisibility.SECURITY_ONLY:
            return normalized in {"owner", "admin", "security", "super_admin"}

        return False

    def check_access(
        self,
        *,
        role: Optional[str],
        subscription_plan: Optional[str] = None,
        require_active_plan: bool = False,
    ) -> Dict[str, Any]:
        if not self.can_be_seen_by_role(role):
            return {
                "decision": WorkflowAccessDecision.DENY.value,
                "reason": "Role cannot access this workflow.",
            }

        if require_active_plan and not subscription_plan:
            return {
                "decision": WorkflowAccessDecision.SUBSCRIPTION_REQUIRED.value,
                "reason": "Active subscription plan is required.",
            }

        if self.needs_security_agent:
            return {
                "decision": WorkflowAccessDecision.SECURITY_REVIEW.value,
                "reason": "Security Agent review is required.",
            }

        return {
            "decision": WorkflowAccessDecision.ALLOW.value,
            "reason": "Access allowed.",
        }

    def to_dashboard_payload(self, *, viewer_role: Optional[str] = None) -> Dict[str, Any]:
        can_view_internal = (viewer_role or "").lower().strip() in {
            "owner",
            "admin",
            "security",
            "developer",
            "super_admin",
        }

        data = {
            "id": self.id,
            "workflow_uid": self.workflow_uid,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "status": self.status.value,
            "visibility": self.visibility.value,
            "trigger_type": self.trigger_type.value,
            "version": self.version,
            "is_template": self.is_template,
            "is_system_workflow": self.is_system_workflow,
            "subscription_plan": self.subscription_plan if can_view_internal else None,
            "requires_security_review": self.requires_security_review,
            "security_reviewed": self.security_reviewed,
            "security_approved": self.security_approved,
            "run_count": self.run_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "definition_hash": self.definition_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
        }

        if can_view_internal:
            data["definition"] = self.sanitize_payload(self.definition)
            data["trigger_config"] = self.sanitize_payload(self.trigger_config)
            data["variables"] = self.sanitize_payload(self.variables)
            data["permissions"] = self.sanitize_payload(self.permissions)
            data["metadata"] = self.sanitize_payload(self.metadata_json)

        return data

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.to_dashboard_payload(viewer_role="admin"),
            "created_by_actor_type": self.created_by_actor_type.value,
            "created_by_actor_id": self.created_by_actor_id,
            "owner_role": self.owner_role,
            "security_reason": self.security_reason,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

    @classmethod
    def query_scope_filters(cls, *, user_id: str, workspace_id: str) -> tuple[Any, Any]:
        return (
            cls.user_id == cls.clean_identifier(user_id, "user_id"),
            cls.workspace_id == cls.clean_identifier(workspace_id, "workspace_id"),
        )


class WorkflowRun(Base, WorkflowMixin):
    """Workflow execution/run model."""

    __tablename__ = "workflow_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    run_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"wfr_{uuid.uuid4().hex}",
        index=True,
    )

    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    status: Mapped[WorkflowRunStatus] = mapped_column(
        SAEnum(WorkflowRunStatus, name="workflow_run_status"),
        nullable=False,
        default=WorkflowRunStatus.QUEUED,
        index=True,
    )

    trigger_type: Mapped[WorkflowTriggerType] = mapped_column(
        SAEnum(WorkflowTriggerType, name="workflow_run_trigger_type"),
        nullable=False,
        default=WorkflowTriggerType.MANUAL,
        index=True,
    )

    actor_type: Mapped[WorkflowActorType] = mapped_column(
        SAEnum(WorkflowActorType, name="workflow_run_actor_type"),
        nullable=False,
        default=WorkflowActorType.USER,
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    subscription_plan: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)

    correlation_id: Mapped[str] = mapped_column(
        String(96),
        nullable=False,
        default=lambda: f"corr_{uuid.uuid4().hex}",
        index=True,
    )
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(160), nullable=True, index=True)

    input_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    output_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    runtime_context: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    memory_context: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    verification_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    progress_current: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    requires_security_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    security_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    verification_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    verification_ready: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    verification_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    error_code: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    failed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )

    workflow: Mapped["Workflow"] = relationship("Workflow", back_populates="runs")

    logs: Mapped[list["WorkflowLog"]] = relationship(
        "WorkflowLog",
        back_populates="run",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    failures: Mapped[list["WorkflowFailure"]] = relationship(
        "WorkflowFailure",
        back_populates="run",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "run_uid", name="uq_workflow_runs_workspace_uid"),
        UniqueConstraint("workspace_id", "idempotency_key", name="uq_workflow_runs_workspace_idempotency"),
        Index("ix_workflow_runs_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_workflow_runs_task", "workspace_id", "user_id", "task_id"),
        Index("ix_workflow_runs_security_queue", "workspace_id", "requires_security_review", "security_reviewed"),
        Index("ix_workflow_runs_verification_queue", "workspace_id", "verification_required", "verification_ready"),
    )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for WorkflowRun isolation.")
        return cleaned

    @classmethod
    def create(
        cls,
        *,
        workflow: Workflow,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        trigger_type: WorkflowTriggerType | str = WorkflowTriggerType.MANUAL,
        actor_type: WorkflowActorType | str = WorkflowActorType.USER,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        input_payload: Optional[Mapping[str, Any]] = None,
        runtime_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> "WorkflowRun":
        workflow.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        run = cls(
            workflow_id=workflow.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            task_id=cls.clean_identifier(task_id, "task_id") if task_id else None,
            trigger_type=cls.coerce_enum(trigger_type, WorkflowTriggerType),
            actor_type=cls.coerce_enum(actor_type, WorkflowActorType),
            actor_id=str(actor_id)[:120] if actor_id else None,
            actor_role=str(actor_role)[:80] if actor_role else None,
            subscription_plan=str(subscription_plan)[:80] if subscription_plan else None,
            input_payload=cls.sanitize_payload(input_payload),
            runtime_context=cls.sanitize_payload(runtime_context),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "workflow_uid": workflow.workflow_uid,
                "workflow_version": workflow.version,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "WorkflowRun",
            },
            idempotency_key=str(idempotency_key)[:160] if idempotency_key else None,
            requires_security_review=workflow.requires_security_review,
            status=WorkflowRunStatus.WAITING_SECURITY
            if workflow.requires_security_review and not workflow.security_approved
            else WorkflowRunStatus.QUEUED,
        )

        run.memory_context = run.prepare_memory_context(workflow=workflow)
        run.audit_payload = run.to_audit_payload(workflow=workflow)
        return run

    @property
    def scope_key(self) -> str:
        return self.build_scope_key(self.user_id, self.workspace_id)

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            WorkflowRunStatus.COMPLETED,
            WorkflowRunStatus.FAILED,
            WorkflowRunStatus.CANCELLED,
            WorkflowRunStatus.REJECTED,
        }

    @property
    def needs_security_agent(self) -> bool:
        return self.requires_security_review and not self.security_reviewed

    @property
    def needs_verification_agent(self) -> bool:
        return self.verification_required and self.verification_ready and bool(self.verification_payload)

    def assert_same_scope(self, *, user_id: str, workspace_id: str) -> None:
        if self.user_id != str(user_id).strip() or self.workspace_id != str(workspace_id).strip():
            raise PermissionError("WorkflowRun access denied for this user/workspace scope.")

    def start(self) -> None:
        if self.needs_security_agent:
            self.status = WorkflowRunStatus.WAITING_SECURITY
            self.updated_at = utc_now()
            raise PermissionError("Workflow run requires Security Agent approval before start.")
        self.status = WorkflowRunStatus.RUNNING
        self.started_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def pause(self) -> None:
        self.status = WorkflowRunStatus.PAUSED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def resume(self) -> None:
        if self.needs_security_agent:
            self.status = WorkflowRunStatus.WAITING_SECURITY
        else:
            self.status = WorkflowRunStatus.RUNNING
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def complete(self, *, output_payload: Optional[Mapping[str, Any]] = None) -> None:
        self.status = WorkflowRunStatus.COMPLETED
        self.output_payload = self.sanitize_payload(output_payload)
        self.progress_current = self.progress_total
        self.progress_percent = 100
        self.completed_at = utc_now()
        self.verification_required = True
        self.verification_ready = True
        self.verification_id = self.verification_id or f"ver_{uuid.uuid4().hex}"
        self.verification_payload = self.prepare_verification_payload()
        self.memory_context = self.prepare_memory_context()
        self.audit_payload = self.to_audit_payload()
        self.updated_at = utc_now()

    def fail(
        self,
        *,
        error_code: str,
        error_message: str,
        output_payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.status = WorkflowRunStatus.FAILED
        self.error_code = str(error_code)[:120]
        self.error_message = str(error_message)
        self.output_payload = self.sanitize_payload(output_payload)
        self.failed_at = utc_now()
        self.audit_payload = self.to_audit_payload()
        self.updated_at = utc_now()

    def cancel(self, *, reason: Optional[str] = None) -> None:
        self.status = WorkflowRunStatus.CANCELLED
        self.cancelled_at = utc_now()
        self.error_message = reason or self.error_message
        self.audit_payload = self.to_audit_payload()
        self.updated_at = utc_now()

    def mark_security_decision(self, *, approved: bool, reason: Optional[str] = None) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.security_reason = reason
        self.status = WorkflowRunStatus.QUEUED if approved else WorkflowRunStatus.REJECTED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def update_progress(self, *, current: int, total: Optional[int] = None) -> None:
        if total is not None:
            self.progress_total = max(int(total), 1)
        self.progress_current = max(int(current), 0)
        self.progress_percent = self.calculate_progress_percent(self.progress_current, self.progress_total)
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def increment_retry(self) -> None:
        self.retry_count += 1
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def prepare_memory_context(self, workflow: Optional[Workflow] = None) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "type": "workflow_run",
                "run_uid": self.run_uid,
                "workflow_id": self.workflow_id,
                "workflow_uid": workflow.workflow_uid if workflow else None,
                "workflow_name": workflow.name if workflow else None,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "status": self.status.value,
                "trigger_type": self.trigger_type.value,
                "input_summary": self.input_payload,
                "output_summary": self.output_payload,
                "progress_percent": self.progress_percent,
                "scope_key": self.scope_key,
                "correlation_id": self.correlation_id,
                "updated_at": self.updated_at,
            }
        )

    def prepare_verification_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "verification_id": self.verification_id or f"ver_{uuid.uuid4().hex}",
                "type": "workflow_run",
                "run_uid": self.run_uid,
                "workflow_id": self.workflow_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "status": self.status.value,
                "output_hash": self.compute_hash(self.output_payload),
                "audit_payload": self.audit_payload,
                "completed_at": self.completed_at,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
            }
        )

    def to_audit_payload(self, workflow: Optional[Workflow] = None) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "run_uid": self.run_uid,
                "workflow_id": self.workflow_id,
                "workflow_uid": workflow.workflow_uid if workflow else None,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "status": self.status.value,
                "trigger_type": self.trigger_type.value,
                "actor_type": self.actor_type.value,
                "actor_id": self.actor_id,
                "actor_role": self.actor_role,
                "subscription_plan": self.subscription_plan,
                "correlation_id": self.correlation_id,
                "idempotency_key": self.idempotency_key,
                "progress_percent": self.progress_percent,
                "requires_security_review": self.requires_security_review,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "security_reason": self.security_reason,
                "verification_required": self.verification_required,
                "verification_ready": self.verification_ready,
                "verification_id": self.verification_id,
                "error_code": self.error_code,
                "error_message": self.error_message,
                "retry_count": self.retry_count,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "failed_at": self.failed_at,
                "cancelled_at": self.cancelled_at,
            }
        )

    def to_dashboard_payload(self, *, viewer_role: Optional[str] = None) -> Dict[str, Any]:
        can_view_internal = (viewer_role or "").lower().strip() in {
            "owner",
            "admin",
            "security",
            "developer",
            "super_admin",
        }

        data = {
            "id": self.id,
            "run_uid": self.run_uid,
            "workflow_id": self.workflow_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "trigger_type": self.trigger_type.value,
            "correlation_id": self.correlation_id,
            "progress": {
                "current": self.progress_current,
                "total": self.progress_total,
                "percent": self.progress_percent,
            },
            "security": {
                "requires_review": self.requires_security_review,
                "reviewed": self.security_reviewed,
                "approved": self.security_approved,
                "reason": self.security_reason if can_view_internal else None,
            },
            "verification": {
                "required": self.verification_required,
                "ready": self.verification_ready,
                "verification_id": self.verification_id,
            },
            "error": {
                "code": self.error_code,
                "message": self.error_message,
            },
            "retry_count": self.retry_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "failed_at": self.failed_at.isoformat() if self.failed_at else None,
        }

        if can_view_internal:
            data["input_payload"] = self.sanitize_payload(self.input_payload)
            data["output_payload"] = self.sanitize_payload(self.output_payload)
            data["runtime_context"] = self.sanitize_payload(self.runtime_context)
            data["metadata"] = self.sanitize_payload(self.metadata_json)

        return data

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.to_dashboard_payload(viewer_role="admin"),
            "actor_type": self.actor_type.value,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "subscription_plan": self.subscription_plan,
            "memory_context": self.sanitize_payload(self.memory_context),
            "verification_payload": self.sanitize_payload(self.verification_payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
        }


class WorkflowNode(Base, WorkflowMixin):
    """Workflow node definition and execution metadata."""

    __tablename__ = "workflow_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    node_uid: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        default=lambda: f"wfn_{uuid.uuid4().hex}",
        index=True,
    )

    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    node_type: Mapped[WorkflowNodeType] = mapped_column(
        SAEnum(WorkflowNodeType, name="workflow_node_type"),
        nullable=False,
        default=WorkflowNodeType.AGENT,
        index=True,
    )
    status: Mapped[WorkflowNodeStatus] = mapped_column(
        SAEnum(WorkflowNodeStatus, name="workflow_node_status"),
        nullable=False,
        default=WorkflowNodeStatus.PENDING,
        index=True,
    )

    position_x: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    position_y: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    agent_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    agent_type: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    action: Mapped[Optional[str]] = mapped_column(String(160), nullable=True, index=True)

    config: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    input_schema: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    output_schema: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    dependencies: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    conditions: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    requires_security_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    security_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    verification_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    verification_ready: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    retry_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )

    workflow: Mapped["Workflow"] = relationship("Workflow", back_populates="nodes")

    logs: Mapped[list["WorkflowLog"]] = relationship(
        "WorkflowLog",
        back_populates="node",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    failures: Mapped[list["WorkflowFailure"]] = relationship(
        "WorkflowFailure",
        back_populates="node",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "workflow_id", "node_uid", name="uq_workflow_nodes_workflow_uid"),
        Index("ix_workflow_nodes_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_workflow_nodes_agent", "workspace_id", "agent_name", "agent_type"),
        Index("ix_workflow_nodes_security_queue", "workspace_id", "requires_security_review", "security_reviewed"),
    )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for WorkflowNode isolation.")
        return cleaned

    @validates("name")
    def validate_name(self, key: str, value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("Workflow node name is required.")
        return cleaned[:180]

    @classmethod
    def create(
        cls,
        *,
        workflow: Workflow,
        user_id: str,
        workspace_id: str,
        name: str,
        node_type: WorkflowNodeType | str,
        agent_name: Optional[str] = None,
        agent_type: Optional[str] = None,
        action: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        input_schema: Optional[Mapping[str, Any]] = None,
        output_schema: Optional[Mapping[str, Any]] = None,
        dependencies: Optional[Mapping[str, Any]] = None,
        conditions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        sort_order: int = 0,
        position_x: int = 0,
        position_y: int = 0,
        retry_limit: int = 0,
        timeout_seconds: int = 300,
        requires_security_review: bool = False,
        verification_required: bool = False,
    ) -> "WorkflowNode":
        workflow.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        node = cls(
            workflow_id=workflow.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            name=name,
            node_type=cls.coerce_enum(node_type, WorkflowNodeType),
            agent_name=str(agent_name)[:120] if agent_name else None,
            agent_type=str(agent_type)[:80] if agent_type else None,
            action=str(action)[:160] if action else None,
            config=cls.sanitize_payload(config),
            input_schema=cls.sanitize_payload(input_schema),
            output_schema=cls.sanitize_payload(output_schema),
            dependencies=cls.sanitize_payload(dependencies),
            conditions=cls.sanitize_payload(conditions),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "workflow_uid": workflow.workflow_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "WorkflowNode",
            },
            sort_order=max(int(sort_order or 0), 0),
            position_x=int(position_x or 0),
            position_y=int(position_y or 0),
            retry_limit=max(int(retry_limit or 0), 0),
            timeout_seconds=max(int(timeout_seconds or 300), 1),
            requires_security_review=bool(requires_security_review),
            verification_required=bool(verification_required),
        )
        return node

    @property
    def scope_key(self) -> str:
        return self.build_scope_key(self.user_id, self.workspace_id)

    @property
    def needs_security_agent(self) -> bool:
        return self.requires_security_review and not self.security_reviewed

    def mark_security_decision(self, *, approved: bool, reason: Optional[str] = None) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.security_reason = reason
        self.status = WorkflowNodeStatus.PENDING if approved else WorkflowNodeStatus.REJECTED
        self.updated_at = utc_now()

    def start(self) -> None:
        if self.needs_security_agent:
            self.status = WorkflowNodeStatus.WAITING_SECURITY
            self.updated_at = utc_now()
            raise PermissionError("Workflow node requires Security Agent approval before start.")
        self.status = WorkflowNodeStatus.RUNNING
        self.updated_at = utc_now()

    def complete(self) -> None:
        self.status = WorkflowNodeStatus.COMPLETED
        self.verification_ready = self.verification_required
        self.updated_at = utc_now()

    def fail(self) -> None:
        self.status = WorkflowNodeStatus.FAILED
        self.updated_at = utc_now()

    def skip(self) -> None:
        self.status = WorkflowNodeStatus.SKIPPED
        self.updated_at = utc_now()

    def cancel(self) -> None:
        self.status = WorkflowNodeStatus.CANCELLED
        self.updated_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "node_uid": self.node_uid,
            "workflow_id": self.workflow_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "name": self.name,
            "node_type": self.node_type.value,
            "status": self.status.value,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "action": self.action,
            "position": {
                "x": self.position_x,
                "y": self.position_y,
            },
            "sort_order": self.sort_order,
            "config": self.sanitize_payload(self.config),
            "input_schema": self.sanitize_payload(self.input_schema),
            "output_schema": self.sanitize_payload(self.output_schema),
            "dependencies": self.sanitize_payload(self.dependencies),
            "conditions": self.sanitize_payload(self.conditions),
            "metadata": self.sanitize_payload(self.metadata_json),
            "requires_security_review": self.requires_security_review,
            "security_reviewed": self.security_reviewed,
            "security_approved": self.security_approved,
            "security_reason": self.security_reason,
            "verification_required": self.verification_required,
            "verification_ready": self.verification_ready,
            "retry_limit": self.retry_limit,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class WorkflowLog(Base, WorkflowMixin):
    """Audit-friendly workflow log record."""

    __tablename__ = "workflow_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    log_uid: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        default=lambda: f"wfl_{uuid.uuid4().hex}",
        index=True,
    )

    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("workflow_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    node_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("workflow_nodes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    level: Mapped[WorkflowLogLevel] = mapped_column(
        SAEnum(WorkflowLogLevel, name="workflow_log_level"),
        nullable=False,
        default=WorkflowLogLevel.INFO,
        index=True,
    )

    event_name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    actor_type: Mapped[WorkflowActorType] = mapped_column(
        SAEnum(WorkflowActorType, name="workflow_log_actor_type"),
        nullable=False,
        default=WorkflowActorType.SYSTEM,
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    agent_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    action: Mapped[Optional[str]] = mapped_column(String(160), nullable=True, index=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(96), nullable=True, index=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    workflow: Mapped["Workflow"] = relationship("Workflow", back_populates="logs")
    run: Mapped[Optional["WorkflowRun"]] = relationship("WorkflowRun", back_populates="logs")
    node: Mapped[Optional["WorkflowNode"]] = relationship("WorkflowNode", back_populates="logs")

    __table_args__ = (
        Index("ix_workflow_logs_scope_time", "workspace_id", "user_id", "created_at"),
        Index("ix_workflow_logs_workflow_time", "workspace_id", "workflow_id", "created_at"),
        Index("ix_workflow_logs_run_time", "workspace_id", "run_id", "created_at"),
        Index("ix_workflow_logs_level_time", "workspace_id", "level", "created_at"),
    )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for WorkflowLog isolation.")
        return cleaned

    @classmethod
    def create(
        cls,
        *,
        workflow_id: str,
        user_id: str,
        workspace_id: str,
        event_name: str,
        message: str,
        level: WorkflowLogLevel | str = WorkflowLogLevel.INFO,
        run_id: Optional[str] = None,
        node_id: Optional[str] = None,
        actor_type: WorkflowActorType | str = WorkflowActorType.SYSTEM,
        actor_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        correlation_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "WorkflowLog":
        safe_payload = cls.sanitize_payload(payload)
        safe_metadata = cls.sanitize_payload(metadata)

        log = cls(
            workflow_id=workflow_id,
            run_id=run_id,
            node_id=node_id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            level=cls.coerce_enum(level, WorkflowLogLevel),
            event_name=str(event_name)[:160],
            message=str(message),
            actor_type=cls.coerce_enum(actor_type, WorkflowActorType),
            actor_id=str(actor_id)[:120] if actor_id else None,
            agent_name=str(agent_name)[:120] if agent_name else None,
            action=str(action)[:160] if action else None,
            correlation_id=str(correlation_id)[:96] if correlation_id else None,
            payload=safe_payload,
            metadata_json={
                **safe_metadata,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "WorkflowLog",
            },
        )
        log.audit_payload = log.to_audit_payload()
        return log

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "log_uid": self.log_uid,
                "workflow_id": self.workflow_id,
                "run_id": self.run_id,
                "node_id": self.node_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "level": self.level.value,
                "event_name": self.event_name,
                "message": self.message,
                "actor_type": self.actor_type.value,
                "actor_id": self.actor_id,
                "agent_name": self.agent_name,
                "action": self.action,
                "correlation_id": self.correlation_id,
                "payload_hash": self.compute_hash(self.payload),
                "created_at": self.created_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "log_uid": self.log_uid,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "node_id": self.node_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "level": self.level.value,
            "event_name": self.event_name,
            "message": self.message,
            "actor_type": self.actor_type.value,
            "actor_id": self.actor_id,
            "agent_name": self.agent_name,
            "action": self.action,
            "correlation_id": self.correlation_id,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WorkflowFailure(Base, WorkflowMixin):
    """Structured failure record for workflow runs and nodes."""

    __tablename__ = "workflow_failures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    failure_uid: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        default=lambda: f"wff_{uuid.uuid4().hex}",
        index=True,
    )

    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("workflow_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    node_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("workflow_nodes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    failure_type: Mapped[WorkflowFailureType] = mapped_column(
        SAEnum(WorkflowFailureType, name="workflow_failure_type"),
        nullable=False,
        default=WorkflowFailureType.UNKNOWN,
        index=True,
    )

    error_code: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    safe_user_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    agent_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    action: Mapped[Optional[str]] = mapped_column(String(160), nullable=True, index=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(96), nullable=True, index=True)

    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    resolved_by_actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    resolution_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    workflow: Mapped["Workflow"] = relationship("Workflow", back_populates="failures")
    run: Mapped[Optional["WorkflowRun"]] = relationship("WorkflowRun", back_populates="failures")
    node: Mapped[Optional["WorkflowNode"]] = relationship("WorkflowNode", back_populates="failures")

    __table_args__ = (
        Index("ix_workflow_failures_scope_time", "workspace_id", "user_id", "created_at"),
        Index("ix_workflow_failures_workflow_time", "workspace_id", "workflow_id", "created_at"),
        Index("ix_workflow_failures_run_time", "workspace_id", "run_id", "created_at"),
        Index("ix_workflow_failures_type_time", "workspace_id", "failure_type", "created_at"),
    )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for WorkflowFailure isolation.")
        return cleaned

    @classmethod
    def create(
        cls,
        *,
        workflow_id: str,
        user_id: str,
        workspace_id: str,
        error_code: str,
        error_message: str,
        failure_type: WorkflowFailureType | str = WorkflowFailureType.UNKNOWN,
        run_id: Optional[str] = None,
        node_id: Optional[str] = None,
        safe_user_message: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        correlation_id: Optional[str] = None,
        retryable: bool = False,
        retry_count: int = 0,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "WorkflowFailure":
        failure = cls(
            workflow_id=workflow_id,
            run_id=run_id,
            node_id=node_id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            failure_type=cls.coerce_enum(failure_type, WorkflowFailureType),
            error_code=str(error_code)[:120],
            error_message=str(error_message),
            safe_user_message=safe_user_message,
            agent_name=str(agent_name)[:120] if agent_name else None,
            action=str(action)[:160] if action else None,
            correlation_id=str(correlation_id)[:96] if correlation_id else None,
            retryable=bool(retryable),
            retry_count=max(int(retry_count or 0), 0),
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "WorkflowFailure",
            },
        )
        failure.audit_payload = failure.to_audit_payload()
        return failure

    @property
    def is_resolved(self) -> bool:
        return self.resolved_at is not None

    def mark_resolved(self, *, actor_id: Optional[str] = None, note: Optional[str] = None) -> None:
        self.resolved_at = utc_now()
        self.resolved_by_actor_id = str(actor_id)[:120] if actor_id else None
        self.resolution_note = note
        self.audit_payload = self.to_audit_payload()

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "failure_uid": self.failure_uid,
                "workflow_id": self.workflow_id,
                "run_id": self.run_id,
                "node_id": self.node_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "failure_type": self.failure_type.value,
                "error_code": self.error_code,
                "error_message": self.error_message,
                "safe_user_message": self.safe_user_message,
                "agent_name": self.agent_name,
                "action": self.action,
                "correlation_id": self.correlation_id,
                "retryable": self.retryable,
                "retry_count": self.retry_count,
                "payload_hash": self.compute_hash(self.payload),
                "created_at": self.created_at,
                "resolved_at": self.resolved_at,
                "resolved_by_actor_id": self.resolved_by_actor_id,
                "resolution_note": self.resolution_note,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "failure_uid": self.failure_uid,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "node_id": self.node_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "failure_type": self.failure_type.value,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "safe_user_message": self.safe_user_message,
            "agent_name": self.agent_name,
            "action": self.action,
            "correlation_id": self.correlation_id,
            "retryable": self.retryable,
            "retry_count": self.retry_count,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by_actor_id": self.resolved_by_actor_id,
            "resolution_note": self.resolution_note,
        }


def summarize_workflow_runs(runs: Iterable[WorkflowRun]) -> Dict[str, Any]:
    """
    Build a dashboard-friendly summary from workflow runs.
    """
    total = 0
    by_status: Dict[str, int] = {}
    security_pending = 0
    verification_ready = 0
    failed = 0
    completed = 0

    for run in runs:
        total += 1
        by_status[run.status.value] = by_status.get(run.status.value, 0) + 1
        if run.needs_security_agent:
            security_pending += 1
        if run.needs_verification_agent:
            verification_ready += 1
        if run.status == WorkflowRunStatus.FAILED:
            failed += 1
        if run.status == WorkflowRunStatus.COMPLETED:
            completed += 1

    success_rate = round((completed / total) * 100, 2) if total else 0.0

    return {
        "total": total,
        "by_status": by_status,
        "security_pending": security_pending,
        "verification_ready": verification_ready,
        "failed": failed,
        "completed": completed,
        "success_rate": success_rate,
    }


__all__ = [
    "Workflow",
    "WorkflowRun",
    "WorkflowNode",
    "WorkflowLog",
    "WorkflowFailure",
    "WorkflowStatus",
    "WorkflowRunStatus",
    "WorkflowNodeStatus",
    "WorkflowNodeType",
    "WorkflowTriggerType",
    "WorkflowLogLevel",
    "WorkflowVisibility",
    "WorkflowFailureType",
    "WorkflowActorType",
    "WorkflowAccessDecision",
    "summarize_workflow_runs",
]