"""
database/models/agent_event.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Event stream records and audit-friendly payloads for all agent/task/system events.

This model is designed for:
    - SaaS user/workspace isolation
    - Master Agent orchestration visibility
    - Security Agent approval workflows
    - Verification Agent confirmation payloads
    - Memory Agent compatible context snapshots
    - Audit-friendly structured event records
    - Dashboard analytics and event-stream consumption

The file intentionally avoids importing future project modules directly so it can import safely
even when other files are not created yet.
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
from sqlalchemy.orm import Mapped, mapped_column, validates

try:
    from sqlalchemy.dialects.postgresql import JSONB
except Exception:  # pragma: no cover - only used when PostgreSQL dialect is unavailable
    JSONB = None

try:
    from sqlalchemy import JSON
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "SQLAlchemy JSON support is required for database/models/agent_event.py"
    ) from exc

try:
    from database.db import Base
except Exception:  # pragma: no cover
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):
        """Fallback SQLAlchemy base so this model can import before project base exists."""


JsonColumn = JSONB if JSONB is not None and os.getenv("WILLIAM_DB_DIALECT", "").lower() == "postgresql" else JSON


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a stable string UUID for cross-service compatibility."""
    return str(uuid.uuid4())


class AgentEventType(str, Enum):
    """High-level event categories used by the event stream."""

    SYSTEM = "system"
    TASK = "task"
    SUBTASK = "subtask"
    AGENT = "agent"
    MASTER_AGENT = "master_agent"
    SECURITY = "security"
    VERIFICATION = "verification"
    MEMORY = "memory"
    WORKFLOW = "workflow"
    TOOL = "tool"
    FILE = "file"
    BILLING = "billing"
    DASHBOARD = "dashboard"
    ERROR = "error"
    AUDIT = "audit"


class AgentEventName(str, Enum):
    """Common event names used across William/Jarvis agents."""

    CREATED = "created"
    QUEUED = "queued"
    STARTED = "started"
    PROGRESS = "progress"
    MESSAGE = "message"
    TOOL_CALLED = "tool_called"
    TOOL_RESULT = "tool_result"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    SECURITY_APPROVED = "security_approved"
    SECURITY_REJECTED = "security_rejected"
    MEMORY_CONTEXT_PREPARED = "memory_context_prepared"
    VERIFICATION_PREPARED = "verification_prepared"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRIED = "retried"
    HEARTBEAT = "heartbeat"
    AUDIT_RECORDED = "audit_recorded"


class AgentEventStatus(str, Enum):
    """Lifecycle status for streamable event records."""

    NEW = "new"
    ACCEPTED = "accepted"
    PROCESSING = "processing"
    WAITING_SECURITY = "waiting_security"
    WAITING_VERIFICATION = "waiting_verification"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class AgentEventSeverity(str, Enum):
    """Severity level for dashboard filtering and audit triage."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AgentActorType(str, Enum):
    """Actor type responsible for creating the event."""

    USER = "user"
    AGENT = "agent"
    MASTER_AGENT = "master_agent"
    SECURITY_AGENT = "security_agent"
    VERIFICATION_AGENT = "verification_agent"
    MEMORY_AGENT = "memory_agent"
    SYSTEM = "system"
    WORKER = "worker"
    API = "api"


class AgentEventVisibility(str, Enum):
    """Visibility scope used by dashboards and APIs."""

    INTERNAL = "internal"
    USER_VISIBLE = "user_visible"
    ADMIN_VISIBLE = "admin_visible"
    SECURITY_ONLY = "security_only"


class AgentEventDeliveryStatus(str, Enum):
    """Delivery state for stream/websocket/event-bus consumers."""

    NOT_DISPATCHED = "not_dispatched"
    DISPATCHED = "dispatched"
    ACKNOWLEDGED = "acknowledged"
    DELIVERY_FAILED = "delivery_failed"


class AgentEvent(Base):
    """
    Event stream and audit-friendly payload model.

    Every event that touches user data, tasks, files, memory, logs, analytics,
    billing, agent permissions, or workspace execution must include both:
        - user_id
        - workspace_id

    This model does not perform direct role/plan checks because it is a database
    record, not an API endpoint. It stores role/plan context and provides
    helper methods so API/services can enforce permissions before exposing data.
    """

    __tablename__ = "agent_events"

    SECRET_REDACTION: ClassVar[str] = "[REDACTED]"
    DEFAULT_PAYLOAD_LIMIT: ClassVar[int] = 64_000

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
        }
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
        nullable=False,
    )

    event_uid: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"evt_{uuid.uuid4().hex}",
        index=True,
    )

    user_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Owner user ID. Required for SaaS isolation.",
    )

    workspace_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Owner workspace ID. Required for SaaS isolation.",
    )

    task_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Related task ID when the event belongs to a user task.",
    )

    subtask_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    parent_event_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("agent_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    correlation_id: Mapped[str] = mapped_column(
        String(96),
        nullable=False,
        default=lambda: f"corr_{uuid.uuid4().hex}",
        index=True,
        doc="Trace ID shared across related events.",
    )

    causation_id: Mapped[Optional[str]] = mapped_column(
        String(96),
        nullable=True,
        index=True,
        doc="ID of the command/event that caused this event.",
    )

    event_type: Mapped[AgentEventType] = mapped_column(
        SAEnum(AgentEventType, name="agent_event_type"),
        nullable=False,
        default=AgentEventType.AGENT,
        index=True,
    )

    event_name: Mapped[AgentEventName] = mapped_column(
        SAEnum(AgentEventName, name="agent_event_name"),
        nullable=False,
        default=AgentEventName.CREATED,
        index=True,
    )

    status: Mapped[AgentEventStatus] = mapped_column(
        SAEnum(AgentEventStatus, name="agent_event_status"),
        nullable=False,
        default=AgentEventStatus.NEW,
        index=True,
    )

    severity: Mapped[AgentEventSeverity] = mapped_column(
        SAEnum(AgentEventSeverity, name="agent_event_severity"),
        nullable=False,
        default=AgentEventSeverity.INFO,
        index=True,
    )

    visibility: Mapped[AgentEventVisibility] = mapped_column(
        SAEnum(AgentEventVisibility, name="agent_event_visibility"),
        nullable=False,
        default=AgentEventVisibility.INTERNAL,
        index=True,
    )

    delivery_status: Mapped[AgentEventDeliveryStatus] = mapped_column(
        SAEnum(AgentEventDeliveryStatus, name="agent_event_delivery_status"),
        nullable=False,
        default=AgentEventDeliveryStatus.NOT_DISPATCHED,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="william.database",
        index=True,
        doc="Service/module/worker that emitted the event.",
    )

    agent_name: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
        doc="Specific agent name, e.g. Master Agent, Security Agent, Memory Agent.",
    )

    agent_type: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
        index=True,
        doc="Agent category or registry key.",
    )

    actor_type: Mapped[AgentActorType] = mapped_column(
        SAEnum(AgentActorType, name="agent_actor_type"),
        nullable=False,
        default=AgentActorType.SYSTEM,
        index=True,
    )

    actor_id: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
        doc="User/agent/worker/API actor ID.",
    )

    actor_role: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
        index=True,
        doc="Role context at time of event, e.g. owner/admin/member/agent.",
    )

    subscription_plan: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
        index=True,
        doc="Plan context at time of event for API/dashboard enforcement.",
    )

    action: Mapped[Optional[str]] = mapped_column(
        String(160),
        nullable=True,
        index=True,
        doc="Action being performed, e.g. run_task, open_browser, send_email.",
    )

    resource_type: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
    )

    resource_id: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
    )

    title: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    payload: Mapped[Dict[str, Any]] = mapped_column(
        JsonColumn,
        nullable=False,
        default=dict,
        doc="Sanitized structured event payload.",
    )

    audit_payload: Mapped[Dict[str, Any]] = mapped_column(
        JsonColumn,
        nullable=False,
        default=dict,
        doc="Audit-friendly payload with redacted secrets and stable identifiers.",
    )

    memory_context: Mapped[Dict[str, Any]] = mapped_column(
        JsonColumn,
        nullable=False,
        default=dict,
        doc="Memory Agent compatible context snapshot.",
    )

    verification_payload: Mapped[Dict[str, Any]] = mapped_column(
        JsonColumn,
        nullable=False,
        default=dict,
        doc="Verification Agent compatible completion/confirmation payload.",
    )

    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JsonColumn,
        nullable=False,
        default=dict,
        doc="Non-sensitive metadata for dashboards, routing, and analytics.",
    )

    progress_current: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    progress_total: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
    )

    progress_percent: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
    )

    requires_security_review: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    security_reviewed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    security_approved: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        index=True,
    )

    security_approval_id: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
    )

    security_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    verification_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    verification_ready: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    verification_id: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
    )

    error_code: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    payload_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )

    dispatched_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    archived_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_agent_events_workspace_user_time",
            "workspace_id",
            "user_id",
            "occurred_at",
        ),
        Index(
            "ix_agent_events_task_stream",
            "workspace_id",
            "user_id",
            "task_id",
            "occurred_at",
        ),
        Index(
            "ix_agent_events_agent_stream",
            "workspace_id",
            "user_id",
            "agent_name",
            "occurred_at",
        ),
        Index(
            "ix_agent_events_security_queue",
            "workspace_id",
            "requires_security_review",
            "security_reviewed",
            "occurred_at",
        ),
        Index(
            "ix_agent_events_verification_queue",
            "workspace_id",
            "verification_required",
            "verification_ready",
            "occurred_at",
        ),
        UniqueConstraint(
            "workspace_id",
            "event_uid",
            name="uq_agent_events_workspace_event_uid",
        ),
    )

    def __repr__(self) -> str:
        return (
            "AgentEvent("
            f"id={self.id!r}, "
            f"event_uid={self.event_uid!r}, "
            f"user_id={self.user_id!r}, "
            f"workspace_id={self.workspace_id!r}, "
            f"event_type={self.event_type.value!r}, "
            f"event_name={self.event_name.value!r}, "
            f"status={self.status.value!r}"
            ")"
        )

    @validates("user_id", "workspace_id")
    def validate_required_scope(self, key: str, value: str) -> str:
        cleaned = self._clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for AgentEvent isolation.")
        return cleaned

    @validates("progress_current", "progress_total", "progress_percent", "retry_count")
    def validate_non_negative_integer(self, key: str, value: int) -> int:
        if value is None:
            return 0
        integer_value = int(value)
        if integer_value < 0:
            raise ValueError(f"{key} cannot be negative.")
        if key == "progress_percent" and integer_value > 100:
            return 100
        return integer_value

    @staticmethod
    def _clean_identifier(value: Any, field_name: str = "identifier") -> str:
        if value is None:
            return ""
        cleaned = str(value).strip()
        if len(cleaned) > 128:
            raise ValueError(f"{field_name} is too long.")
        return cleaned

    @classmethod
    def _enum_value(cls, value: Any) -> Any:
        return value.value if isinstance(value, Enum) else value

    @classmethod
    def _safe_json_value(cls, value: Any, depth: int = 0) -> Any:
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
                    safe_dict[key] = cls._safe_json_value(raw_value, depth + 1)
            return safe_dict

        if isinstance(value, (list, tuple, set, frozenset)):
            return [cls._safe_json_value(item, depth + 1) for item in value]

        return str(value)

    @classmethod
    def sanitize_payload(cls, payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Return a JSON-safe payload with secrets redacted."""
        if not payload:
            return {}

        safe_payload = cls._safe_json_value(dict(payload))
        serialized = json.dumps(safe_payload, sort_keys=True, default=str)

        max_size = int(os.getenv("WILLIAM_AGENT_EVENT_PAYLOAD_LIMIT", cls.DEFAULT_PAYLOAD_LIMIT))
        if len(serialized.encode("utf-8")) > max_size:
            return {
                "payload_truncated": True,
                "payload_size_bytes": len(serialized.encode("utf-8")),
                "payload_preview": serialized[: max_size // 2],
            }

        return safe_payload

    @classmethod
    def compute_payload_hash(cls, payload: Optional[Mapping[str, Any]]) -> str:
        safe_payload = cls.sanitize_payload(payload)
        serialized = json.dumps(safe_payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def build_scope_key(cls, user_id: str, workspace_id: str) -> str:
        safe_user_id = cls._clean_identifier(user_id, "user_id")
        safe_workspace_id = cls._clean_identifier(workspace_id, "workspace_id")
        if not safe_user_id or not safe_workspace_id:
            raise ValueError("Both user_id and workspace_id are required to build scope key.")
        return f"{safe_workspace_id}:{safe_user_id}"

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        event_type: AgentEventType | str = AgentEventType.AGENT,
        event_name: AgentEventName | str = AgentEventName.CREATED,
        status: AgentEventStatus | str = AgentEventStatus.NEW,
        severity: AgentEventSeverity | str = AgentEventSeverity.INFO,
        visibility: AgentEventVisibility | str = AgentEventVisibility.INTERNAL,
        source: str = "william.database",
        task_id: Optional[str] = None,
        subtask_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_type: Optional[str] = None,
        actor_type: AgentActorType | str = AgentActorType.SYSTEM,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        title: Optional[str] = None,
        message: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        progress_current: int = 0,
        progress_total: int = 100,
        requires_security_review: bool = False,
        verification_required: bool = False,
        occurred_at: Optional[datetime] = None,
    ) -> "AgentEvent":
        """
        Factory for a sanitized and audit-ready event.

        Services should create events through this method where possible so payload
        redaction, hashes, scope metadata, and progress normalization are consistent.
        """
        safe_payload = cls.sanitize_payload(payload)
        safe_metadata = cls.sanitize_payload(metadata)
        progress_percent = cls.calculate_progress_percent(progress_current, progress_total)

        event = cls(
            user_id=cls._clean_identifier(user_id, "user_id"),
            workspace_id=cls._clean_identifier(workspace_id, "workspace_id"),
            task_id=cls._clean_identifier(task_id, "task_id") if task_id else None,
            subtask_id=cls._clean_identifier(subtask_id, "subtask_id") if subtask_id else None,
            parent_event_id=parent_event_id,
            correlation_id=correlation_id or f"corr_{uuid.uuid4().hex}",
            causation_id=causation_id,
            event_type=cls._coerce_enum(event_type, AgentEventType),
            event_name=cls._coerce_enum(event_name, AgentEventName),
            status=cls._coerce_enum(status, AgentEventStatus),
            severity=cls._coerce_enum(severity, AgentEventSeverity),
            visibility=cls._coerce_enum(visibility, AgentEventVisibility),
            source=str(source or "william.database")[:120],
            agent_name=str(agent_name)[:120] if agent_name else None,
            agent_type=str(agent_type)[:80] if agent_type else None,
            actor_type=cls._coerce_enum(actor_type, AgentActorType),
            actor_id=str(actor_id)[:120] if actor_id else None,
            actor_role=str(actor_role)[:80] if actor_role else None,
            subscription_plan=str(subscription_plan)[:80] if subscription_plan else None,
            action=str(action)[:160] if action else None,
            resource_type=str(resource_type)[:120] if resource_type else None,
            resource_id=str(resource_id)[:120] if resource_id else None,
            title=str(title)[:255] if title else None,
            message=str(message) if message else None,
            payload=safe_payload,
            metadata_json={
                **safe_metadata,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "created_by_model": "AgentEvent",
                "schema_version": "1.0",
            },
            progress_current=int(progress_current or 0),
            progress_total=max(int(progress_total or 100), 1),
            progress_percent=progress_percent,
            requires_security_review=bool(requires_security_review),
            verification_required=bool(verification_required),
            occurred_at=occurred_at or utc_now(),
        )

        event.payload_hash = cls.compute_payload_hash(
            {
                "payload": event.payload,
                "metadata": event.metadata_json,
                "event_type": event.event_type.value,
                "event_name": event.event_name.value,
                "workspace_id": event.workspace_id,
                "user_id": event.user_id,
                "task_id": event.task_id,
            }
        )
        event.audit_payload = event.to_audit_payload()
        event.memory_context = event.prepare_memory_context()
        if event.verification_required:
            event.verification_payload = event.prepare_verification_payload()
        return event

    @staticmethod
    def _coerce_enum(value: Any, enum_cls: type[Enum]) -> Enum:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            normalized = value.strip()
            for item in enum_cls:
                if item.value == normalized or item.name.lower() == normalized.lower():
                    return item
        raise ValueError(f"Invalid {enum_cls.__name__}: {value!r}")

    @staticmethod
    def calculate_progress_percent(current: int, total: int) -> int:
        safe_total = max(int(total or 100), 1)
        safe_current = max(int(current or 0), 0)
        return min(int(round((safe_current / safe_total) * 100)), 100)

    @classmethod
    def task_event(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        event_name: AgentEventName | str,
        status: AgentEventStatus | str,
        title: Optional[str] = None,
        message: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        correlation_id: Optional[str] = None,
        progress_current: int = 0,
        progress_total: int = 100,
    ) -> "AgentEvent":
        """Create a task-scoped event with isolation and audit payloads."""
        return cls.create(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            event_type=AgentEventType.TASK,
            event_name=event_name,
            status=status,
            title=title,
            message=message,
            payload=payload,
            actor_type=AgentActorType.USER if actor_id else AgentActorType.SYSTEM,
            actor_id=actor_id,
            actor_role=actor_role,
            subscription_plan=subscription_plan,
            correlation_id=correlation_id,
            progress_current=progress_current,
            progress_total=progress_total,
            verification_required=cls._coerce_enum(status, AgentEventStatus) == AgentEventStatus.COMPLETED,
        )

    @classmethod
    def agent_event(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        agent_name: str,
        agent_type: Optional[str],
        task_id: Optional[str],
        event_name: AgentEventName | str,
        status: AgentEventStatus | str = AgentEventStatus.PROCESSING,
        message: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
        action: Optional[str] = None,
        requires_security_review: bool = False,
    ) -> "AgentEvent":
        """Create an agent-scoped event for Master Agent dashboards and traces."""
        return cls.create(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            event_type=AgentEventType.AGENT,
            event_name=event_name,
            status=status,
            severity=AgentEventSeverity.NOTICE if requires_security_review else AgentEventSeverity.INFO,
            agent_name=agent_name,
            agent_type=agent_type,
            actor_type=AgentActorType.AGENT,
            actor_id=agent_name,
            message=message,
            payload=payload,
            correlation_id=correlation_id,
            action=action,
            requires_security_review=requires_security_review,
            verification_required=cls._coerce_enum(status, AgentEventStatus) == AgentEventStatus.COMPLETED,
        )

    @classmethod
    def security_review_required_event(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        agent_name: Optional[str],
        action: str,
        reason: str,
        payload: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> "AgentEvent":
        """Create a Security Agent review event for sensitive actions."""
        event = cls.create(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            event_type=AgentEventType.SECURITY,
            event_name=AgentEventName.SECURITY_REVIEW_REQUIRED,
            status=AgentEventStatus.WAITING_SECURITY,
            severity=AgentEventSeverity.WARNING,
            visibility=AgentEventVisibility.SECURITY_ONLY,
            source="william.security_router",
            agent_name=agent_name,
            actor_type=AgentActorType.SECURITY_AGENT,
            actor_id="security_agent",
            action=action,
            title="Security Review Required",
            message=reason,
            payload=payload,
            correlation_id=correlation_id,
            requires_security_review=True,
            verification_required=False,
        )
        event.security_reason = reason
        event.audit_payload = event.to_audit_payload()
        return event

    @classmethod
    def failed_event(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        error_code: str,
        error_message: str,
        payload: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
        agent_name: Optional[str] = None,
    ) -> "AgentEvent":
        """Create a safe failure event without leaking sensitive payload data."""
        event = cls.create(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            event_type=AgentEventType.ERROR,
            event_name=AgentEventName.FAILED,
            status=AgentEventStatus.FAILED,
            severity=AgentEventSeverity.ERROR,
            agent_name=agent_name,
            actor_type=AgentActorType.SYSTEM,
            title="Agent Event Failed",
            message=error_message,
            payload=payload,
            correlation_id=correlation_id,
        )
        event.error_code = str(error_code)[:120]
        event.error_message = str(error_message)
        event.audit_payload = event.to_audit_payload()
        return event

    def mark_processing(self, message: Optional[str] = None) -> None:
        self.status = AgentEventStatus.PROCESSING
        if message:
            self.message = message
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_completed(
        self,
        *,
        message: Optional[str] = None,
        result_payload: Optional[Mapping[str, Any]] = None,
        prepare_verification: bool = True,
    ) -> None:
        self.status = AgentEventStatus.COMPLETED
        self.event_name = AgentEventName.COMPLETED
        self.progress_current = self.progress_total
        self.progress_percent = 100
        if message:
            self.message = message
        if result_payload:
            self.payload = self.sanitize_payload({**self.payload, "result": dict(result_payload)})
        if prepare_verification:
            self.verification_required = True
            self.verification_ready = True
            self.verification_payload = self.prepare_verification_payload()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()
        self.memory_context = self.prepare_memory_context()

    def mark_failed(
        self,
        *,
        error_code: str,
        error_message: str,
        retryable: bool = False,
    ) -> None:
        self.status = AgentEventStatus.FAILED
        self.event_name = AgentEventName.FAILED
        self.severity = AgentEventSeverity.ERROR
        self.error_code = str(error_code)[:120]
        self.error_message = str(error_message)
        self.metadata_json = {
            **self.metadata_json,
            "retryable": bool(retryable),
        }
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_cancelled(self, reason: Optional[str] = None) -> None:
        self.status = AgentEventStatus.CANCELLED
        self.event_name = AgentEventName.CANCELLED
        self.message = reason or self.message or "Event cancelled."
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_security_decision(
        self,
        *,
        approved: bool,
        approval_id: Optional[str],
        reason: Optional[str],
        reviewer_actor_id: Optional[str] = "security_agent",
    ) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.security_approval_id = approval_id
        self.security_reason = reason
        self.actor_type = AgentActorType.SECURITY_AGENT
        self.actor_id = reviewer_actor_id
        self.event_type = AgentEventType.SECURITY
        self.event_name = (
            AgentEventName.SECURITY_APPROVED if approved else AgentEventName.SECURITY_REJECTED
        )
        self.status = AgentEventStatus.ACCEPTED if approved else AgentEventStatus.REJECTED
        self.severity = AgentEventSeverity.NOTICE if approved else AgentEventSeverity.WARNING
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_dispatched(self) -> None:
        self.delivery_status = AgentEventDeliveryStatus.DISPATCHED
        self.dispatched_at = utc_now()
        self.updated_at = utc_now()

    def mark_acknowledged(self) -> None:
        self.delivery_status = AgentEventDeliveryStatus.ACKNOWLEDGED
        self.acknowledged_at = utc_now()
        self.updated_at = utc_now()

    def mark_delivery_failed(self, reason: Optional[str] = None) -> None:
        self.delivery_status = AgentEventDeliveryStatus.DELIVERY_FAILED
        self.metadata_json = {
            **self.metadata_json,
            "delivery_failure_reason": reason or "Unknown delivery failure.",
        }
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def archive(self) -> None:
        self.status = AgentEventStatus.ARCHIVED
        self.archived_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def increment_retry(self) -> None:
        self.retry_count += 1
        self.event_name = AgentEventName.RETRIED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def update_progress(
        self,
        *,
        current: int,
        total: Optional[int] = None,
        message: Optional[str] = None,
    ) -> None:
        if total is not None:
            self.progress_total = max(int(total), 1)
        self.progress_current = max(int(current), 0)
        self.progress_percent = self.calculate_progress_percent(
            self.progress_current,
            self.progress_total,
        )
        self.event_name = AgentEventName.PROGRESS
        self.status = AgentEventStatus.PROCESSING
        if message:
            self.message = message
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def prepare_memory_context(self) -> Dict[str, Any]:
        """
        Build a Memory Agent compatible context snapshot.

        It avoids raw secrets and keeps user/workspace scope explicit.
        """
        return self.sanitize_payload(
            {
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "event_type": self.event_type.value,
                "event_name": self.event_name.value,
                "status": self.status.value,
                "action": self.action,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
                "title": self.title,
                "message": self.message,
                "payload_summary": self.payload,
                "occurred_at": self.occurred_at,
                "correlation_id": self.correlation_id,
                "scope_key": self.scope_key,
            }
        )

    def prepare_verification_payload(self) -> Dict[str, Any]:
        """
        Build a Verification Agent compatible payload.

        Completed actions should call this so the Verification Agent can confirm
        outcome, scope, agent, task, and audit hash.
        """
        return self.sanitize_payload(
            {
                "verification_id": self.verification_id or f"ver_{uuid.uuid4().hex}",
                "event_uid": self.event_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "subtask_id": self.subtask_id,
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "action": self.action,
                "status": self.status.value,
                "result_message": self.message,
                "payload_hash": self.payload_hash,
                "audit_payload": self.audit_payload,
                "occurred_at": self.occurred_at,
                "completed_at": utc_now(),
                "requires_security_review": self.requires_security_review,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
            }
        )

    def to_audit_payload(self) -> Dict[str, Any]:
        """Return a minimal, safe, audit-friendly payload."""
        return self.sanitize_payload(
            {
                "event_uid": self.event_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "subtask_id": self.subtask_id,
                "correlation_id": self.correlation_id,
                "causation_id": self.causation_id,
                "event_type": self.event_type.value,
                "event_name": self.event_name.value,
                "status": self.status.value,
                "severity": self.severity.value,
                "visibility": self.visibility.value,
                "source": self.source,
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "actor_type": self.actor_type.value,
                "actor_id": self.actor_id,
                "actor_role": self.actor_role,
                "subscription_plan": self.subscription_plan,
                "action": self.action,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
                "title": self.title,
                "message": self.message,
                "progress_percent": self.progress_percent,
                "requires_security_review": self.requires_security_review,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "security_approval_id": self.security_approval_id,
                "security_reason": self.security_reason,
                "verification_required": self.verification_required,
                "verification_ready": self.verification_ready,
                "verification_id": self.verification_id,
                "error_code": self.error_code,
                "error_message": self.error_message,
                "retry_count": self.retry_count,
                "payload_hash": self.payload_hash,
                "occurred_at": self.occurred_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def to_stream_payload(self, *, include_payload: bool = True) -> Dict[str, Any]:
        """
        Return event payload for frontend streams, dashboards, websocket consumers,
        or API responses.

        API layers should still enforce role/plan checks before returning this.
        """
        data: Dict[str, Any] = {
            "id": self.id,
            "event_uid": self.event_uid,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "subtask_id": self.subtask_id,
            "parent_event_id": self.parent_event_id,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type.value,
            "event_name": self.event_name.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "visibility": self.visibility.value,
            "delivery_status": self.delivery_status.value,
            "source": self.source,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "actor_type": self.actor_type.value,
            "actor_id": self.actor_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "title": self.title,
            "message": self.message,
            "progress": {
                "current": self.progress_current,
                "total": self.progress_total,
                "percent": self.progress_percent,
            },
            "security": {
                "requires_review": self.requires_security_review,
                "reviewed": self.security_reviewed,
                "approved": self.security_approved,
                "approval_id": self.security_approval_id,
                "reason": self.security_reason,
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
            "payload_hash": self.payload_hash,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_payload:
            data["payload"] = self.sanitize_payload(self.payload)
            data["metadata"] = self.sanitize_payload(self.metadata_json)

        return data

    def to_dashboard_payload(self, *, viewer_role: Optional[str] = None) -> Dict[str, Any]:
        """
        Return dashboard-safe event data.

        This method reduces sensitive detail for non-admin/security viewers.
        API services should enforce full access checks before calling it.
        """
        role = (viewer_role or "").lower().strip()
        can_view_internal = role in {"owner", "admin", "security", "developer", "super_admin"}

        payload = self.to_stream_payload(include_payload=can_view_internal)

        if not can_view_internal:
            payload.pop("actor_id", None)
            payload["security"] = {
                "requires_review": self.requires_security_review,
                "reviewed": self.security_reviewed,
                "approved": self.security_approved,
            }
            payload["metadata"] = {}

        return payload

    def to_dict(self) -> Dict[str, Any]:
        """Return a complete sanitized dictionary representation."""
        return {
            **self.to_stream_payload(include_payload=True),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "memory_context": self.sanitize_payload(self.memory_context),
            "verification_payload": self.sanitize_payload(self.verification_payload),
            "dispatched_at": self.dispatched_at.isoformat() if self.dispatched_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
        }

    def assert_same_scope(self, *, user_id: str, workspace_id: str) -> None:
        """
        Raise a safe error if another user/workspace tries to access this event.
        """
        if self.user_id != str(user_id).strip() or self.workspace_id != str(workspace_id).strip():
            raise PermissionError("AgentEvent access denied for this user/workspace scope.")

    def can_be_seen_by_role(self, role: Optional[str]) -> bool:
        """
        Basic role visibility helper.

        Final API/service layers should combine this with subscription and workspace
        membership checks.
        """
        normalized_role = (role or "").lower().strip()

        if self.visibility == AgentEventVisibility.USER_VISIBLE:
            return normalized_role in {"owner", "admin", "member", "viewer", "user"}

        if self.visibility == AgentEventVisibility.ADMIN_VISIBLE:
            return normalized_role in {"owner", "admin", "super_admin"}

        if self.visibility == AgentEventVisibility.SECURITY_ONLY:
            return normalized_role in {"owner", "admin", "security", "super_admin"}

        return normalized_role in {"owner", "admin", "developer", "security", "super_admin"}

    @property
    def scope_key(self) -> str:
        return self.build_scope_key(self.user_id, self.workspace_id)

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            AgentEventStatus.COMPLETED,
            AgentEventStatus.FAILED,
            AgentEventStatus.CANCELLED,
            AgentEventStatus.REJECTED,
            AgentEventStatus.ARCHIVED,
        }

    @property
    def needs_security_agent(self) -> bool:
        return self.requires_security_review and not self.security_reviewed

    @property
    def needs_verification_agent(self) -> bool:
        return self.verification_required and self.verification_ready and bool(self.verification_payload)

    @property
    def is_error(self) -> bool:
        return self.severity in {AgentEventSeverity.ERROR, AgentEventSeverity.CRITICAL} or (
            self.status == AgentEventStatus.FAILED
        )

    @classmethod
    def safe_error_response(
        cls,
        *,
        code: str,
        message: str,
        event_uid: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return structured safe errors for service/API layers."""
        return {
            "ok": False,
            "error": {
                "code": str(code),
                "message": str(message),
                "event_uid": event_uid,
                "correlation_id": correlation_id,
            },
        }

    @classmethod
    def success_response(
        cls,
        *,
        event: "AgentEvent",
        message: str = "Agent event recorded successfully.",
    ) -> Dict[str, Any]:
        """Return structured success response for service/API layers."""
        return {
            "ok": True,
            "message": message,
            "event": event.to_stream_payload(include_payload=True),
        }

    @classmethod
    def query_scope_filters(cls, *, user_id: str, workspace_id: str) -> tuple[Any, Any]:
        """
        Return SQLAlchemy filters for strict SaaS isolation.

        Usage:
            session.query(AgentEvent).filter(*AgentEvent.query_scope_filters(...))
        """
        return (
            cls.user_id == cls._clean_identifier(user_id, "user_id"),
            cls.workspace_id == cls._clean_identifier(workspace_id, "workspace_id"),
        )

    @classmethod
    def query_task_filters(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
    ) -> tuple[Any, Any, Any]:
        """
        Return SQLAlchemy filters for task-scoped event retrieval.
        """
        return (
            cls.user_id == cls._clean_identifier(user_id, "user_id"),
            cls.workspace_id == cls._clean_identifier(workspace_id, "workspace_id"),
            cls.task_id == cls._clean_identifier(task_id, "task_id"),
        )

    @classmethod
    def summarize_events(cls, events: Iterable["AgentEvent"]) -> Dict[str, Any]:
        """
        Build a dashboard-friendly summary from an iterable of events.
        """
        total = 0
        by_status: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        security_pending = 0
        verification_ready = 0
        errors = 0

        for event in events:
            total += 1
            by_status[event.status.value] = by_status.get(event.status.value, 0) + 1
            by_type[event.event_type.value] = by_type.get(event.event_type.value, 0) + 1
            if event.needs_security_agent:
                security_pending += 1
            if event.needs_verification_agent:
                verification_ready += 1
            if event.is_error:
                errors += 1

        return {
            "total": total,
            "by_status": by_status,
            "by_type": by_type,
            "security_pending": security_pending,
            "verification_ready": verification_ready,
            "errors": errors,
        }