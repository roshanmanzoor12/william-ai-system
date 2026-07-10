"""
database/models/agent_task.py

William / Jarvis Multi-Agent AI SaaS System
Agent Task & Subtask Model + Task Service Layer

Purpose:
- Store user/workspace isolated tasks
- Store subtasks and parent/child task relationships
- Track assigned agent
- Track status, priority, progress, retries, timestamps
- Prepare Security Agent approval payloads
- Prepare Verification Agent completion payloads
- Prepare Memory Agent compatible context payloads
- Add audit logging hooks for sensitive/state-changing actions
- Provide safe structured responses
- Import safely even when future files are not created yet

Author: Digital Promotix
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Float,
        ForeignKey,
        Index,
        Integer,
        String,
        Text,
    )
    from sqlalchemy.orm import Session, relationship
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/agent_task.py. "
        "Install it with: pip install sqlalchemy"
    ) from exc


# ---------------------------------------------------------------------
# Safe Base Import
# ---------------------------------------------------------------------

try:
    from database.db import Base
except Exception:  # pragma: no cover
    try:
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()
    except Exception as exc:
        raise ImportError(
            "Could not import SQLAlchemy Base. Ensure database/db.py exists "
            "or SQLAlchemy is installed correctly."
        ) from exc


# ---------------------------------------------------------------------
# Optional Agent Registry Import
# ---------------------------------------------------------------------

try:
    from database.models.agent_registry import AgentRegistry
except Exception:  # pragma: no cover
    AgentRegistry = None  # type: ignore


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger("william.database.models.agent_task")

if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

logger.setLevel(os.getenv("AGENT_TASK_LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

UTC = timezone.utc

TASK_STATUS_PENDING = "pending"
TASK_STATUS_QUEUED = "queued"
TASK_STATUS_ASSIGNED = "assigned"
TASK_STATUS_RUNNING = "running"
TASK_STATUS_WAITING_APPROVAL = "waiting_approval"
TASK_STATUS_PAUSED = "paused"
TASK_STATUS_COMPLETED = "completed"
TASK_STATUS_FAILED = "failed"
TASK_STATUS_CANCELLED = "cancelled"
TASK_STATUS_RETRYING = "retrying"

VALID_TASK_STATUSES = {
    TASK_STATUS_PENDING,
    TASK_STATUS_QUEUED,
    TASK_STATUS_ASSIGNED,
    TASK_STATUS_RUNNING,
    TASK_STATUS_WAITING_APPROVAL,
    TASK_STATUS_PAUSED,
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUS_CANCELLED,
    TASK_STATUS_RETRYING,
}

FINAL_TASK_STATUSES = {
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUS_CANCELLED,
}

TASK_PRIORITY_LOW = "low"
TASK_PRIORITY_NORMAL = "normal"
TASK_PRIORITY_HIGH = "high"
TASK_PRIORITY_URGENT = "urgent"

VALID_TASK_PRIORITIES = {
    TASK_PRIORITY_LOW,
    TASK_PRIORITY_NORMAL,
    TASK_PRIORITY_HIGH,
    TASK_PRIORITY_URGENT,
}

PRIORITY_SCORE = {
    TASK_PRIORITY_LOW: 25,
    TASK_PRIORITY_NORMAL: 50,
    TASK_PRIORITY_HIGH: 75,
    TASK_PRIORITY_URGENT: 100,
}

TASK_TYPE_GENERAL = "general"
TASK_TYPE_USER_REQUEST = "user_request"
TASK_TYPE_SYSTEM = "system"
TASK_TYPE_WORKFLOW = "workflow"
TASK_TYPE_SUBTASK = "subtask"
TASK_TYPE_DEVICE = "device"

DEFAULT_SYSTEM_USER_ID = "system"
DEFAULT_SYSTEM_WORKSPACE_ID = "system"

DEFAULT_PLAN_TIERS = {
    "free": 0,
    "starter": 1,
    "growth": 2,
    "pro": 3,
    "business": 4,
    "enterprise": 5,
    "admin": 99,
    "system": 100,
}


# ---------------------------------------------------------------------
# Utility Helpers
# ---------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _new_id(prefix: str = "task") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return json.dumps({"raw": str(value)}, ensure_ascii=False, sort_keys=True)


def _safe_json_loads(value: Optional[str], fallback: Any) -> Any:
    if value in (None, ""):
        return fallback

    try:
        return json.loads(value)
    except Exception:
        return fallback


def _normalize_text(value: Optional[Any], max_length: Optional[int] = None) -> str:
    text = str(value or "").strip()
    if max_length and len(text) > max_length:
        return text[:max_length]
    return text


def _normalize_status(status: Optional[str]) -> str:
    cleaned = _normalize_text(status or TASK_STATUS_PENDING).lower()
    return cleaned if cleaned in VALID_TASK_STATUSES else TASK_STATUS_PENDING


def _normalize_priority(priority: Optional[str]) -> str:
    cleaned = _normalize_text(priority or TASK_PRIORITY_NORMAL).lower()
    return cleaned if cleaned in VALID_TASK_PRIORITIES else TASK_PRIORITY_NORMAL


def _normalize_progress(progress: Union[int, float, None]) -> float:
    try:
        value = float(progress if progress is not None else 0.0)
    except Exception:
        value = 0.0

    if value < 0:
        return 0.0

    if value > 100:
        return 100.0

    return round(value, 2)


def _normalize_list(values: Optional[Union[str, Sequence[str]]]) -> List[str]:
    if values is None:
        return []

    if isinstance(values, str):
        raw_items = [item.strip() for item in values.split(",")]
    else:
        raw_items = [str(item).strip() for item in values]

    return sorted({item for item in raw_items if item})


def _normalize_dict(value: Optional[Union[str, Dict[str, Any]]]) -> Dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        loaded = _safe_json_loads(value, {})
        return loaded if isinstance(loaded, dict) else {}

    return {}


def _mask_sensitive_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not metadata:
        return {}

    sensitive_keys = {
        "secret",
        "token",
        "api_key",
        "apikey",
        "password",
        "private_key",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "session",
    }

    clean: Dict[str, Any] = {}

    for key, value in metadata.items():
        key_lower = str(key).lower()

        if any(secret_key in key_lower for secret_key in sensitive_keys):
            clean[str(key)] = "***masked***"
        elif isinstance(value, dict):
            clean[str(key)] = _mask_sensitive_metadata(value)
        elif isinstance(value, list):
            clean[str(key)] = [
                _mask_sensitive_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            clean[str(key)] = value

    return clean


# ---------------------------------------------------------------------
# Safe Integration Stubs
# ---------------------------------------------------------------------

class SecurityAgentStub:
    """
    Fallback security approval adapter.

    Replace later with real Security Agent.
    """

    def authorize(self, **kwargs: Any) -> bool:
        logger.warning("SecurityAgentStub used. Approval allowed. kwargs=%s", kwargs)
        return True


class AuditLoggerStub:
    """
    Fallback audit logger.

    Replace later with real audit log service.
    """

    def record(self, **kwargs: Any) -> None:
        logger.info("[AUDIT] %s", kwargs)


class MemoryAgentStub:
    """
    Fallback Memory Agent adapter.

    Replace later with real Memory Agent.
    """

    def prepare_context(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "memory_ready": True,
            "payload": kwargs,
            "timestamp": _iso_now(),
        }


class VerificationAgentStub:
    """
    Fallback Verification Agent adapter.

    Replace later with real Verification Agent.
    """

    def prepare_confirmation(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "verification_ready": True,
            "payload": kwargs,
            "timestamp": _iso_now(),
        }


# ---------------------------------------------------------------------
# ORM Model
# ---------------------------------------------------------------------

class AgentTask(Base):
    """
    SQLAlchemy model for William/Jarvis task execution.

    Important SaaS rule:
    Every user task must carry user_id and workspace_id.
    This model never assumes global user task access.

    Parent/child relationship:
    - parent_task_id stores subtasks
    - parent task and subtasks must remain inside same user/workspace
    """

    __tablename__ = "agent_tasks"

    id = Column(String(90), primary_key=True, default=lambda: _new_id("task"))

    user_id = Column(String(90), nullable=False, index=True)
    workspace_id = Column(String(90), nullable=False, index=True)

    parent_task_id = Column(String(90), ForeignKey("agent_tasks.id"), nullable=True, index=True)

    task_type = Column(String(60), nullable=False, default=TASK_TYPE_GENERAL)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default="")

    requested_by = Column(String(90), nullable=False, default="")
    assigned_agent_key = Column(String(120), nullable=False, index=True, default="")
    assigned_agent_version = Column(String(50), nullable=False, default="")

    status = Column(String(50), nullable=False, index=True, default=TASK_STATUS_PENDING)
    priority = Column(String(30), nullable=False, default=TASK_PRIORITY_NORMAL)
    priority_score = Column(Integer, nullable=False, default=PRIORITY_SCORE[TASK_PRIORITY_NORMAL])

    progress = Column(Float, nullable=False, default=0.0)
    progress_message = Column(Text, nullable=False, default="")

    input_json = Column(Text, nullable=False, default="{}")
    output_json = Column(Text, nullable=False, default="{}")
    error_json = Column(Text, nullable=False, default="{}")
    metadata_json = Column(Text, nullable=False, default="{}")
    required_permissions_json = Column(Text, nullable=False, default="[]")

    requires_security_approval = Column(Boolean, nullable=False, default=True)
    security_approved = Column(Boolean, nullable=False, default=False)
    security_approved_by = Column(String(90), nullable=False, default="")
    security_approved_at = Column(DateTime(timezone=True), nullable=True)

    requires_verification = Column(Boolean, nullable=False, default=True)
    verification_payload_json = Column(Text, nullable=False, default="{}")
    verified = Column(Boolean, nullable=False, default=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    memory_payload_json = Column(Text, nullable=False, default="{}")
    memory_ready = Column(Boolean, nullable=False, default=False)

    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=0)

    worker_id = Column(String(120), nullable=False, default="")
    lock_token = Column(String(120), nullable=False, default="")

    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    queued_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    paused_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    cancelled_at = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    subtasks = relationship(
        "AgentTask",
        backref="parent_task",
        remote_side=[id],
        cascade="all, delete-orphan",
        single_parent=True,
    )

    __table_args__ = (
        Index("ix_agent_tasks_tenant_status", "user_id", "workspace_id", "status"),
        Index("ix_agent_tasks_agent_status", "assigned_agent_key", "status"),
        Index("ix_agent_tasks_priority_queue", "status", "priority_score", "created_at"),
        Index("ix_agent_tasks_parent_status", "parent_task_id", "status"),
        Index("ix_agent_tasks_worker_lock", "worker_id", "lock_token"),
    )

    # -----------------------------------------------------------------
    # JSON Properties
    # -----------------------------------------------------------------

    @property
    def input_data(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.input_json, {})
        return data if isinstance(data, dict) else {}

    @input_data.setter
    def input_data(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.input_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def output_data(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.output_json, {})
        return data if isinstance(data, dict) else {}

    @output_data.setter
    def output_data(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.output_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def error_data(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.error_json, {})
        return data if isinstance(data, dict) else {}

    @error_data.setter
    def error_data(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.error_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def metadata(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.metadata_json, {})
        return data if isinstance(data, dict) else {}

    @metadata.setter
    def metadata(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.metadata_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def required_permissions(self) -> List[str]:
        data = _safe_json_loads(self.required_permissions_json, [])
        return _normalize_list(data if isinstance(data, list) else [])

    @required_permissions.setter
    def required_permissions(self, value: Optional[Union[str, Sequence[str]]]) -> None:
        self.required_permissions_json = _safe_json_dumps(_normalize_list(value))

    @property
    def verification_payload(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.verification_payload_json, {})
        return data if isinstance(data, dict) else {}

    @verification_payload.setter
    def verification_payload(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.verification_payload_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def memory_payload(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.memory_payload_json, {})
        return data if isinstance(data, dict) else {}

    @memory_payload.setter
    def memory_payload(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.memory_payload_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    # -----------------------------------------------------------------
    # Model Helpers
    # -----------------------------------------------------------------

    def belongs_to(self, user_id: str, workspace_id: str) -> bool:
        return self.user_id == user_id and self.workspace_id == workspace_id

    def is_final(self) -> bool:
        return self.status in FINAL_TASK_STATUSES

    def can_start(self) -> bool:
        return (
            self.deleted_at is None
            and self.status in {TASK_STATUS_PENDING, TASK_STATUS_QUEUED, TASK_STATUS_ASSIGNED, TASK_STATUS_RETRYING}
            and (not self.requires_security_approval or self.security_approved)
        )

    def can_retry(self) -> bool:
        return self.status == TASK_STATUS_FAILED and self.retry_count < self.max_retries

    def set_status(self, status: str, message: Optional[str] = None) -> None:
        normalized = _normalize_status(status)
        self.status = normalized

        if message is not None:
            self.progress_message = _normalize_text(message, 4000)

        now = _utc_now()

        if normalized == TASK_STATUS_QUEUED:
            self.queued_at = now
        elif normalized == TASK_STATUS_RUNNING:
            self.started_at = self.started_at or now
        elif normalized == TASK_STATUS_PAUSED:
            self.paused_at = now
        elif normalized == TASK_STATUS_COMPLETED:
            self.completed_at = now
            self.progress = 100.0
        elif normalized == TASK_STATUS_FAILED:
            self.failed_at = now
        elif normalized == TASK_STATUS_CANCELLED:
            self.cancelled_at = now

        self.updated_at = now

    def update_progress(self, progress: Union[int, float], message: Optional[str] = None) -> None:
        self.progress = _normalize_progress(progress)

        if message is not None:
            self.progress_message = _normalize_text(message, 4000)

        self.last_heartbeat_at = _utc_now()
        self.updated_at = _utc_now()

    def mark_security_approved(self, approved_by: str) -> None:
        self.security_approved = True
        self.security_approved_by = _normalize_text(approved_by, 90)
        self.security_approved_at = _utc_now()
        self.updated_at = _utc_now()

    def mark_verified(self, payload: Dict[str, Any]) -> None:
        self.verified = True
        self.verified_at = _utc_now()
        self.verification_payload = payload
        self.updated_at = _utc_now()

    def mark_memory_ready(self, payload: Dict[str, Any]) -> None:
        self.memory_ready = True
        self.memory_payload = payload
        self.updated_at = _utc_now()

    def assign_worker(self, worker_id: str, lock_token: Optional[str] = None) -> None:
        self.worker_id = _normalize_text(worker_id, 120)
        self.lock_token = _normalize_text(lock_token or _new_id("lock"), 120)
        self.last_heartbeat_at = _utc_now()
        self.updated_at = _utc_now()

    def clear_worker_lock(self) -> None:
        self.worker_id = ""
        self.lock_token = ""
        self.updated_at = _utc_now()

    def to_dict(
        self,
        include_internal: bool = False,
        include_subtasks: bool = False,
    ) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "parent_task_id": self.parent_task_id,
            "task_type": self.task_type,
            "title": self.title,
            "description": self.description,
            "requested_by": self.requested_by,
            "assigned_agent_key": self.assigned_agent_key,
            "assigned_agent_version": self.assigned_agent_version,
            "status": self.status,
            "priority": self.priority,
            "priority_score": self.priority_score,
            "progress": self.progress,
            "progress_message": self.progress_message,
            "requires_security_approval": self.requires_security_approval,
            "security_approved": self.security_approved,
            "requires_verification": self.requires_verification,
            "verified": self.verified,
            "memory_ready": self.memory_ready,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "scheduled_at": self.scheduled_at.isoformat() if self.scheduled_at else None,
            "queued_at": self.queued_at.isoformat() if self.queued_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "paused_at": self.paused_at.isoformat() if self.paused_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "failed_at": self.failed_at.isoformat() if self.failed_at else None,
            "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

        if include_internal:
            data.update(
                {
                    "input_data": self.input_data,
                    "output_data": self.output_data,
                    "error_data": self.error_data,
                    "metadata": self.metadata,
                    "required_permissions": self.required_permissions,
                    "security_approved_by": self.security_approved_by,
                    "security_approved_at": self.security_approved_at.isoformat() if self.security_approved_at else None,
                    "verification_payload": self.verification_payload,
                    "memory_payload": self.memory_payload,
                    "worker_id": self.worker_id,
                    "lock_token": self.lock_token,
                }
            )

        if include_subtasks:
            data["subtasks"] = [
                subtask.to_dict(include_internal=include_internal, include_subtasks=False)
                for subtask in self.subtasks
                if subtask.deleted_at is None
            ]

        return data

    def __repr__(self) -> str:
        return (
            f"<AgentTask id={self.id!r} "
            f"user_id={self.user_id!r} workspace_id={self.workspace_id!r} "
            f"agent={self.assigned_agent_key!r} status={self.status!r}>"
        )


# ---------------------------------------------------------------------
# Service Layer
# ---------------------------------------------------------------------

class AgentTaskService:
    """
    Service layer for AgentTask.

    Use this from:
    - Master Agent
    - API routes
    - Worker nodes
    - Dashboard layer
    - Workflow Agent

    It enforces:
    - user/workspace isolation
    - security approval hooks
    - audit logging
    - memory payload preparation
    - verification payload preparation
    """

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        plan_tiers: Optional[Dict[str, int]] = None,
    ) -> None:
        self.security_agent = security_agent or SecurityAgentStub()
        self.audit_logger = audit_logger or AuditLoggerStub()
        self.memory_agent = memory_agent or MemoryAgentStub()
        self.verification_agent = verification_agent or VerificationAgentStub()
        self.plan_tiers = plan_tiers or DEFAULT_PLAN_TIERS.copy()

    # -----------------------------------------------------------------
    # Structured Responses
    # -----------------------------------------------------------------

    def _success(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
            "timestamp": _iso_now(),
        }

    def _error(
        self,
        message: str,
        error: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": str(error) if error else None,
            "metadata": metadata or {},
            "timestamp": _iso_now(),
        }

    # -----------------------------------------------------------------
    # Context / Access Helpers
    # -----------------------------------------------------------------

    def validate_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> bool:
        return bool(str(user_id or "").strip()) and bool(str(workspace_id or "").strip())

    def _plan_rank(self, plan: Optional[str]) -> int:
        return self.plan_tiers.get(str(plan or "free").lower(), 0)

    def _has_plan_access(
        self,
        user_plan: Optional[str],
        required_plan: Optional[str],
    ) -> bool:
        return self._plan_rank(user_plan) >= self._plan_rank(required_plan)

    def _has_role_access(
        self,
        user_roles: Optional[Sequence[str]],
        allowed_roles: Optional[Sequence[str]] = None,
    ) -> bool:
        roles = set(_normalize_list(user_roles))
        allowed = set(_normalize_list(allowed_roles or ["owner", "admin", "manager", "operator"]))

        if not allowed:
            return True

        return bool(roles.intersection(allowed)) or "owner" in roles or "admin" in roles

    def _has_permission_access(
        self,
        user_permissions: Optional[Sequence[str]],
        required_permissions: Optional[Sequence[str]],
    ) -> bool:
        required = set(_normalize_list(required_permissions))
        if not required:
            return True

        owned = set(_normalize_list(user_permissions))
        return required.issubset(owned) or "*" in owned or "admin:*" in owned

    def _assert_task_access(
        self,
        task: AgentTask,
        user_id: str,
        workspace_id: str,
    ) -> Optional[Dict[str, Any]]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not task.belongs_to(user_id, workspace_id):
            return self._error(
                "Task access denied due to workspace isolation.",
                metadata={
                    "task_id": task.id,
                    "requested_user_id": user_id,
                    "requested_workspace_id": workspace_id,
                },
            )

        if task.deleted_at is not None:
            return self._error("Task not found or has been deleted.", metadata={"task_id": task.id})

        return None

    # -----------------------------------------------------------------
    # Integration Hooks
    # -----------------------------------------------------------------

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        agent_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        try:
            return bool(
                self.security_agent.authorize(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    agent_key=agent_key,
                    metadata=_mask_sensitive_metadata(metadata or {}),
                    timestamp=_iso_now(),
                )
            )
        except Exception as exc:
            logger.exception("Security approval failed for action=%s", action)
            logger.error("Security error: %s", exc)
            return False

    def _audit(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        agent_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            self.audit_logger.record(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                agent_key=agent_key,
                metadata=_mask_sensitive_metadata(metadata or {}),
                timestamp=_iso_now(),
            )
        except Exception as exc:
            logger.exception("Audit logging failed for action=%s", action)
            logger.error("Audit error: %s", exc)

    def _memory_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task: Optional[AgentTask] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "source": "agent_task",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task": task.to_dict(include_internal=False, include_subtasks=False) if task else None,
            "metadata": _mask_sensitive_metadata(metadata or {}),
            "timestamp": _iso_now(),
        }

        try:
            return self.memory_agent.prepare_context(**payload)
        except Exception:
            return payload

    def _verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task: Optional[AgentTask] = None,
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "source": "agent_task",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task": task.to_dict(include_internal=False, include_subtasks=True) if task else None,
            "result": result or {},
            "timestamp": _iso_now(),
        }

        try:
            return self.verification_agent.prepare_confirmation(**payload)
        except Exception:
            return payload

    # -----------------------------------------------------------------
    # Query Helpers
    # -----------------------------------------------------------------

    def get_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        include_deleted: bool = False,
    ) -> Optional[AgentTask]:
        if not self.validate_context(user_id, workspace_id):
            return None

        query = db.query(AgentTask).filter(
            AgentTask.id == str(task_id).strip(),
            AgentTask.user_id == str(user_id).strip(),
            AgentTask.workspace_id == str(workspace_id).strip(),
        )

        if not include_deleted:
            query = query.filter(AgentTask.deleted_at.is_(None))

        return query.first()

    def get_task_response(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        include_internal: bool = False,
        include_subtasks: bool = True,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        access_error = self._assert_task_access(task, user_id, workspace_id)
        if access_error:
            return access_error

        return self._success(
            "Task loaded successfully.",
            data={
                "task": task.to_dict(
                    include_internal=include_internal,
                    include_subtasks=include_subtasks,
                )
            },
            metadata={
                "memory_payload": self._memory_payload(
                    action="agent_task.get_task",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task=task,
                )
            },
        )

    def list_tasks(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        assigned_agent_key: Optional[str] = None,
        parent_task_id: Optional[str] = None,
        include_subtasks: bool = False,
        include_internal: bool = False,
        limit: int = 100,
        offset: int = 0,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        List tasks for dashboard/API with strict user/workspace isolation.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not self._has_plan_access(user_plan, "free"):
            return self._error("Task dashboard access denied by subscription plan.")

        if not self._has_role_access(user_roles):
            return self._error(
                "Task dashboard access denied by role.",
                metadata={"user_roles": _normalize_list(user_roles)},
            )

        if not self._has_permission_access(user_permissions, ["task:read"]):
            return self._error(
                "Task dashboard access denied by permission.",
                metadata={"required_permissions": ["task:read"]},
            )

        safe_limit = max(1, min(int(limit or 100), 500))
        safe_offset = max(0, int(offset or 0))

        try:
            query = db.query(AgentTask).filter(
                AgentTask.user_id == user_id,
                AgentTask.workspace_id == workspace_id,
                AgentTask.deleted_at.is_(None),
            )

            if status:
                query = query.filter(AgentTask.status == _normalize_status(status))

            if assigned_agent_key:
                query = query.filter(AgentTask.assigned_agent_key == _normalize_text(assigned_agent_key, 120))

            if parent_task_id:
                query = query.filter(AgentTask.parent_task_id == _normalize_text(parent_task_id, 90))
            elif not include_subtasks:
                query = query.filter(AgentTask.parent_task_id.is_(None))

            total = query.count()

            tasks = (
                query.order_by(
                    AgentTask.priority_score.desc(),
                    AgentTask.created_at.desc(),
                )
                .offset(safe_offset)
                .limit(safe_limit)
                .all()
            )

            rows = [
                task.to_dict(
                    include_internal=include_internal,
                    include_subtasks=include_subtasks,
                )
                for task in tasks
            ]

            result = {
                "tasks": rows,
                "count": len(rows),
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
            }

            return self._success(
                "Tasks listed successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.list_tasks",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata={
                            "count": len(rows),
                            "status": status,
                            "assigned_agent_key": assigned_agent_key,
                        },
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_task.list_tasks",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            logger.exception("Failed to list tasks.")
            return self._error("Failed to list tasks.", exc)

    # -----------------------------------------------------------------
    # Create Task
    # -----------------------------------------------------------------

    def create_task(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        title: str,
        description: str = "",
        task_type: str = TASK_TYPE_USER_REQUEST,
        assigned_agent_key: str = "",
        assigned_agent_version: str = "",
        requested_by: str = "",
        input_data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        required_permissions: Optional[Sequence[str]] = None,
        priority: str = TASK_PRIORITY_NORMAL,
        parent_task_id: Optional[str] = None,
        requires_security_approval: bool = True,
        requires_verification: bool = True,
        max_retries: int = 0,
        scheduled_at: Optional[datetime] = None,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a task or subtask.

        Every user task requires user_id and workspace_id.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        clean_title = _normalize_text(title, 255)
        if not clean_title:
            return self._error("Task title is required.")

        clean_priority = _normalize_priority(priority)
        clean_agent_key = _normalize_text(assigned_agent_key, 120)

        required_perms = _normalize_list(required_permissions)

        if not self._has_plan_access(user_plan, "free"):
            return self._error("Task creation denied by subscription plan.")

        if not self._has_role_access(user_roles):
            return self._error(
                "Task creation denied by role.",
                metadata={"user_roles": _normalize_list(user_roles)},
            )

        if not self._has_permission_access(user_permissions, ["task:create"]):
            return self._error(
                "Task creation denied by permission.",
                metadata={"required_permissions": ["task:create"]},
            )

        if parent_task_id:
            parent = self.get_task(db, parent_task_id, user_id, workspace_id)
            if not parent:
                return self._error("Parent task not found in this workspace.")

        approval_metadata = {
            "title": clean_title,
            "task_type": task_type,
            "assigned_agent_key": clean_agent_key,
            "priority": clean_priority,
            "parent_task_id": parent_task_id,
            "required_permissions": required_perms,
        }

        security_approved = False
        security_approved_by = ""

        if requires_security_approval:
            security_approved = self._request_security_approval(
                action="agent_task.create_task",
                user_id=user_id,
                workspace_id=workspace_id,
                agent_key=clean_agent_key,
                metadata=approval_metadata,
            )

            if not security_approved:
                return self._error("Security approval denied for task creation.")
            security_approved_by = "security_agent"
        else:
            security_approved = True
            security_approved_by = "system_policy"

        try:
            task = AgentTask(
                id=_new_id("task"),
                user_id=user_id,
                workspace_id=workspace_id,
                parent_task_id=parent_task_id,
                task_type=_normalize_text(task_type, 60) or TASK_TYPE_GENERAL,
                title=clean_title,
                description=_normalize_text(description),
                requested_by=_normalize_text(requested_by or user_id, 90),
                assigned_agent_key=clean_agent_key,
                assigned_agent_version=_normalize_text(assigned_agent_version, 50),
                status=TASK_STATUS_PENDING,
                priority=clean_priority,
                priority_score=PRIORITY_SCORE[clean_priority],
                progress=0.0,
                progress_message="Task created.",
                requires_security_approval=bool(requires_security_approval),
                security_approved=bool(security_approved),
                security_approved_by=security_approved_by,
                security_approved_at=_utc_now() if security_approved else None,
                requires_verification=bool(requires_verification),
                max_retries=max(0, int(max_retries or 0)),
                scheduled_at=scheduled_at,
                created_at=_utc_now(),
                updated_at=_utc_now(),
            )

            task.input_data = input_data or {}
            task.metadata = metadata or {}
            task.required_permissions = required_perms

            memory_payload = self._memory_payload(
                action="agent_task.create_task",
                user_id=user_id,
                workspace_id=workspace_id,
                task=task,
                metadata={"input_data": task.input_data},
            )
            task.mark_memory_ready(memory_payload)

            db.add(task)
            db.commit()
            db.refresh(task)

            self._audit(
                action="agent_task.created",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={
                    "title": task.title,
                    "task_type": task.task_type,
                    "parent_task_id": task.parent_task_id,
                    "priority": task.priority,
                },
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                "Task created successfully.",
                data=result,
                metadata={
                    "memory_payload": memory_payload,
                    "verification_payload": self._verification_payload(
                        action="agent_task.created",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to create task.")
            return self._error("Failed to create task.", exc)

    # -----------------------------------------------------------------
    # Subtasks
    # -----------------------------------------------------------------

    def create_subtask(
        self,
        db: Session,
        parent_task_id: str,
        user_id: str,
        workspace_id: str,
        title: str,
        description: str = "",
        assigned_agent_key: str = "",
        input_data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        priority: str = TASK_PRIORITY_NORMAL,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        return self.create_task(
            db=db,
            user_id=user_id,
            workspace_id=workspace_id,
            title=title,
            description=description,
            task_type=TASK_TYPE_SUBTASK,
            assigned_agent_key=assigned_agent_key,
            input_data=input_data,
            metadata=metadata,
            priority=priority,
            parent_task_id=parent_task_id,
            requires_security_approval=True,
            requires_verification=True,
            user_plan=user_plan,
            user_roles=user_roles,
            user_permissions=user_permissions,
        )

    # -----------------------------------------------------------------
    # Lifecycle Updates
    # -----------------------------------------------------------------

    def queue_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        return self.update_task_status(
            db=db,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=TASK_STATUS_QUEUED,
            progress_message="Task queued.",
            requires_security=True,
        )

    def start_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        worker_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        access_error = self._assert_task_access(task, user_id, workspace_id)
        if access_error:
            return access_error

        if not task.can_start():
            return self._error(
                "Task cannot be started in its current state.",
                metadata={
                    "task_id": task.id,
                    "status": task.status,
                    "requires_security_approval": task.requires_security_approval,
                    "security_approved": task.security_approved,
                },
            )

        if not self._request_security_approval(
            action="agent_task.start_task",
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task.id,
            agent_key=task.assigned_agent_key,
        ):
            return self._error("Security approval denied for starting task.")

        try:
            task.set_status(TASK_STATUS_RUNNING, "Task started.")
            task.update_progress(max(task.progress, 1.0), "Task started.")

            if worker_id:
                task.assign_worker(worker_id)

            db.commit()
            db.refresh(task)

            self._audit(
                action="agent_task.started",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"worker_id": worker_id},
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                "Task started successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.started",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_task.started",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to start task.")
            return self._error("Failed to start task.", exc)

    def update_task_status(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        status: str,
        progress_message: Optional[str] = None,
        requires_security: bool = True,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        access_error = self._assert_task_access(task, user_id, workspace_id)
        if access_error:
            return access_error

        normalized_status = _normalize_status(status)

        if task.is_final():
            return self._error(
                "Finalized task status cannot be changed.",
                metadata={"task_id": task.id, "current_status": task.status},
            )

        if requires_security:
            if not self._request_security_approval(
                action="agent_task.update_status",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"new_status": normalized_status},
            ):
                return self._error("Security approval denied for task status update.")

        try:
            task.set_status(normalized_status, progress_message)

            db.commit()
            db.refresh(task)

            self._audit(
                action="agent_task.status_updated",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"status": normalized_status},
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                "Task status updated successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.status_updated",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        metadata={"status": normalized_status},
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_task.status_updated",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to update task status.")
            return self._error("Failed to update task status.", exc)

    def update_progress(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        progress: Union[int, float],
        message: Optional[str] = None,
        worker_id: Optional[str] = None,
        lock_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        access_error = self._assert_task_access(task, user_id, workspace_id)
        if access_error:
            return access_error

        if task.is_final():
            return self._error("Cannot update progress for finalized task.")

        if worker_id and task.worker_id and task.worker_id != worker_id:
            return self._error(
                "Worker cannot update task locked by another worker.",
                metadata={"task_worker_id": task.worker_id, "requested_worker_id": worker_id},
            )

        if lock_token and task.lock_token and task.lock_token != lock_token:
            return self._error("Invalid task lock token.")

        try:
            task.update_progress(progress, message)

            if task.status in {TASK_STATUS_PENDING, TASK_STATUS_QUEUED, TASK_STATUS_ASSIGNED}:
                task.set_status(TASK_STATUS_RUNNING, message or "Task running.")

            db.commit()
            db.refresh(task)

            result = {"task": task.to_dict(include_internal=False, include_subtasks=False)}

            return self._success(
                "Task progress updated successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.progress_updated",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        metadata={"progress": task.progress, "message": message},
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to update task progress.")
            return self._error("Failed to update task progress.", exc)

    def pause_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.update_task_status(
            db=db,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=TASK_STATUS_PAUSED,
            progress_message=reason or "Task paused.",
            requires_security=True,
        )

    def resume_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        if task.status != TASK_STATUS_PAUSED:
            return self._error("Only paused tasks can be resumed.")

        return self.update_task_status(
            db=db,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=TASK_STATUS_QUEUED,
            progress_message="Task resumed and queued.",
            requires_security=True,
        )

    def cancel_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        if task.is_final():
            return self._error("Task is already finalized.")

        if not self._request_security_approval(
            action="agent_task.cancel_task",
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task.id,
            agent_key=task.assigned_agent_key,
            metadata={"reason": reason},
        ):
            return self._error("Security approval denied for task cancellation.")

        try:
            task.set_status(TASK_STATUS_CANCELLED, reason or "Task cancelled.")
            task.clear_worker_lock()

            meta = task.metadata
            meta["cancel_reason"] = reason or ""
            task.metadata = meta

            db.commit()
            db.refresh(task)

            self._audit(
                action="agent_task.cancelled",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"reason": reason},
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                "Task cancelled successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.cancelled",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        metadata={"reason": reason},
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_task.cancelled",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to cancel task.")
            return self._error("Failed to cancel task.", exc)

    def complete_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        output_data: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
        worker_id: Optional[str] = None,
        lock_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        access_error = self._assert_task_access(task, user_id, workspace_id)
        if access_error:
            return access_error

        if task.is_final():
            return self._error("Task is already finalized.")

        if worker_id and task.worker_id and task.worker_id != worker_id:
            return self._error("Worker cannot complete task locked by another worker.")

        if lock_token and task.lock_token and task.lock_token != lock_token:
            return self._error("Invalid task lock token.")

        if not self._request_security_approval(
            action="agent_task.complete_task",
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task.id,
            agent_key=task.assigned_agent_key,
            metadata={"has_output": bool(output_data)},
        ):
            return self._error("Security approval denied for task completion.")

        try:
            task.output_data = output_data or {}
            task.set_status(TASK_STATUS_COMPLETED, message or "Task completed successfully.")
            task.clear_worker_lock()

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            verification_payload = self._verification_payload(
                action="agent_task.completed",
                user_id=user_id,
                workspace_id=workspace_id,
                task=task,
                result=result,
            )

            if task.requires_verification:
                task.mark_verified(verification_payload)

            memory_payload = self._memory_payload(
                action="agent_task.completed",
                user_id=user_id,
                workspace_id=workspace_id,
                task=task,
                metadata={"output_data": task.output_data},
            )
            task.mark_memory_ready(memory_payload)

            db.commit()
            db.refresh(task)

            self._audit(
                action="agent_task.completed",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"progress": task.progress},
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                "Task completed successfully.",
                data=result,
                metadata={
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to complete task.")
            return self._error("Failed to complete task.", exc)

    def fail_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        error: Any,
        worker_id: Optional[str] = None,
        lock_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        access_error = self._assert_task_access(task, user_id, workspace_id)
        if access_error:
            return access_error

        if task.is_final():
            return self._error("Task is already finalized.")

        if worker_id and task.worker_id and task.worker_id != worker_id:
            return self._error("Worker cannot fail task locked by another worker.")

        if lock_token and task.lock_token and task.lock_token != lock_token:
            return self._error("Invalid task lock token.")

        try:
            task.error_data = {
                "error": str(error),
                "failed_at": _iso_now(),
            }

            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.set_status(TASK_STATUS_RETRYING, "Task failed and will retry.")
                task.clear_worker_lock()
                final_message = "Task marked for retry."
                action = "agent_task.retrying"
            else:
                task.set_status(TASK_STATUS_FAILED, "Task failed.")
                task.clear_worker_lock()
                final_message = "Task failed."
                action = "agent_task.failed"

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            verification_payload = self._verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=task,
                result={"error": str(error)},
            )
            task.verification_payload = verification_payload

            memory_payload = self._memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=task,
                metadata={"error": str(error)},
            )
            task.mark_memory_ready(memory_payload)

            db.commit()
            db.refresh(task)

            self._audit(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={
                    "error": str(error),
                    "retry_count": task.retry_count,
                    "max_retries": task.max_retries,
                },
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                final_message,
                data=result,
                metadata={
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to mark task as failed.")
            return self._error("Failed to mark task as failed.", exc)

    # -----------------------------------------------------------------
    # Worker Polling
    # -----------------------------------------------------------------

    def poll_next_task(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        worker_id: str,
        allowed_agent_keys: Optional[Sequence[str]] = None,
        lock_task: bool = True,
    ) -> Dict[str, Any]:
        """
        Worker-safe polling method.

        Pulls one task from the same user/workspace only.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        clean_worker_id = _normalize_text(worker_id, 120)
        if not clean_worker_id:
            return self._error("worker_id is required.")

        try:
            query = db.query(AgentTask).filter(
                AgentTask.user_id == user_id,
                AgentTask.workspace_id == workspace_id,
                AgentTask.deleted_at.is_(None),
                AgentTask.status.in_(
                    [
                        TASK_STATUS_PENDING,
                        TASK_STATUS_QUEUED,
                        TASK_STATUS_ASSIGNED,
                        TASK_STATUS_RETRYING,
                    ]
                ),
                AgentTask.security_approved.is_(True),
            )

            allowed = _normalize_list(allowed_agent_keys)
            if allowed:
                query = query.filter(AgentTask.assigned_agent_key.in_(allowed))

            task = (
                query.order_by(
                    AgentTask.priority_score.desc(),
                    AgentTask.created_at.asc(),
                )
                .first()
            )

            if not task:
                return self._success(
                    "No task available.",
                    data={"task": None},
                    metadata={"empty": True},
                )

            if lock_task:
                task.assign_worker(clean_worker_id)
                task.set_status(TASK_STATUS_ASSIGNED, "Task assigned to worker.")
                db.commit()
                db.refresh(task)

            self._audit(
                action="agent_task.polled",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"worker_id": clean_worker_id, "lock_task": lock_task},
            )

            return self._success(
                "Task polled successfully.",
                data={"task": task.to_dict(include_internal=True, include_subtasks=True)},
                metadata={
                    "verification_payload": self._verification_payload(
                        action="agent_task.polled",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to poll next task.")
            return self._error("Failed to poll next task.", exc)

    def heartbeat_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        worker_id: str,
        lock_token: Optional[str] = None,
        progress: Optional[Union[int, float]] = None,
        message: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        if task.worker_id and task.worker_id != worker_id:
            return self._error("Worker heartbeat denied. Task belongs to another worker.")

        if lock_token and task.lock_token and task.lock_token != lock_token:
            return self._error("Invalid task lock token.")

        try:
            if progress is not None:
                task.update_progress(progress, message)
            else:
                task.last_heartbeat_at = _utc_now()
                if message:
                    task.progress_message = _normalize_text(message, 4000)
                task.updated_at = _utc_now()

            db.commit()
            db.refresh(task)

            return self._success(
                "Task heartbeat recorded.",
                data={"task": task.to_dict(include_internal=False, include_subtasks=False)},
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to record task heartbeat.")
            return self._error("Failed to record task heartbeat.", exc)

    # -----------------------------------------------------------------
    # Soft Delete
    # -----------------------------------------------------------------

    def soft_delete_task(
        self,
        db: Session,
        task_id: str,
        user_id: str,
        workspace_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        task = self.get_task(db, task_id, user_id, workspace_id)

        if not task:
            return self._error("Task not found.")

        if not self._request_security_approval(
            action="agent_task.soft_delete_task",
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task.id,
            agent_key=task.assigned_agent_key,
            metadata={"reason": reason},
        ):
            return self._error("Security approval denied for task deletion.")

        try:
            task.deleted_at = _utc_now()
            task.set_status(TASK_STATUS_CANCELLED, reason or "Task deleted.")
            task.clear_worker_lock()

            meta = task.metadata
            meta["delete_reason"] = reason or ""
            task.metadata = meta

            for subtask in task.subtasks:
                if subtask.deleted_at is None:
                    subtask.deleted_at = _utc_now()
                    subtask.set_status(TASK_STATUS_CANCELLED, "Parent task deleted.")
                    subtask.clear_worker_lock()

            db.commit()
            db.refresh(task)

            self._audit(
                action="agent_task.soft_deleted",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task.id,
                agent_key=task.assigned_agent_key,
                metadata={"reason": reason},
            )

            result = {"task": task.to_dict(include_internal=True, include_subtasks=True)}

            return self._success(
                "Task deleted safely.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.soft_deleted",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        metadata={"reason": reason},
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_task.soft_deleted",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task=task,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to delete task.")
            return self._error("Failed to delete task.", exc)

    # -----------------------------------------------------------------
    # Dashboard Stats
    # -----------------------------------------------------------------

    def task_statistics(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Dashboard-ready task statistics with isolation.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not self._has_role_access(user_roles):
            return self._error("Task statistics access denied by role.")

        if not self._has_permission_access(user_permissions, ["task:read"]):
            return self._error("Task statistics access denied by permission.")

        if not self._has_plan_access(user_plan, "free"):
            return self._error("Task statistics access denied by plan.")

        try:
            base = db.query(AgentTask).filter(
                AgentTask.user_id == user_id,
                AgentTask.workspace_id == workspace_id,
                AgentTask.deleted_at.is_(None),
            )

            total = base.count()

            by_status: Dict[str, int] = {}
            for status in VALID_TASK_STATUSES:
                by_status[status] = base.filter(AgentTask.status == status).count()

            by_priority: Dict[str, int] = {}
            for priority in VALID_TASK_PRIORITIES:
                by_priority[priority] = base.filter(AgentTask.priority == priority).count()

            result = {
                "total": total,
                "by_status": by_status,
                "by_priority": by_priority,
                "open_tasks": total - sum(by_status.get(status, 0) for status in FINAL_TASK_STATUSES),
                "finalized_tasks": sum(by_status.get(status, 0) for status in FINAL_TASK_STATUSES),
            }

            return self._success(
                "Task statistics generated successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_task.statistics",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_task.statistics",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            logger.exception("Failed to generate task statistics.")
            return self._error("Failed to generate task statistics.", exc)


# ---------------------------------------------------------------------
# Module-Level Service Singleton
# ---------------------------------------------------------------------

agent_task_service = AgentTaskService()


# ---------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------

def create_task(
    db: Session,
    user_id: str,
    workspace_id: str,
    title: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.create_task(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        title=title,
        **kwargs,
    )


def create_subtask(
    db: Session,
    parent_task_id: str,
    user_id: str,
    workspace_id: str,
    title: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.create_subtask(
        db=db,
        parent_task_id=parent_task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        title=title,
        **kwargs,
    )


def get_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Optional[AgentTask]:
    return agent_task_service.get_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def get_task_response(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.get_task_response(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def list_tasks(
    db: Session,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.list_tasks(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def queue_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
) -> Dict[str, Any]:
    return agent_task_service.queue_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
    )


def start_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.start_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def update_task_progress(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    progress: Union[int, float],
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.update_progress(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        progress=progress,
        **kwargs,
    )


def complete_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.complete_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def fail_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    error: Any,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.fail_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        error=error,
        **kwargs,
    )


def cancel_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.cancel_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def poll_next_task(
    db: Session,
    user_id: str,
    workspace_id: str,
    worker_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.poll_next_task(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        worker_id=worker_id,
        **kwargs,
    )


def heartbeat_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    worker_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.heartbeat_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        worker_id=worker_id,
        **kwargs,
    )


def soft_delete_task(
    db: Session,
    task_id: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.soft_delete_task(
        db=db,
        task_id=task_id,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def task_statistics(
    db: Session,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_task_service.task_statistics(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


__all__ = [
    "AgentTask",
    "AgentTaskService",
    "agent_task_service",
    "create_task",
    "create_subtask",
    "get_task",
    "get_task_response",
    "list_tasks",
    "queue_task",
    "start_task",
    "update_task_progress",
    "complete_task",
    "fail_task",
    "cancel_task",
    "poll_next_task",
    "heartbeat_task",
    "soft_delete_task",
    "task_statistics",
    "TASK_STATUS_PENDING",
    "TASK_STATUS_QUEUED",
    "TASK_STATUS_ASSIGNED",
    "TASK_STATUS_RUNNING",
    "TASK_STATUS_WAITING_APPROVAL",
    "TASK_STATUS_PAUSED",
    "TASK_STATUS_COMPLETED",
    "TASK_STATUS_FAILED",
    "TASK_STATUS_CANCELLED",
    "TASK_STATUS_RETRYING",
    "VALID_TASK_STATUSES",
    "FINAL_TASK_STATUSES",
    "TASK_PRIORITY_LOW",
    "TASK_PRIORITY_NORMAL",
    "TASK_PRIORITY_HIGH",
    "TASK_PRIORITY_URGENT",
]