"""
database/models/worker_task.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real task-dispatch queue for the Windows device worker
(apps/worker_nodes/windows/windows_worker.py). Before this table existed,
agents/system_agent/system_agent.py's open_app()/close_app() could only ever
report device_worker_offline or external_dependency_required -- there was no
real "backend queues a task, worker polls it, worker reports a result" path
anywhere in the codebase. This table is that path.

Single-device model, deliberately: database/models/system_worker.py's
SystemWorkerStatus is one row per workspace (no device registry), and this
table's device_id is an opaque, worker-reported display string -- not a
foreign key into a device registry. A real multi-device pairing/identity
system is a future phase; today's real requirement is "one Windows laptop
per workspace," and device_id costs nothing to extend later since it is
just a string column.

SaaS isolation: every row is scoped by (user_id, workspace_id). A worker
polling for tasks, or reporting a result, must never see or mutate another
workspace's rows -- see WorkerTaskService.list_queued_for_workspace() and
get_for_workspace(), both of which filter by workspace_id unconditionally.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import Boolean, Column, DateTime, Index, String, Text
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/worker_task.py. "
        "Install it with: pip install sqlalchemy"
    ) from exc

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


logger = logging.getLogger("william.database.models.worker_task")
if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


UTC = timezone.utc


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else {}, ensure_ascii=False)
    except TypeError:
        return json.dumps(str(value), ensure_ascii=False)


def _json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# =============================================================================
# Status vocabulary -- exact spec: queued / running / completed / failed /
# blocked / approval_required (plain string constants, matching this
# codebase's Text-column-with-validated-choices convention).
# =============================================================================

TASK_QUEUED = "queued"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_FAILED = "failed"
TASK_BLOCKED = "blocked"
TASK_APPROVAL_REQUIRED = "approval_required"

VALID_WORKER_TASK_STATUSES = {
    TASK_QUEUED,
    TASK_RUNNING,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_BLOCKED,
    TASK_APPROVAL_REQUIRED,
}

# A task is still "live" (worth showing to a poller, worth counting toward
# System Agent's honest "active" status) in these states.
ACTIVE_WORKER_TASK_STATUSES = {TASK_QUEUED, TASK_RUNNING, TASK_COMPLETED}


class WorkerTask(Base):
    __tablename__ = "worker_tasks"

    task_id = Column(String(80), primary_key=True, default=lambda: _new_id("wtask"))

    user_id = Column(String(140), nullable=False, index=True)
    workspace_id = Column(String(140), nullable=False, index=True)
    device_id = Column(String(140), nullable=True)

    action_type = Column(String(60), nullable=False)
    action_payload_json = Column(Text, nullable=True)

    status = Column(String(30), nullable=False, default=TASK_QUEUED)
    requires_approval = Column(Boolean, nullable=False, default=False)
    approved_by_security = Column(Boolean, nullable=False, default=False)

    result_message = Column(Text, nullable=True)
    error_code = Column(String(120), nullable=True)
    error_details = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_worker_tasks_workspace_status", "workspace_id", "status"),
    )

    @property
    def action_payload(self) -> Dict[str, Any]:
        return _json_loads(self.action_payload_json, {})

    @action_payload.setter
    def action_payload(self, value: Dict[str, Any]) -> None:
        self.action_payload_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "device_id": self.device_id,
            "action_type": self.action_type,
            "action_payload": self.action_payload,
            "status": self.status,
            "requires_approval": bool(self.requires_approval),
            "approved_by_security": bool(self.approved_by_security),
            "result_message": self.result_message,
            "error_code": self.error_code,
            "error_details": self.error_details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class WorkerTaskService:
    """Thin, dependency-free state-transition helper -- no security/memory/
    verification hooks here. Security approval is decided by the CALLER
    (apps/api/routes/system_worker.py::classify_worker_action(), reusing
    apps.api.routes.agents.security_review()) before create() is invoked;
    this service only ever records the outcome, never decides it."""

    @staticmethod
    def create(
        db: Session,
        *,
        user_id: str,
        workspace_id: str,
        action_type: str,
        action_payload: Optional[Dict[str, Any]] = None,
        device_id: Optional[str] = None,
        requires_approval: bool = False,
        approved_by_security: bool = False,
    ) -> WorkerTask:
        status = TASK_APPROVAL_REQUIRED if requires_approval and not approved_by_security else TASK_QUEUED

        task = WorkerTask(
            task_id=_new_id("wtask"),
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            action_type=action_type,
            status=status,
            requires_approval=requires_approval,
            approved_by_security=approved_by_security,
        )
        task.action_payload = action_payload or {}
        db.add(task)
        db.flush()
        return task

    @staticmethod
    def list_queued_for_workspace(
        db: Session,
        *,
        workspace_id: str,
        limit: int = 5,
    ) -> List[WorkerTask]:
        return (
            db.query(WorkerTask)
            .filter(
                WorkerTask.workspace_id == workspace_id,
                WorkerTask.status == TASK_QUEUED,
            )
            .order_by(WorkerTask.created_at.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_for_workspace(
        db: Session,
        *,
        task_id: str,
        workspace_id: str,
    ) -> Optional[WorkerTask]:
        return (
            db.query(WorkerTask)
            .filter(
                WorkerTask.task_id == task_id,
                WorkerTask.workspace_id == workspace_id,
            )
            .first()
        )

    @staticmethod
    def recent_active_count_for_workspace(
        db: Session,
        *,
        workspace_id: str,
        since: datetime,
    ) -> int:
        return (
            db.query(WorkerTask)
            .filter(
                WorkerTask.workspace_id == workspace_id,
                WorkerTask.status.in_(ACTIVE_WORKER_TASK_STATUSES),
                WorkerTask.updated_at >= since,
            )
            .count()
        )

    @staticmethod
    def mark_running(db: Session, task: WorkerTask, *, device_id: Optional[str] = None) -> WorkerTask:
        task.status = TASK_RUNNING
        task.started_at = _utc_now()
        if device_id:
            task.device_id = device_id
        db.add(task)
        db.flush()
        return task

    @staticmethod
    def mark_completed(
        db: Session,
        task: WorkerTask,
        *,
        result_message: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> WorkerTask:
        task.status = TASK_COMPLETED
        task.result_message = result_message
        task.completed_at = _utc_now()
        if device_id:
            task.device_id = device_id
        db.add(task)
        db.flush()
        return task

    @staticmethod
    def mark_failed(
        db: Session,
        task: WorkerTask,
        *,
        error_code: Optional[str] = None,
        error_details: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> WorkerTask:
        task.status = TASK_FAILED
        task.error_code = error_code
        task.error_details = error_details
        task.completed_at = _utc_now()
        if device_id:
            task.device_id = device_id
        db.add(task)
        db.flush()
        return task


__all__ = [
    "WorkerTask",
    "WorkerTaskService",
    "TASK_QUEUED",
    "TASK_RUNNING",
    "TASK_COMPLETED",
    "TASK_FAILED",
    "TASK_BLOCKED",
    "TASK_APPROVAL_REQUIRED",
    "VALID_WORKER_TASK_STATUSES",
    "ACTIVE_WORKER_TASK_STATUSES",
]
