"""
database/models/system_worker_event.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, persisted worker telemetry -- apps/worker_nodes/windows/windows_worker.py
::record_event() has always POSTed to /system/worker/events (device
registration, heartbeats, task lifecycle, pause/resume/stop, permission
denials) but that route never existed server-side until now, so every one
of those calls 404'd (fail_silently=True on the worker's side kept it from
crashing, but the backend logged a 404 on every single one). This table is
the real persistence layer POST /system/worker/events writes to.

Mirrors database/models/worker_task.py's style and SaaS-isolation
convention exactly: every row is scoped by (user_id, workspace_id), a
plain Column-based model (not the heavier SQLAlchemy 2.0 Mapped style
database/models/agent_event.py uses for the broader agent-lifecycle event
stream -- that model's schema is shaped around agent actions/WebSocket
delivery, not raw device-worker telemetry, so this stays a separate,
purpose-built table rather than overloading it).
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import Column, DateTime, Index, String, Text
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/system_worker_event.py. "
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


logger = logging.getLogger("william.database.models.system_worker_event")
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


EVENT_LEVEL_INFO = "info"
EVENT_LEVEL_WARNING = "warning"
EVENT_LEVEL_ERROR = "error"

VALID_EVENT_LEVELS = {EVENT_LEVEL_INFO, EVENT_LEVEL_WARNING, EVENT_LEVEL_ERROR}

# event_type values that honestly default to a non-"info" level when the
# caller doesn't specify one explicitly -- matches
# apps/worker_nodes/windows/windows_worker.py::WorkerEventType's own
# vocabulary (ERROR/TASK_FAILED/PERMISSION_DENIED/SECURITY_REQUIRED).
_ERROR_EVENT_TYPES = {"error", "task_failed"}
_WARNING_EVENT_TYPES = {"permission_denied", "security_required", "task_rejected", "task_cancelled"}


def infer_level(event_type: str) -> str:
    normalized = (event_type or "").strip().lower()
    if normalized in _ERROR_EVENT_TYPES:
        return EVENT_LEVEL_ERROR
    if normalized in _WARNING_EVENT_TYPES:
        return EVENT_LEVEL_WARNING
    return EVENT_LEVEL_INFO


class SystemWorkerEvent(Base):
    __tablename__ = "system_worker_events"

    event_id = Column(String(80), primary_key=True, default=lambda: _new_id("wevt"))

    user_id = Column(String(140), nullable=False, index=True)
    workspace_id = Column(String(140), nullable=False, index=True)
    device_id = Column(String(140), nullable=True)

    event_type = Column(String(80), nullable=False)
    message = Column(Text, nullable=True)
    level = Column(String(20), nullable=False, default=EVENT_LEVEL_INFO)

    worker_task_id = Column(String(80), nullable=True)
    action_type = Column(String(60), nullable=True)
    metadata_json = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    __table_args__ = (
        Index("ix_system_worker_events_workspace_created", "workspace_id", "created_at"),
    )

    @property
    def metadata_(self) -> Dict[str, Any]:
        return _json_loads(self.metadata_json, {})

    @metadata_.setter
    def metadata_(self, value: Dict[str, Any]) -> None:
        self.metadata_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "message": self.message,
            "level": self.level,
            "worker_task_id": self.worker_task_id,
            "action_type": self.action_type,
            "metadata": self.metadata_,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SystemWorkerEventService:
    """Thin, dependency-free create/list helper -- same shape as
    database/models/worker_task.py::WorkerTaskService. No retention/
    pruning policy here yet (a future phase's concern); every call site
    today writes a small number of short-lived telemetry rows per
    heartbeat/task cycle, not a high-volume stream."""

    @staticmethod
    def create(
        db: Session,
        *,
        user_id: str,
        workspace_id: str,
        event_type: str,
        message: Optional[str] = None,
        level: Optional[str] = None,
        device_id: Optional[str] = None,
        worker_task_id: Optional[str] = None,
        action_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SystemWorkerEvent:
        clean_level = level if level in VALID_EVENT_LEVELS else infer_level(event_type)

        event = SystemWorkerEvent(
            event_id=_new_id("wevt"),
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            event_type=event_type,
            message=message,
            level=clean_level,
            worker_task_id=worker_task_id,
            action_type=action_type,
        )
        event.metadata_ = metadata or {}
        db.add(event)
        db.flush()
        return event

    @staticmethod
    def list_recent_for_workspace(
        db: Session,
        *,
        workspace_id: str,
        limit: int = 50,
    ) -> List[SystemWorkerEvent]:
        return (
            db.query(SystemWorkerEvent)
            .filter(SystemWorkerEvent.workspace_id == workspace_id)
            .order_by(SystemWorkerEvent.created_at.desc())
            .limit(max(1, min(limit, 200)))
            .all()
        )


__all__ = [
    "SystemWorkerEvent",
    "SystemWorkerEventService",
    "EVENT_LEVEL_INFO",
    "EVENT_LEVEL_WARNING",
    "EVENT_LEVEL_ERROR",
    "VALID_EVENT_LEVELS",
    "infer_level",
]
