"""
core/task_manager.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Tracks task lifecycle, statuses, progress, retries, failures,
    parent/child tasks, and user/workspace isolation.

This TaskManager connects:
    - Master Agent: stores and updates planned/executed task lifecycle.
    - Router: provides task records before/after routing execution.
    - Security Agent: flags sensitive tasks requiring security approval.
    - Verification Agent: prepares verification payloads for completed tasks.
    - Memory Agent: prepares memory-compatible task context.
    - Dashboard/API: exposes task history, progress, status, failures, retries.
    - SaaS Layer: enforces strict user_id/workspace_id isolation.

Import-safe:
    This file uses safe fallback classes so it can be imported even before
    the entire William/Jarvis project is fully created.
"""

from __future__ import annotations

import copy
import logging
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Optional imports with safe fallbacks
# =============================================================================

try:
    from core.context import TaskContext  # type: ignore
except Exception:  # pragma: no cover
    @dataclass
    class TaskContext:
        """
        Fallback TaskContext.

        Real implementation should live in core/context.py.
        """
        user_id: Optional[Union[str, int]] = None
        workspace_id: Optional[Union[str, int]] = None
        role: Optional[str] = None
        permissions: List[str] = field(default_factory=list)
        subscription_plan: Optional[str] = None
        request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
        session_id: Optional[str] = None
        metadata: Dict[str, Any] = field(default_factory=dict)

        def to_dict(self) -> Dict[str, Any]:
            return {
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "role": self.role,
                "permissions": list(self.permissions),
                "subscription_plan": self.subscription_plan,
                "request_id": self.request_id,
                "session_id": self.session_id,
                "metadata": dict(self.metadata or {}),
            }


# =============================================================================
# Enums
# =============================================================================

class TaskStatus(str, Enum):
    """
    Task lifecycle status values.

    These values are dashboard/API safe and should remain stable.
    """

    CREATED = "created"
    QUEUED = "queued"
    PLANNED = "planned"
    ROUTING = "routing"
    SECURITY_CHECK = "security_check"
    SECURITY_BLOCKED = "security_blocked"
    APPROVED = "approved"
    RUNNING = "running"
    WAITING = "waiting"
    RETRYING = "retrying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    PARTIAL = "partial"
    EXPIRED = "expired"


class TaskPriority(str, Enum):
    """
    Task priority values.
    """

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class TaskRiskLevel(str, Enum):
    """
    Risk level used for Security Agent compatibility.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskEventType(str, Enum):
    """
    Task event types for dashboard analytics, audit logs, and task history.
    """

    CREATED = "task_created"
    UPDATED = "task_updated"
    STATUS_CHANGED = "task_status_changed"
    PROGRESS_UPDATED = "task_progress_updated"
    RETRY_SCHEDULED = "task_retry_scheduled"
    FAILED = "task_failed"
    COMPLETED = "task_completed"
    CANCELLED = "task_cancelled"
    CHILD_ATTACHED = "task_child_attached"
    SECURITY_REQUIRED = "task_security_required"
    VERIFICATION_PREPARED = "task_verification_prepared"
    MEMORY_PREPARED = "task_memory_prepared"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class TaskManagerConfig:
    """
    TaskManager configuration.

    Safe defaults are used for SaaS and dashboard integration.
    """

    strict_workspace_isolation: bool = True
    require_user_workspace_for_user_tasks: bool = True
    default_max_retries: int = 3
    default_retry_delay_seconds: int = 5
    max_progress_value: int = 100
    min_progress_value: int = 0
    keep_history_limit: int = 5000
    emit_events: bool = True
    audit_enabled: bool = True
    verification_enabled: bool = True
    memory_enabled: bool = True
    redact_sensitive_data: bool = True


@dataclass
class TaskEvent:
    """
    A task lifecycle event.
    """

    event_id: str
    task_id: str
    event_type: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ManagedTask:
    """
    Internal task record.

    Designed to be serializable for database, FastAPI, dashboard,
    task history, retry queues, and analytics.
    """

    task_id: str
    task_type: str = "general.task"
    action: Optional[str] = None
    agent: Optional[str] = None
    capability: Optional[str] = None

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None

    status: TaskStatus = TaskStatus.CREATED
    priority: TaskPriority = TaskPriority.NORMAL
    risk_level: TaskRiskLevel = TaskRiskLevel.LOW

    progress: int = 0
    progress_message: str = ""

    input: Dict[str, Any] = field(default_factory=dict)
    output: Any = None
    error: Optional[str] = None

    parent_task_id: Optional[str] = None
    child_task_ids: List[str] = field(default_factory=list)

    requires_security: bool = False
    security_result: Optional[Dict[str, Any]] = None

    verification_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None

    retry_count: int = 0
    max_retries: int = 3
    retry_delay_seconds: int = 5
    next_retry_at: Optional[float] = None

    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    failed_at: Optional[float] = None
    cancelled_at: Optional[float] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["priority"] = self.priority.value
        data["risk_level"] = self.risk_level.value

        if redact:
            data = redact_sensitive_values(data)

        return data


# =============================================================================
# Redaction helpers
# =============================================================================

SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "session_cookie",
}


def redact_sensitive_values(value: Any) -> Any:
    """
    Recursively redact sensitive values.

    Used before emitting dashboard events, audit logs, memory payloads,
    verification payloads, and public API responses.
    """
    if isinstance(value, Mapping):
        clean: Dict[str, Any] = {}
        for key, item in value.items():
            key_lower = str(key).lower()
            if any(secret_key in key_lower for secret_key in SENSITIVE_KEYS):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = redact_sensitive_values(item)
        return clean

    if isinstance(value, list):
        return [redact_sensitive_values(item) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_sensitive_values(item) for item in value)

    return value


# =============================================================================
# TaskManager
# =============================================================================

class TaskManager:
    """
    Tracks task lifecycle for William/Jarvis Core Master Control.

    Responsibilities:
        - Create task records.
        - Enforce user_id/workspace_id isolation.
        - Track statuses and progress.
        - Track retries and failures.
        - Link parent/child tasks.
        - Prepare Verification Agent payloads.
        - Prepare Memory Agent payloads.
        - Emit dashboard-compatible events.
        - Write audit-compatible events.
        - Provide structured JSON-style results.

    Public methods:
        - create_task()
        - update_task()
        - get_task()
        - list_tasks()
        - set_status()
        - update_progress()
        - mark_running()
        - mark_completed()
        - mark_failed()
        - cancel_task()
        - schedule_retry()
        - get_retryable_tasks()
        - attach_child_task()
        - get_task_tree()
        - delete_task()
    """

    def __init__(
        self,
        config: Optional[TaskManagerConfig] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        self.config = config or TaskManagerConfig()
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self._tasks: Dict[str, ManagedTask] = {}
        self._events: List[TaskEvent] = []
        self._lock = threading.RLock()

    # =========================================================================
    # Task creation
    # =========================================================================

    def create_task(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        parent_task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a managed task record.

        This does not execute the task. Router/MasterAgent can call this before
        routing, then update it after execution.
        """
        try:
            task_dict = self._normalize_task(task, context=context)
            if parent_task_id:
                task_dict["parent_task_id"] = parent_task_id

            validation = self._validate_task_context(task_dict, context)
            if not validation.get("success"):
                return validation

            task_id = str(task_dict.get("id") or task_dict.get("task_id") or uuid.uuid4())

            with self._lock:
                if task_id in self._tasks:
                    return self._error_result(
                        message="Task creation failed.",
                        error=f"Task already exists: {task_id}",
                        metadata={"task_id": task_id},
                    )

                managed_task = ManagedTask(
                    task_id=task_id,
                    task_type=str(task_dict.get("type") or "general.task"),
                    action=task_dict.get("action"),
                    agent=task_dict.get("agent") or task_dict.get("agent_name"),
                    capability=task_dict.get("capability"),
                    user_id=task_dict.get("user_id"),
                    workspace_id=task_dict.get("workspace_id"),
                    status=self._parse_status(task_dict.get("status"), TaskStatus.CREATED),
                    priority=self._parse_priority(task_dict.get("priority"), TaskPriority.NORMAL),
                    risk_level=self._get_task_risk_level(task_dict),
                    progress=self._clamp_progress(task_dict.get("progress", 0)),
                    progress_message=str(task_dict.get("progress_message") or ""),
                    input=dict(task_dict.get("input") or {}),
                    output=task_dict.get("output"),
                    error=task_dict.get("error"),
                    parent_task_id=task_dict.get("parent_task_id"),
                    child_task_ids=list(task_dict.get("child_task_ids") or []),
                    requires_security=self._requires_security_check(task_dict),
                    retry_count=int(task_dict.get("retry_count") or 0),
                    max_retries=int(task_dict.get("max_retries") or self.config.default_max_retries),
                    retry_delay_seconds=int(
                        task_dict.get("retry_delay_seconds")
                        or self.config.default_retry_delay_seconds
                    ),
                    metadata=dict(task_dict.get("metadata") or {}),
                )

                self._tasks[task_id] = managed_task

                if managed_task.parent_task_id:
                    self._attach_child_task_locked(
                        parent_task_id=managed_task.parent_task_id,
                        child_task_id=task_id,
                    )

                self._append_event_locked(
                    task=managed_task,
                    event_type=TaskEventType.CREATED,
                    message="Task created.",
                    data={"task": managed_task.to_dict(redact=self.config.redact_sensitive_data)},
                )

            self._emit_agent_event(
                event_type=TaskEventType.CREATED.value,
                payload={
                    "task_id": task_id,
                    "user_id": managed_task.user_id,
                    "workspace_id": managed_task.workspace_id,
                    "status": managed_task.status.value,
                },
            )

            self._log_audit_event(
                action="task_created",
                task=managed_task,
                context=context,
                metadata={"parent_task_id": managed_task.parent_task_id},
            )

            if managed_task.requires_security:
                self._emit_agent_event(
                    event_type=TaskEventType.SECURITY_REQUIRED.value,
                    payload={
                        "task_id": task_id,
                        "risk_level": managed_task.risk_level.value,
                        "user_id": managed_task.user_id,
                        "workspace_id": managed_task.workspace_id,
                    },
                )

            return self._safe_result(
                message="Task created successfully.",
                data={"task": managed_task.to_dict(redact=self.config.redact_sensitive_data)},
                metadata={
                    "task_id": task_id,
                    "requires_security": managed_task.requires_security,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Task creation crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Task retrieval
    # =========================================================================

    def get_task(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Get one task by ID with SaaS isolation check.
        """
        try:
            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Task not found.",
                        error=f"No task exists with id: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                return self._safe_result(
                    message="Task loaded successfully.",
                    data={"task": task.to_dict(redact=self.config.redact_sensitive_data)},
                    metadata={"task_id": task_id},
                )

        except Exception as exc:
            return self._error_result(
                message="Task retrieval crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def list_tasks(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        status: Optional[Union[str, TaskStatus]] = None,
        parent_task_id: Optional[str] = None,
        include_children: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List tasks visible to the provided user/workspace context.
        """
        try:
            status_filter = self._parse_status(status, None) if status else None
            context_dict = self._context_to_dict(context)

            with self._lock:
                visible_tasks: List[ManagedTask] = []

                for task in self._tasks.values():
                    if not self._can_access_record(task, context_dict):
                        continue

                    if status_filter and task.status != status_filter:
                        continue

                    if parent_task_id is not None:
                        if include_children:
                            if task.parent_task_id != parent_task_id and task.task_id != parent_task_id:
                                continue
                        else:
                            if task.parent_task_id != parent_task_id:
                                continue

                    visible_tasks.append(task)

                visible_tasks.sort(key=lambda item: item.created_at, reverse=True)

                safe_offset = max(0, int(offset))
                safe_limit = max(1, int(limit))
                paged = visible_tasks[safe_offset:safe_offset + safe_limit]

                return self._safe_result(
                    message="Tasks loaded successfully.",
                    data={
                        "tasks": [
                            task.to_dict(redact=self.config.redact_sensitive_data)
                            for task in paged
                        ],
                        "pagination": {
                            "total": len(visible_tasks),
                            "limit": safe_limit,
                            "offset": safe_offset,
                            "returned": len(paged),
                        },
                    },
                    metadata={
                        "user_id": context_dict.get("user_id"),
                        "workspace_id": context_dict.get("workspace_id"),
                        "status_filter": status_filter.value if status_filter else None,
                    },
                )

        except Exception as exc:
            return self._error_result(
                message="Task listing crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Task updates
    # =========================================================================

    def update_task(
        self,
        task_id: str,
        updates: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Update allowed task fields.

        Does not allow changing task_id, user_id, or workspace_id after creation
        unless isolation is explicitly disabled.
        """
        try:
            if not isinstance(updates, Mapping):
                return self._error_result(
                    message="Task update failed.",
                    error="Updates must be a dictionary.",
                    metadata={"task_id": task_id},
                )

            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Task update failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                protected_fields = {"task_id", "id"}
                if self.config.strict_workspace_isolation:
                    protected_fields.update({"user_id", "workspace_id"})

                safe_updates = {
                    key: value
                    for key, value in dict(updates).items()
                    if key not in protected_fields
                }

                previous = task.to_dict(redact=True)

                self._apply_updates_locked(task, safe_updates)
                task.updated_at = time.time()

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.UPDATED,
                    message="Task updated.",
                    data={
                        "updates": redact_sensitive_values(safe_updates)
                        if self.config.redact_sensitive_data
                        else safe_updates
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.UPDATED.value,
                payload={
                    "task_id": task_id,
                    "updates": redact_sensitive_values(safe_updates),
                },
            )

            self._log_audit_event(
                action="task_updated",
                task=task,
                context=context,
                metadata={
                    "updates": redact_sensitive_values(safe_updates),
                    "previous_status": previous.get("status"),
                    "new_status": result_task.get("status"),
                },
            )

            return self._safe_result(
                message="Task updated successfully.",
                data={"task": result_task},
                metadata={"task_id": task_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Task update crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def set_status(
        self,
        task_id: str,
        status: Union[str, TaskStatus],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        message: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set task status.
        """
        try:
            new_status = self._parse_status(status, None)
            if not new_status:
                return self._error_result(
                    message="Status update failed.",
                    error=f"Invalid task status: {status}",
                    metadata={"task_id": task_id},
                )

            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Status update failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                previous_status = task.status
                task.status = new_status
                task.updated_at = time.time()

                now = time.time()
                if new_status == TaskStatus.RUNNING and not task.started_at:
                    task.started_at = now
                elif new_status == TaskStatus.COMPLETED:
                    task.completed_at = now
                    task.progress = self.config.max_progress_value
                elif new_status == TaskStatus.FAILED:
                    task.failed_at = now
                elif new_status == TaskStatus.CANCELLED:
                    task.cancelled_at = now

                if message:
                    task.progress_message = message

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.STATUS_CHANGED,
                    message=message or f"Task status changed to {new_status.value}.",
                    data={
                        "previous_status": previous_status.value,
                        "new_status": new_status.value,
                        "metadata": dict(metadata or {}),
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.STATUS_CHANGED.value,
                payload={
                    "task_id": task_id,
                    "previous_status": previous_status.value,
                    "new_status": new_status.value,
                    "message": message,
                },
            )

            self._log_audit_event(
                action="task_status_changed",
                task=task,
                context=context,
                metadata={
                    "previous_status": previous_status.value,
                    "new_status": new_status.value,
                    **dict(metadata or {}),
                },
            )

            return self._safe_result(
                message="Task status updated successfully.",
                data={"task": result_task},
                metadata={
                    "task_id": task_id,
                    "previous_status": previous_status.value,
                    "new_status": new_status.value,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Status update crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def update_progress(
        self,
        task_id: str,
        progress: int,
        message: str = "",
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update task progress from 0 to 100.
        """
        try:
            clean_progress = self._clamp_progress(progress)

            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Progress update failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                previous_progress = task.progress
                task.progress = clean_progress
                task.progress_message = message or task.progress_message
                task.updated_at = time.time()

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.PROGRESS_UPDATED,
                    message=message or f"Task progress updated to {clean_progress}%.",
                    data={
                        "previous_progress": previous_progress,
                        "progress": clean_progress,
                        "metadata": dict(metadata or {}),
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.PROGRESS_UPDATED.value,
                payload={
                    "task_id": task_id,
                    "previous_progress": previous_progress,
                    "progress": clean_progress,
                    "message": message,
                },
            )

            return self._safe_result(
                message="Task progress updated successfully.",
                data={"task": result_task},
                metadata={
                    "task_id": task_id,
                    "progress": clean_progress,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Progress update crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Lifecycle helpers
    # =========================================================================

    def mark_running(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        message: str = "Task is running.",
    ) -> Dict[str, Any]:
        """
        Mark task as running.
        """
        return self.set_status(task_id, TaskStatus.RUNNING, context=context, message=message)

    def mark_completed(
        self,
        task_id: str,
        output: Any = None,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        message: str = "Task completed successfully.",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mark task completed and prepare verification/memory payloads.
        """
        try:
            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Task completion failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                task.output = output
                task.error = None
                task.status = TaskStatus.COMPLETED
                task.progress = self.config.max_progress_value
                task.progress_message = message
                task.completed_at = time.time()
                task.updated_at = time.time()

                task.verification_payload = self._prepare_verification_payload(
                    task=task,
                    result={
                        "success": True,
                        "message": message,
                        "data": output,
                        "error": None,
                    },
                    context=context,
                )

                task.memory_payload = self._prepare_memory_payload(
                    task=task,
                    result={
                        "success": True,
                        "message": message,
                        "data": output,
                        "error": None,
                    },
                    context=context,
                )

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.COMPLETED,
                    message=message,
                    data={
                        "output_preview": self._safe_data_preview(output),
                        "metadata": dict(metadata or {}),
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.COMPLETED.value,
                payload={
                    "task_id": task_id,
                    "message": message,
                    "verification_payload": task.verification_payload,
                    "memory_payload": task.memory_payload,
                },
            )

            self._emit_agent_event(
                event_type=TaskEventType.VERIFICATION_PREPARED.value,
                payload={
                    "task_id": task_id,
                    "verification_payload": task.verification_payload,
                },
            )

            self._emit_agent_event(
                event_type=TaskEventType.MEMORY_PREPARED.value,
                payload={
                    "task_id": task_id,
                    "memory_payload": task.memory_payload,
                },
            )

            self._log_audit_event(
                action="task_completed",
                task=task,
                context=context,
                metadata={
                    "message": message,
                    **dict(metadata or {}),
                },
            )

            return self._safe_result(
                message=message,
                data={
                    "task": result_task,
                    "verification_payload": task.verification_payload,
                    "memory_payload": task.memory_payload,
                },
                metadata={"task_id": task_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Task completion crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def mark_failed(
        self,
        task_id: str,
        error: Union[str, Exception],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        message: str = "Task failed.",
        retryable: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mark task failed and optionally schedule retry.
        """
        try:
            error_text = str(error)

            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Task failure update failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                task.error = error_text
                task.status = TaskStatus.FAILED
                task.progress_message = message
                task.failed_at = time.time()
                task.updated_at = time.time()

                can_retry = retryable and task.retry_count < task.max_retries

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.FAILED,
                    message=message,
                    data={
                        "error": error_text,
                        "retryable": can_retry,
                        "retry_count": task.retry_count,
                        "max_retries": task.max_retries,
                        "metadata": dict(metadata or {}),
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.FAILED.value,
                payload={
                    "task_id": task_id,
                    "error": error_text,
                    "retryable": can_retry,
                    "retry_count": task.retry_count,
                    "max_retries": task.max_retries,
                },
            )

            self._log_audit_event(
                action="task_failed",
                task=task,
                context=context,
                metadata={
                    "error": error_text,
                    "retryable": can_retry,
                    **dict(metadata or {}),
                },
            )

            response_data: Dict[str, Any] = {
                "task": result_task,
                "retryable": can_retry,
            }

            if can_retry:
                retry_result = self.schedule_retry(task_id, context=context)
                response_data["retry"] = retry_result

            return self._safe_result(
                success=False,
                message=message,
                data=response_data,
                error=error_text,
                metadata={
                    "task_id": task_id,
                    "retryable": can_retry,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Task failure update crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def cancel_task(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        reason: str = "Task cancelled.",
        cancel_children: bool = True,
    ) -> Dict[str, Any]:
        """
        Cancel task and optionally cancel child tasks.
        """
        try:
            cancelled_children: List[str] = []

            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Task cancellation failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                task.status = TaskStatus.CANCELLED
                task.progress_message = reason
                task.cancelled_at = time.time()
                task.updated_at = time.time()

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.CANCELLED,
                    message=reason,
                    data={"cancel_children": cancel_children},
                )

                if cancel_children:
                    for child_id in list(task.child_task_ids):
                        child = self._tasks.get(child_id)
                        if not child:
                            continue
                        if not self._can_access_record(child, self._context_to_dict(context)):
                            continue

                        child.status = TaskStatus.CANCELLED
                        child.progress_message = f"Cancelled because parent task {task_id} was cancelled."
                        child.cancelled_at = time.time()
                        child.updated_at = time.time()
                        cancelled_children.append(child_id)

                        self._append_event_locked(
                            task=child,
                            event_type=TaskEventType.CANCELLED,
                            message=child.progress_message,
                            data={"parent_task_id": task_id},
                        )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.CANCELLED.value,
                payload={
                    "task_id": task_id,
                    "reason": reason,
                    "cancelled_children": cancelled_children,
                },
            )

            self._log_audit_event(
                action="task_cancelled",
                task=task,
                context=context,
                metadata={
                    "reason": reason,
                    "cancelled_children": cancelled_children,
                },
            )

            return self._safe_result(
                message="Task cancelled successfully.",
                data={
                    "task": result_task,
                    "cancelled_children": cancelled_children,
                },
                metadata={"task_id": task_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Task cancellation crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Retry management
    # =========================================================================

    def schedule_retry(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        delay_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Schedule task retry.
        """
        try:
            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Retry scheduling failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                if task.retry_count >= task.max_retries:
                    return self._error_result(
                        message="Retry scheduling failed.",
                        error="Task has reached maximum retry limit.",
                        metadata={
                            "task_id": task_id,
                            "retry_count": task.retry_count,
                            "max_retries": task.max_retries,
                        },
                    )

                delay = int(delay_seconds if delay_seconds is not None else task.retry_delay_seconds)
                delay = max(0, delay)

                task.retry_count += 1
                task.next_retry_at = time.time() + delay
                task.status = TaskStatus.RETRYING
                task.updated_at = time.time()

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.RETRY_SCHEDULED,
                    message=f"Task retry scheduled in {delay} seconds.",
                    data={
                        "retry_count": task.retry_count,
                        "max_retries": task.max_retries,
                        "next_retry_at": task.next_retry_at,
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.RETRY_SCHEDULED.value,
                payload={
                    "task_id": task_id,
                    "retry_count": task.retry_count,
                    "max_retries": task.max_retries,
                    "next_retry_at": task.next_retry_at,
                },
            )

            return self._safe_result(
                message="Task retry scheduled successfully.",
                data={"task": result_task},
                metadata={
                    "task_id": task_id,
                    "retry_count": task.retry_count,
                    "next_retry_at": task.next_retry_at,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Retry scheduling crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def get_retryable_tasks(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        now: Optional[float] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return retryable tasks whose next_retry_at is due.
        """
        try:
            current_time = now if now is not None else time.time()
            context_dict = self._context_to_dict(context)

            with self._lock:
                retryable: List[ManagedTask] = []

                for task in self._tasks.values():
                    if not self._can_access_record(task, context_dict):
                        continue

                    if task.status != TaskStatus.RETRYING:
                        continue

                    if task.next_retry_at is None:
                        continue

                    if task.next_retry_at <= current_time:
                        retryable.append(task)

                retryable.sort(key=lambda item: item.next_retry_at or 0)
                paged = retryable[:max(1, int(limit))]

                return self._safe_result(
                    message="Retryable tasks loaded successfully.",
                    data={
                        "tasks": [
                            task.to_dict(redact=self.config.redact_sensitive_data)
                            for task in paged
                        ],
                        "count": len(paged),
                    },
                    metadata={
                        "total_retryable": len(retryable),
                        "checked_at": current_time,
                    },
                )

        except Exception as exc:
            return self._error_result(
                message="Retryable task lookup crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    def reset_for_retry(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Reset retrying task to queued status for Router/MasterAgent execution.
        """
        try:
            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Retry reset failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                isolation = self._validate_record_access(task, context)
                if not isolation.get("success"):
                    return isolation

                if task.status != TaskStatus.RETRYING:
                    return self._error_result(
                        message="Retry reset failed.",
                        error="Task is not in retrying status.",
                        metadata={
                            "task_id": task_id,
                            "status": task.status.value,
                        },
                    )

                task.status = TaskStatus.QUEUED
                task.next_retry_at = None
                task.progress_message = "Task reset for retry execution."
                task.updated_at = time.time()

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.STATUS_CHANGED,
                    message=task.progress_message,
                    data={"new_status": task.status.value},
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            return self._safe_result(
                message="Task reset for retry successfully.",
                data={"task": result_task},
                metadata={"task_id": task_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Retry reset crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Parent/child tasks
    # =========================================================================

    def attach_child_task(
        self,
        parent_task_id: str,
        child_task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Attach one task as child of another task.
        """
        try:
            with self._lock:
                parent = self._tasks.get(str(parent_task_id))
                child = self._tasks.get(str(child_task_id))

                if not parent:
                    return self._error_result(
                        message="Child task attachment failed.",
                        error=f"Parent task not found: {parent_task_id}",
                        metadata={"parent_task_id": parent_task_id},
                    )

                if not child:
                    return self._error_result(
                        message="Child task attachment failed.",
                        error=f"Child task not found: {child_task_id}",
                        metadata={"child_task_id": child_task_id},
                    )

                parent_access = self._validate_record_access(parent, context)
                if not parent_access.get("success"):
                    return parent_access

                child_access = self._validate_record_access(child, context)
                if not child_access.get("success"):
                    return child_access

                if str(parent.user_id) != str(child.user_id) or str(parent.workspace_id) != str(child.workspace_id):
                    return self._error_result(
                        message="Child task attachment failed.",
                        error="Parent and child task must belong to same user/workspace.",
                        metadata={
                            "parent_user_id": parent.user_id,
                            "parent_workspace_id": parent.workspace_id,
                            "child_user_id": child.user_id,
                            "child_workspace_id": child.workspace_id,
                        },
                    )

                self._attach_child_task_locked(parent_task_id, child_task_id)

                self._append_event_locked(
                    task=parent,
                    event_type=TaskEventType.CHILD_ATTACHED,
                    message="Child task attached.",
                    data={"child_task_id": child_task_id},
                )

                result_parent = parent.to_dict(redact=self.config.redact_sensitive_data)
                result_child = child.to_dict(redact=self.config.redact_sensitive_data)

            self._emit_agent_event(
                event_type=TaskEventType.CHILD_ATTACHED.value,
                payload={
                    "parent_task_id": parent_task_id,
                    "child_task_id": child_task_id,
                },
            )

            return self._safe_result(
                message="Child task attached successfully.",
                data={
                    "parent": result_parent,
                    "child": result_child,
                },
                metadata={
                    "parent_task_id": parent_task_id,
                    "child_task_id": child_task_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Child task attachment crashed.",
                error=str(exc),
                metadata={
                    "parent_task_id": parent_task_id,
                    "child_task_id": child_task_id,
                    "traceback": traceback.format_exc(),
                },
            )

    def get_task_tree(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Return task with nested child task tree.
        """
        try:
            with self._lock:
                root = self._tasks.get(str(task_id))
                if not root:
                    return self._error_result(
                        message="Task tree lookup failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                access = self._validate_record_access(root, context)
                if not access.get("success"):
                    return access

                tree = self._build_task_tree_locked(root, self._context_to_dict(context))

                return self._safe_result(
                    message="Task tree loaded successfully.",
                    data={"tree": tree},
                    metadata={"task_id": task_id},
                )

        except Exception as exc:
            return self._error_result(
                message="Task tree lookup crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Security, verification, memory compatibility hooks
    # =========================================================================

    def _requires_security_check(self, task: Mapping[str, Any]) -> bool:
        """
        Decide whether a task requires Security Agent approval.
        """
        if bool(task.get("requires_security")):
            return True

        risk_level = self._get_task_risk_level(task)
        if risk_level in (TaskRiskLevel.HIGH, TaskRiskLevel.CRITICAL):
            return True

        scan_text = " ".join(
            [
                str(task.get("type") or ""),
                str(task.get("action") or ""),
                str(task.get("agent") or ""),
                str(task.get("capability") or ""),
            ]
        ).lower()

        sensitive_terms = {
            "delete",
            "destroy",
            "remove",
            "payment",
            "transfer",
            "finance",
            "charge",
            "call",
            "send",
            "email",
            "message",
            "browser_purchase",
            "system_command",
            "shell",
            "terminal",
            "file_delete",
            "permission",
            "credential",
            "secret",
            "token",
            "oauth",
        }

        return any(term in scan_text for term in sensitive_terms)

    def _request_security_approval(
        self,
        task_id: str,
        security_result: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Store Security Agent approval/rejection result.

        This does not call the Security Agent directly. Router/SafetyBridge can call
        Security Agent, then save the result here.
        """
        try:
            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Security result update failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                access = self._validate_record_access(task, context)
                if not access.get("success"):
                    return access

                clean_result = dict(security_result or {})
                task.security_result = (
                    redact_sensitive_values(clean_result)
                    if self.config.redact_sensitive_data
                    else clean_result
                )

                approved = bool(
                    clean_result.get("approved") is True
                    or clean_result.get("allowed") is True
                    or clean_result.get("success") is True
                )

                task.status = TaskStatus.APPROVED if approved else TaskStatus.SECURITY_BLOCKED
                task.updated_at = time.time()

                self._append_event_locked(
                    task=task,
                    event_type=TaskEventType.SECURITY_REQUIRED,
                    message="Security result stored.",
                    data={
                        "approved": approved,
                        "security_result": task.security_result,
                    },
                )

                result_task = task.to_dict(redact=self.config.redact_sensitive_data)

            return self._safe_result(
                success=approved,
                message=(
                    "Security approval stored successfully."
                    if approved
                    else "Security rejection stored successfully."
                ),
                data={"task": result_task},
                error=None if approved else "Task was not approved by Security Agent.",
                metadata={
                    "task_id": task_id,
                    "approved": approved,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Security result update crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def _prepare_verification_payload(
        self,
        task: ManagedTask,
        result: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload for a completed task.
        """
        context_dict = self._context_to_dict(context)

        payload = {
            "id": f"verify-{task.task_id}",
            "type": "verification.review",
            "action": "verify_task_result",
            "user_id": context_dict.get("user_id") or task.user_id,
            "workspace_id": context_dict.get("workspace_id") or task.workspace_id,
            "input": {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "agent": task.agent,
                "capability": task.capability,
                "success": bool(result.get("success")),
                "message": result.get("message"),
                "error": result.get("error"),
                "result_preview": self._safe_data_preview(result.get("data")),
            },
            "metadata": {
                "source": "core.task_manager",
                "created_at": time.time(),
                "requires_security": task.requires_security,
                "risk_level": task.risk_level.value,
            },
        }

        return redact_sensitive_values(payload) if self.config.redact_sensitive_data else payload

    def _prepare_memory_payload(
        self,
        task: ManagedTask,
        result: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload for useful context.

        Always scoped by user_id/workspace_id to prevent data mixing.
        """
        context_dict = self._context_to_dict(context)

        payload = {
            "id": f"memory-{task.task_id}",
            "type": "memory.store_candidate",
            "action": "prepare_memory_candidate",
            "user_id": context_dict.get("user_id") or task.user_id,
            "workspace_id": context_dict.get("workspace_id") or task.workspace_id,
            "input": {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "agent": task.agent,
                "capability": task.capability,
                "useful_context": {
                    "input_preview": self._safe_data_preview(task.input),
                    "output_preview": self._safe_data_preview(result.get("data")),
                    "message": result.get("message"),
                },
            },
            "metadata": {
                "source": "core.task_manager",
                "created_at": time.time(),
                "memory_scope": "workspace",
            },
        }

        return redact_sensitive_values(payload) if self.config.redact_sensitive_data else payload

    # =========================================================================
    # Events and audit
    # =========================================================================

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API-compatible event.

        Safe no-op if no callback is configured.
        """
        if not self.config.emit_events:
            return

        event = {
            "id": str(uuid.uuid4()),
            "event_type": event_type,
            "source": "core.task_manager",
            "payload": redact_sensitive_values(dict(payload or {}))
            if self.config.redact_sensitive_data
            else dict(payload or {}),
            "timestamp": time.time(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
            else:
                logger.debug("TaskManager event: %s", event)
        except Exception:
            logger.exception("TaskManager event callback failed.")

    def _log_audit_event(
        self,
        action: str,
        task: Optional[ManagedTask] = None,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Write audit-compatible event.

        Safe no-op if audit callback is not configured.
        """
        if not self.config.audit_enabled:
            return

        audit_event = {
            "id": str(uuid.uuid4()),
            "action": action,
            "source": "core.task_manager",
            "task_id": task.task_id if task else None,
            "task_type": task.task_type if task else None,
            "user_id": task.user_id if task else self._context_to_dict(context).get("user_id"),
            "workspace_id": task.workspace_id if task else self._context_to_dict(context).get("workspace_id"),
            "context": self._context_to_dict(context),
            "metadata": dict(metadata or {}),
            "timestamp": time.time(),
        }

        if self.config.redact_sensitive_data:
            audit_event = redact_sensitive_values(audit_event)

        try:
            if self.audit_callback:
                self.audit_callback(audit_event)
            else:
                logger.info("TaskManager audit event: %s", audit_event)
        except Exception:
            logger.exception("TaskManager audit callback failed.")

    def get_events(
        self,
        task_id: Optional[str] = None,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get task events visible to the current user/workspace.
        """
        try:
            context_dict = self._context_to_dict(context)

            with self._lock:
                events: List[TaskEvent] = []

                for event in self._events:
                    if task_id and event.task_id != task_id:
                        continue

                    if context_dict.get("user_id") and str(event.user_id) != str(context_dict.get("user_id")):
                        continue

                    if context_dict.get("workspace_id") and str(event.workspace_id) != str(context_dict.get("workspace_id")):
                        continue

                    events.append(event)

                events.sort(key=lambda item: item.created_at, reverse=True)
                safe_limit = max(1, int(limit))
                paged = events[:safe_limit]

                return self._safe_result(
                    message="Task events loaded successfully.",
                    data={
                        "events": [
                            redact_sensitive_values(event.to_dict())
                            if self.config.redact_sensitive_data
                            else event.to_dict()
                            for event in paged
                        ],
                        "count": len(paged),
                    },
                    metadata={
                        "task_id": task_id,
                        "total_matching": len(events),
                    },
                )

        except Exception as exc:
            return self._error_result(
                message="Task events lookup crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Delete / cleanup
    # =========================================================================

    def delete_task(
        self,
        task_id: str,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        delete_children: bool = False,
    ) -> Dict[str, Any]:
        """
        Delete task from in-memory manager.

        Production DB systems may prefer soft-delete. This helper is useful for
        tests and temporary task queues.
        """
        try:
            deleted_ids: List[str] = []

            with self._lock:
                task = self._tasks.get(str(task_id))
                if not task:
                    return self._error_result(
                        message="Task deletion failed.",
                        error=f"Task not found: {task_id}",
                        metadata={"task_id": task_id},
                    )

                access = self._validate_record_access(task, context)
                if not access.get("success"):
                    return access

                if task.child_task_ids and not delete_children:
                    return self._error_result(
                        message="Task deletion failed.",
                        error="Task has child tasks. Set delete_children=True to delete tree.",
                        metadata={
                            "task_id": task_id,
                            "child_task_ids": list(task.child_task_ids),
                        },
                    )

                if delete_children:
                    for child_id in list(task.child_task_ids):
                        if child_id in self._tasks:
                            child = self._tasks[child_id]
                            if self._can_access_record(child, self._context_to_dict(context)):
                                deleted_ids.append(child_id)
                                del self._tasks[child_id]

                if task.parent_task_id and task.parent_task_id in self._tasks:
                    parent = self._tasks[task.parent_task_id]
                    if task_id in parent.child_task_ids:
                        parent.child_task_ids.remove(task_id)
                        parent.updated_at = time.time()

                deleted_ids.append(task_id)
                del self._tasks[task_id]

            self._emit_agent_event(
                event_type="task_deleted",
                payload={
                    "task_id": task_id,
                    "deleted_ids": deleted_ids,
                },
            )

            self._log_audit_event(
                action="task_deleted",
                task=task,
                context=context,
                metadata={
                    "deleted_ids": deleted_ids,
                    "delete_children": delete_children,
                },
            )

            return self._safe_result(
                message="Task deleted successfully.",
                data={"deleted_ids": deleted_ids},
                metadata={"task_id": task_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Task deletion crashed.",
                error=str(exc),
                metadata={"task_id": task_id, "traceback": traceback.format_exc()},
            )

    def clear_all(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Clear tasks visible to provided context.

        If no context is provided, clears all in-memory records.
        Useful for tests. Production systems should restrict this.
        """
        try:
            context_dict = self._context_to_dict(context)

            with self._lock:
                if not context_dict:
                    task_count = len(self._tasks)
                    event_count = len(self._events)
                    self._tasks.clear()
                    self._events.clear()

                    return self._safe_result(
                        message="All in-memory tasks and events cleared.",
                        data={
                            "tasks_cleared": task_count,
                            "events_cleared": event_count,
                        },
                    )

                delete_ids = [
                    task_id
                    for task_id, task in self._tasks.items()
                    if self._can_access_record(task, context_dict)
                ]

                for task_id in delete_ids:
                    self._tasks.pop(task_id, None)

                self._events = [
                    event
                    for event in self._events
                    if not (
                        str(event.user_id) == str(context_dict.get("user_id"))
                        and str(event.workspace_id) == str(context_dict.get("workspace_id"))
                    )
                ]

            return self._safe_result(
                message="Scoped in-memory tasks cleared.",
                data={"tasks_cleared": len(delete_ids)},
                metadata={
                    "user_id": context_dict.get("user_id"),
                    "workspace_id": context_dict.get("workspace_id"),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Task cleanup crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Validate user/workspace isolation for task creation and updates.
        """
        try:
            task_dict = dict(task or {})
            context_dict = self._context_to_dict(context)

            user_id = task_dict.get("user_id") or context_dict.get("user_id")
            workspace_id = task_dict.get("workspace_id") or context_dict.get("workspace_id")

            user_specific = bool(
                task_dict.get("user_specific", True)
                or task_dict.get("requires_user_context", True)
                or user_id
                or workspace_id
            )

            if self.config.require_user_workspace_for_user_tasks and user_specific:
                if user_id in (None, "", 0, "0"):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Missing user_id for user-specific task.",
                        metadata={"task_id": task_dict.get("id") or task_dict.get("task_id")},
                    )

                if workspace_id in (None, "", 0, "0"):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Missing workspace_id for user-specific task.",
                        metadata={"task_id": task_dict.get("id") or task_dict.get("task_id")},
                    )

            if self.config.strict_workspace_isolation:
                task_user_id = task_dict.get("user_id")
                task_workspace_id = task_dict.get("workspace_id")

                if task_user_id and context_dict.get("user_id") and str(task_user_id) != str(context_dict["user_id"]):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Task user_id does not match context user_id.",
                        metadata={
                            "task_user_id": task_user_id,
                            "context_user_id": context_dict.get("user_id"),
                        },
                    )

                if (
                    task_workspace_id
                    and context_dict.get("workspace_id")
                    and str(task_workspace_id) != str(context_dict["workspace_id"])
                ):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Task workspace_id does not match context workspace_id.",
                        metadata={
                            "task_workspace_id": task_workspace_id,
                            "context_workspace_id": context_dict.get("workspace_id"),
                        },
                    )

            return self._safe_result(
                message="Task context validated successfully.",
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "user_specific": user_specific,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Task context validation crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    def _safe_result(
        self,
        message: str = "Success.",
        data: Any = None,
        error: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[str] = None,
        data: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """
        return {
            "success": False,
            "message": message,
            "data": data,
            "error": error or message,
            "metadata": dict(metadata or {}),
        }

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _normalize_task(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize incoming task shape.
        """
        task_dict = dict(task or {})
        context_dict = self._context_to_dict(context)

        task_id = task_dict.get("id") or task_dict.get("task_id") or str(uuid.uuid4())
        task_dict["id"] = str(task_id)
        task_dict["task_id"] = str(task_id)

        if not task_dict.get("type"):
            task_dict["type"] = str(task_dict.get("action") or "general.task")

        if "input" not in task_dict or not isinstance(task_dict.get("input"), Mapping):
            task_dict["input"] = {}

        if "metadata" not in task_dict or not isinstance(task_dict.get("metadata"), Mapping):
            task_dict["metadata"] = {}

        task_dict["user_id"] = task_dict.get("user_id") or context_dict.get("user_id")
        task_dict["workspace_id"] = task_dict.get("workspace_id") or context_dict.get("workspace_id")

        return task_dict

    def _context_to_dict(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convert TaskContext or mapping into dictionary.
        """
        if context is None:
            return {}

        if isinstance(context, Mapping):
            return dict(context)

        if hasattr(context, "to_dict") and callable(getattr(context, "to_dict")):
            try:
                return dict(context.to_dict())
            except Exception:
                logger.debug("context.to_dict() failed.", exc_info=True)

        data: Dict[str, Any] = {}
        for key in [
            "user_id",
            "workspace_id",
            "role",
            "permissions",
            "subscription_plan",
            "request_id",
            "session_id",
            "metadata",
        ]:
            if hasattr(context, key):
                data[key] = getattr(context, key)

        return data

    def _parse_status(
        self,
        value: Optional[Union[str, TaskStatus]],
        default: Optional[TaskStatus],
    ) -> Optional[TaskStatus]:
        """
        Parse task status safely.
        """
        if isinstance(value, TaskStatus):
            return value

        if value is None:
            return default

        try:
            return TaskStatus(str(value).lower())
        except Exception:
            return default

    def _parse_priority(
        self,
        value: Optional[Union[str, TaskPriority]],
        default: TaskPriority,
    ) -> TaskPriority:
        """
        Parse priority safely.
        """
        if isinstance(value, TaskPriority):
            return value

        if value is None:
            return default

        try:
            return TaskPriority(str(value).lower())
        except Exception:
            return default

    def _get_task_risk_level(self, task: Mapping[str, Any]) -> TaskRiskLevel:
        """
        Resolve risk level from explicit value or task text.
        """
        raw = str(task.get("risk_level") or "").lower().strip()
        if raw:
            try:
                return TaskRiskLevel(raw)
            except Exception:
                pass

        scan_text = " ".join(
            [
                str(task.get("type") or ""),
                str(task.get("action") or ""),
                str(task.get("agent") or ""),
                str(task.get("capability") or ""),
            ]
        ).lower()

        critical_terms = {"delete_account", "credential", "secret", "token", "private_key"}
        high_terms = {"delete", "payment", "transfer", "finance", "call", "send_email", "shell"}
        medium_terms = {"browser", "message", "file_write", "external_api", "oauth"}

        if any(term in scan_text for term in critical_terms):
            return TaskRiskLevel.CRITICAL

        if any(term in scan_text for term in high_terms):
            return TaskRiskLevel.HIGH

        if any(term in scan_text for term in medium_terms):
            return TaskRiskLevel.MEDIUM

        return TaskRiskLevel.LOW

    def _clamp_progress(self, progress: Any) -> int:
        """
        Clamp progress to configured min/max.
        """
        try:
            value = int(progress)
        except Exception:
            value = 0

        return max(self.config.min_progress_value, min(self.config.max_progress_value, value))

    def _apply_updates_locked(self, task: ManagedTask, updates: Mapping[str, Any]) -> None:
        """
        Apply safe updates to ManagedTask.

        Caller must hold lock.
        """
        allowed_fields = {
            "task_type",
            "action",
            "agent",
            "capability",
            "status",
            "priority",
            "risk_level",
            "progress",
            "progress_message",
            "input",
            "output",
            "error",
            "parent_task_id",
            "child_task_ids",
            "requires_security",
            "security_result",
            "verification_payload",
            "memory_payload",
            "retry_count",
            "max_retries",
            "retry_delay_seconds",
            "next_retry_at",
            "metadata",
        }

        for key, value in dict(updates).items():
            if key not in allowed_fields:
                continue

            if key == "status":
                parsed = self._parse_status(value, task.status)
                if parsed:
                    task.status = parsed
            elif key == "priority":
                task.priority = self._parse_priority(value, task.priority)
            elif key == "risk_level":
                try:
                    task.risk_level = TaskRiskLevel(str(value).lower())
                except Exception:
                    pass
            elif key == "progress":
                task.progress = self._clamp_progress(value)
            elif key == "input":
                task.input = dict(value or {}) if isinstance(value, Mapping) else {}
            elif key == "metadata":
                task.metadata.update(dict(value or {}) if isinstance(value, Mapping) else {})
            elif key == "child_task_ids":
                task.child_task_ids = [str(item) for item in list(value or [])]
            else:
                setattr(task, key, value)

    def _validate_record_access(
        self,
        task: ManagedTask,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Validate whether context can access a task.
        """
        context_dict = self._context_to_dict(context)

        if not context_dict:
            return self._safe_result(message="Task access allowed without context.")

        if self._can_access_record(task, context_dict):
            return self._safe_result(message="Task access validated successfully.")

        return self._error_result(
            message="Task access denied.",
            error="Task does not belong to the provided user/workspace context.",
            metadata={
                "task_id": task.task_id,
                "task_user_id": task.user_id,
                "task_workspace_id": task.workspace_id,
                "context_user_id": context_dict.get("user_id"),
                "context_workspace_id": context_dict.get("workspace_id"),
            },
        )

    def _can_access_record(self, task: ManagedTask, context_dict: Mapping[str, Any]) -> bool:
        """
        Check user/workspace isolation.
        """
        if not context_dict:
            return True

        context_user_id = context_dict.get("user_id")
        context_workspace_id = context_dict.get("workspace_id")

        if context_user_id and str(task.user_id) != str(context_user_id):
            return False

        if context_workspace_id and str(task.workspace_id) != str(context_workspace_id):
            return False

        return True

    def _append_event_locked(
        self,
        task: ManagedTask,
        event_type: TaskEventType,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Append task event.

        Caller must hold lock.
        """
        event = TaskEvent(
            event_id=str(uuid.uuid4()),
            task_id=task.task_id,
            event_type=event_type.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            message=message,
            data=redact_sensitive_values(dict(data or {}))
            if self.config.redact_sensitive_data
            else dict(data or {}),
            metadata=redact_sensitive_values(dict(metadata or {}))
            if self.config.redact_sensitive_data
            else dict(metadata or {}),
        )

        self._events.append(event)

        if len(self._events) > self.config.keep_history_limit:
            self._events = self._events[-self.config.keep_history_limit:]

    def _attach_child_task_locked(
        self,
        parent_task_id: str,
        child_task_id: str,
    ) -> None:
        """
        Attach child to parent.

        Caller must hold lock.
        """
        parent = self._tasks.get(str(parent_task_id))
        child = self._tasks.get(str(child_task_id))

        if not parent or not child:
            return

        if child_task_id not in parent.child_task_ids:
            parent.child_task_ids.append(str(child_task_id))
            parent.updated_at = time.time()

        child.parent_task_id = str(parent_task_id)
        child.updated_at = time.time()

    def _build_task_tree_locked(
        self,
        task: ManagedTask,
        context_dict: Mapping[str, Any],
        visited: Optional[set] = None,
    ) -> Dict[str, Any]:
        """
        Build nested task tree.

        Caller must hold lock.
        """
        visited = visited or set()

        if task.task_id in visited:
            return {
                "task": task.to_dict(redact=self.config.redact_sensitive_data),
                "children": [],
                "cycle_detected": True,
            }

        visited.add(task.task_id)

        children = []
        for child_id in task.child_task_ids:
            child = self._tasks.get(child_id)
            if not child:
                continue

            if not self._can_access_record(child, context_dict):
                continue

            children.append(self._build_task_tree_locked(child, context_dict, visited))

        return {
            "task": task.to_dict(redact=self.config.redact_sensitive_data),
            "children": children,
        }

    def _safe_data_preview(self, data: Any, max_chars: int = 1000) -> Any:
        """
        Return short safe preview of data.
        """
        try:
            clean_data = redact_sensitive_values(data) if self.config.redact_sensitive_data else data

            if clean_data is None:
                return None

            if isinstance(clean_data, (str, int, float, bool)):
                text = str(clean_data)
                return text[:max_chars] + "...[truncated]" if len(text) > max_chars else clean_data

            if isinstance(clean_data, Mapping):
                text = str(dict(clean_data))
                return text[:max_chars] + "...[truncated]" if len(text) > max_chars else dict(clean_data)

            if isinstance(clean_data, Sequence) and not isinstance(clean_data, (str, bytes)):
                return list(clean_data)[:10]

            text = repr(clean_data)
            return text[:max_chars] + "...[truncated]" if len(text) > max_chars else text

        except Exception:
            return "[unavailable_preview]"

    # =========================================================================
    # Statistics / dashboard helpers
    # =========================================================================

    def get_stats(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Return dashboard-ready task statistics.
        """
        try:
            context_dict = self._context_to_dict(context)

            with self._lock:
                visible = [
                    task
                    for task in self._tasks.values()
                    if self._can_access_record(task, context_dict)
                ]

                by_status: Dict[str, int] = {}
                by_priority: Dict[str, int] = {}
                by_risk: Dict[str, int] = {}

                for task in visible:
                    by_status[task.status.value] = by_status.get(task.status.value, 0) + 1
                    by_priority[task.priority.value] = by_priority.get(task.priority.value, 0) + 1
                    by_risk[task.risk_level.value] = by_risk.get(task.risk_level.value, 0) + 1

                completed = by_status.get(TaskStatus.COMPLETED.value, 0)
                failed = by_status.get(TaskStatus.FAILED.value, 0)
                total = len(visible)

                success_rate = round((completed / total) * 100, 2) if total else 0.0
                failure_rate = round((failed / total) * 100, 2) if total else 0.0

                return self._safe_result(
                    message="Task statistics loaded successfully.",
                    data={
                        "total_tasks": total,
                        "by_status": by_status,
                        "by_priority": by_priority,
                        "by_risk": by_risk,
                        "success_rate": success_rate,
                        "failure_rate": failure_rate,
                    },
                    metadata={
                        "user_id": context_dict.get("user_id"),
                        "workspace_id": context_dict.get("workspace_id"),
                    },
                )

        except Exception as exc:
            return self._error_result(
                message="Task statistics crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )


__all__ = [
    "TaskManager",
    "TaskManagerConfig",
    "ManagedTask",
    "TaskEvent",
    "TaskStatus",
    "TaskPriority",
    "TaskRiskLevel",
    "TaskEventType",
    "redact_sensitive_values",
]