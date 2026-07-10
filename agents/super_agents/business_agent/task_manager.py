"""
agents/super_agents/business_agent/task_manager.py

BusinessTaskManager
Purpose:
    Business tasks, reminders, assignment, deadlines, status.

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

This file provides a production-ready, import-safe task manager for the
Business Agent module. It manages business tasks, reminders, assignments,
deadlines, priorities, statuses, audit logging, verification payloads, memory
payloads, dashboard summaries, and SaaS-safe user/workspace isolation.

Architecture Connections:
    - Master Agent:
        Routes business task actions to BusinessTaskManager public methods.
    - Security Agent:
        Sensitive actions such as delete, bulk status updates, reassignment,
        reminder escalation, and external notification preparation can be gated
        through _requires_security_check() and _request_security_approval().
    - Memory Agent:
        Completed tasks, important reminders, task summaries, assignment
        changes, and useful business context can be converted into memory
        payloads through _prepare_memory_payload().
    - Verification Agent:
        Every completed action prepares a verification payload using
        _prepare_verification_payload().
    - Dashboard/API:
        Methods return structured dicts with success, message, data, error,
        and metadata for easy FastAPI/dashboard integration.
    - Registry/Loader/Router:
        Exposes get_agent_metadata(), health_check(), capability names, and
        stable class name BusinessTaskManager.

Safety:
    - No destructive external actions are executed directly.
    - No cross-user/workspace mixing is allowed.
    - All public task operations require user_id and workspace_id.
    - Storage is in-memory by default for import safety and testability.
      A future database adapter can be injected without changing public methods.
"""

from __future__ import annotations

import copy
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This makes the file safe to import before the full William/Jarvis
        framework exists. The real BaseAgent should provide richer lifecycle,
        logging, registry, routing, and permission hooks.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.security.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

class TaskStatus(str, Enum):
    """Supported task lifecycle statuses."""

    TODO = "todo"
    IN_PROGRESS = "in_progress"
    WAITING = "waiting"
    BLOCKED = "blocked"
    DONE = "done"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


class TaskPriority(str, Enum):
    """Supported task priority levels."""

    LOW = "low"
    NORMAL = "normal"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class ReminderStatus(str, Enum):
    """Reminder lifecycle status."""

    SCHEDULED = "scheduled"
    SENT = "sent"
    SNOOZED = "snoozed"
    CANCELLED = "cancelled"


class TaskEventType(str, Enum):
    """Internal event names used for audit, dashboard, and agent events."""

    TASK_CREATED = "business_task.created"
    TASK_UPDATED = "business_task.updated"
    TASK_ASSIGNED = "business_task.assigned"
    TASK_STATUS_CHANGED = "business_task.status_changed"
    TASK_COMPLETED = "business_task.completed"
    TASK_CANCELLED = "business_task.cancelled"
    TASK_ARCHIVED = "business_task.archived"
    TASK_DELETED = "business_task.deleted"
    REMINDER_ADDED = "business_task.reminder_added"
    REMINDER_UPDATED = "business_task.reminder_updated"
    REMINDER_CANCELLED = "business_task.reminder_cancelled"
    COMMENT_ADDED = "business_task.comment_added"
    BULK_UPDATED = "business_task.bulk_updated"


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 250
MAX_TITLE_LENGTH = 220
MAX_DESCRIPTION_LENGTH = 10000
MAX_COMMENT_LENGTH = 5000
MAX_TAGS = 40
MAX_ASSIGNEES = 50


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TaskReminder:
    """
    Represents a task reminder.

    The manager prepares reminder records only. It does not send emails, calls,
    SMS, push notifications, or external messages directly. A notification
    engine can consume due reminders through get_due_reminders().
    """

    reminder_id: str
    remind_at: str
    status: str = ReminderStatus.SCHEDULED.value
    message: Optional[str] = None
    channel: str = "dashboard"
    created_at: str = field(default_factory=lambda: BusinessTaskManager.utcnow_iso())
    updated_at: str = field(default_factory=lambda: BusinessTaskManager.utcnow_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskComment:
    """Comment/note attached to a task."""

    comment_id: str
    author_id: str
    body: str
    created_at: str = field(default_factory=lambda: BusinessTaskManager.utcnow_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessTask:
    """
    Canonical business task record.

    Every task is scoped by user_id and workspace_id to preserve SaaS isolation.
    """

    task_id: str
    user_id: str
    workspace_id: str
    title: str
    description: Optional[str] = None
    status: str = TaskStatus.TODO.value
    priority: str = TaskPriority.NORMAL.value
    due_at: Optional[str] = None
    start_at: Optional[str] = None
    completed_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    archived_at: Optional[str] = None
    created_by: Optional[str] = None
    assigned_to: List[str] = field(default_factory=list)
    related_entity_type: Optional[str] = None
    related_entity_id: Optional[str] = None
    source_agent: str = "business_agent"
    tags: List[str] = field(default_factory=list)
    reminders: List[TaskReminder] = field(default_factory=list)
    comments: List[TaskComment] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    is_deleted: bool = False
    deleted_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: BusinessTaskManager.utcnow_iso())
    updated_at: str = field(default_factory=lambda: BusinessTaskManager.utcnow_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# In-memory repository
# ---------------------------------------------------------------------------

class InMemoryBusinessTaskRepository:
    """
    Import-safe in-memory repository.

    This repository is intentionally simple and deterministic for tests.
    A database-backed repository can later implement the same method names.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, BusinessTask] = {}

    def save(self, task: BusinessTask) -> BusinessTask:
        self._tasks[task.task_id] = copy.deepcopy(task)
        return copy.deepcopy(task)

    def get(self, task_id: str) -> Optional[BusinessTask]:
        task = self._tasks.get(task_id)
        return copy.deepcopy(task) if task else None

    def delete_soft(self, task: BusinessTask) -> BusinessTask:
        task.is_deleted = True
        task.deleted_at = BusinessTaskManager.utcnow_iso()
        task.updated_at = BusinessTaskManager.utcnow_iso()
        self._tasks[task.task_id] = copy.deepcopy(task)
        return copy.deepcopy(task)

    def list_all(self) -> List[BusinessTask]:
        return [copy.deepcopy(task) for task in self._tasks.values()]

    def clear(self) -> None:
        self._tasks.clear()


# ---------------------------------------------------------------------------
# BusinessTaskManager
# ---------------------------------------------------------------------------

class BusinessTaskManager(BaseAgent):
    """
    Business task manager for William/Jarvis Business Agent.

    Responsibilities:
        - Create business tasks.
        - Assign tasks to users/team members.
        - Track status, priority, deadlines, and comments.
        - Manage reminders without directly sending external messages.
        - Prepare verification payloads after successful actions.
        - Prepare memory payloads for useful business context.
        - Emit audit and dashboard-friendly events.
        - Maintain strict SaaS user/workspace isolation.

    Public methods return structured dicts:
        {
            "success": bool,
            "message": str,
            "data": dict | list | None,
            "error": str | None,
            "metadata": dict
        }
    """

    agent_name = "BusinessTaskManager"
    agent_type = "business_agent_helper"
    module_name = "business_agent"
    file_name = "task_manager.py"

    def __init__(
        self,
        repository: Optional[InMemoryBusinessTaskRepository] = None,
        security_agent: Any = None,
        memory_agent: Any = None,
        verification_agent: Any = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Dict[str, Any]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, *args, **kwargs)

        self.repository = repository or InMemoryBusinessTaskRepository()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.config = config or {}

        self.allow_soft_delete = bool(self.config.get("allow_soft_delete", True))
        self.default_reminder_channel = str(
            self.config.get("default_reminder_channel", "dashboard")
        )
        self.security_required_actions = set(
            self.config.get(
                "security_required_actions",
                {
                    "delete_task",
                    "bulk_update_status",
                    "assign_task",
                    "cancel_task",
                    "archive_task",
                    "restore_task",
                },
            )
        )

    # ------------------------------------------------------------------
    # Time and serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def utcnow_iso() -> str:
        """Return current UTC datetime as ISO-8601 string."""

        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def parse_datetime(value: Optional[Union[str, datetime]]) -> Optional[datetime]:
        """
        Parse a datetime-like value safely.

        Accepts:
            - None
            - datetime
            - ISO strings with or without trailing Z
        """

        if value is None:
            return None

        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        if isinstance(value, str):
            cleaned = value.strip()
            if not cleaned:
                return None
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1] + "+00:00"
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

        raise ValueError("Invalid datetime value")

    @staticmethod
    def normalize_datetime(value: Optional[Union[str, datetime]]) -> Optional[str]:
        """Normalize datetime input to UTC ISO string."""

        parsed = BusinessTaskManager.parse_datetime(value)
        if parsed is None:
            return None
        return parsed.replace(microsecond=0).isoformat()

    @staticmethod
    def _task_to_dict(task: BusinessTask) -> Dict[str, Any]:
        """Convert task dataclass to plain dict."""

        return asdict(task)

    @staticmethod
    def _safe_copy(data: Any) -> Any:
        """Return a deep copy of serializable data."""

        return copy.deepcopy(data)

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a successful structured result."""

        return {
            "success": True,
            "message": message,
            "data": data,
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a failed structured result."""

        if isinstance(error, Exception):
            error_text = f"{error.__class__.__name__}: {str(error)}"
        else:
            error_text = error or message

        logger.debug("BusinessTaskManager error: %s", error_text)

        return {
            "success": False,
            "message": message,
            "data": None,
            "error": error_text,
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Context, validation, permissions
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        action: str = "task_operation",
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate SaaS task context.

        All user/workspace-scoped operations must provide both user_id and
        workspace_id. This prevents cross-tenant data mixing.
        """

        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            return False, f"user_id is required for {action}"

        if not workspace_id or not isinstance(workspace_id, str) or not workspace_id.strip():
            return False, f"workspace_id is required for {action}"

        return True, None

    def _assert_task_scope(
        self,
        task: BusinessTask,
        user_id: str,
        workspace_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """Ensure a task belongs to the requesting user/workspace scope."""

        if task.user_id != user_id or task.workspace_id != workspace_id:
            return False, "Task does not belong to this user/workspace context"
        return True, None

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decide whether action needs Security Agent approval.

        Security-sensitive actions are configurable and safe by default.
        """

        if action in self.security_required_actions:
            return True

        payload = payload or {}

        if action == "update_task":
            if payload.get("is_deleted") is True:
                return True
            if payload.get("status") in {TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
                return True

        if action == "add_reminder":
            channel = str(payload.get("channel", "")).lower()
            if channel in {"email", "sms", "whatsapp", "call", "voice", "webhook"}:
                return True

        return False

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request security approval when available.

        This method never assumes approval if a real Security Agent denies it.
        If no Security Agent is injected, local safe approval is returned for
        import-safe development. Integrations can enforce stricter behavior by
        injecting a security_agent with validate_action/request_approval methods.
        """

        approval_payload = {
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "agent": self.agent_name,
            "requested_at": self.utcnow_iso(),
        }

        try:
            if self.security_agent and hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_payload)
                if isinstance(response, dict):
                    return response

            if self.security_agent and hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_payload)
                if isinstance(response, dict):
                    return response

            return {
                "approved": True,
                "reason": "No external Security Agent configured; local safe approval applied.",
                "metadata": {
                    "approval_mode": "local_fallback",
                    "action": action,
                },
            }

        except Exception as exc:
            logger.exception("Security approval failed")
            return {
                "approved": False,
                "reason": str(exc),
                "metadata": {
                    "approval_mode": "error",
                    "action": action,
                },
            }

    # ------------------------------------------------------------------
    # Payload hooks
    # ------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task: Optional[BusinessTask] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The manager prepares the payload and optionally emits it. It does not
        force external verification execution.
        """

        payload = {
            "verification_type": "business_task_action",
            "action": action,
            "agent": self.agent_name,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task.task_id if task else None,
            "before": before,
            "after": after or (self._task_to_dict(task) if task else None),
            "extra": extra or {},
            "created_at": self.utcnow_iso(),
        }

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task: Optional[BusinessTask] = None,
        summary: Optional[str] = None,
        importance: str = "normal",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Useful business context can be stored by a Memory Agent integration.
        """

        payload = {
            "memory_type": "business_task_context",
            "action": action,
            "agent": self.agent_name,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "importance": importance,
            "summary": summary or self._build_task_summary(task) if task else summary,
            "entity": {
                "type": "business_task",
                "id": task.task_id if task else None,
                "title": task.title if task else None,
                "status": task.status if task else None,
                "priority": task.priority if task else None,
                "due_at": task.due_at if task else None,
                "assigned_to": task.assigned_to if task else [],
            },
            "extra": extra or {},
            "created_at": self.utcnow_iso(),
        }

        return payload

    def _emit_agent_event(
        self,
        event_type: Union[str, TaskEventType],
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an internal agent event.

        Dashboard, analytics, workflow, or task history systems can subscribe
        through event_callback.
        """

        event_name = event_type.value if isinstance(event_type, TaskEventType) else str(event_type)

        event = {
            "event_type": event_name,
            "agent": self.agent_name,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": self.utcnow_iso(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
        except Exception:
            logger.exception("Failed to emit agent event")

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Audit logs must remain user/workspace-scoped.
        """

        audit = {
            "action": action,
            "agent": self.agent_name,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "before": before,
            "after": after,
            "metadata": metadata or {},
            "created_at": self.utcnow_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit)
            else:
                logger.info("Audit event: %s", audit)
        except Exception:
            logger.exception("Failed to log audit event")

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_title(self, title: Any) -> Tuple[bool, Optional[str]]:
        """Validate task title."""

        if not isinstance(title, str) or not title.strip():
            return False, "Task title is required"

        if len(title.strip()) > MAX_TITLE_LENGTH:
            return False, f"Task title must be {MAX_TITLE_LENGTH} characters or fewer"

        return True, None

    def _validate_description(self, description: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Validate task description."""

        if description is not None and len(str(description)) > MAX_DESCRIPTION_LENGTH:
            return False, f"Task description must be {MAX_DESCRIPTION_LENGTH} characters or fewer"

        return True, None

    def _normalize_status(self, status: Optional[str]) -> str:
        """Normalize and validate status."""

        if status is None:
            return TaskStatus.TODO.value

        value = str(status).strip().lower()
        allowed = {item.value for item in TaskStatus}

        if value not in allowed:
            raise ValueError(f"Invalid task status: {status}")

        return value

    def _normalize_priority(self, priority: Optional[str]) -> str:
        """Normalize and validate priority."""

        if priority is None:
            return TaskPriority.NORMAL.value

        value = str(priority).strip().lower()
        aliases = {
            "default": TaskPriority.NORMAL.value,
            "standard": TaskPriority.NORMAL.value,
            "med": TaskPriority.MEDIUM.value,
            "critical": TaskPriority.URGENT.value,
        }
        value = aliases.get(value, value)

        allowed = {item.value for item in TaskPriority}

        if value not in allowed:
            raise ValueError(f"Invalid task priority: {priority}")

        return value

    def _normalize_assignees(self, assigned_to: Optional[Iterable[str]]) -> List[str]:
        """Normalize assignee list."""

        if not assigned_to:
            return []

        normalized: List[str] = []

        for assignee in assigned_to:
            if assignee is None:
                continue
            item = str(assignee).strip()
            if item and item not in normalized:
                normalized.append(item)

        if len(normalized) > MAX_ASSIGNEES:
            raise ValueError(f"assigned_to cannot exceed {MAX_ASSIGNEES} assignees")

        return normalized

    def _normalize_tags(self, tags: Optional[Iterable[str]]) -> List[str]:
        """Normalize tags."""

        if not tags:
            return []

        normalized: List[str] = []

        for tag in tags:
            if tag is None:
                continue
            item = str(tag).strip().lower()
            if item and item not in normalized:
                normalized.append(item)

        if len(normalized) > MAX_TAGS:
            raise ValueError(f"tags cannot exceed {MAX_TAGS} items")

        return normalized

    def _validate_due_start(
        self,
        due_at: Optional[Union[str, datetime]],
        start_at: Optional[Union[str, datetime]],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Normalize and validate due/start dates."""

        normalized_due = self.normalize_datetime(due_at)
        normalized_start = self.normalize_datetime(start_at)

        if normalized_due and normalized_start:
            due_dt = self.parse_datetime(normalized_due)
            start_dt = self.parse_datetime(normalized_start)
            if due_dt and start_dt and start_dt > due_dt:
                raise ValueError("start_at cannot be later than due_at")

        return normalized_due, normalized_start

    def _build_task_summary(self, task: Optional[BusinessTask]) -> str:
        """Build short memory/dashboard summary for a task."""

        if not task:
            return "Business task action completed."

        parts = [
            f"Task '{task.title}'",
            f"status={task.status}",
            f"priority={task.priority}",
        ]

        if task.due_at:
            parts.append(f"due_at={task.due_at}")

        if task.assigned_to:
            parts.append(f"assigned_to={', '.join(task.assigned_to)}")

        return "; ".join(parts)

    def _get_scoped_task(
        self,
        task_id: str,
        user_id: str,
        workspace_id: str,
        include_deleted: bool = False,
    ) -> Tuple[Optional[BusinessTask], Optional[Dict[str, Any]]]:
        """Fetch task and enforce user/workspace scope."""

        if not task_id or not isinstance(task_id, str):
            return None, self._error_result("task_id is required", "Missing task_id")

        task = self.repository.get(task_id)

        if not task:
            return None, self._error_result("Task not found", f"Task not found: {task_id}")

        ok, scope_error = self._assert_task_scope(task, user_id, workspace_id)
        if not ok:
            return None, self._error_result("Task scope mismatch", scope_error)

        if task.is_deleted and not include_deleted:
            return None, self._error_result("Task is deleted", "Deleted task is hidden by default")

        return task, None

    # ------------------------------------------------------------------
    # Core public methods
    # ------------------------------------------------------------------

    def create_task(
        self,
        user_id: str,
        workspace_id: str,
        title: str,
        description: Optional[str] = None,
        due_at: Optional[Union[str, datetime]] = None,
        start_at: Optional[Union[str, datetime]] = None,
        priority: str = TaskPriority.NORMAL.value,
        status: str = TaskStatus.TODO.value,
        assigned_to: Optional[Iterable[str]] = None,
        created_by: Optional[str] = None,
        related_entity_type: Optional[str] = None,
        related_entity_id: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        reminders: Optional[List[Dict[str, Any]]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        source_agent: str = "business_agent",
    ) -> Dict[str, Any]:
        """
        Create a new business task.

        This method is suitable for Master Agent routing, dashboard creation,
        CRM follow-ups, lead follow-ups, sales pipeline actions, client work,
        campaign action items, and revenue follow-up tasks.
        """

        action = "create_task"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            valid_title, title_error = self._validate_title(title)
            if not valid_title:
                return self._error_result("Invalid task title", title_error)

            valid_description, description_error = self._validate_description(description)
            if not valid_description:
                return self._error_result("Invalid task description", description_error)

            normalized_due, normalized_start = self._validate_due_start(due_at, start_at)
            normalized_status = self._normalize_status(status)
            normalized_priority = self._normalize_priority(priority)
            normalized_assignees = self._normalize_assignees(assigned_to)
            normalized_tags = self._normalize_tags(tags)

            task = BusinessTask(
                task_id=str(uuid.uuid4()),
                user_id=user_id.strip(),
                workspace_id=workspace_id.strip(),
                title=title.strip(),
                description=description.strip() if isinstance(description, str) else description,
                status=normalized_status,
                priority=normalized_priority,
                due_at=normalized_due,
                start_at=normalized_start,
                created_by=created_by or user_id,
                assigned_to=normalized_assignees,
                related_entity_type=related_entity_type,
                related_entity_id=related_entity_id,
                source_agent=source_agent or "business_agent",
                tags=normalized_tags,
                custom_fields=self._safe_copy(custom_fields or {}),
                metadata=self._safe_copy(metadata or {}),
            )

            if reminders:
                for reminder in reminders:
                    reminder_result = self._build_reminder_from_payload(reminder)
                    task.reminders.append(reminder_result)

            saved = self.repository.save(task)
            task_dict = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                after=task_dict,
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                importance="normal",
            )

            self._emit_agent_event(
                TaskEventType.TASK_CREATED,
                user_id,
                workspace_id,
                {"task": task_dict, "verification_payload": verification_payload},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=saved.task_id,
                after=task_dict,
                metadata={"memory_payload": memory_payload},
            )

            return self._safe_result(
                "Business task created successfully",
                data={
                    "task": task_dict,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to create business task")
            return self._error_result("Failed to create business task", exc)

    def get_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        include_deleted: bool = False,
    ) -> Dict[str, Any]:
        """Get one task by ID with SaaS scope enforcement."""

        action = "get_task"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id, include_deleted)
            if err:
                return err

            return self._safe_result(
                "Task retrieved successfully",
                data={"task": self._task_to_dict(task)},  # type: ignore[arg-type]
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to retrieve task")
            return self._error_result("Failed to retrieve task", exc)

    def list_tasks(
        self,
        user_id: str,
        workspace_id: str,
        status: Optional[Union[str, Iterable[str]]] = None,
        priority: Optional[Union[str, Iterable[str]]] = None,
        assigned_to: Optional[str] = None,
        created_by: Optional[str] = None,
        related_entity_type: Optional[str] = None,
        related_entity_id: Optional[str] = None,
        tag: Optional[str] = None,
        due_before: Optional[Union[str, datetime]] = None,
        due_after: Optional[Union[str, datetime]] = None,
        include_deleted: bool = False,
        include_archived: bool = False,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        """
        List tasks for a user/workspace with filters.

        This is dashboard/API-ready and avoids cross-workspace leakage.
        """

        action = "list_tasks"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            normalized_statuses = self._normalize_filter_values(status, TaskStatus)
            normalized_priorities = self._normalize_filter_values(priority, TaskPriority)
            due_before_dt = self.parse_datetime(due_before)
            due_after_dt = self.parse_datetime(due_after)

            tasks = [
                task
                for task in self.repository.list_all()
                if task.user_id == user_id
                and task.workspace_id == workspace_id
                and (include_deleted or not task.is_deleted)
            ]

            if not include_archived:
                tasks = [task for task in tasks if task.status != TaskStatus.ARCHIVED.value]

            if normalized_statuses:
                tasks = [task for task in tasks if task.status in normalized_statuses]

            if normalized_priorities:
                tasks = [task for task in tasks if task.priority in normalized_priorities]

            if assigned_to:
                tasks = [task for task in tasks if assigned_to in task.assigned_to]

            if created_by:
                tasks = [task for task in tasks if task.created_by == created_by]

            if related_entity_type:
                tasks = [task for task in tasks if task.related_entity_type == related_entity_type]

            if related_entity_id:
                tasks = [task for task in tasks if task.related_entity_id == related_entity_id]

            if tag:
                normalized_tag = tag.strip().lower()
                tasks = [task for task in tasks if normalized_tag in task.tags]

            if due_before_dt:
                tasks = [
                    task for task in tasks
                    if task.due_at and self.parse_datetime(task.due_at) and self.parse_datetime(task.due_at) <= due_before_dt
                ]

            if due_after_dt:
                tasks = [
                    task for task in tasks
                    if task.due_at and self.parse_datetime(task.due_at) and self.parse_datetime(task.due_at) >= due_after_dt
                ]

            tasks = self._sort_tasks(tasks, sort_by=sort_by, sort_order=sort_order)

            page = max(1, int(page or 1))
            page_size = min(MAX_PAGE_SIZE, max(1, int(page_size or DEFAULT_PAGE_SIZE)))
            total = len(tasks)
            start = (page - 1) * page_size
            end = start + page_size
            paginated = tasks[start:end]

            return self._safe_result(
                "Tasks listed successfully",
                data={
                    "tasks": [self._task_to_dict(task) for task in paginated],
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "has_next": end < total,
                        "has_previous": page > 1,
                    },
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "filters": {
                        "status": list(normalized_statuses),
                        "priority": list(normalized_priorities),
                        "assigned_to": assigned_to,
                        "created_by": created_by,
                        "related_entity_type": related_entity_type,
                        "related_entity_id": related_entity_id,
                        "tag": tag,
                        "include_deleted": include_deleted,
                        "include_archived": include_archived,
                    },
                },
            )

        except Exception as exc:
            logger.exception("Failed to list tasks")
            return self._error_result("Failed to list tasks", exc)

    def update_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        due_at: Optional[Union[str, datetime]] = None,
        start_at: Optional[Union[str, datetime]] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        assigned_to: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        related_entity_type: Optional[str] = None,
        related_entity_id: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        merge_custom_fields: bool = True,
        merge_metadata: bool = True,
    ) -> Dict[str, Any]:
        """Update a task safely within the same user/workspace scope."""

        action = "update_task"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id)
            if err:
                return err

            before = self._task_to_dict(task)  # type: ignore[arg-type]

            update_payload = {
                "title": title,
                "description": description,
                "due_at": due_at,
                "start_at": start_at,
                "priority": priority,
                "status": status,
                "assigned_to": list(assigned_to) if assigned_to is not None else None,
                "tags": list(tags) if tags is not None else None,
                "related_entity_type": related_entity_type,
                "related_entity_id": related_entity_id,
            }

            if self._requires_security_check(action, update_payload):
                approval = self._request_security_approval(action, user_id, workspace_id, update_payload)
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            if title is not None:
                valid_title, title_error = self._validate_title(title)
                if not valid_title:
                    return self._error_result("Invalid task title", title_error)
                task.title = title.strip()  # type: ignore[union-attr]

            if description is not None:
                valid_description, description_error = self._validate_description(description)
                if not valid_description:
                    return self._error_result("Invalid task description", description_error)
                task.description = description.strip() if isinstance(description, str) else description  # type: ignore[union-attr]

            if due_at is not None or start_at is not None:
                normalized_due, normalized_start = self._validate_due_start(
                    due_at if due_at is not None else task.due_at,  # type: ignore[union-attr]
                    start_at if start_at is not None else task.start_at,  # type: ignore[union-attr]
                )
                task.due_at = normalized_due  # type: ignore[union-attr]
                task.start_at = normalized_start  # type: ignore[union-attr]

            if priority is not None:
                task.priority = self._normalize_priority(priority)  # type: ignore[union-attr]

            if status is not None:
                task = self._apply_status_transition(task, self._normalize_status(status), user_id)  # type: ignore[arg-type]

            if assigned_to is not None:
                task.assigned_to = self._normalize_assignees(assigned_to)  # type: ignore[union-attr]

            if tags is not None:
                task.tags = self._normalize_tags(tags)  # type: ignore[union-attr]

            if related_entity_type is not None:
                task.related_entity_type = related_entity_type  # type: ignore[union-attr]

            if related_entity_id is not None:
                task.related_entity_id = related_entity_id  # type: ignore[union-attr]

            if custom_fields is not None:
                if merge_custom_fields:
                    task.custom_fields.update(self._safe_copy(custom_fields))  # type: ignore[union-attr]
                else:
                    task.custom_fields = self._safe_copy(custom_fields)  # type: ignore[union-attr]

            if metadata is not None:
                if merge_metadata:
                    task.metadata.update(self._safe_copy(metadata))  # type: ignore[union-attr]
                else:
                    task.metadata = self._safe_copy(metadata)  # type: ignore[union-attr]

            task.updated_at = self.utcnow_iso()  # type: ignore[union-attr]

            saved = self.repository.save(task)  # type: ignore[arg-type]
            after = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                before=before,
                after=after,
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                importance="normal",
            )

            self._emit_agent_event(
                TaskEventType.TASK_UPDATED,
                user_id,
                workspace_id,
                {"task_id": task_id, "before": before, "after": after},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
                metadata={"verification_payload": verification_payload},
            )

            return self._safe_result(
                "Task updated successfully",
                data={
                    "task": after,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to update task")
            return self._error_result("Failed to update task", exc)

    def assign_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        assigned_to: Iterable[str],
        assigned_by: Optional[str] = None,
        replace_existing: bool = True,
    ) -> Dict[str, Any]:
        """Assign or reassign task to one or more assignees."""

        action = "assign_task"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id)
            if err:
                return err

            normalized_assignees = self._normalize_assignees(assigned_to)
            if not normalized_assignees:
                return self._error_result("Invalid assignees", "At least one assignee is required")

            approval_payload = {
                "task_id": task_id,
                "assigned_to": normalized_assignees,
                "assigned_by": assigned_by or user_id,
                "replace_existing": replace_existing,
            }

            if self._requires_security_check(action, approval_payload):
                approval = self._request_security_approval(action, user_id, workspace_id, approval_payload)
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            before = self._task_to_dict(task)  # type: ignore[arg-type]

            if replace_existing:
                task.assigned_to = normalized_assignees  # type: ignore[union-attr]
            else:
                for assignee in normalized_assignees:
                    if assignee not in task.assigned_to:  # type: ignore[union-attr]
                        task.assigned_to.append(assignee)  # type: ignore[union-attr]

            task.updated_at = self.utcnow_iso()  # type: ignore[union-attr]
            saved = self.repository.save(task)  # type: ignore[arg-type]
            after = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                before=before,
                after=after,
                extra={"assigned_by": assigned_by or user_id},
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                importance="normal",
                extra={"assigned_by": assigned_by or user_id},
            )

            self._emit_agent_event(
                TaskEventType.TASK_ASSIGNED,
                user_id,
                workspace_id,
                {"task_id": task_id, "assigned_to": saved.assigned_to},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
            )

            return self._safe_result(
                "Task assigned successfully",
                data={
                    "task": after,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to assign task")
            return self._error_result("Failed to assign task", exc)

    def update_status(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        status: str,
        changed_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update task status with lifecycle timestamps."""

        action = "update_status"

        try:
            normalized_status = self._normalize_status(status)

            result = self.update_task(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                status=normalized_status,
                metadata={
                    "last_status_changed_by": changed_by or user_id,
                    "last_status_note": note,
                    "last_status_changed_at": self.utcnow_iso(),
                },
                merge_metadata=True,
            )

            if result.get("success"):
                task = result["data"]["task"]
                self._emit_agent_event(
                    TaskEventType.TASK_STATUS_CHANGED,
                    user_id,
                    workspace_id,
                    {"task_id": task_id, "status": normalized_status, "note": note},
                )
                result["message"] = "Task status updated successfully"
                result["metadata"]["action"] = action
                result["data"]["verification_payload"]["action"] = action

                if normalized_status == TaskStatus.DONE.value:
                    self._emit_agent_event(
                        TaskEventType.TASK_COMPLETED,
                        user_id,
                        workspace_id,
                        {"task_id": task_id, "task": task},
                    )

            return result

        except Exception as exc:
            logger.exception("Failed to update task status")
            return self._error_result("Failed to update task status", exc)

    def complete_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        completed_by: Optional[str] = None,
        completion_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark task as done and prepare verification/memory payload."""

        return self.update_status(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            status=TaskStatus.DONE.value,
            changed_by=completed_by or user_id,
            note=completion_note,
        )

    def cancel_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        cancelled_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a task after security-aware handling."""

        action = "cancel_task"

        try:
            if self._requires_security_check(action, {"task_id": task_id, "reason": reason}):
                approval = self._request_security_approval(
                    action,
                    user_id,
                    workspace_id,
                    {"task_id": task_id, "reason": reason},
                )
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            result = self.update_status(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                status=TaskStatus.CANCELLED.value,
                changed_by=cancelled_by or user_id,
                note=reason,
            )

            if result.get("success"):
                result["message"] = "Task cancelled successfully"
                result["metadata"]["action"] = action
                self._emit_agent_event(
                    TaskEventType.TASK_CANCELLED,
                    user_id,
                    workspace_id,
                    {"task_id": task_id, "reason": reason},
                )

            return result

        except Exception as exc:
            logger.exception("Failed to cancel task")
            return self._error_result("Failed to cancel task", exc)

    def archive_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        archived_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Archive a task without deleting it."""

        action = "archive_task"

        try:
            if self._requires_security_check(action, {"task_id": task_id}):
                approval = self._request_security_approval(action, user_id, workspace_id, {"task_id": task_id})
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            result = self.update_status(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                status=TaskStatus.ARCHIVED.value,
                changed_by=archived_by or user_id,
                note="Task archived",
            )

            if result.get("success"):
                result["message"] = "Task archived successfully"
                result["metadata"]["action"] = action
                self._emit_agent_event(
                    TaskEventType.TASK_ARCHIVED,
                    user_id,
                    workspace_id,
                    {"task_id": task_id},
                )

            return result

        except Exception as exc:
            logger.exception("Failed to archive task")
            return self._error_result("Failed to archive task", exc)

    def delete_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        deleted_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Soft-delete a task.

        The manager does not hard-delete records by default to preserve audit
        history and SaaS accountability.
        """

        action = "delete_task"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id)
            if err:
                return err

            approval_payload = {
                "task_id": task_id,
                "deleted_by": deleted_by or user_id,
                "reason": reason,
                "soft_delete": True,
            }

            if self._requires_security_check(action, approval_payload):
                approval = self._request_security_approval(action, user_id, workspace_id, approval_payload)
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            before = self._task_to_dict(task)  # type: ignore[arg-type]
            task.metadata["deleted_by"] = deleted_by or user_id  # type: ignore[union-attr]
            task.metadata["delete_reason"] = reason  # type: ignore[union-attr]
            deleted = self.repository.delete_soft(task)  # type: ignore[arg-type]
            after = self._task_to_dict(deleted)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=deleted,
                before=before,
                after=after,
            )

            self._emit_agent_event(
                TaskEventType.TASK_DELETED,
                user_id,
                workspace_id,
                {"task_id": task_id, "soft_delete": True},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
                metadata={"deleted_by": deleted_by or user_id, "reason": reason},
            )

            return self._safe_result(
                "Task deleted successfully",
                data={
                    "task": after,
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "soft_delete": True,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to delete task")
            return self._error_result("Failed to delete task", exc)

    def restore_task(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        restored_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Restore a soft-deleted task."""

        action = "restore_task"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id, include_deleted=True)
            if err:
                return err

            approval = self._request_security_approval(
                action,
                user_id,
                workspace_id,
                {"task_id": task_id, "restored_by": restored_by or user_id},
            )
            if self._requires_security_check(action, {"task_id": task_id}) and not approval.get("approved", False):
                return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            before = self._task_to_dict(task)  # type: ignore[arg-type]
            task.is_deleted = False  # type: ignore[union-attr]
            task.deleted_at = None  # type: ignore[union-attr]
            task.updated_at = self.utcnow_iso()  # type: ignore[union-attr]
            task.metadata["restored_by"] = restored_by or user_id  # type: ignore[union-attr]
            task.metadata["restored_at"] = self.utcnow_iso()  # type: ignore[union-attr]

            saved = self.repository.save(task)  # type: ignore[arg-type]
            after = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                before=before,
                after=after,
            )

            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
            )

            return self._safe_result(
                "Task restored successfully",
                data={
                    "task": after,
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to restore task")
            return self._error_result("Failed to restore task", exc)

    # ------------------------------------------------------------------
    # Reminder methods
    # ------------------------------------------------------------------

    def add_reminder(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        remind_at: Union[str, datetime],
        message: Optional[str] = None,
        channel: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add reminder to task.

        This only schedules/stores reminder intent. A notification or workflow
        agent can consume due reminders and perform approved delivery.
        """

        action = "add_reminder"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id)
            if err:
                return err

            reminder_payload = {
                "remind_at": remind_at,
                "message": message,
                "channel": channel or self.default_reminder_channel,
                "metadata": metadata or {},
            }

            if self._requires_security_check(action, reminder_payload):
                approval = self._request_security_approval(action, user_id, workspace_id, reminder_payload)
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            before = self._task_to_dict(task)  # type: ignore[arg-type]
            reminder = self._build_reminder_from_payload(reminder_payload)

            task.reminders.append(reminder)  # type: ignore[union-attr]
            task.updated_at = self.utcnow_iso()  # type: ignore[union-attr]

            saved = self.repository.save(task)  # type: ignore[arg-type]
            after = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                before=before,
                after=after,
                extra={"reminder": asdict(reminder)},
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                importance="normal",
                extra={"reminder": asdict(reminder)},
            )

            self._emit_agent_event(
                TaskEventType.REMINDER_ADDED,
                user_id,
                workspace_id,
                {"task_id": task_id, "reminder": asdict(reminder)},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
            )

            return self._safe_result(
                "Reminder added successfully",
                data={
                    "task": after,
                    "reminder": asdict(reminder),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to add reminder")
            return self._error_result("Failed to add reminder", exc)

    def update_reminder(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        reminder_id: str,
        remind_at: Optional[Union[str, datetime]] = None,
        message: Optional[str] = None,
        channel: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update an existing reminder."""

        action = "update_reminder"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task, err = self._get_scoped_task(task_id, user_id, workspace_id)
            if err:
                return err

            reminder_index = self._find_reminder_index(task, reminder_id)  # type: ignore[arg-type]
            if reminder_index < 0:
                return self._error_result("Reminder not found", f"Reminder not found: {reminder_id}")

            before = self._task_to_dict(task)  # type: ignore[arg-type]
            reminder = task.reminders[reminder_index]  # type: ignore[union-attr]

            if remind_at is not None:
                reminder.remind_at = self.normalize_datetime(remind_at) or reminder.remind_at

            if message is not None:
                reminder.message = message

            if channel is not None:
                reminder.channel = channel

            if status is not None:
                normalized_status = str(status).strip().lower()
                allowed = {item.value for item in ReminderStatus}
                if normalized_status not in allowed:
                    return self._error_result("Invalid reminder status", f"Invalid reminder status: {status}")
                reminder.status = normalized_status

            if metadata is not None:
                reminder.metadata.update(self._safe_copy(metadata))

            reminder.updated_at = self.utcnow_iso()
            task.reminders[reminder_index] = reminder  # type: ignore[union-attr]
            task.updated_at = self.utcnow_iso()  # type: ignore[union-attr]

            saved = self.repository.save(task)  # type: ignore[arg-type]
            after = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                before=before,
                after=after,
                extra={"reminder_id": reminder_id},
            )

            self._emit_agent_event(
                TaskEventType.REMINDER_UPDATED,
                user_id,
                workspace_id,
                {"task_id": task_id, "reminder_id": reminder_id},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
            )

            return self._safe_result(
                "Reminder updated successfully",
                data={
                    "task": after,
                    "reminder": asdict(reminder),
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to update reminder")
            return self._error_result("Failed to update reminder", exc)

    def cancel_reminder(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        reminder_id: str,
    ) -> Dict[str, Any]:
        """Cancel a scheduled reminder."""

        return self.update_reminder(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            reminder_id=reminder_id,
            status=ReminderStatus.CANCELLED.value,
        )

    def snooze_reminder(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        reminder_id: str,
        snooze_minutes: int = 30,
    ) -> Dict[str, Any]:
        """Snooze reminder by a given number of minutes."""

        try:
            minutes = max(1, int(snooze_minutes))
            new_time = datetime.now(timezone.utc) + timedelta(minutes=minutes)

            return self.update_reminder(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                reminder_id=reminder_id,
                remind_at=new_time,
                status=ReminderStatus.SNOOZED.value,
                metadata={"snoozed_minutes": minutes, "snoozed_at": self.utcnow_iso()},
            )

        except Exception as exc:
            logger.exception("Failed to snooze reminder")
            return self._error_result("Failed to snooze reminder", exc)

    def mark_reminder_sent(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        reminder_id: str,
        delivery_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark reminder as sent after notification agent handles delivery."""

        return self.update_reminder(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            reminder_id=reminder_id,
            status=ReminderStatus.SENT.value,
            metadata={
                "delivery_metadata": delivery_metadata or {},
                "sent_at": self.utcnow_iso(),
            },
        )

    def get_due_reminders(
        self,
        user_id: str,
        workspace_id: str,
        as_of: Optional[Union[str, datetime]] = None,
        include_snoozed: bool = True,
    ) -> Dict[str, Any]:
        """
        Return due reminders for the workspace.

        A workflow/notification agent can call this method and then request
        appropriate security approval before any external delivery.
        """

        action = "get_due_reminders"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            as_of_dt = self.parse_datetime(as_of) or datetime.now(timezone.utc)
            allowed_statuses = {ReminderStatus.SCHEDULED.value}
            if include_snoozed:
                allowed_statuses.add(ReminderStatus.SNOOZED.value)

            due_items: List[Dict[str, Any]] = []

            for task in self.repository.list_all():
                if task.user_id != user_id or task.workspace_id != workspace_id:
                    continue
                if task.is_deleted or task.status in {TaskStatus.DONE.value, TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
                    continue

                for reminder in task.reminders:
                    reminder_dt = self.parse_datetime(reminder.remind_at)
                    if reminder.status in allowed_statuses and reminder_dt and reminder_dt <= as_of_dt:
                        due_items.append(
                            {
                                "task": self._task_to_dict(task),
                                "reminder": asdict(reminder),
                            }
                        )

            return self._safe_result(
                "Due reminders retrieved successfully",
                data={
                    "due_reminders": due_items,
                    "count": len(due_items),
                    "as_of": as_of_dt.replace(microsecond=0).isoformat(),
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to get due reminders")
            return self._error_result("Failed to get due reminders", exc)

    # ------------------------------------------------------------------
    # Comments and notes
    # ------------------------------------------------------------------

    def add_comment(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        body: str,
        author_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a comment/note to a task."""

        action = "add_comment"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            if not isinstance(body, str) or not body.strip():
                return self._error_result("Invalid comment", "Comment body is required")

            if len(body.strip()) > MAX_COMMENT_LENGTH:
                return self._error_result(
                    "Invalid comment",
                    f"Comment body must be {MAX_COMMENT_LENGTH} characters or fewer",
                )

            task, err = self._get_scoped_task(task_id, user_id, workspace_id)
            if err:
                return err

            before = self._task_to_dict(task)  # type: ignore[arg-type]
            comment = TaskComment(
                comment_id=str(uuid.uuid4()),
                author_id=author_id or user_id,
                body=body.strip(),
                metadata=self._safe_copy(metadata or {}),
            )

            task.comments.append(comment)  # type: ignore[union-attr]
            task.updated_at = self.utcnow_iso()  # type: ignore[union-attr]

            saved = self.repository.save(task)  # type: ignore[arg-type]
            after = self._task_to_dict(saved)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task=saved,
                before=before,
                after=after,
                extra={"comment_id": comment.comment_id},
            )

            self._emit_agent_event(
                TaskEventType.COMMENT_ADDED,
                user_id,
                workspace_id,
                {"task_id": task_id, "comment_id": comment.comment_id},
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                before=before,
                after=after,
            )

            return self._safe_result(
                "Comment added successfully",
                data={
                    "task": after,
                    "comment": asdict(comment),
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to add comment")
            return self._error_result("Failed to add comment", exc)

    # ------------------------------------------------------------------
    # Business views and dashboard helpers
    # ------------------------------------------------------------------

    def get_overdue_tasks(
        self,
        user_id: str,
        workspace_id: str,
        as_of: Optional[Union[str, datetime]] = None,
    ) -> Dict[str, Any]:
        """Return overdue open tasks."""

        try:
            as_of_dt = self.parse_datetime(as_of) or datetime.now(timezone.utc)

            tasks = []
            for task in self.repository.list_all():
                if task.user_id != user_id or task.workspace_id != workspace_id:
                    continue
                if task.is_deleted:
                    continue
                if task.status in {TaskStatus.DONE.value, TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
                    continue
                if not task.due_at:
                    continue
                due_dt = self.parse_datetime(task.due_at)
                if due_dt and due_dt < as_of_dt:
                    tasks.append(task)

            tasks = self._sort_tasks(tasks, "due_at", "asc")

            return self._safe_result(
                "Overdue tasks retrieved successfully",
                data={
                    "tasks": [self._task_to_dict(task) for task in tasks],
                    "count": len(tasks),
                    "as_of": as_of_dt.replace(microsecond=0).isoformat(),
                },
                metadata={
                    "agent": self.agent_name,
                    "action": "get_overdue_tasks",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to get overdue tasks")
            return self._error_result("Failed to get overdue tasks", exc)

    def get_upcoming_tasks(
        self,
        user_id: str,
        workspace_id: str,
        days: int = 7,
        as_of: Optional[Union[str, datetime]] = None,
    ) -> Dict[str, Any]:
        """Return open tasks due within the next N days."""

        action = "get_upcoming_tasks"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            as_of_dt = self.parse_datetime(as_of) or datetime.now(timezone.utc)
            days_int = max(1, int(days))
            until_dt = as_of_dt + timedelta(days=days_int)

            tasks = []

            for task in self.repository.list_all():
                if task.user_id != user_id or task.workspace_id != workspace_id:
                    continue
                if task.is_deleted:
                    continue
                if task.status in {TaskStatus.DONE.value, TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
                    continue
                if not task.due_at:
                    continue
                due_dt = self.parse_datetime(task.due_at)
                if due_dt and as_of_dt <= due_dt <= until_dt:
                    tasks.append(task)

            tasks = self._sort_tasks(tasks, "due_at", "asc")

            return self._safe_result(
                "Upcoming tasks retrieved successfully",
                data={
                    "tasks": [self._task_to_dict(task) for task in tasks],
                    "count": len(tasks),
                    "as_of": as_of_dt.replace(microsecond=0).isoformat(),
                    "until": until_dt.replace(microsecond=0).isoformat(),
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to get upcoming tasks")
            return self._error_result("Failed to get upcoming tasks", exc)

    def get_assignee_workload(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Return task workload grouped by assignee."""

        action = "get_assignee_workload"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            workload: Dict[str, Dict[str, Any]] = {}

            for task in self.repository.list_all():
                if task.user_id != user_id or task.workspace_id != workspace_id:
                    continue
                if task.is_deleted or task.status == TaskStatus.ARCHIVED.value:
                    continue

                assignees = task.assigned_to or ["unassigned"]

                for assignee in assignees:
                    if assignee not in workload:
                        workload[assignee] = {
                            "assignee": assignee,
                            "total": 0,
                            "open": 0,
                            "done": 0,
                            "overdue": 0,
                            "by_status": {},
                            "by_priority": {},
                        }

                    item = workload[assignee]
                    item["total"] += 1
                    item["by_status"][task.status] = item["by_status"].get(task.status, 0) + 1
                    item["by_priority"][task.priority] = item["by_priority"].get(task.priority, 0) + 1

                    if task.status == TaskStatus.DONE.value:
                        item["done"] += 1
                    else:
                        item["open"] += 1

                    if self._is_task_overdue(task):
                        item["overdue"] += 1

            return self._safe_result(
                "Assignee workload retrieved successfully",
                data={"workload": list(workload.values())},
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to get assignee workload")
            return self._error_result("Failed to get assignee workload", exc)

    def get_dashboard_summary(
        self,
        user_id: str,
        workspace_id: str,
        as_of: Optional[Union[str, datetime]] = None,
    ) -> Dict[str, Any]:
        """
        Return dashboard-ready task summary.

        Useful for Business Agent dashboard cards and analytics snapshots.
        """

        action = "get_dashboard_summary"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            as_of_dt = self.parse_datetime(as_of) or datetime.now(timezone.utc)
            tasks = [
                task for task in self.repository.list_all()
                if task.user_id == user_id
                and task.workspace_id == workspace_id
                and not task.is_deleted
            ]

            summary = {
                "total": len(tasks),
                "open": 0,
                "done": 0,
                "cancelled": 0,
                "archived": 0,
                "overdue": 0,
                "due_today": 0,
                "due_next_7_days": 0,
                "by_status": {},
                "by_priority": {},
                "unassigned": 0,
                "scheduled_reminders": 0,
                "due_reminders": 0,
            }

            today_start = as_of_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            next_7 = as_of_dt + timedelta(days=7)

            for task in tasks:
                summary["by_status"][task.status] = summary["by_status"].get(task.status, 0) + 1
                summary["by_priority"][task.priority] = summary["by_priority"].get(task.priority, 0) + 1

                if task.status == TaskStatus.DONE.value:
                    summary["done"] += 1
                elif task.status == TaskStatus.CANCELLED.value:
                    summary["cancelled"] += 1
                elif task.status == TaskStatus.ARCHIVED.value:
                    summary["archived"] += 1
                else:
                    summary["open"] += 1

                if not task.assigned_to:
                    summary["unassigned"] += 1

                due_dt = self.parse_datetime(task.due_at) if task.due_at else None
                if due_dt:
                    if task.status not in {TaskStatus.DONE.value, TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
                        if due_dt < as_of_dt:
                            summary["overdue"] += 1
                        if today_start <= due_dt < today_end:
                            summary["due_today"] += 1
                        if as_of_dt <= due_dt <= next_7:
                            summary["due_next_7_days"] += 1

                for reminder in task.reminders:
                    if reminder.status in {ReminderStatus.SCHEDULED.value, ReminderStatus.SNOOZED.value}:
                        summary["scheduled_reminders"] += 1
                        reminder_dt = self.parse_datetime(reminder.remind_at)
                        if reminder_dt and reminder_dt <= as_of_dt:
                            summary["due_reminders"] += 1

            return self._safe_result(
                "Task dashboard summary retrieved successfully",
                data={
                    "summary": summary,
                    "as_of": as_of_dt.replace(microsecond=0).isoformat(),
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to get task dashboard summary")
            return self._error_result("Failed to get task dashboard summary", exc)

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def bulk_update_status(
        self,
        user_id: str,
        workspace_id: str,
        task_ids: Iterable[str],
        status: str,
        changed_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Bulk update status for scoped tasks."""

        action = "bulk_update_status"

        try:
            ok, error = self._validate_task_context(user_id, workspace_id, action)
            if not ok:
                return self._error_result("Invalid task context", error)

            task_id_list = [str(task_id).strip() for task_id in task_ids if str(task_id).strip()]
            if not task_id_list:
                return self._error_result("Invalid task_ids", "At least one task_id is required")

            normalized_status = self._normalize_status(status)

            approval_payload = {
                "task_ids": task_id_list,
                "status": normalized_status,
                "changed_by": changed_by or user_id,
                "note": note,
            }

            if self._requires_security_check(action, approval_payload):
                approval = self._request_security_approval(action, user_id, workspace_id, approval_payload)
                if not approval.get("approved", False):
                    return self._error_result("Security approval denied", approval.get("reason"), {"approval": approval})

            updated: List[Dict[str, Any]] = []
            failed: List[Dict[str, Any]] = []

            for task_id in task_id_list:
                result = self.update_status(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    status=normalized_status,
                    changed_by=changed_by or user_id,
                    note=note,
                )
                if result.get("success"):
                    updated.append(result["data"]["task"])
                else:
                    failed.append({"task_id": task_id, "error": result.get("error")})

            verification_payload = {
                "verification_type": "business_task_bulk_action",
                "action": action,
                "agent": self.agent_name,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "updated_count": len(updated),
                "failed_count": len(failed),
                "status": normalized_status,
                "created_at": self.utcnow_iso(),
            }

            self._emit_agent_event(
                TaskEventType.BULK_UPDATED,
                user_id,
                workspace_id,
                {
                    "action": action,
                    "updated_count": len(updated),
                    "failed_count": len(failed),
                    "status": normalized_status,
                },
            )
            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=verification_payload,
            )

            return self._safe_result(
                "Bulk task status update completed",
                data={
                    "updated": updated,
                    "failed": failed,
                    "updated_count": len(updated),
                    "failed_count": len(failed),
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to bulk update task status")
            return self._error_result("Failed to bulk update task status", exc)

    # ------------------------------------------------------------------
    # Export and integration helpers
    # ------------------------------------------------------------------

    def export_tasks(
        self,
        user_id: str,
        workspace_id: str,
        include_deleted: bool = False,
        include_archived: bool = True,
    ) -> Dict[str, Any]:
        """
        Export scoped tasks as JSON-serializable data.

        This does not write files directly. Dashboard/API can transform the
        returned data into CSV, PDF, spreadsheet, or other formats.
        """

        action = "export_tasks"

        try:
            list_result = self.list_tasks(
                user_id=user_id,
                workspace_id=workspace_id,
                include_deleted=include_deleted,
                include_archived=include_archived,
                page=1,
                page_size=MAX_PAGE_SIZE,
                sort_by="created_at",
                sort_order="desc",
            )

            if not list_result.get("success"):
                return list_result

            tasks = list_result["data"]["tasks"]

            export_payload = {
                "export_type": "business_tasks_json",
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_count": len(tasks),
                "tasks": tasks,
                "exported_at": self.utcnow_iso(),
            }

            return self._safe_result(
                "Tasks exported successfully",
                data=export_payload,
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "format": "json",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Failed to export tasks")
            return self._error_result("Failed to export tasks", exc)

    def get_agent_metadata(self) -> Dict[str, Any]:
        """
        Return registry-compatible metadata.

        Agent Loader, Agent Registry, and Master Agent Router can use this.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module_name": self.module_name,
            "file_name": self.file_name,
            "class_name": self.__class__.__name__,
            "description": "Business tasks, reminders, assignment, deadlines, and status manager.",
            "capabilities": [
                "create_business_task",
                "list_business_tasks",
                "get_business_task",
                "update_business_task",
                "assign_business_task",
                "complete_business_task",
                "cancel_business_task",
                "archive_business_task",
                "delete_business_task",
                "restore_business_task",
                "add_task_reminder",
                "update_task_reminder",
                "cancel_task_reminder",
                "snooze_task_reminder",
                "get_due_reminders",
                "add_task_comment",
                "get_overdue_tasks",
                "get_upcoming_tasks",
                "get_assignee_workload",
                "get_task_dashboard_summary",
                "bulk_update_task_status",
                "export_business_tasks",
            ],
            "requires_user_id": True,
            "requires_workspace_id": True,
            "security_hooks": [
                "_requires_security_check",
                "_request_security_approval",
            ],
            "verification_hook": "_prepare_verification_payload",
            "memory_hook": "_prepare_memory_payload",
            "audit_hook": "_log_audit_event",
            "event_hook": "_emit_agent_event",
            "safe_to_import": True,
            "storage": self.repository.__class__.__name__,
            "version": "1.0.0",
        }

    def health_check(self) -> Dict[str, Any]:
        """Return lightweight health status."""

        try:
            task_count = len(self.repository.list_all())
            return self._safe_result(
                "BusinessTaskManager is healthy",
                data={
                    "status": "healthy",
                    "task_count": task_count,
                    "repository": self.repository.__class__.__name__,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                    "checked_at": self.utcnow_iso(),
                },
            )
        except Exception as exc:
            return self._error_result("BusinessTaskManager health check failed", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_reminder_from_payload(self, payload: Dict[str, Any]) -> TaskReminder:
        """Build TaskReminder from input payload."""

        if not isinstance(payload, dict):
            raise ValueError("Reminder payload must be a dictionary")

        remind_at = self.normalize_datetime(payload.get("remind_at"))
        if not remind_at:
            raise ValueError("remind_at is required for reminder")

        channel = str(payload.get("channel") or self.default_reminder_channel).strip().lower()
        if not channel:
            channel = "dashboard"

        return TaskReminder(
            reminder_id=str(payload.get("reminder_id") or uuid.uuid4()),
            remind_at=remind_at,
            status=str(payload.get("status") or ReminderStatus.SCHEDULED.value).strip().lower(),
            message=payload.get("message"),
            channel=channel,
            metadata=self._safe_copy(payload.get("metadata") or {}),
        )

    def _find_reminder_index(self, task: BusinessTask, reminder_id: str) -> int:
        """Find reminder index by ID."""

        for index, reminder in enumerate(task.reminders):
            if reminder.reminder_id == reminder_id:
                return index
        return -1

    def _apply_status_transition(
        self,
        task: BusinessTask,
        new_status: str,
        actor_id: Optional[str] = None,
    ) -> BusinessTask:
        """Apply status and lifecycle timestamps."""

        previous_status = task.status
        now = self.utcnow_iso()

        task.status = new_status
        task.metadata["previous_status"] = previous_status
        task.metadata["last_status_changed_at"] = now

        if actor_id:
            task.metadata["last_status_changed_by"] = actor_id

        if new_status == TaskStatus.DONE.value:
            task.completed_at = task.completed_at or now
            task.cancelled_at = None
        elif new_status == TaskStatus.CANCELLED.value:
            task.cancelled_at = task.cancelled_at or now
        elif new_status == TaskStatus.ARCHIVED.value:
            task.archived_at = task.archived_at or now
        elif new_status not in {TaskStatus.DONE.value, TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
            if previous_status == TaskStatus.DONE.value:
                task.completed_at = None
            if previous_status == TaskStatus.CANCELLED.value:
                task.cancelled_at = None
            if previous_status == TaskStatus.ARCHIVED.value:
                task.archived_at = None

        return task

    def _normalize_filter_values(
        self,
        values: Optional[Union[str, Iterable[str]]],
        enum_cls: Any,
    ) -> set:
        """Normalize filter value(s) against enum values."""

        if values is None:
            return set()

        if isinstance(values, str):
            raw_values = [values]
        else:
            raw_values = list(values)

        allowed = {item.value for item in enum_cls}
        normalized = set()

        for value in raw_values:
            item = str(value).strip().lower()
            if item in allowed:
                normalized.add(item)

        return normalized

    def _sort_tasks(
        self,
        tasks: List[BusinessTask],
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> List[BusinessTask]:
        """Sort tasks safely by known fields."""

        allowed_fields = {
            "created_at",
            "updated_at",
            "due_at",
            "start_at",
            "completed_at",
            "priority",
            "status",
            "title",
        }

        field_name = sort_by if sort_by in allowed_fields else "created_at"
        reverse = str(sort_order).lower() != "asc"

        priority_weight = {
            TaskPriority.URGENT.value: 5,
            TaskPriority.HIGH.value: 4,
            TaskPriority.MEDIUM.value: 3,
            TaskPriority.NORMAL.value: 2,
            TaskPriority.LOW.value: 1,
        }

        def sort_key(task: BusinessTask) -> Any:
            value = getattr(task, field_name, None)

            if field_name == "priority":
                return priority_weight.get(task.priority, 0)

            if field_name in {"created_at", "updated_at", "due_at", "start_at", "completed_at"}:
                parsed = self.parse_datetime(value) if value else None
                return parsed or datetime.min.replace(tzinfo=timezone.utc)

            if value is None:
                return ""

            return value

        return sorted(tasks, key=sort_key, reverse=reverse)

    def _is_task_overdue(self, task: BusinessTask, as_of: Optional[datetime] = None) -> bool:
        """Check whether task is overdue."""

        if not task.due_at:
            return False

        if task.status in {TaskStatus.DONE.value, TaskStatus.CANCELLED.value, TaskStatus.ARCHIVED.value}:
            return False

        due_dt = self.parse_datetime(task.due_at)
        if not due_dt:
            return False

        return due_dt < (as_of or datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Module-level factory for registry/loader convenience
# ---------------------------------------------------------------------------

def create_business_task_manager(
    repository: Optional[InMemoryBusinessTaskRepository] = None,
    security_agent: Any = None,
    memory_agent: Any = None,
    verification_agent: Any = None,
    event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> BusinessTaskManager:
    """
    Factory function for Agent Loader / Registry.

    Keeps construction stable even if dependency injection changes later.
    """

    return BusinessTaskManager(
        repository=repository,
        security_agent=security_agent,
        memory_agent=memory_agent,
        verification_agent=verification_agent,
        event_callback=event_callback,
        audit_callback=audit_callback,
        config=config,
    )


__all__ = [
    "BusinessTaskManager",
    "BusinessTask",
    "TaskReminder",
    "TaskComment",
    "TaskStatus",
    "TaskPriority",
    "ReminderStatus",
    "TaskEventType",
    "InMemoryBusinessTaskRepository",
    "create_business_task_manager",
]