"""
agents/workflow_agent/scheduler.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Runs recurring/time-based workflows and delayed actions for the Workflow Agent.

This module is designed to be:
    - Import-safe even when the wider William/Jarvis codebase is incomplete.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - SaaS-safe with strict user_id/workspace_id isolation.
    - Security-aware: sensitive scheduled executions can require Security Agent approval.
    - Verification-ready: every completed execution prepares a Verification Agent payload.
    - Memory-ready: useful scheduling/execution context can be passed to Memory Agent.
    - Dashboard/API-ready: all public methods return structured dict results.

Responsibilities:
    - Create one-time delayed scheduled actions.
    - Create recurring time-based workflow schedules.
    - Pause, resume, cancel, delete, and inspect schedules.
    - Run due schedules manually or through a safe background loop.
    - Avoid direct destructive/system/financial/message/call/browser actions unless approval hooks allow it.
    - Provide audit, event, verification, and memory payload hooks.

Notes:
    - This file does not directly send emails, messages, calls, browser actions, payments,
      or destructive operations.
    - Actual execution should be delegated to an injected callable such as ActionRouter,
      WorkflowAgent, MasterAgent route method, or another approved executor.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import heapq
import inspect
import logging
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# =============================================================================
# Optional imports / fallback compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import/testing
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent may provide richer lifecycle,
        registry, routing, permission, and telemetry methods. This fallback
        keeps scheduler.py import-safe before all system files exist.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "workflow")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s", payload)


try:
    from agents.workflow_agent.action_router import ActionRouter  # type: ignore
except Exception:  # pragma: no cover
    ActionRouter = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums / data structures
# =============================================================================

class ScheduleType(str, enum.Enum):
    """Supported schedule types."""

    ONCE = "once"
    INTERVAL = "interval"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ScheduleStatus(str, enum.Enum):
    """Lifecycle status for a scheduled workflow/action."""

    ACTIVE = "active"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class ExecutionStatus(str, enum.Enum):
    """Execution status for scheduled runs."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_APPROVAL = "requires_approval"


class SensitivityLevel(str, enum.Enum):
    """Security sensitivity level used before execution."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclasses.dataclass
class SchedulePolicy:
    """
    Execution policy for scheduled workflows.

    max_runs:
        Maximum total runs before schedule completes.
    max_failures:
        Maximum failures before schedule is marked failed.
    retry_on_failure:
        Whether scheduler should keep next recurring run after failure.
    require_security_approval:
        Force Security Agent approval even if payload does not look sensitive.
    allow_background_execution:
        If False, schedule can be listed/detected but not executed by background loop.
    """

    max_runs: Optional[int] = None
    max_failures: int = 5
    retry_on_failure: bool = True
    require_security_approval: bool = False
    allow_background_execution: bool = True


@dataclasses.dataclass
class ScheduledItem:
    """
    Represents a scheduled workflow or delayed action.

    user_id/workspace_id are mandatory for SaaS isolation.
    action_payload is intentionally generic so Workflow Agent, Master Agent,
    Action Router, or future plugin executors can consume it.
    """

    schedule_id: str
    user_id: str
    workspace_id: str
    schedule_type: ScheduleType
    action_payload: Dict[str, Any]
    next_run_at: datetime
    created_at: datetime
    updated_at: datetime
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    name: Optional[str] = None
    description: Optional[str] = None
    timezone_name: str = "UTC"
    interval_seconds: Optional[int] = None
    day_of_week: Optional[int] = None  # Monday=0, Sunday=6
    day_of_month: Optional[int] = None  # 1-31
    time_of_day: Optional[str] = None  # HH:MM
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    policy: SchedulePolicy = dataclasses.field(default_factory=SchedulePolicy)
    run_count: int = 0
    failure_count: int = 0
    last_run_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error: Optional[str] = None
    locked_until: Optional[datetime] = None

    def to_dict(self, include_payload: bool = True) -> Dict[str, Any]:
        data = {
            "schedule_id": self.schedule_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "schedule_type": self.schedule_type.value,
            "status": self.status.value,
            "name": self.name,
            "description": self.description,
            "next_run_at": _dt_to_iso(self.next_run_at),
            "created_at": _dt_to_iso(self.created_at),
            "updated_at": _dt_to_iso(self.updated_at),
            "timezone_name": self.timezone_name,
            "interval_seconds": self.interval_seconds,
            "day_of_week": self.day_of_week,
            "day_of_month": self.day_of_month,
            "time_of_day": self.time_of_day,
            "metadata": copy.deepcopy(self.metadata),
            "policy": dataclasses.asdict(self.policy),
            "run_count": self.run_count,
            "failure_count": self.failure_count,
            "last_run_at": _dt_to_iso(self.last_run_at),
            "last_success_at": _dt_to_iso(self.last_success_at),
            "last_failure_at": _dt_to_iso(self.last_failure_at),
            "last_error": self.last_error,
            "locked_until": _dt_to_iso(self.locked_until),
        }
        if include_payload:
            data["action_payload"] = copy.deepcopy(self.action_payload)
        return data


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_now() -> datetime:
    """Return timezone-aware UTC now."""

    return datetime.now(timezone.utc)


def _dt_to_iso(value: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO string safely."""

    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: Union[str, datetime]) -> datetime:
    """
    Parse string/datetime into timezone-aware UTC datetime.

    Accepts:
        - datetime object
        - ISO string with timezone
        - ISO string without timezone, treated as UTC
    """

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        dt = datetime.fromisoformat(normalized)
    else:
        raise TypeError("Expected datetime or ISO datetime string.")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def _parse_time_of_day(value: str) -> Tuple[int, int]:
    """Parse HH:MM string."""

    if not isinstance(value, str) or ":" not in value:
        raise ValueError("time_of_day must be in HH:MM format.")

    hour_raw, minute_raw = value.split(":", 1)
    hour = int(hour_raw)
    minute = int(minute_raw)

    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError("time_of_day must be a valid 24-hour HH:MM value.")

    return hour, minute


def _safe_deepcopy(value: Any) -> Any:
    """Safely deepcopy arbitrary payloads."""

    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _contains_sensitive_action(payload: Dict[str, Any]) -> bool:
    """
    Heuristic detector for actions that should require Security Agent approval.

    This does not replace Security Agent. It is a local safety pre-check so the
    scheduler does not silently execute sensitive workflows.
    """

    sensitive_keywords = {
        "send_email",
        "email_send",
        "send_whatsapp",
        "whatsapp_send",
        "send_sms",
        "sms_send",
        "call",
        "voice_call",
        "payment",
        "charge",
        "refund",
        "invoice",
        "delete",
        "archive",
        "browser",
        "system",
        "shell",
        "terminal",
        "file_delete",
        "financial",
        "crm_update",
        "deal_update",
        "webhook_post",
        "external_api",
    }

    try:
        serialized = str(payload).lower()
    except Exception:
        return True

    return any(keyword in serialized for keyword in sensitive_keywords)


def _call_maybe_async_unsafe(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """
    Call a function and handle coroutine return when possible.

    This scheduler is stdlib-friendly and does not require asyncio. If an
    async coroutine is returned, we try to run it safely with asyncio.run unless
    an event loop is already running. If a loop is already running, return the
    coroutine object for the caller/executor layer to handle.
    """

    result = func(*args, **kwargs)

    if inspect.isawaitable(result):
        try:
            import asyncio

            try:
                asyncio.get_running_loop()
                return result
            except RuntimeError:
                return asyncio.run(result)
        except Exception:
            return result

    return result


# =============================================================================
# WorkflowScheduler
# =============================================================================

class WorkflowScheduler(BaseAgent):
    """
    Runs recurring/time-based workflows and delayed actions.

    Master Agent connection:
        The Master Agent can route scheduling tasks to this class using
        public methods such as schedule_workflow(), schedule_delayed_action(),
        run_due(), pause_schedule(), resume_schedule(), and cancel_schedule().

    Security Agent connection:
        Before a sensitive scheduled item executes, _requires_security_check()
        and _request_security_approval() are called. In production, inject
        security_agent or override these hooks through BaseAgent.

    Memory Agent connection:
        After schedule creation and execution, _prepare_memory_payload() returns
        a compact memory-compatible payload that can be stored by Memory Agent.

    Verification Agent connection:
        After execution, _prepare_verification_payload() returns a structured
        payload for Verification Agent.

    Dashboard/API connection:
        Every public method returns a structured dict with:
            success, message, data, error, metadata

    Registry/Loader compatibility:
        Class name is stable: WorkflowScheduler.
        Import is safe even when future modules are missing.
    """

    agent_name = "workflow_scheduler"
    agent_type = "workflow"
    public_methods = [
        "schedule_workflow",
        "schedule_delayed_action",
        "schedule_recurring_workflow",
        "run_due",
        "start",
        "stop",
        "pause_schedule",
        "resume_schedule",
        "cancel_schedule",
        "delete_schedule",
        "get_schedule",
        "list_schedules",
        "get_execution_history",
        "health_check",
    ]

    def __init__(
        self,
        *,
        action_executor: Optional[Callable[..., Any]] = None,
        action_router: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        default_poll_interval_seconds: float = 1.0,
        lock_ttl_seconds: int = 300,
        max_history_items: int = 1000,
        auto_start: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type=self.agent_type, **kwargs)

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.action_executor = action_executor
        self.action_router = action_router
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.default_poll_interval_seconds = max(float(default_poll_interval_seconds), 0.25)
        self.lock_ttl_seconds = max(int(lock_ttl_seconds), 30)
        self.max_history_items = max(int(max_history_items), 100)

        self._schedules: Dict[str, ScheduledItem] = {}
        self._due_heap: List[Tuple[float, str]] = []
        self._execution_history: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        if auto_start:
            self.start()

    # -------------------------------------------------------------------------
    # Public scheduling methods
    # -------------------------------------------------------------------------

    def schedule_delayed_action(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action_payload: Dict[str, Any],
        run_at: Optional[Union[str, datetime]] = None,
        delay_seconds: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        policy: Optional[Union[SchedulePolicy, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Schedule a one-time delayed action.

        Either run_at or delay_seconds must be provided.
        """

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(action_payload, dict) or not action_payload:
                return self._error_result(
                    message="action_payload must be a non-empty dict.",
                    error="invalid_action_payload",
                    metadata={"method": "schedule_delayed_action"},
                )

            if run_at is None and delay_seconds is None:
                return self._error_result(
                    message="Either run_at or delay_seconds is required.",
                    error="missing_schedule_time",
                    metadata={"method": "schedule_delayed_action"},
                )

            if delay_seconds is not None:
                if int(delay_seconds) < 0:
                    return self._error_result(
                        message="delay_seconds cannot be negative.",
                        error="invalid_delay_seconds",
                    )
                next_run_at = _utc_now() + timedelta(seconds=int(delay_seconds))
            else:
                next_run_at = _parse_datetime(run_at)  # type: ignore[arg-type]

            item = self._create_scheduled_item(
                user_id=user_id,
                workspace_id=workspace_id,
                schedule_type=ScheduleType.ONCE,
                action_payload=action_payload,
                next_run_at=next_run_at,
                name=name,
                description=description,
                metadata=metadata,
                policy=policy,
            )

            self._store_schedule(item)
            self._log_audit_event(
                "workflow_schedule_created",
                item,
                extra={"schedule_mode": "delayed_action"},
            )
            self._emit_agent_event(
                "workflow.scheduler.created",
                {
                    "schedule_id": item.schedule_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "schedule_type": item.schedule_type.value,
                    "next_run_at": _dt_to_iso(item.next_run_at),
                },
            )

            memory_payload = self._prepare_memory_payload(
                event_type="schedule_created",
                item=item,
                execution_result=None,
            )

            return self._safe_result(
                message="Delayed action scheduled successfully.",
                data={
                    "schedule": item.to_dict(),
                    "memory_payload": memory_payload,
                },
                metadata={"method": "schedule_delayed_action"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="schedule_delayed_action")

    def schedule_workflow(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_payload: Dict[str, Any],
        schedule_type: Union[str, ScheduleType] = ScheduleType.ONCE,
        run_at: Optional[Union[str, datetime]] = None,
        interval_seconds: Optional[int] = None,
        time_of_day: Optional[str] = None,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timezone_name: str = "UTC",
        metadata: Optional[Dict[str, Any]] = None,
        policy: Optional[Union[SchedulePolicy, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Schedule a workflow.

        Supported schedule_type:
            - once
            - interval
            - daily
            - weekly
            - monthly
        """

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(workflow_payload, dict) or not workflow_payload:
                return self._error_result(
                    message="workflow_payload must be a non-empty dict.",
                    error="invalid_workflow_payload",
                    metadata={"method": "schedule_workflow"},
                )

            normalized_type = ScheduleType(schedule_type.value if isinstance(schedule_type, ScheduleType) else str(schedule_type))

            next_run_at = self._calculate_initial_run_time(
                schedule_type=normalized_type,
                run_at=run_at,
                interval_seconds=interval_seconds,
                time_of_day=time_of_day,
                day_of_week=day_of_week,
                day_of_month=day_of_month,
            )

            item = self._create_scheduled_item(
                user_id=user_id,
                workspace_id=workspace_id,
                schedule_type=normalized_type,
                action_payload={
                    "kind": "workflow",
                    "workflow_payload": _safe_deepcopy(workflow_payload),
                },
                next_run_at=next_run_at,
                name=name,
                description=description,
                timezone_name=timezone_name,
                interval_seconds=interval_seconds,
                day_of_week=day_of_week,
                day_of_month=day_of_month,
                time_of_day=time_of_day,
                metadata=metadata,
                policy=policy,
            )

            validation = self._validate_schedule_item(item)
            if not validation["success"]:
                return validation

            self._store_schedule(item)
            self._log_audit_event(
                "workflow_schedule_created",
                item,
                extra={"schedule_mode": "workflow"},
            )
            self._emit_agent_event(
                "workflow.scheduler.created",
                {
                    "schedule_id": item.schedule_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "schedule_type": item.schedule_type.value,
                    "next_run_at": _dt_to_iso(item.next_run_at),
                },
            )

            memory_payload = self._prepare_memory_payload(
                event_type="schedule_created",
                item=item,
                execution_result=None,
            )

            return self._safe_result(
                message="Workflow scheduled successfully.",
                data={
                    "schedule": item.to_dict(),
                    "memory_payload": memory_payload,
                },
                metadata={"method": "schedule_workflow"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="schedule_workflow")

    def schedule_recurring_workflow(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_payload: Dict[str, Any],
        schedule_type: Union[str, ScheduleType],
        interval_seconds: Optional[int] = None,
        time_of_day: Optional[str] = None,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        start_at: Optional[Union[str, datetime]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timezone_name: str = "UTC",
        metadata: Optional[Dict[str, Any]] = None,
        policy: Optional[Union[SchedulePolicy, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Convenience method for recurring schedules."""

        normalized_type = ScheduleType(schedule_type.value if isinstance(schedule_type, ScheduleType) else str(schedule_type))
        if normalized_type == ScheduleType.ONCE:
            return self._error_result(
                message="schedule_recurring_workflow does not accept schedule_type='once'.",
                error="invalid_recurring_type",
            )

        return self.schedule_workflow(
            user_id=user_id,
            workspace_id=workspace_id,
            workflow_payload=workflow_payload,
            schedule_type=normalized_type,
            run_at=start_at,
            interval_seconds=interval_seconds,
            time_of_day=time_of_day,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            name=name,
            description=description,
            timezone_name=timezone_name,
            metadata=metadata,
            policy=policy,
        )

    # -------------------------------------------------------------------------
    # Public control methods
    # -------------------------------------------------------------------------

    def start(self) -> Dict[str, Any]:
        """
        Start background scheduler loop.

        Background execution only runs schedules whose policy allows it.
        """

        try:
            with self._lock:
                if self._worker_thread and self._worker_thread.is_alive():
                    return self._safe_result(
                        message="Workflow scheduler is already running.",
                        data={"running": True},
                        metadata={"method": "start"},
                    )

                self._stop_event.clear()
                self._worker_thread = threading.Thread(
                    target=self._run_loop,
                    name="WilliamWorkflowScheduler",
                    daemon=True,
                )
                self._worker_thread.start()

            self._emit_agent_event("workflow.scheduler.started", {"started_at": _dt_to_iso(_utc_now())})
            return self._safe_result(
                message="Workflow scheduler started.",
                data={"running": True},
                metadata={"method": "start"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="start")

    def stop(self, *, timeout_seconds: float = 5.0) -> Dict[str, Any]:
        """Stop background scheduler loop."""

        try:
            self._stop_event.set()
            thread = self._worker_thread
            if thread and thread.is_alive():
                thread.join(timeout=max(float(timeout_seconds), 0.1))

            running = bool(thread and thread.is_alive())
            self._emit_agent_event(
                "workflow.scheduler.stopped",
                {"stopped_at": _dt_to_iso(_utc_now()), "running": running},
            )
            return self._safe_result(
                message="Workflow scheduler stop requested.",
                data={"running": running},
                metadata={"method": "stop"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="stop")

    def pause_schedule(
        self,
        *,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Pause an active schedule within the same user/workspace boundary."""

        return self._set_schedule_status(
            schedule_id=schedule_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=ScheduleStatus.PAUSED,
            message="Schedule paused successfully.",
            event_name="workflow.scheduler.paused",
            method="pause_schedule",
        )

    def resume_schedule(
        self,
        *,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
        next_run_at: Optional[Union[str, datetime]] = None,
    ) -> Dict[str, Any]:
        """Resume a paused schedule."""

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            with self._lock:
                item = self._get_owned_schedule_or_none(schedule_id, user_id, workspace_id)
                if item is None:
                    return self._not_found_or_forbidden(schedule_id)

                if item.status in {ScheduleStatus.CANCELLED, ScheduleStatus.COMPLETED}:
                    return self._error_result(
                        message=f"Cannot resume schedule with status '{item.status.value}'.",
                        error="invalid_schedule_status",
                        metadata={"schedule_id": schedule_id, "status": item.status.value},
                    )

                item.status = ScheduleStatus.ACTIVE
                item.updated_at = _utc_now()
                if next_run_at is not None:
                    item.next_run_at = _parse_datetime(next_run_at)
                elif item.next_run_at <= _utc_now():
                    item.next_run_at = self._calculate_next_run(item, from_time=_utc_now()) or _utc_now()

                self._push_due_heap(item)

            self._log_audit_event("workflow_schedule_resumed", item)
            self._emit_agent_event(
                "workflow.scheduler.resumed",
                {
                    "schedule_id": item.schedule_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "next_run_at": _dt_to_iso(item.next_run_at),
                },
            )

            return self._safe_result(
                message="Schedule resumed successfully.",
                data={"schedule": item.to_dict()},
                metadata={"method": "resume_schedule"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="resume_schedule")

    def cancel_schedule(
        self,
        *,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Cancel a schedule without deleting its record/history."""

        return self._set_schedule_status(
            schedule_id=schedule_id,
            user_id=user_id,
            workspace_id=workspace_id,
            status=ScheduleStatus.CANCELLED,
            message="Schedule cancelled successfully.",
            event_name="workflow.scheduler.cancelled",
            method="cancel_schedule",
        )

    def delete_schedule(
        self,
        *,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """
        Delete a schedule from the local store.

        This does not delete execution history. Dashboard/API layers may choose
        to preserve records in persistent storage.
        """

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            with self._lock:
                item = self._get_owned_schedule_or_none(schedule_id, user_id, workspace_id)
                if item is None:
                    return self._not_found_or_forbidden(schedule_id)

                removed = self._schedules.pop(schedule_id)

            self._log_audit_event("workflow_schedule_deleted", removed)
            self._emit_agent_event(
                "workflow.scheduler.deleted",
                {
                    "schedule_id": schedule_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

            return self._safe_result(
                message="Schedule deleted successfully.",
                data={"schedule_id": schedule_id},
                metadata={"method": "delete_schedule"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="delete_schedule")

    # -------------------------------------------------------------------------
    # Public read methods
    # -------------------------------------------------------------------------

    def get_schedule(
        self,
        *,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
        include_payload: bool = True,
    ) -> Dict[str, Any]:
        """Get one schedule, enforcing user/workspace isolation."""

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            with self._lock:
                item = self._get_owned_schedule_or_none(schedule_id, user_id, workspace_id)
                if item is None:
                    return self._not_found_or_forbidden(schedule_id)

                data = item.to_dict(include_payload=include_payload)

            return self._safe_result(
                message="Schedule retrieved successfully.",
                data={"schedule": data},
                metadata={"method": "get_schedule"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="get_schedule")

    def list_schedules(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[Union[str, ScheduleStatus]] = None,
        schedule_type: Optional[Union[str, ScheduleType]] = None,
        include_payload: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List schedules for a single user/workspace only."""

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            normalized_status = None
            if status is not None:
                normalized_status = ScheduleStatus(status.value if isinstance(status, ScheduleStatus) else str(status))

            normalized_type = None
            if schedule_type is not None:
                normalized_type = ScheduleType(schedule_type.value if isinstance(schedule_type, ScheduleType) else str(schedule_type))

            safe_limit = max(min(int(limit), 500), 1)
            safe_offset = max(int(offset), 0)

            with self._lock:
                items = [
                    item
                    for item in self._schedules.values()
                    if item.user_id == user_id and item.workspace_id == workspace_id
                ]

                if normalized_status is not None:
                    items = [item for item in items if item.status == normalized_status]

                if normalized_type is not None:
                    items = [item for item in items if item.schedule_type == normalized_type]

                items.sort(key=lambda x: x.next_run_at)
                total = len(items)
                page = items[safe_offset:safe_offset + safe_limit]

                schedules = [item.to_dict(include_payload=include_payload) for item in page]

            return self._safe_result(
                message="Schedules listed successfully.",
                data={
                    "schedules": schedules,
                    "total": total,
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
                metadata={"method": "list_schedules"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="list_schedules")

    def get_execution_history(
        self,
        *,
        user_id: str,
        workspace_id: str,
        schedule_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Return execution history for a single user/workspace only."""

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            safe_limit = max(min(int(limit), 500), 1)
            safe_offset = max(int(offset), 0)

            with self._lock:
                history = [
                    item
                    for item in self._execution_history
                    if item.get("user_id") == user_id and item.get("workspace_id") == workspace_id
                ]

                if schedule_id:
                    history = [item for item in history if item.get("schedule_id") == schedule_id]

                history.sort(key=lambda x: x.get("started_at") or "", reverse=True)
                total = len(history)
                page = copy.deepcopy(history[safe_offset:safe_offset + safe_limit])

            return self._safe_result(
                message="Execution history retrieved successfully.",
                data={
                    "history": page,
                    "total": total,
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
                metadata={"method": "get_execution_history"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="get_execution_history")

    def health_check(self) -> Dict[str, Any]:
        """Return scheduler health for dashboard/monitoring."""

        try:
            with self._lock:
                active = sum(1 for item in self._schedules.values() if item.status == ScheduleStatus.ACTIVE)
                paused = sum(1 for item in self._schedules.values() if item.status == ScheduleStatus.PAUSED)
                failed = sum(1 for item in self._schedules.values() if item.status == ScheduleStatus.FAILED)
                completed = sum(1 for item in self._schedules.values() if item.status == ScheduleStatus.COMPLETED)
                cancelled = sum(1 for item in self._schedules.values() if item.status == ScheduleStatus.CANCELLED)
                total = len(self._schedules)
                due_heap_size = len(self._due_heap)

            running = bool(self._worker_thread and self._worker_thread.is_alive())

            return self._safe_result(
                message="Workflow scheduler health check completed.",
                data={
                    "agent_name": self.agent_name,
                    "agent_type": self.agent_type,
                    "running": running,
                    "total_schedules": total,
                    "active_schedules": active,
                    "paused_schedules": paused,
                    "failed_schedules": failed,
                    "completed_schedules": completed,
                    "cancelled_schedules": cancelled,
                    "due_heap_size": due_heap_size,
                    "history_items": len(self._execution_history),
                    "poll_interval_seconds": self.default_poll_interval_seconds,
                    "lock_ttl_seconds": self.lock_ttl_seconds,
                },
                metadata={"method": "health_check"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="health_check")

    # -------------------------------------------------------------------------
    # Execution methods
    # -------------------------------------------------------------------------

    def run_due(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        max_items: int = 50,
        execute: bool = True,
        allow_sensitive_without_approval: bool = False,
    ) -> Dict[str, Any]:
        """
        Run schedules that are due.

        If user_id/workspace_id are provided, only that tenant boundary is used.
        If omitted, this method can run all due schedules; use carefully from
        trusted internal Master Agent/system context only.

        execute=False is useful for dashboard preview / dry-run.
        """

        try:
            if (user_id and not workspace_id) or (workspace_id and not user_id):
                return self._error_result(
                    message="Both user_id and workspace_id are required when filtering run_due.",
                    error="invalid_context_filter",
                    metadata={"method": "run_due"},
                )

            if user_id and workspace_id:
                context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
                if not context_result["success"]:
                    return context_result

            safe_max = max(min(int(max_items), 500), 1)
            due_items = self._pop_due_items(
                max_items=safe_max,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            results: List[Dict[str, Any]] = []

            for item in due_items:
                if not execute:
                    results.append({
                        "schedule_id": item.schedule_id,
                        "status": ExecutionStatus.SKIPPED.value,
                        "message": "Due schedule detected but not executed because execute=False.",
                        "next_run_at": _dt_to_iso(item.next_run_at),
                    })
                    self._reschedule_or_complete(item, execution_succeeded=True, skipped=True)
                    continue

                execution_result = self._execute_scheduled_item(
                    item,
                    allow_sensitive_without_approval=allow_sensitive_without_approval,
                    background=False,
                )
                results.append(execution_result)

            return self._safe_result(
                message="Due schedules processed.",
                data={
                    "processed_count": len(results),
                    "results": results,
                },
                metadata={"method": "run_due"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="run_due")

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, *, user_id: str, workspace_id: str, **_: Any) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific scheduled item must include both user_id and workspace_id.
        """

        if not isinstance(user_id, str) or not user_id.strip():
            return self._error_result(
                message="user_id is required for WorkflowScheduler operations.",
                error="missing_user_id",
                metadata={"hook": "_validate_task_context"},
            )

        if not isinstance(workspace_id, str) or not workspace_id.strip():
            return self._error_result(
                message="workspace_id is required for WorkflowScheduler operations.",
                error="missing_workspace_id",
                metadata={"hook": "_validate_task_context"},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id.strip(),
                "workspace_id": workspace_id.strip(),
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        *,
        item: ScheduledItem,
        sensitivity_level: Optional[Union[str, SensitivityLevel]] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Production systems may override this through BaseAgent or inject a
        richer Security Agent. This conservative fallback checks policy and
        payload keywords.
        """

        if item.policy.require_security_approval:
            return True

        if sensitivity_level:
            level = SensitivityLevel(
                sensitivity_level.value if isinstance(sensitivity_level, SensitivityLevel) else str(sensitivity_level)
            )
            if level in {SensitivityLevel.HIGH, SensitivityLevel.CRITICAL}:
                return True

        return _contains_sensitive_action(item.action_payload)

    def _request_security_approval(
        self,
        *,
        item: ScheduledItem,
        reason: str,
        sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Expected security_agent interfaces supported:
            - approve_scheduled_action(payload)
            - request_approval(payload)
            - validate_action(payload)

        If no Security Agent exists, sensitive actions are denied by default.
        """

        approval_payload = {
            "request_id": str(uuid.uuid4()),
            "reason": reason,
            "sensitivity_level": sensitivity_level.value,
            "agent": self.agent_name,
            "user_id": item.user_id,
            "workspace_id": item.workspace_id,
            "schedule_id": item.schedule_id,
            "schedule_type": item.schedule_type.value,
            "action_payload": _safe_deepcopy(item.action_payload),
            "requested_at": _dt_to_iso(_utc_now()),
            "metadata": _safe_deepcopy(item.metadata),
        }

        if self.security_agent is None:
            return self._error_result(
                message="Security approval required but no Security Agent is configured.",
                error="security_agent_unavailable",
                data={
                    "approved": False,
                    "approval_payload": approval_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        try:
            for method_name in ("approve_scheduled_action", "request_approval", "validate_action"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    response = _call_maybe_async_unsafe(method, approval_payload)

                    if isinstance(response, dict):
                        approved = bool(
                            response.get("approved")
                            or response.get("success") is True and response.get("data", {}).get("approved", False)
                        )
                        if approved:
                            return self._safe_result(
                                message="Security approval granted.",
                                data={
                                    "approved": True,
                                    "security_response": response,
                                    "approval_payload": approval_payload,
                                },
                                metadata={"hook": "_request_security_approval"},
                            )

                        return self._error_result(
                            message="Security approval denied.",
                            error="security_approval_denied",
                            data={
                                "approved": False,
                                "security_response": response,
                                "approval_payload": approval_payload,
                            },
                            metadata={"hook": "_request_security_approval"},
                        )

                    if response is True:
                        return self._safe_result(
                            message="Security approval granted.",
                            data={
                                "approved": True,
                                "security_response": response,
                                "approval_payload": approval_payload,
                            },
                            metadata={"hook": "_request_security_approval"},
                        )

            return self._error_result(
                message="Configured Security Agent does not expose an approval method.",
                error="security_agent_invalid_interface",
                data={
                    "approved": False,
                    "approval_payload": approval_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        except Exception as exc:
            return self._exception_result(exc, method="_request_security_approval")

    def _prepare_verification_payload(
        self,
        *,
        item: ScheduledItem,
        execution_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after scheduled execution.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "source": "workflow_scheduler",
            "user_id": item.user_id,
            "workspace_id": item.workspace_id,
            "schedule_id": item.schedule_id,
            "schedule_type": item.schedule_type.value,
            "execution_status": execution_result.get("status"),
            "execution_success": execution_result.get("success"),
            "message": execution_result.get("message"),
            "started_at": execution_result.get("started_at"),
            "finished_at": execution_result.get("finished_at"),
            "run_count": item.run_count,
            "failure_count": item.failure_count,
            "next_run_at": _dt_to_iso(item.next_run_at),
            "result_data": _safe_deepcopy(execution_result.get("data")),
            "error": _safe_deepcopy(execution_result.get("error")),
            "metadata": {
                "prepared_at": _dt_to_iso(_utc_now()),
                "schedule_metadata": _safe_deepcopy(item.metadata),
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        event_type: str,
        item: ScheduledItem,
        execution_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This intentionally avoids storing secrets and full sensitive payloads.
        """

        safe_action_summary = {
            "kind": item.action_payload.get("kind"),
            "workflow_name": (
                item.action_payload.get("workflow_payload", {}).get("name")
                if isinstance(item.action_payload.get("workflow_payload"), dict)
                else None
            ),
            "action_type": item.action_payload.get("action_type") or item.action_payload.get("type"),
        }

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "source": "workflow_scheduler",
            "event_type": event_type,
            "user_id": item.user_id,
            "workspace_id": item.workspace_id,
            "schedule_id": item.schedule_id,
            "schedule_name": item.name,
            "schedule_type": item.schedule_type.value,
            "status": item.status.value,
            "next_run_at": _dt_to_iso(item.next_run_at),
            "last_run_at": _dt_to_iso(item.last_run_at),
            "run_count": item.run_count,
            "failure_count": item.failure_count,
            "action_summary": safe_action_summary,
            "execution_summary": {
                "success": execution_result.get("success") if execution_result else None,
                "message": execution_result.get("message") if execution_result else None,
                "status": execution_result.get("status") if execution_result else None,
            },
            "metadata": {
                "prepared_at": _dt_to_iso(_utc_now()),
                "schedule_metadata": _safe_deepcopy(item.metadata),
            },
        }

    def _emit_agent_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for dashboard/API/registry observability.

        Supports injected event_emitter or BaseAgent emit_event fallback.
        """

        try:
            safe_payload = _safe_deepcopy(payload)
            safe_payload.setdefault("agent", self.agent_name)
            safe_payload.setdefault("emitted_at", _dt_to_iso(_utc_now()))

            if callable(self.event_emitter):
                self.event_emitter(event_type, safe_payload)
                return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_type, safe_payload)
                return

            self.logger.debug("Agent event: %s %s", event_type, safe_payload)

        except Exception as exc:
            self.logger.warning("Failed to emit agent event: %s", exc)

    def _log_audit_event(
        self,
        event_type: str,
        item: Optional[ScheduledItem] = None,
        *,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event with tenant isolation fields.

        Does not leak schedules across users/workspaces.
        """

        try:
            payload = {
                "audit_id": str(uuid.uuid4()),
                "event_type": event_type,
                "agent": self.agent_name,
                "created_at": _dt_to_iso(_utc_now()),
                "extra": _safe_deepcopy(extra or {}),
            }

            if item is not None:
                payload.update({
                    "user_id": item.user_id,
                    "workspace_id": item.workspace_id,
                    "schedule_id": item.schedule_id,
                    "schedule_type": item.schedule_type.value,
                    "schedule_status": item.status.value,
                    "run_count": item.run_count,
                    "failure_count": item.failure_count,
                })

            if callable(self.audit_logger):
                self.audit_logger(payload)
                return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(payload)
                return

            self.logger.info("Audit event: %s", payload)

        except Exception as exc:
            self.logger.warning("Failed to log audit event: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard successful result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Internal store / lifecycle helpers
    # -------------------------------------------------------------------------

    def _create_scheduled_item(
        self,
        *,
        user_id: str,
        workspace_id: str,
        schedule_type: ScheduleType,
        action_payload: Dict[str, Any],
        next_run_at: datetime,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timezone_name: str = "UTC",
        interval_seconds: Optional[int] = None,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        time_of_day: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        policy: Optional[Union[SchedulePolicy, Dict[str, Any]]] = None,
    ) -> ScheduledItem:
        """Create ScheduledItem with safe defaults."""

        now = _utc_now()

        if isinstance(policy, SchedulePolicy):
            schedule_policy = policy
        elif isinstance(policy, dict):
            schedule_policy = SchedulePolicy(**policy)
        else:
            schedule_policy = SchedulePolicy()

        return ScheduledItem(
            schedule_id=str(uuid.uuid4()),
            user_id=user_id.strip(),
            workspace_id=workspace_id.strip(),
            schedule_type=schedule_type,
            action_payload=_safe_deepcopy(action_payload),
            next_run_at=next_run_at,
            created_at=now,
            updated_at=now,
            name=name,
            description=description,
            timezone_name=timezone_name or "UTC",
            interval_seconds=interval_seconds,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            time_of_day=time_of_day,
            metadata=_safe_deepcopy(metadata or {}),
            policy=schedule_policy,
        )

    def _store_schedule(self, item: ScheduledItem) -> None:
        """Store schedule and push it into due heap."""

        with self._lock:
            self._schedules[item.schedule_id] = item
            self._push_due_heap(item)

    def _push_due_heap(self, item: ScheduledItem) -> None:
        """Push active schedule into heap."""

        if item.status != ScheduleStatus.ACTIVE:
            return

        heapq.heappush(self._due_heap, (item.next_run_at.timestamp(), item.schedule_id))

    def _get_owned_schedule_or_none(
        self,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[ScheduledItem]:
        """Get schedule only if it belongs to user/workspace."""

        item = self._schedules.get(schedule_id)
        if item is None:
            return None

        if item.user_id != user_id or item.workspace_id != workspace_id:
            return None

        return item

    def _not_found_or_forbidden(self, schedule_id: str) -> Dict[str, Any]:
        """Do not reveal cross-tenant existence."""

        return self._error_result(
            message="Schedule not found or access denied.",
            error="schedule_not_found_or_forbidden",
            metadata={"schedule_id": schedule_id},
        )

    def _set_schedule_status(
        self,
        *,
        schedule_id: str,
        user_id: str,
        workspace_id: str,
        status: ScheduleStatus,
        message: str,
        event_name: str,
        method: str,
    ) -> Dict[str, Any]:
        """Shared status update helper."""

        try:
            context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
            if not context_result["success"]:
                return context_result

            with self._lock:
                item = self._get_owned_schedule_or_none(schedule_id, user_id, workspace_id)
                if item is None:
                    return self._not_found_or_forbidden(schedule_id)

                item.status = status
                item.updated_at = _utc_now()

            self._log_audit_event(f"workflow_schedule_{status.value}", item)
            self._emit_agent_event(
                event_name,
                {
                    "schedule_id": schedule_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "status": status.value,
                },
            )

            return self._safe_result(
                message=message,
                data={"schedule": item.to_dict()},
                metadata={"method": method},
            )

        except Exception as exc:
            return self._exception_result(exc, method=method)

    # -------------------------------------------------------------------------
    # Internal schedule validation / time calculation
    # -------------------------------------------------------------------------

    def _validate_schedule_item(self, item: ScheduledItem) -> Dict[str, Any]:
        """Validate schedule-specific fields."""

        if item.schedule_type == ScheduleType.INTERVAL:
            if item.interval_seconds is None or int(item.interval_seconds) <= 0:
                return self._error_result(
                    message="interval_seconds must be greater than 0 for interval schedules.",
                    error="invalid_interval_seconds",
                )

        if item.schedule_type in {ScheduleType.DAILY, ScheduleType.WEEKLY, ScheduleType.MONTHLY}:
            if item.time_of_day:
                _parse_time_of_day(item.time_of_day)

        if item.schedule_type == ScheduleType.WEEKLY:
            if item.day_of_week is None or int(item.day_of_week) < 0 or int(item.day_of_week) > 6:
                return self._error_result(
                    message="day_of_week must be 0-6 for weekly schedules. Monday=0, Sunday=6.",
                    error="invalid_day_of_week",
                )

        if item.schedule_type == ScheduleType.MONTHLY:
            if item.day_of_month is None or int(item.day_of_month) < 1 or int(item.day_of_month) > 31:
                return self._error_result(
                    message="day_of_month must be 1-31 for monthly schedules.",
                    error="invalid_day_of_month",
                )

        return self._safe_result(message="Schedule item validated.", data={"schedule_id": item.schedule_id})

    def _calculate_initial_run_time(
        self,
        *,
        schedule_type: ScheduleType,
        run_at: Optional[Union[str, datetime]],
        interval_seconds: Optional[int],
        time_of_day: Optional[str],
        day_of_week: Optional[int],
        day_of_month: Optional[int],
    ) -> datetime:
        """Calculate first run time."""

        now = _utc_now()

        if run_at is not None:
            parsed = _parse_datetime(run_at)
            if parsed < now:
                return now
            return parsed

        if schedule_type == ScheduleType.ONCE:
            return now

        if schedule_type == ScheduleType.INTERVAL:
            if interval_seconds is None or int(interval_seconds) <= 0:
                raise ValueError("interval_seconds must be greater than 0.")
            return now + timedelta(seconds=int(interval_seconds))

        hour, minute = _parse_time_of_day(time_of_day or "00:00")

        if schedule_type == ScheduleType.DAILY:
            candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if candidate <= now:
                candidate += timedelta(days=1)
            return candidate

        if schedule_type == ScheduleType.WEEKLY:
            if day_of_week is None or int(day_of_week) < 0 or int(day_of_week) > 6:
                raise ValueError("day_of_week must be 0-6 for weekly schedules.")
            candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            days_ahead = int(day_of_week) - candidate.weekday()
            if days_ahead < 0 or (days_ahead == 0 and candidate <= now):
                days_ahead += 7
            return candidate + timedelta(days=days_ahead)

        if schedule_type == ScheduleType.MONTHLY:
            if day_of_month is None or int(day_of_month) < 1 or int(day_of_month) > 31:
                raise ValueError("day_of_month must be 1-31 for monthly schedules.")
            return self._next_monthly_datetime(
                from_time=now,
                day_of_month=int(day_of_month),
                hour=hour,
                minute=minute,
            )

        raise ValueError(f"Unsupported schedule_type: {schedule_type}")

    def _calculate_next_run(
        self,
        item: ScheduledItem,
        *,
        from_time: Optional[datetime] = None,
    ) -> Optional[datetime]:
        """Calculate next run for recurring schedules."""

        base = from_time or _utc_now()

        if item.schedule_type == ScheduleType.ONCE:
            return None

        if item.schedule_type == ScheduleType.INTERVAL:
            seconds = int(item.interval_seconds or 0)
            if seconds <= 0:
                return None
            return base + timedelta(seconds=seconds)

        hour, minute = _parse_time_of_day(item.time_of_day or "00:00")

        if item.schedule_type == ScheduleType.DAILY:
            candidate = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if candidate <= base:
                candidate += timedelta(days=1)
            return candidate

        if item.schedule_type == ScheduleType.WEEKLY:
            if item.day_of_week is None:
                return None
            candidate = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
            days_ahead = int(item.day_of_week) - candidate.weekday()
            if days_ahead < 0 or (days_ahead == 0 and candidate <= base):
                days_ahead += 7
            return candidate + timedelta(days=days_ahead)

        if item.schedule_type == ScheduleType.MONTHLY:
            if item.day_of_month is None:
                return None
            return self._next_monthly_datetime(
                from_time=base,
                day_of_month=int(item.day_of_month),
                hour=hour,
                minute=minute,
            )

        return None

    def _next_monthly_datetime(
        self,
        *,
        from_time: datetime,
        day_of_month: int,
        hour: int,
        minute: int,
    ) -> datetime:
        """
        Calculate next monthly datetime.

        If requested day does not exist in a month, uses the last day of that month.
        """

        year = from_time.year
        month = from_time.month

        for _ in range(15):
            candidate_day = min(day_of_month, self._days_in_month(year, month))
            candidate = from_time.replace(
                year=year,
                month=month,
                day=candidate_day,
                hour=hour,
                minute=minute,
                second=0,
                microsecond=0,
            )

            if candidate > from_time:
                return candidate

            month += 1
            if month > 12:
                month = 1
                year += 1

        return from_time + timedelta(days=31)

    @staticmethod
    def _days_in_month(year: int, month: int) -> int:
        """Return days in month without external dependencies."""

        if month == 12:
            next_month = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            next_month = datetime(year, month + 1, 1, tzinfo=timezone.utc)
        this_month = datetime(year, month, 1, tzinfo=timezone.utc)
        return int((next_month - this_month).days)

    # -------------------------------------------------------------------------
    # Internal execution
    # -------------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Background scheduler loop."""

        self.logger.info("WorkflowScheduler background loop started.")

        while not self._stop_event.is_set():
            try:
                due_items = self._pop_due_items(max_items=50)

                for item in due_items:
                    if self._stop_event.is_set():
                        break

                    if not item.policy.allow_background_execution:
                        self._reschedule_or_complete(item, execution_succeeded=True, skipped=True)
                        continue

                    self._execute_scheduled_item(
                        item,
                        allow_sensitive_without_approval=False,
                        background=True,
                    )

                self._stop_event.wait(self.default_poll_interval_seconds)

            except Exception as exc:
                self.logger.error("WorkflowScheduler loop error: %s", exc, exc_info=True)
                self._stop_event.wait(self.default_poll_interval_seconds)

        self.logger.info("WorkflowScheduler background loop stopped.")

    def _pop_due_items(
        self,
        *,
        max_items: int,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> List[ScheduledItem]:
        """Pop due active schedules with tenant filter."""

        now = _utc_now()
        due: List[ScheduledItem] = []

        with self._lock:
            while self._due_heap and len(due) < max_items:
                run_ts, schedule_id = heapq.heappop(self._due_heap)

                if run_ts > now.timestamp():
                    heapq.heappush(self._due_heap, (run_ts, schedule_id))
                    break

                item = self._schedules.get(schedule_id)
                if item is None:
                    continue

                if item.status != ScheduleStatus.ACTIVE:
                    continue

                # Skip stale heap entries.
                if abs(item.next_run_at.timestamp() - run_ts) > 0.001:
                    continue

                if user_id and item.user_id != user_id:
                    self._push_due_heap(item)
                    continue

                if workspace_id and item.workspace_id != workspace_id:
                    self._push_due_heap(item)
                    continue

                if item.locked_until and item.locked_until > now:
                    self._push_due_heap(item)
                    continue

                item.locked_until = now + timedelta(seconds=self.lock_ttl_seconds)
                item.updated_at = now
                due.append(item)

        return due

    def _execute_scheduled_item(
        self,
        item: ScheduledItem,
        *,
        allow_sensitive_without_approval: bool,
        background: bool,
    ) -> Dict[str, Any]:
        """Execute one due scheduled item safely."""

        execution_id = str(uuid.uuid4())
        started_at = _utc_now()

        execution_record: Dict[str, Any] = {
            "execution_id": execution_id,
            "schedule_id": item.schedule_id,
            "user_id": item.user_id,
            "workspace_id": item.workspace_id,
            "schedule_type": item.schedule_type.value,
            "status": ExecutionStatus.RUNNING.value,
            "success": False,
            "message": "Scheduled execution started.",
            "started_at": _dt_to_iso(started_at),
            "finished_at": None,
            "background": background,
            "data": {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "schedule_name": item.name,
            },
        }

        self._emit_agent_event(
            "workflow.scheduler.execution.started",
            {
                "execution_id": execution_id,
                "schedule_id": item.schedule_id,
                "user_id": item.user_id,
                "workspace_id": item.workspace_id,
                "background": background,
            },
        )

        try:
            if self._requires_security_check(item=item) and not allow_sensitive_without_approval:
                approval = self._request_security_approval(
                    item=item,
                    reason="Scheduled item contains sensitive or externally-effectful action.",
                    sensitivity_level=SensitivityLevel.HIGH,
                )

                if not approval.get("success"):
                    execution_record.update({
                        "status": ExecutionStatus.REQUIRES_APPROVAL.value,
                        "success": False,
                        "message": "Scheduled execution requires Security Agent approval.",
                        "error": approval.get("error"),
                        "data": {"security_approval": approval.get("data", {})},
                    })
                    self._finalize_execution_record(item, execution_record)
                    self._mark_failure(item, "Security approval required or denied.")
                    self._reschedule_or_complete(item, execution_succeeded=False)
                    return execution_record

            result = self._dispatch_action(item)

            success = True
            message = "Scheduled item executed successfully."
            error = None
            data: Dict[str, Any] = {}

            if isinstance(result, dict):
                success = bool(result.get("success", True))
                message = str(result.get("message") or message)
                error = result.get("error")
                data = _safe_deepcopy(result.get("data", result))
            else:
                data = {"executor_result": _safe_deepcopy(result)}

            execution_record.update({
                "status": ExecutionStatus.SUCCESS.value if success else ExecutionStatus.FAILED.value,
                "success": success,
                "message": message,
                "data": data,
                "error": error,
            })

            self._finalize_execution_record(item, execution_record)

            if success:
                self._mark_success(item)
            else:
                self._mark_failure(item, str(error or message))

            self._reschedule_or_complete(item, execution_succeeded=success)

            return execution_record

        except Exception as exc:
            execution_record.update({
                "status": ExecutionStatus.FAILED.value,
                "success": False,
                "message": "Scheduled execution failed.",
                "error": {
                    "type": exc.__class__.__name__,
                    "detail": str(exc),
                    "traceback": traceback.format_exc(),
                },
            })

            self._finalize_execution_record(item, execution_record)
            self._mark_failure(item, str(exc))
            self._reschedule_or_complete(item, execution_succeeded=False)

            return execution_record

    def _dispatch_action(self, item: ScheduledItem) -> Any:
        """
        Dispatch action to configured executor.

        Executor options:
            1. action_executor callable
            2. action_router.route_action(payload)
            3. action_router.execute(payload)
            4. ActionRouter fallback instance if import exists
            5. Dry-safe no-op result
        """

        execution_context = {
            "user_id": item.user_id,
            "workspace_id": item.workspace_id,
            "schedule_id": item.schedule_id,
            "schedule_type": item.schedule_type.value,
            "triggered_by": self.agent_name,
            "triggered_at": _dt_to_iso(_utc_now()),
        }

        payload = {
            "context": execution_context,
            "action_payload": _safe_deepcopy(item.action_payload),
            "metadata": _safe_deepcopy(item.metadata),
        }

        if callable(self.action_executor):
            return _call_maybe_async_unsafe(self.action_executor, payload)

        router = self.action_router
        if router is None and ActionRouter is not None:
            try:
                router = ActionRouter()
            except Exception:
                router = None

        if router is not None:
            for method_name in ("route_action", "execute", "run", "handle"):
                method = getattr(router, method_name, None)
                if callable(method):
                    return _call_maybe_async_unsafe(method, payload)

        return self._safe_result(
            message=(
                "No action executor configured. Schedule was processed in dry-safe mode "
                "without performing external effects."
            ),
            data={
                "dry_safe": True,
                "schedule_id": item.schedule_id,
                "context": execution_context,
            },
            metadata={"method": "_dispatch_action"},
        )

    def _finalize_execution_record(
        self,
        item: ScheduledItem,
        execution_record: Dict[str, Any],
    ) -> None:
        """Finalize execution record, audit, event, verification, and memory payloads."""

        finished_at = _utc_now()
        execution_record["finished_at"] = _dt_to_iso(finished_at)

        verification_payload = self._prepare_verification_payload(
            item=item,
            execution_result=execution_record,
        )
        memory_payload = self._prepare_memory_payload(
            event_type="schedule_executed",
            item=item,
            execution_result=execution_record,
        )

        execution_record.setdefault("data", {})
        execution_record["data"]["verification_payload"] = verification_payload
        execution_record["data"]["memory_payload"] = memory_payload

        with self._lock:
            self._execution_history.append(copy.deepcopy(execution_record))
            if len(self._execution_history) > self.max_history_items:
                self._execution_history = self._execution_history[-self.max_history_items:]

        self._send_to_verification_agent(verification_payload)
        self._send_to_memory_agent(memory_payload)

        self._log_audit_event(
            "workflow_schedule_executed",
            item,
            extra={
                "execution_id": execution_record.get("execution_id"),
                "success": execution_record.get("success"),
                "status": execution_record.get("status"),
            },
        )

        self._emit_agent_event(
            "workflow.scheduler.execution.finished",
            {
                "execution_id": execution_record.get("execution_id"),
                "schedule_id": item.schedule_id,
                "user_id": item.user_id,
                "workspace_id": item.workspace_id,
                "success": execution_record.get("success"),
                "status": execution_record.get("status"),
            },
        )

    def _send_to_verification_agent(self, payload: Dict[str, Any]) -> None:
        """Send verification payload when a compatible Verification Agent is injected."""

        if self.verification_agent is None:
            return

        try:
            for method_name in ("verify", "prepare_verification", "handle_verification_payload", "receive"):
                method = getattr(self.verification_agent, method_name, None)
                if callable(method):
                    _call_maybe_async_unsafe(method, payload)
                    return
        except Exception as exc:
            self.logger.warning("Failed to send payload to Verification Agent: %s", exc)

    def _send_to_memory_agent(self, payload: Dict[str, Any]) -> None:
        """Send memory payload when a compatible Memory Agent is injected."""

        if self.memory_agent is None:
            return

        try:
            for method_name in ("store", "remember", "save_memory", "receive"):
                method = getattr(self.memory_agent, method_name, None)
                if callable(method):
                    _call_maybe_async_unsafe(method, payload)
                    return
        except Exception as exc:
            self.logger.warning("Failed to send payload to Memory Agent: %s", exc)

    def _mark_success(self, item: ScheduledItem) -> None:
        """Update schedule success counters."""

        now = _utc_now()
        with self._lock:
            item.run_count += 1
            item.last_run_at = now
            item.last_success_at = now
            item.last_error = None
            item.locked_until = None
            item.updated_at = now

    def _mark_failure(self, item: ScheduledItem, error_message: str) -> None:
        """Update schedule failure counters."""

        now = _utc_now()
        with self._lock:
            item.run_count += 1
            item.failure_count += 1
            item.last_run_at = now
            item.last_failure_at = now
            item.last_error = error_message
            item.locked_until = None
            item.updated_at = now

            if item.failure_count >= item.policy.max_failures:
                item.status = ScheduleStatus.FAILED

    def _reschedule_or_complete(
        self,
        item: ScheduledItem,
        *,
        execution_succeeded: bool,
        skipped: bool = False,
    ) -> None:
        """Reschedule recurring item or mark one-time/completed/failed."""

        with self._lock:
            if item.status in {ScheduleStatus.CANCELLED, ScheduleStatus.PAUSED, ScheduleStatus.FAILED}:
                item.locked_until = None
                item.updated_at = _utc_now()
                return

            if item.policy.max_runs is not None and item.run_count >= item.policy.max_runs:
                item.status = ScheduleStatus.COMPLETED
                item.locked_until = None
                item.updated_at = _utc_now()
                return

            if not execution_succeeded and not item.policy.retry_on_failure:
                item.status = ScheduleStatus.FAILED
                item.locked_until = None
                item.updated_at = _utc_now()
                return

            next_run = self._calculate_next_run(item, from_time=_utc_now())

            if next_run is None:
                item.status = ScheduleStatus.COMPLETED
                item.locked_until = None
                item.updated_at = _utc_now()
                return

            item.next_run_at = next_run
            item.locked_until = None
            item.updated_at = _utc_now()
            self._push_due_heap(item)

            if skipped:
                self._emit_agent_event(
                    "workflow.scheduler.execution.skipped",
                    {
                        "schedule_id": item.schedule_id,
                        "user_id": item.user_id,
                        "workspace_id": item.workspace_id,
                        "next_run_at": _dt_to_iso(item.next_run_at),
                    },
                )

    # -------------------------------------------------------------------------
    # Error helper
    # -------------------------------------------------------------------------

    def _exception_result(self, exc: Exception, *, method: str) -> Dict[str, Any]:
        """Return structured exception result."""

        self.logger.error("%s failed: %s", method, exc, exc_info=True)
        return self._error_result(
            message=f"{method} failed.",
            error={
                "type": exc.__class__.__name__,
                "detail": str(exc),
                "traceback": traceback.format_exc(),
            },
            metadata={"method": method},
        )


# =============================================================================
# Registry helper
# =============================================================================

def get_agent() -> WorkflowScheduler:
    """
    Registry/loader convenience factory.

    Agent Loader or Agent Registry can call get_agent() when dynamically
    importing agents/workflow_agent/scheduler.py.
    """

    return WorkflowScheduler()


__all__ = [
    "WorkflowScheduler",
    "ScheduleType",
    "ScheduleStatus",
    "ExecutionStatus",
    "SensitivityLevel",
    "SchedulePolicy",
    "ScheduledItem",
    "get_agent",
]