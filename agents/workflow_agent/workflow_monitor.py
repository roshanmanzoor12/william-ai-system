"""
agents/workflow_agent/workflow_monitor.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Tracks workflow runs, step status, failures, analytics, timelines, and
    dashboard-ready monitoring summaries for the Workflow Agent.

This module is intentionally import-safe:
    - It does not require other William/Jarvis files to exist.
    - It provides fallback BaseAgent compatibility.
    - It avoids direct destructive/system/financial/message/call/browser actions.
    - It keeps SaaS tenant isolation enforced through user_id + workspace_id.

Connections:
    - Master Agent / Agent Router:
        Public methods return structured dict results and can be routed safely.
    - Security Agent:
        Sensitive actions such as purge/export can request approval through
        optional injected security_agent.
    - Memory Agent:
        Useful run/failure summaries can be prepared as memory payloads.
    - Verification Agent:
        Completed run/step actions prepare verification payloads.
    - Dashboard/API:
        Analytics, timelines, run summaries, and failure reports are returned
        as JSON-style dictionaries ready for FastAPI or dashboard use.
    - Agent Registry / Loader:
        Class name is stable: WorkflowMonitor.
"""

from __future__ import annotations

import copy
import json
import logging
import statistics
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even before the full William/Jarvis
        agent framework exists. The real BaseAgent can replace this class
        automatically when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run is not implemented.",
                "data": None,
                "error": "base_agent_not_available",
                "metadata": {},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AGENT_NAME = "WorkflowMonitor"
AGENT_MODULE = "workflow_agent"
FILE_NAME = "workflow_monitor.py"
SCHEMA_VERSION = "1.0.0"

DEFAULT_MAX_RUNS_PER_WORKSPACE = 10000
DEFAULT_MAX_EVENTS_PER_RUN = 1000
DEFAULT_SLOW_STEP_SECONDS = 30.0
DEFAULT_STALE_HEARTBEAT_SECONDS = 300.0


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WorkflowRunStatus(str, Enum):
    """Supported workflow run statuses."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RETRY_SCHEDULED = "retry_scheduled"


class WorkflowStepStatus(str, Enum):
    """Supported workflow step statuses."""

    PENDING = "pending"
    SKIPPED = "skipped"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    TIMEOUT = "timeout"


class MonitorEventType(str, Enum):
    """Timeline event types for workflow monitoring."""

    RUN_CREATED = "run_created"
    RUN_STARTED = "run_started"
    RUN_HEARTBEAT = "run_heartbeat"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    RUN_CANCELLED = "run_cancelled"
    RUN_PAUSED = "run_paused"
    RUN_RESUMED = "run_resumed"
    RUN_RETRY_SCHEDULED = "run_retry_scheduled"

    STEP_CREATED = "step_created"
    STEP_STARTED = "step_started"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED = "step_failed"
    STEP_SKIPPED = "step_skipped"
    STEP_CANCELLED = "step_cancelled"
    STEP_RETRYING = "step_retrying"
    STEP_TIMEOUT = "step_timeout"

    AUDIT = "audit"
    WARNING = "warning"
    INFO = "info"


class FailureSeverity(str, Enum):
    """Failure severity used for dashboard alerting."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MonitorConfig:
    """
    Runtime configuration for WorkflowMonitor.

    allow_sensitive_without_security:
        Safe default is False. If False, sensitive operations require approval
        when a security agent is configured, or are denied when no approval path
        exists.

    enable_memory_payloads:
        If True, monitor prepares memory-compatible payloads for important
        workflow events.

    enable_verification_payloads:
        If True, monitor prepares verification-compatible payloads for completed
        or failed actions.
    """

    max_runs_per_workspace: int = DEFAULT_MAX_RUNS_PER_WORKSPACE
    max_events_per_run: int = DEFAULT_MAX_EVENTS_PER_RUN
    slow_step_seconds: float = DEFAULT_SLOW_STEP_SECONDS
    stale_heartbeat_seconds: float = DEFAULT_STALE_HEARTBEAT_SECONDS
    allow_sensitive_without_security: bool = False
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True
    enable_audit_log: bool = True
    enable_agent_events: bool = True
    safe_metadata_keys: Tuple[str, ...] = (
        "source",
        "trigger_type",
        "workflow_version",
        "environment",
        "request_id",
        "correlation_id",
        "initiated_by",
        "priority",
        "tags",
    )


@dataclass
class WorkflowMonitorEvent:
    """A single workflow monitoring timeline event."""

    event_id: str
    run_id: str
    user_id: str
    workspace_id: str
    event_type: str
    message: str
    timestamp: str
    step_id: Optional[str] = None
    severity: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowStepRecord:
    """Tracked status and metrics for a workflow step."""

    step_id: str
    name: str
    status: str
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    attempt: int = 1
    connector: Optional[str] = None
    agent: Optional[str] = None
    input_summary: Dict[str, Any] = field(default_factory=dict)
    output_summary: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowRunRecord:
    """Tracked status and metrics for a workflow run."""

    run_id: str
    workflow_id: str
    workflow_name: str
    user_id: str
    workspace_id: str
    status: str
    created_at: str
    updated_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    trigger_type: Optional[str] = None
    initiated_by: Optional[str] = None
    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    retry_count: int = 0
    last_heartbeat_at: Optional[str] = None
    error: Optional[Dict[str, Any]] = None
    steps: Dict[str, WorkflowStepRecord] = field(default_factory=dict)
    events: List[WorkflowMonitorEvent] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def _iso_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""

    return _utcnow().isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp safely."""

    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _duration_seconds(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[float]:
    """Calculate duration between ISO timestamps."""

    start = _parse_iso(start_iso)
    end = _parse_iso(end_iso)

    if not start or not end:
        return None

    try:
        return max(0.0, (end - start).total_seconds())
    except Exception:
        return None


def _safe_uuid(prefix: str) -> str:
    """Create a stable readable identifier."""

    return f"{prefix}_{uuid.uuid4().hex}"


def _deepcopy_json_safe(value: Any) -> Any:
    """
    Return a JSON-safe deep copy.

    Non-serializable values are converted to strings. This protects monitoring
    output from crashing dashboards/API responses.
    """

    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        try:
            return copy.deepcopy(value)
        except Exception:
            return str(value)


def _redact_sensitive_value(key: str, value: Any) -> Any:
    """
    Redact values for common secret-bearing keys.

    Monitoring should never leak secrets to analytics, audit logs, memory,
    verification payloads, or dashboards.
    """

    lowered = key.lower()
    sensitive_markers = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "bearer",
        "private_key",
        "access_key",
        "refresh",
        "credential",
        "session",
        "cookie",
    )

    if any(marker in lowered for marker in sensitive_markers):
        return "***REDACTED***"

    if isinstance(value, Mapping):
        return {str(k): _redact_sensitive_value(str(k), v) for k, v in value.items()}

    if isinstance(value, list):
        return [_redact_sensitive_value(key, item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive_value(key, item) for item in value)

    return value


def _sanitize_dict(payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sanitize dict-like data for safe monitoring output."""

    if not payload:
        return {}

    safe: Dict[str, Any] = {}
    for key, value in payload.items():
        safe[str(key)] = _redact_sensitive_value(str(key), _deepcopy_json_safe(value))
    return safe


def _normalize_error(
    error: Optional[Union[str, BaseException, Mapping[str, Any]]],
    *,
    code: Optional[str] = None,
    severity: Union[str, FailureSeverity, None] = None,
    recoverable: Optional[bool] = None,
) -> Dict[str, Any]:
    """Normalize any error input into a structured JSON-style error dict."""

    if isinstance(severity, FailureSeverity):
        severity_value = severity.value
    else:
        severity_value = severity or FailureSeverity.MEDIUM.value

    if error is None:
        message = "Unknown workflow monitor error."
        error_type = "unknown_error"
        extra: Dict[str, Any] = {}
    elif isinstance(error, BaseException):
        message = str(error) or error.__class__.__name__
        error_type = error.__class__.__name__
        extra = {}
    elif isinstance(error, Mapping):
        sanitized = _sanitize_dict(error)
        message = str(
            sanitized.get("message")
            or sanitized.get("error")
            or sanitized.get("detail")
            or "Workflow error"
        )
        error_type = str(sanitized.get("type") or sanitized.get("error_type") or "workflow_error")
        extra = sanitized
    else:
        message = str(error)
        error_type = "workflow_error"
        extra = {}

    normalized = {
        "code": code or extra.get("code") or error_type,
        "type": error_type,
        "message": message,
        "severity": severity_value,
        "recoverable": bool(recoverable) if recoverable is not None else None,
        "timestamp": _iso_now(),
    }

    if extra:
        normalized["details"] = extra

    return normalized


def _status_value(value: Union[str, Enum]) -> str:
    """Return enum value or string."""

    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _as_serializable_dataclass(value: Any) -> Any:
    """Convert dataclasses/enums to JSON-style structures."""

    if isinstance(value, Enum):
        return value.value

    if hasattr(value, "__dataclass_fields__"):
        return _as_serializable_dataclass(asdict(value))

    if isinstance(value, dict):
        return {str(k): _as_serializable_dataclass(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_as_serializable_dataclass(v) for v in value]

    if isinstance(value, tuple):
        return [_as_serializable_dataclass(v) for v in value]

    return _deepcopy_json_safe(value)


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

class InMemoryWorkflowMonitorStore:
    """
    Thread-safe in-memory store for workflow monitor records.

    This is suitable for tests, local development, and as a safe default.
    Production deployments can replace this with a database-backed store while
    preserving the same public methods.
    """

    def __init__(self, max_runs_per_workspace: int = DEFAULT_MAX_RUNS_PER_WORKSPACE) -> None:
        self._runs: Dict[str, WorkflowRunRecord] = {}
        self._workspace_index: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        self._lock = threading.RLock()
        self.max_runs_per_workspace = max_runs_per_workspace

    @staticmethod
    def make_key(user_id: str, workspace_id: str, run_id: str) -> str:
        """Build a tenant-isolated run key."""

        return f"{user_id}::{workspace_id}::{run_id}"

    def save_run(self, run: WorkflowRunRecord) -> None:
        """Save or replace a run record."""

        with self._lock:
            key = self.make_key(run.user_id, run.workspace_id, run.run_id)
            workspace_key = (run.user_id, run.workspace_id)

            is_new = key not in self._runs
            self._runs[key] = run

            if is_new:
                self._workspace_index[workspace_key].append(run.run_id)

            self._enforce_workspace_limit(workspace_key)

    def get_run(self, user_id: str, workspace_id: str, run_id: str) -> Optional[WorkflowRunRecord]:
        """Fetch a run by tenant-isolated key."""

        with self._lock:
            key = self.make_key(user_id, workspace_id, run_id)
            return self._runs.get(key)

    def delete_run(self, user_id: str, workspace_id: str, run_id: str) -> bool:
        """Delete a run by tenant-isolated key."""

        with self._lock:
            key = self.make_key(user_id, workspace_id, run_id)
            existed = key in self._runs

            if existed:
                del self._runs[key]

            workspace_key = (user_id, workspace_id)
            if run_id in self._workspace_index.get(workspace_key, []):
                self._workspace_index[workspace_key] = [
                    existing for existing in self._workspace_index[workspace_key]
                    if existing != run_id
                ]

            return existed

    def list_runs(
        self,
        user_id: str,
        workspace_id: str,
        *,
        status: Optional[str] = None,
        workflow_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        newest_first: bool = True,
    ) -> List[WorkflowRunRecord]:
        """List tenant-isolated runs with filters."""

        with self._lock:
            workspace_key = (user_id, workspace_id)
            run_ids = list(self._workspace_index.get(workspace_key, []))
            runs: List[WorkflowRunRecord] = []

            for run_id in run_ids:
                run = self._runs.get(self.make_key(user_id, workspace_id, run_id))
                if not run:
                    continue

                if status and run.status != status:
                    continue

                if workflow_id and run.workflow_id != workflow_id:
                    continue

                runs.append(run)

            runs.sort(key=lambda item: item.created_at, reverse=newest_first)
            return runs[max(0, offset): max(0, offset) + max(1, limit)]

    def all_runs_for_workspace(self, user_id: str, workspace_id: str) -> List[WorkflowRunRecord]:
        """Return all runs for analytics in a workspace."""

        return self.list_runs(
            user_id=user_id,
            workspace_id=workspace_id,
            limit=self.max_runs_per_workspace,
            offset=0,
            newest_first=False,
        )

    def count_runs(self, user_id: str, workspace_id: str) -> int:
        """Count runs in a workspace."""

        with self._lock:
            return len(self._workspace_index.get((user_id, workspace_id), []))

    def purge_runs(
        self,
        user_id: str,
        workspace_id: str,
        *,
        before_iso: Optional[str] = None,
        statuses: Optional[Iterable[str]] = None,
    ) -> int:
        """Delete matching runs for a workspace."""

        with self._lock:
            statuses_set = set(statuses or [])
            run_ids = list(self._workspace_index.get((user_id, workspace_id), []))
            deleted = 0

            before_dt = _parse_iso(before_iso) if before_iso else None

            for run_id in run_ids:
                run = self._runs.get(self.make_key(user_id, workspace_id, run_id))
                if not run:
                    continue

                if statuses_set and run.status not in statuses_set:
                    continue

                if before_dt:
                    created = _parse_iso(run.created_at)
                    if not created or created >= before_dt:
                        continue

                if self.delete_run(user_id, workspace_id, run_id):
                    deleted += 1

            return deleted

    def _enforce_workspace_limit(self, workspace_key: Tuple[str, str]) -> None:
        """Enforce max runs per workspace by deleting oldest runs."""

        user_id, workspace_id = workspace_key
        run_ids = self._workspace_index.get(workspace_key, [])

        if len(run_ids) <= self.max_runs_per_workspace:
            return

        runs: List[Tuple[str, str]] = []
        for run_id in run_ids:
            run = self._runs.get(self.make_key(user_id, workspace_id, run_id))
            if run:
                runs.append((run.created_at, run_id))

        runs.sort(key=lambda pair: pair[0])
        overflow = len(runs) - self.max_runs_per_workspace

        for _, run_id in runs[:max(0, overflow)]:
            key = self.make_key(user_id, workspace_id, run_id)
            self._runs.pop(key, None)

        self._workspace_index[workspace_key] = [
            run_id for _, run_id in runs[max(0, overflow):]
        ]


# ---------------------------------------------------------------------------
# WorkflowMonitor
# ---------------------------------------------------------------------------

class WorkflowMonitor(BaseAgent):
    """
    Tracks workflow runs, step statuses, failures, analytics, and timelines.

    Public methods are intentionally structured for Master Agent routing and
    FastAPI/dashboard integration. Every method that reads or writes user data
    validates user_id and workspace_id to prevent cross-tenant data mixing.
    """

    def __init__(
        self,
        *,
        config: Optional[MonitorConfig] = None,
        store: Optional[InMemoryWorkflowMonitorStore] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        agent_name: str = AGENT_NAME,
        agent_id: str = "workflow_monitor",
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.module_name = AGENT_MODULE

        self.config = config or MonitorConfig()
        self.store = store or InMemoryWorkflowMonitorStore(
            max_runs_per_workspace=self.config.max_runs_per_workspace
        )

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_sink = event_sink
        self.audit_sink = audit_sink

        self.logger = getattr(self, "logger", logging.getLogger(f"{AGENT_MODULE}.{AGENT_NAME}"))

    # ------------------------------------------------------------------
    # BaseAgent / Router-compatible entrypoint
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route a monitor task from Master Agent / Agent Router.

        Expected structure:
            {
                "action": "start_run" | "complete_run" | "fail_run" | ...,
                "user_id": "...",
                "workspace_id": "...",
                ...
            }
        """

        if not isinstance(task, dict):
            return self._error_result(
                message="WorkflowMonitor task must be a dictionary.",
                error="invalid_task_type",
            )

        action = str(task.get("action") or "").strip()

        if not action:
            return self._error_result(
                message="Missing monitor action.",
                error="missing_action",
                metadata={"allowed_actions": self.allowed_actions()},
            )

        action_map = {
            "start_run": self.start_run,
            "create_run": self.start_run,
            "heartbeat": self.heartbeat,
            "pause_run": self.pause_run,
            "resume_run": self.resume_run,
            "complete_run": self.complete_run,
            "fail_run": self.fail_run,
            "cancel_run": self.cancel_run,
            "create_step": self.create_step,
            "record_step_started": self.record_step_started,
            "start_step": self.record_step_started,
            "record_step_completed": self.record_step_completed,
            "complete_step": self.record_step_completed,
            "record_step_failed": self.record_step_failed,
            "fail_step": self.record_step_failed,
            "record_step_skipped": self.record_step_skipped,
            "skip_step": self.record_step_skipped,
            "record_step_cancelled": self.record_step_cancelled,
            "cancel_step": self.record_step_cancelled,
            "mark_step_retrying": self.mark_step_retrying,
            "mark_step_timeout": self.mark_step_timeout,
            "mark_run_retry_scheduled": self.mark_run_retry_scheduled,
            "get_run": self.get_run,
            "list_runs": self.list_runs,
            "get_run_timeline": self.get_run_timeline,
            "get_analytics": self.get_analytics,
            "get_failure_report": self.get_failure_report,
            "export_dashboard_summary": self.export_dashboard_summary,
            "detect_stale_runs": self.detect_stale_runs,
            "purge_runs": self.purge_runs,
        }

        handler = action_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported WorkflowMonitor action: {action}",
                error="unsupported_action",
                metadata={"allowed_actions": self.allowed_actions()},
            )

        kwargs = {k: v for k, v in task.items() if k != "action"}

        try:
            result = handler(**kwargs)
            if hasattr(result, "__await__"):
                return await result  # type: ignore[no-any-return]
            return result
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid arguments for action '{action}'.",
                error=exc,
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception("WorkflowMonitor action failed: %s", action)
            return self._error_result(
                message=f"WorkflowMonitor action failed: {action}",
                error=exc,
                metadata={"action": action},
            )

    def allowed_actions(self) -> List[str]:
        """Return actions supported by the router entrypoint."""

        return [
            "start_run",
            "create_run",
            "heartbeat",
            "pause_run",
            "resume_run",
            "complete_run",
            "fail_run",
            "cancel_run",
            "create_step",
            "record_step_started",
            "start_step",
            "record_step_completed",
            "complete_step",
            "record_step_failed",
            "fail_step",
            "record_step_skipped",
            "skip_step",
            "record_step_cancelled",
            "cancel_step",
            "mark_step_retrying",
            "mark_step_timeout",
            "mark_run_retry_scheduled",
            "get_run",
            "list_runs",
            "get_run_timeline",
            "get_analytics",
            "get_failure_report",
            "export_dashboard_summary",
            "detect_stale_runs",
            "purge_runs",
        ]

    # ------------------------------------------------------------------
    # Run lifecycle
    # ------------------------------------------------------------------

    def start_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_id: str,
        workflow_name: Optional[str] = None,
        run_id: Optional[str] = None,
        trigger_type: Optional[str] = None,
        initiated_by: Optional[str] = None,
        correlation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        expected_steps: Optional[Iterable[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create and start a workflow run."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        if not workflow_id or not str(workflow_id).strip():
            return self._error_result(
                message="workflow_id is required to start a workflow run.",
                error="missing_workflow_id",
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        now = _iso_now()
        resolved_run_id = str(run_id or _safe_uuid("run"))
        safe_metadata = self._sanitize_metadata(metadata)

        if self.store.get_run(user_id, workspace_id, resolved_run_id):
            return self._error_result(
                message="Workflow run already exists for this user/workspace.",
                error="run_already_exists",
                metadata={
                    "run_id": resolved_run_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        run = WorkflowRunRecord(
            run_id=resolved_run_id,
            workflow_id=str(workflow_id),
            workflow_name=str(workflow_name or workflow_id),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            status=WorkflowRunStatus.RUNNING.value,
            created_at=now,
            updated_at=now,
            started_at=now,
            trigger_type=trigger_type,
            initiated_by=initiated_by,
            correlation_id=correlation_id,
            request_id=request_id,
            last_heartbeat_at=now,
            metadata=safe_metadata,
        )

        if expected_steps:
            for index, step in enumerate(expected_steps, start=1):
                step_id = str(step.get("step_id") or step.get("id") or f"step_{index}")
                step_name = str(step.get("name") or step.get("title") or step_id)
                run.steps[step_id] = WorkflowStepRecord(
                    step_id=step_id,
                    name=step_name,
                    status=WorkflowStepStatus.PENDING.value,
                    created_at=now,
                    connector=step.get("connector"),  # type: ignore[arg-type]
                    agent=step.get("agent"),  # type: ignore[arg-type]
                    metadata=self._sanitize_metadata(step.get("metadata") if isinstance(step, Mapping) else {}),
                )
            run.total_steps = len(run.steps)

        self._append_event(
            run,
            event_type=MonitorEventType.RUN_STARTED,
            message="Workflow run started.",
            data={
                "workflow_id": run.workflow_id,
                "workflow_name": run.workflow_name,
                "trigger_type": trigger_type,
            },
        )

        self.store.save_run(run)

        self._emit_agent_event(
            event_name="workflow.run.started",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=self._run_summary(run),
        )
        self._log_audit_event(
            action="workflow_run_started",
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run.run_id,
            details={"workflow_id": run.workflow_id, "workflow_name": run.workflow_name},
        )

        return self._safe_result(
            message="Workflow run started.",
            data={
                "run": self._serialize_run(run, include_steps=True, include_events=False),
                "verification_payload": self._prepare_verification_payload(
                    action="workflow_run_started",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    run_id=run.run_id,
                    status=run.status,
                    data=self._run_summary(run),
                ),
                "memory_payload": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    event_type="workflow_run_started",
                    data=self._run_summary(run),
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id, run.run_id),
        )

    def heartbeat(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a heartbeat for a running workflow."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        now = _iso_now()
        run.last_heartbeat_at = now
        run.updated_at = now

        if metadata:
            run.metadata.update(self._sanitize_metadata(metadata))

        self._append_event(
            run,
            event_type=MonitorEventType.RUN_HEARTBEAT,
            message="Workflow run heartbeat recorded.",
            data={"metadata": self._sanitize_metadata(metadata)},
        )

        self.store.save_run(run)

        return self._safe_result(
            message="Workflow heartbeat recorded.",
            data={"run": self._serialize_run(run, include_steps=False, include_events=False)},
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def pause_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow run as paused."""

        return self._transition_run_status(
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            status=WorkflowRunStatus.PAUSED,
            event_type=MonitorEventType.RUN_PAUSED,
            message="Workflow run paused.",
            reason=reason,
        )

    def resume_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resume a paused workflow run."""

        return self._transition_run_status(
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            status=WorkflowRunStatus.RUNNING,
            event_type=MonitorEventType.RUN_RESUMED,
            message="Workflow run resumed.",
            reason=reason,
        )

    def complete_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        output_summary: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow run as completed."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        now = _iso_now()

        self._refresh_run_step_counts(run)

        run.status = WorkflowRunStatus.COMPLETED.value
        run.finished_at = now
        run.updated_at = now
        run.duration_seconds = _duration_seconds(run.started_at, run.finished_at)
        run.error = None

        if metadata:
            run.metadata.update(self._sanitize_metadata(metadata))

        event_data = {"output_summary": _sanitize_dict(output_summary)}
        self._append_event(
            run,
            event_type=MonitorEventType.RUN_COMPLETED,
            message="Workflow run completed.",
            data=event_data,
        )

        self.store.save_run(run)

        summary = self._run_summary(run)
        self._emit_agent_event(
            event_name="workflow.run.completed",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=summary,
        )
        self._log_audit_event(
            action="workflow_run_completed",
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            details=summary,
        )

        return self._safe_result(
            message="Workflow run completed.",
            data={
                "run": self._serialize_run(run, include_steps=True, include_events=False),
                "verification_payload": self._prepare_verification_payload(
                    action="workflow_run_completed",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    run_id=run_id,
                    status=run.status,
                    data=summary,
                ),
                "memory_payload": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    event_type="workflow_run_completed",
                    data=summary,
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def fail_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        severity: Union[str, FailureSeverity, None] = FailureSeverity.HIGH,
        recoverable: Optional[bool] = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow run as failed."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        now = _iso_now()
        normalized_error = _normalize_error(
            error,
            severity=severity,
            recoverable=recoverable,
        )

        run.status = WorkflowRunStatus.FAILED.value
        run.finished_at = now
        run.updated_at = now
        run.duration_seconds = _duration_seconds(run.started_at, run.finished_at)
        run.error = normalized_error

        if metadata:
            run.metadata.update(self._sanitize_metadata(metadata))

        self._refresh_run_step_counts(run)

        self._append_event(
            run,
            event_type=MonitorEventType.RUN_FAILED,
            message="Workflow run failed.",
            severity=normalized_error.get("severity"),
            data={"error": normalized_error},
        )

        self.store.save_run(run)

        summary = self._run_summary(run)
        self._emit_agent_event(
            event_name="workflow.run.failed",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=summary,
        )
        self._log_audit_event(
            action="workflow_run_failed",
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            details={"error": normalized_error, "summary": summary},
        )

        return self._safe_result(
            message="Workflow run failed.",
            data={
                "run": self._serialize_run(run, include_steps=True, include_events=False),
                "failure": normalized_error,
                "verification_payload": self._prepare_verification_payload(
                    action="workflow_run_failed",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    run_id=run_id,
                    status=run.status,
                    data={"error": normalized_error, "summary": summary},
                ),
                "memory_payload": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    event_type="workflow_run_failed",
                    data={"error": normalized_error, "summary": summary},
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def cancel_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow run as cancelled."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        now = _iso_now()

        run.status = WorkflowRunStatus.CANCELLED.value
        run.finished_at = now
        run.updated_at = now
        run.duration_seconds = _duration_seconds(run.started_at, run.finished_at)

        if metadata:
            run.metadata.update(self._sanitize_metadata(metadata))

        for step in run.steps.values():
            if step.status in {WorkflowStepStatus.PENDING.value, WorkflowStepStatus.RUNNING.value}:
                step.status = WorkflowStepStatus.CANCELLED.value
                step.finished_at = now
                step.duration_seconds = _duration_seconds(step.started_at, step.finished_at)

        self._refresh_run_step_counts(run)

        self._append_event(
            run,
            event_type=MonitorEventType.RUN_CANCELLED,
            message="Workflow run cancelled.",
            severity=FailureSeverity.MEDIUM.value,
            data={"reason": reason},
        )

        self.store.save_run(run)

        self._emit_agent_event(
            event_name="workflow.run.cancelled",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=self._run_summary(run),
        )
        self._log_audit_event(
            action="workflow_run_cancelled",
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            details={"reason": reason},
        )

        return self._safe_result(
            message="Workflow run cancelled.",
            data={
                "run": self._serialize_run(run, include_steps=True, include_events=False),
                "verification_payload": self._prepare_verification_payload(
                    action="workflow_run_cancelled",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    run_id=run_id,
                    status=run.status,
                    data={"reason": reason},
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def mark_run_retry_scheduled(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        retry_at: Optional[str] = None,
        retry_reason: Optional[str] = None,
        retry_count: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a failed run as scheduled for retry."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        run.status = WorkflowRunStatus.RETRY_SCHEDULED.value
        run.updated_at = _iso_now()
        run.retry_count = int(retry_count if retry_count is not None else run.retry_count + 1)

        if metadata:
            run.metadata.update(self._sanitize_metadata(metadata))

        self._append_event(
            run,
            event_type=MonitorEventType.RUN_RETRY_SCHEDULED,
            message="Workflow run retry scheduled.",
            data={
                "retry_at": retry_at,
                "retry_reason": retry_reason,
                "retry_count": run.retry_count,
            },
        )

        self.store.save_run(run)

        self._emit_agent_event(
            event_name="workflow.run.retry_scheduled",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=self._run_summary(run),
        )

        return self._safe_result(
            message="Workflow run retry scheduled.",
            data={"run": self._serialize_run(run, include_steps=True, include_events=False)},
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    # ------------------------------------------------------------------
    # Step lifecycle
    # ------------------------------------------------------------------

    def create_step(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: Optional[str] = None,
        name: Optional[str] = None,
        connector: Optional[str] = None,
        agent: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a pending step record inside a workflow run."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        resolved_step_id = str(step_id or _safe_uuid("step"))

        if resolved_step_id in run.steps:
            return self._error_result(
                message="Step already exists in this run.",
                error="step_already_exists",
                metadata=self._base_metadata(user_id, workspace_id, run_id, resolved_step_id),
            )

        now = _iso_now()
        step = WorkflowStepRecord(
            step_id=resolved_step_id,
            name=str(name or resolved_step_id),
            status=WorkflowStepStatus.PENDING.value,
            created_at=now,
            connector=connector,
            agent=agent,
            metadata=self._sanitize_metadata(metadata),
        )

        run.steps[resolved_step_id] = step
        run.total_steps = len(run.steps)
        run.updated_at = now

        self._append_event(
            run,
            event_type=MonitorEventType.STEP_CREATED,
            message="Workflow step created.",
            step_id=resolved_step_id,
            data={"name": step.name, "connector": connector, "agent": agent},
        )

        self.store.save_run(run)

        return self._safe_result(
            message="Workflow step created.",
            data={"step": self._serialize_step(step), "run_summary": self._run_summary(run)},
            metadata=self._base_metadata(user_id, workspace_id, run_id, resolved_step_id),
        )

    def record_step_started(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        name: Optional[str] = None,
        connector: Optional[str] = None,
        agent: Optional[str] = None,
        input_summary: Optional[Mapping[str, Any]] = None,
        attempt: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as running."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        now = _iso_now()

        step = run.steps.get(step_id)
        if not step:
            step = WorkflowStepRecord(
                step_id=step_id,
                name=str(name or step_id),
                status=WorkflowStepStatus.PENDING.value,
                created_at=now,
                connector=connector,
                agent=agent,
                metadata=self._sanitize_metadata(metadata),
            )
            run.steps[step_id] = step

        step.status = WorkflowStepStatus.RUNNING.value
        step.started_at = step.started_at or now
        step.finished_at = None
        step.duration_seconds = None
        step.name = str(name or step.name or step_id)
        step.connector = connector or step.connector
        step.agent = agent or step.agent
        step.input_summary = _sanitize_dict(input_summary)
        step.attempt = int(attempt or step.attempt or 1)

        if metadata:
            step.metadata.update(self._sanitize_metadata(metadata))

        run.status = WorkflowRunStatus.RUNNING.value
        run.updated_at = now
        run.last_heartbeat_at = now
        run.total_steps = len(run.steps)
        self._refresh_run_step_counts(run)

        self._append_event(
            run,
            event_type=MonitorEventType.STEP_STARTED,
            message="Workflow step started.",
            step_id=step_id,
            data={
                "name": step.name,
                "attempt": step.attempt,
                "connector": step.connector,
                "agent": step.agent,
            },
        )

        self.store.save_run(run)

        self._emit_agent_event(
            event_name="workflow.step.started",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={
                "run_id": run_id,
                "workflow_id": run.workflow_id,
                "step": self._serialize_step(step),
            },
        )

        return self._safe_result(
            message="Workflow step started.",
            data={"step": self._serialize_step(step), "run_summary": self._run_summary(run)},
            metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
        )

    def record_step_completed(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        output_summary: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as completed."""

        return self._finish_step(
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            step_id=step_id,
            status=WorkflowStepStatus.COMPLETED,
            event_type=MonitorEventType.STEP_COMPLETED,
            message="Workflow step completed.",
            output_summary=output_summary,
            metadata=metadata,
        )

    def record_step_failed(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        severity: Union[str, FailureSeverity, None] = FailureSeverity.HIGH,
        recoverable: Optional[bool] = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as failed and update run failure counts."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        step = run.steps.get(step_id)

        if not step:
            return self._error_result(
                message="Step not found in workflow run.",
                error="step_not_found",
                metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
            )

        now = _iso_now()
        normalized_error = _normalize_error(error, severity=severity, recoverable=recoverable)

        step.status = WorkflowStepStatus.FAILED.value
        step.finished_at = now
        step.duration_seconds = _duration_seconds(step.started_at, step.finished_at)
        step.error = normalized_error

        if metadata:
            step.metadata.update(self._sanitize_metadata(metadata))

        run.updated_at = now
        self._refresh_run_step_counts(run)

        self._append_event(
            run,
            event_type=MonitorEventType.STEP_FAILED,
            message="Workflow step failed.",
            step_id=step_id,
            severity=normalized_error.get("severity"),
            data={"error": normalized_error, "step": self._serialize_step(step)},
        )

        self.store.save_run(run)

        payload = {
            "run_id": run_id,
            "workflow_id": run.workflow_id,
            "step_id": step_id,
            "error": normalized_error,
            "step": self._serialize_step(step),
        }

        self._emit_agent_event(
            event_name="workflow.step.failed",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=payload,
        )
        self._log_audit_event(
            action="workflow_step_failed",
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            step_id=step_id,
            details=payload,
        )

        return self._safe_result(
            message="Workflow step failed.",
            data={
                "step": self._serialize_step(step),
                "failure": normalized_error,
                "run_summary": self._run_summary(run),
                "verification_payload": self._prepare_verification_payload(
                    action="workflow_step_failed",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    run_id=run_id,
                    step_id=step_id,
                    status=step.status,
                    data=payload,
                ),
                "memory_payload": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    event_type="workflow_step_failed",
                    data=payload,
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
        )

    def record_step_skipped(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as skipped."""

        return self._finish_step(
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            step_id=step_id,
            status=WorkflowStepStatus.SKIPPED,
            event_type=MonitorEventType.STEP_SKIPPED,
            message="Workflow step skipped.",
            output_summary={"reason": reason},
            metadata=metadata,
        )

    def record_step_cancelled(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as cancelled."""

        return self._finish_step(
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            step_id=step_id,
            status=WorkflowStepStatus.CANCELLED,
            event_type=MonitorEventType.STEP_CANCELLED,
            message="Workflow step cancelled.",
            output_summary={"reason": reason},
            metadata=metadata,
        )

    def mark_step_retrying(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        attempt: Optional[int] = None,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as retrying."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        step = run.steps.get(step_id)

        if not step:
            return self._error_result(
                message="Step not found in workflow run.",
                error="step_not_found",
                metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
            )

        step.status = WorkflowStepStatus.RETRYING.value
        step.attempt = int(attempt or step.attempt + 1)
        step.error = None
        step.finished_at = None
        step.duration_seconds = None

        if metadata:
            step.metadata.update(self._sanitize_metadata(metadata))

        run.retry_count += 1
        run.updated_at = _iso_now()
        self._refresh_run_step_counts(run)

        self._append_event(
            run,
            event_type=MonitorEventType.STEP_RETRYING,
            message="Workflow step retrying.",
            step_id=step_id,
            data={"attempt": step.attempt, "reason": reason},
        )

        self.store.save_run(run)

        return self._safe_result(
            message="Workflow step marked as retrying.",
            data={"step": self._serialize_step(step), "run_summary": self._run_summary(run)},
            metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
        )

    def mark_step_timeout(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        timeout_seconds: Optional[float] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a workflow step as timed out."""

        return self.record_step_failed(
            user_id=user_id,
            workspace_id=workspace_id,
            run_id=run_id,
            step_id=step_id,
            error={
                "code": "step_timeout",
                "message": "Workflow step timed out.",
                "timeout_seconds": timeout_seconds,
            },
            severity=FailureSeverity.HIGH,
            recoverable=True,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Reads / Dashboard methods
    # ------------------------------------------------------------------

    def get_run(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        include_steps: bool = True,
        include_events: bool = True,
    ) -> Dict[str, Any]:
        """Get one workflow run with tenant isolation."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]

        return self._safe_result(
            message="Workflow run fetched.",
            data={"run": self._serialize_run(run, include_steps=include_steps, include_events=include_events)},
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def list_runs(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[Union[str, WorkflowRunStatus]] = None,
        workflow_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        newest_first: bool = True,
    ) -> Dict[str, Any]:
        """List workflow runs for a user/workspace only."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        safe_limit = min(max(1, int(limit)), 1000)
        safe_offset = max(0, int(offset))
        status_value = _status_value(status) if status else None

        runs = self.store.list_runs(
            user_id=user_id,
            workspace_id=workspace_id,
            status=status_value,
            workflow_id=workflow_id,
            limit=safe_limit,
            offset=safe_offset,
            newest_first=newest_first,
        )

        return self._safe_result(
            message="Workflow runs fetched.",
            data={
                "runs": [
                    self._serialize_run(run, include_steps=False, include_events=False)
                    for run in runs
                ],
                "count": len(runs),
                "limit": safe_limit,
                "offset": safe_offset,
            },
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def get_run_timeline(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        limit: int = 500,
        newest_first: bool = False,
    ) -> Dict[str, Any]:
        """Return run timeline events."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        safe_limit = min(max(1, int(limit)), self.config.max_events_per_run)

        events = list(run.events)
        events.sort(key=lambda event: event.timestamp, reverse=newest_first)
        events = events[:safe_limit]

        return self._safe_result(
            message="Workflow run timeline fetched.",
            data={
                "run_id": run_id,
                "events": [self._serialize_event(event) for event in events],
                "count": len(events),
            },
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def get_analytics(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_id: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Calculate workflow analytics for a workspace.

        Returned metrics are dashboard-ready and isolated to one user/workspace.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        runs = self.store.all_runs_for_workspace(user_id, workspace_id)

        since_dt = _parse_iso(since) if since else None
        until_dt = _parse_iso(until) if until else None

        filtered: List[WorkflowRunRecord] = []
        for run in runs:
            if workflow_id and run.workflow_id != workflow_id:
                continue

            created = _parse_iso(run.created_at)
            if since_dt and created and created < since_dt:
                continue

            if until_dt and created and created > until_dt:
                continue

            filtered.append(run)

        status_counts = Counter(run.status for run in filtered)
        workflow_counts = Counter(run.workflow_id for run in filtered)
        trigger_counts = Counter(run.trigger_type or "unknown" for run in filtered)

        durations = [
            run.duration_seconds
            for run in filtered
            if isinstance(run.duration_seconds, (int, float))
        ]

        step_durations: List[float] = []
        slow_steps: List[Dict[str, Any]] = []
        failed_steps: List[Dict[str, Any]] = []

        for run in filtered:
            for step in run.steps.values():
                if isinstance(step.duration_seconds, (int, float)):
                    step_durations.append(float(step.duration_seconds))

                    if step.duration_seconds >= self.config.slow_step_seconds:
                        slow_steps.append({
                            "run_id": run.run_id,
                            "workflow_id": run.workflow_id,
                            "step_id": step.step_id,
                            "name": step.name,
                            "duration_seconds": step.duration_seconds,
                            "status": step.status,
                        })

                if step.status == WorkflowStepStatus.FAILED.value:
                    failed_steps.append({
                        "run_id": run.run_id,
                        "workflow_id": run.workflow_id,
                        "step_id": step.step_id,
                        "name": step.name,
                        "error": step.error,
                    })

        total_runs = len(filtered)
        completed_runs = status_counts.get(WorkflowRunStatus.COMPLETED.value, 0)
        failed_runs = status_counts.get(WorkflowRunStatus.FAILED.value, 0)

        analytics = {
            "total_runs": total_runs,
            "status_counts": dict(status_counts),
            "workflow_counts": dict(workflow_counts),
            "trigger_counts": dict(trigger_counts),
            "success_rate": self._safe_ratio(completed_runs, total_runs),
            "failure_rate": self._safe_ratio(failed_runs, total_runs),
            "retry_scheduled_count": status_counts.get(WorkflowRunStatus.RETRY_SCHEDULED.value, 0),
            "cancelled_count": status_counts.get(WorkflowRunStatus.CANCELLED.value, 0),
            "duration_seconds": self._stats(durations),
            "step_duration_seconds": self._stats(step_durations),
            "slow_step_threshold_seconds": self.config.slow_step_seconds,
            "slow_steps": sorted(
                slow_steps,
                key=lambda item: item.get("duration_seconds") or 0,
                reverse=True,
            )[:50],
            "failed_steps_count": len(failed_steps),
            "recent_failed_steps": failed_steps[-50:],
            "generated_at": _iso_now(),
            "filters": {
                "workflow_id": workflow_id,
                "since": since,
                "until": until,
            },
        }

        return self._safe_result(
            message="Workflow analytics generated.",
            data={"analytics": analytics},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def get_failure_report(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Return workflow and step failures for dashboard/API reporting."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        safe_limit = min(max(1, int(limit)), 1000)
        runs = self.store.all_runs_for_workspace(user_id, workspace_id)

        failures: List[Dict[str, Any]] = []
        error_codes: Counter[str] = Counter()
        severities: Counter[str] = Counter()

        for run in runs:
            if workflow_id and run.workflow_id != workflow_id:
                continue

            if run.error:
                code = str(run.error.get("code") or "unknown")
                severity = str(run.error.get("severity") or "unknown")
                error_codes[code] += 1
                severities[severity] += 1
                failures.append({
                    "scope": "run",
                    "run_id": run.run_id,
                    "workflow_id": run.workflow_id,
                    "workflow_name": run.workflow_name,
                    "status": run.status,
                    "created_at": run.created_at,
                    "finished_at": run.finished_at,
                    "error": run.error,
                })

            for step in run.steps.values():
                if step.error:
                    code = str(step.error.get("code") or "unknown")
                    severity = str(step.error.get("severity") or "unknown")
                    error_codes[code] += 1
                    severities[severity] += 1
                    failures.append({
                        "scope": "step",
                        "run_id": run.run_id,
                        "workflow_id": run.workflow_id,
                        "workflow_name": run.workflow_name,
                        "step_id": step.step_id,
                        "step_name": step.name,
                        "status": step.status,
                        "attempt": step.attempt,
                        "created_at": step.created_at,
                        "finished_at": step.finished_at,
                        "error": step.error,
                    })

        failures.sort(
            key=lambda item: item.get("finished_at") or item.get("created_at") or "",
            reverse=True,
        )

        report = {
            "failures": failures[:safe_limit],
            "total_failures": len(failures),
            "error_codes": dict(error_codes),
            "severities": dict(severities),
            "limit": safe_limit,
            "workflow_id": workflow_id,
            "generated_at": _iso_now(),
        }

        return self._safe_result(
            message="Workflow failure report generated.",
            data={"failure_report": report},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def export_dashboard_summary(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_id: Optional[str] = None,
        include_recent_runs: bool = True,
        recent_limit: int = 20,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export dashboard summary.

        This is treated as sensitive because it may expose operational analytics.
        It requires security approval unless config allows safe operation without
        a Security Agent.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        action = "workflow_dashboard_export"
        if self._requires_security_check(action=action):
            approval = self._request_security_approval(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                context={
                    "workflow_id": workflow_id,
                    "request_context": self._sanitize_metadata(request_context),
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for dashboard export.",
                    error="security_approval_denied",
                    metadata={
                        "approval": approval,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        analytics_result = self.get_analytics(
            user_id=user_id,
            workspace_id=workspace_id,
            workflow_id=workflow_id,
        )
        failure_result = self.get_failure_report(
            user_id=user_id,
            workspace_id=workspace_id,
            workflow_id=workflow_id,
            limit=50,
        )

        recent_runs: List[Dict[str, Any]] = []
        if include_recent_runs:
            runs_result = self.list_runs(
                user_id=user_id,
                workspace_id=workspace_id,
                workflow_id=workflow_id,
                limit=recent_limit,
                offset=0,
                newest_first=True,
            )
            recent_runs = runs_result.get("data", {}).get("runs", [])

        summary = {
            "analytics": analytics_result.get("data", {}).get("analytics", {}),
            "failure_report": failure_result.get("data", {}).get("failure_report", {}),
            "recent_runs": recent_runs,
            "generated_at": _iso_now(),
            "schema_version": SCHEMA_VERSION,
        }

        self._log_audit_event(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            details={"workflow_id": workflow_id, "recent_limit": recent_limit},
        )

        return self._safe_result(
            message="Workflow dashboard summary exported.",
            data={"dashboard_summary": summary},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def detect_stale_runs(
        self,
        *,
        user_id: str,
        workspace_id: str,
        stale_after_seconds: Optional[float] = None,
        mark_timeout: bool = False,
    ) -> Dict[str, Any]:
        """
        Detect running runs with stale heartbeats.

        mark_timeout can update stale runs to timeout status. This is useful for
        scheduler/retry_handler integration.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        threshold = float(stale_after_seconds or self.config.stale_heartbeat_seconds)
        now = _utcnow()
        runs = self.store.all_runs_for_workspace(user_id, workspace_id)
        stale: List[Dict[str, Any]] = []

        for run in runs:
            if run.status not in {WorkflowRunStatus.RUNNING.value, WorkflowRunStatus.PAUSED.value}:
                continue

            heartbeat = _parse_iso(run.last_heartbeat_at or run.updated_at)
            if not heartbeat:
                continue

            age = (now - heartbeat).total_seconds()
            if age < threshold:
                continue

            stale_item = {
                "run_id": run.run_id,
                "workflow_id": run.workflow_id,
                "workflow_name": run.workflow_name,
                "status": run.status,
                "last_heartbeat_at": run.last_heartbeat_at,
                "age_seconds": age,
                "threshold_seconds": threshold,
            }
            stale.append(stale_item)

            if mark_timeout:
                run.status = WorkflowRunStatus.TIMEOUT.value
                run.finished_at = _iso_now()
                run.updated_at = run.finished_at
                run.duration_seconds = _duration_seconds(run.started_at, run.finished_at)
                run.error = _normalize_error(
                    {
                        "code": "run_heartbeat_timeout",
                        "message": "Workflow run heartbeat became stale.",
                        "age_seconds": age,
                        "threshold_seconds": threshold,
                    },
                    severity=FailureSeverity.HIGH,
                    recoverable=True,
                )
                self._append_event(
                    run,
                    event_type=MonitorEventType.RUN_FAILED,
                    message="Workflow run marked timeout because heartbeat is stale.",
                    severity=FailureSeverity.HIGH.value,
                    data={"age_seconds": age, "threshold_seconds": threshold},
                )
                self.store.save_run(run)

        return self._safe_result(
            message="Stale workflow runs detected.",
            data={
                "stale_runs": stale,
                "count": len(stale),
                "marked_timeout": bool(mark_timeout),
            },
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def purge_runs(
        self,
        *,
        user_id: str,
        workspace_id: str,
        before_iso: Optional[str] = None,
        statuses: Optional[Iterable[Union[str, WorkflowRunStatus]]] = None,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Purge old workflow monitor records.

        This is sensitive because it deletes monitoring history. It requires
        security approval unless explicitly allowed by config.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        action = "workflow_monitor_purge"
        if self._requires_security_check(action=action):
            approval = self._request_security_approval(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                context={
                    "before_iso": before_iso,
                    "statuses": list(statuses or []),
                    "request_context": self._sanitize_metadata(request_context),
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for monitor purge.",
                    error="security_approval_denied",
                    metadata={
                        "approval": approval,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        status_values = [_status_value(status) for status in statuses] if statuses else None
        deleted = self.store.purge_runs(
            user_id=user_id,
            workspace_id=workspace_id,
            before_iso=before_iso,
            statuses=status_values,
        )

        self._log_audit_event(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            details={
                "before_iso": before_iso,
                "statuses": status_values,
                "deleted_count": deleted,
            },
        )

        return self._safe_result(
            message="Workflow monitor records purged.",
            data={"deleted_count": deleted},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        require_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate SaaS tenant context.

        Every user-specific monitoring action must include user_id and
        workspace_id to prevent mixing logs, analytics, runs, tasks, or memory
        across tenants.
        """

        if not user_id or not str(user_id).strip():
            return self._error_result(
                message="user_id is required for WorkflowMonitor operations.",
                error="missing_user_id",
            )

        if require_workspace and (not workspace_id or not str(workspace_id).strip()):
            return self._error_result(
                message="workspace_id is required for WorkflowMonitor operations.",
                error="missing_workspace_id",
                metadata={"user_id": user_id},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id) if workspace_id is not None else None,
            },
        )

    def _requires_security_check(self, *, action: str, **_: Any) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        Monitoring writes are generally safe. Exporting analytics or purging
        history is sensitive.
        """

        sensitive_actions = {
            "workflow_monitor_purge",
            "workflow_dashboard_export",
        }

        return action in sensitive_actions

    def _request_security_approval(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Safe default:
            - If action is sensitive and there is no Security Agent, deny unless
              config.allow_sensitive_without_security is True.
        """

        if not self._requires_security_check(action=action):
            return {
                "approved": True,
                "message": "Security approval not required.",
                "source": "workflow_monitor",
            }

        approval_payload = {
            "action": action,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "context": self._sanitize_metadata(context),
            "requested_at": _iso_now(),
        }

        if self.security_agent is None:
            if self.config.allow_sensitive_without_security:
                return {
                    "approved": True,
                    "message": "Sensitive action allowed by monitor config without Security Agent.",
                    "source": "config",
                    "payload": approval_payload,
                }

            return {
                "approved": False,
                "message": "Security Agent is not configured for sensitive action.",
                "source": "workflow_monitor",
                "payload": approval_payload,
            }

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_payload)
            elif hasattr(self.security_agent, "run"):
                response = self.security_agent.run({
                    "action": "approve_action",
                    **approval_payload,
                })
            else:
                return {
                    "approved": False,
                    "message": "Security Agent has no compatible approval method.",
                    "source": "workflow_monitor",
                    "payload": approval_payload,
                }

            if isinstance(response, Mapping):
                approved = bool(
                    response.get("approved")
                    or response.get("success") is True
                    or response.get("status") == "approved"
                )
                return {
                    "approved": approved,
                    "message": str(response.get("message") or "Security Agent response received."),
                    "source": "security_agent",
                    "response": _sanitize_dict(response),
                    "payload": approval_payload,
                }

            return {
                "approved": bool(response),
                "message": "Security Agent returned non-dict response.",
                "source": "security_agent",
                "payload": approval_payload,
            }
        except Exception as exc:
            self.logger.exception("Security approval failed.")
            return {
                "approved": False,
                "message": f"Security approval failed: {exc}",
                "source": "security_agent",
                "payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        run_id: Optional[str] = None,
        step_id: Optional[str] = None,
        status: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Prepare Verification Agent compatible payload.

        This method does not force-send to Verification Agent. It returns a
        payload that Master Agent, Router, Dashboard, or a future verification
        pipeline can consume.
        """

        if not self.config.enable_verification_payloads:
            return None

        payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "run_id": run_id,
            "step_id": step_id,
            "status": status,
            "data": _sanitize_dict(data),
            "schema_version": SCHEMA_VERSION,
            "created_at": _iso_now(),
        }

        if self.verification_agent is not None:
            try:
                if hasattr(self.verification_agent, "prepare_payload"):
                    self.verification_agent.prepare_payload(payload)
                elif hasattr(self.verification_agent, "record"):
                    self.verification_agent.record(payload)
            except Exception:
                self.logger.exception("Verification payload handoff failed.")

        return payload

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        event_type: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Prepare Memory Agent compatible payload.

        Only operational summaries are stored/prepared. Sensitive values are
        redacted before payload creation.
        """

        if not self.config.enable_memory_payloads:
            return None

        payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "memory_type": "workflow_monitor_event",
            "event_type": event_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": _sanitize_dict(data),
            "created_at": _iso_now(),
            "schema_version": SCHEMA_VERSION,
        }

        if self.memory_agent is not None:
            try:
                if hasattr(self.memory_agent, "prepare_memory"):
                    self.memory_agent.prepare_memory(payload)
                elif hasattr(self.memory_agent, "remember"):
                    self.memory_agent.remember(payload)
                elif hasattr(self.memory_agent, "record"):
                    self.memory_agent.record(payload)
            except Exception:
                self.logger.exception("Memory payload handoff failed.")

        return payload

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit internal agent event for Registry/Master/Dashboard integrations.

        The default implementation is safe and local. A production event bus can
        be injected through event_sink.
        """

        if not self.config.enable_agent_events:
            return

        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": _sanitize_dict(payload),
            "timestamp": _iso_now(),
        }

        try:
            if self.event_sink:
                self.event_sink(event)
            else:
                self.logger.debug("Agent event emitted: %s", event)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        run_id: Optional[str] = None,
        step_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Audit logs must remain tenant-isolated and sanitized.
        """

        if not self.config.enable_audit_log:
            return

        audit_event = {
            "action": action,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "run_id": run_id,
            "step_id": step_id,
            "details": _sanitize_dict(details),
            "timestamp": _iso_now(),
            "schema_version": SCHEMA_VERSION,
        }

        try:
            if self.audit_sink:
                self.audit_sink(audit_event)
            else:
                self.logger.info("Audit event: %s", audit_event)
        except Exception:
            self.logger.exception("Failed to write audit event.")

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success response."""

        return {
            "success": True,
            "message": message,
            "data": _as_serializable_dataclass(data if data is not None else {}),
            "error": None,
            "metadata": _sanitize_dict(metadata),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error response."""

        normalized_error = _normalize_error(error or message)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": normalized_error,
            "metadata": _sanitize_dict(metadata),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_run_or_error(
        self,
        user_id: str,
        workspace_id: str,
        run_id: str,
    ) -> Dict[str, Any]:
        """Fetch a run with context validation and structured error."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        if not run_id or not str(run_id).strip():
            return self._error_result(
                message="run_id is required.",
                error="missing_run_id",
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        run = self.store.get_run(user_id, workspace_id, run_id)
        if not run:
            return self._error_result(
                message="Workflow run not found for this user/workspace.",
                error="run_not_found",
                metadata=self._base_metadata(user_id, workspace_id, run_id),
            )

        return self._safe_result(
            message="Workflow run found.",
            data={"run_record": run},
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def _transition_run_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        status: WorkflowRunStatus,
        event_type: MonitorEventType,
        message: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generic helper for simple run status transitions."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        run.status = status.value
        run.updated_at = _iso_now()

        if status == WorkflowRunStatus.RUNNING:
            run.last_heartbeat_at = run.updated_at

        self._append_event(
            run,
            event_type=event_type,
            message=message,
            data={"reason": reason},
        )

        self.store.save_run(run)

        self._emit_agent_event(
            event_name=f"workflow.run.{status.value}",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=self._run_summary(run),
        )

        return self._safe_result(
            message=message,
            data={"run": self._serialize_run(run, include_steps=True, include_events=False)},
            metadata=self._base_metadata(user_id, workspace_id, run_id),
        )

    def _finish_step(
        self,
        *,
        user_id: str,
        workspace_id: str,
        run_id: str,
        step_id: str,
        status: WorkflowStepStatus,
        event_type: MonitorEventType,
        message: str,
        output_summary: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Finish a workflow step with a terminal/non-running status."""

        run_result = self._get_run_or_error(user_id, workspace_id, run_id)
        if not run_result["success"]:
            return run_result

        run: WorkflowRunRecord = run_result["data"]["run_record"]
        step = run.steps.get(step_id)

        if not step:
            return self._error_result(
                message="Step not found in workflow run.",
                error="step_not_found",
                metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
            )

        now = _iso_now()
        step.status = status.value
        step.finished_at = now
        step.duration_seconds = _duration_seconds(step.started_at, step.finished_at)
        step.output_summary = _sanitize_dict(output_summary)
        step.error = None if status == WorkflowStepStatus.COMPLETED else step.error

        if metadata:
            step.metadata.update(self._sanitize_metadata(metadata))

        run.updated_at = now
        run.last_heartbeat_at = now
        self._refresh_run_step_counts(run)

        event_data = {
            "step": self._serialize_step(step),
            "output_summary": step.output_summary,
        }

        if step.duration_seconds is not None and step.duration_seconds >= self.config.slow_step_seconds:
            event_data["slow_step"] = True
            event_data["slow_step_threshold_seconds"] = self.config.slow_step_seconds

        self._append_event(
            run,
            event_type=event_type,
            message=message,
            step_id=step_id,
            data=event_data,
        )

        self.store.save_run(run)

        self._emit_agent_event(
            event_name=f"workflow.step.{status.value}",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={
                "run_id": run_id,
                "workflow_id": run.workflow_id,
                "step": self._serialize_step(step),
            },
        )

        verification_payload = None
        if status in {WorkflowStepStatus.COMPLETED, WorkflowStepStatus.SKIPPED, WorkflowStepStatus.CANCELLED}:
            verification_payload = self._prepare_verification_payload(
                action=f"workflow_step_{status.value}",
                user_id=user_id,
                workspace_id=workspace_id,
                run_id=run_id,
                step_id=step_id,
                status=step.status,
                data={"step": self._serialize_step(step), "run_summary": self._run_summary(run)},
            )

        return self._safe_result(
            message=message,
            data={
                "step": self._serialize_step(step),
                "run_summary": self._run_summary(run),
                "verification_payload": verification_payload,
            },
            metadata=self._base_metadata(user_id, workspace_id, run_id, step_id),
        )

    def _append_event(
        self,
        run: WorkflowRunRecord,
        *,
        event_type: Union[str, MonitorEventType],
        message: str,
        step_id: Optional[str] = None,
        severity: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> WorkflowMonitorEvent:
        """Append a timeline event to a run with max event retention."""

        event = WorkflowMonitorEvent(
            event_id=_safe_uuid("evt"),
            run_id=run.run_id,
            user_id=run.user_id,
            workspace_id=run.workspace_id,
            event_type=_status_value(event_type),
            message=str(message),
            timestamp=_iso_now(),
            step_id=step_id,
            severity=severity,
            data=_sanitize_dict(data),
        )

        run.events.append(event)

        if len(run.events) > self.config.max_events_per_run:
            overflow = len(run.events) - self.config.max_events_per_run
            run.events = run.events[overflow:]

        run.updated_at = event.timestamp
        return event

    def _refresh_run_step_counts(self, run: WorkflowRunRecord) -> None:
        """Refresh step aggregate counters on a run."""

        run.total_steps = len(run.steps)
        run.completed_steps = sum(
            1 for step in run.steps.values()
            if step.status == WorkflowStepStatus.COMPLETED.value
        )
        run.failed_steps = sum(
            1 for step in run.steps.values()
            if step.status == WorkflowStepStatus.FAILED.value
        )
        run.skipped_steps = sum(
            1 for step in run.steps.values()
            if step.status == WorkflowStepStatus.SKIPPED.value
        )

    def _sanitize_metadata(self, metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Sanitize metadata.

        Allows arbitrary keys but redacts sensitive values. safe_metadata_keys
        remain documented for dashboards and integrations.
        """

        return _sanitize_dict(metadata)

    def _serialize_run(
        self,
        run: WorkflowRunRecord,
        *,
        include_steps: bool = True,
        include_events: bool = True,
    ) -> Dict[str, Any]:
        """Serialize run record for API/dashboard output."""

        payload = {
            "run_id": run.run_id,
            "workflow_id": run.workflow_id,
            "workflow_name": run.workflow_name,
            "user_id": run.user_id,
            "workspace_id": run.workspace_id,
            "status": run.status,
            "created_at": run.created_at,
            "updated_at": run.updated_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "duration_seconds": run.duration_seconds,
            "trigger_type": run.trigger_type,
            "initiated_by": run.initiated_by,
            "correlation_id": run.correlation_id,
            "request_id": run.request_id,
            "total_steps": run.total_steps,
            "completed_steps": run.completed_steps,
            "failed_steps": run.failed_steps,
            "skipped_steps": run.skipped_steps,
            "retry_count": run.retry_count,
            "last_heartbeat_at": run.last_heartbeat_at,
            "error": _sanitize_dict(run.error),
            "metadata": _sanitize_dict(run.metadata),
        }

        if include_steps:
            payload["steps"] = {
                step_id: self._serialize_step(step)
                for step_id, step in run.steps.items()
            }

        if include_events:
            payload["events"] = [
                self._serialize_event(event)
                for event in run.events
            ]

        return payload

    def _serialize_step(self, step: WorkflowStepRecord) -> Dict[str, Any]:
        """Serialize step record for API/dashboard output."""

        return {
            "step_id": step.step_id,
            "name": step.name,
            "status": step.status,
            "created_at": step.created_at,
            "started_at": step.started_at,
            "finished_at": step.finished_at,
            "duration_seconds": step.duration_seconds,
            "attempt": step.attempt,
            "connector": step.connector,
            "agent": step.agent,
            "input_summary": _sanitize_dict(step.input_summary),
            "output_summary": _sanitize_dict(step.output_summary),
            "error": _sanitize_dict(step.error),
            "metadata": _sanitize_dict(step.metadata),
        }

    def _serialize_event(self, event: WorkflowMonitorEvent) -> Dict[str, Any]:
        """Serialize timeline event."""

        return {
            "event_id": event.event_id,
            "run_id": event.run_id,
            "user_id": event.user_id,
            "workspace_id": event.workspace_id,
            "event_type": event.event_type,
            "message": event.message,
            "timestamp": event.timestamp,
            "step_id": event.step_id,
            "severity": event.severity,
            "data": _sanitize_dict(event.data),
        }

    def _run_summary(self, run: WorkflowRunRecord) -> Dict[str, Any]:
        """Return compact run summary."""

        self._refresh_run_step_counts(run)

        return {
            "run_id": run.run_id,
            "workflow_id": run.workflow_id,
            "workflow_name": run.workflow_name,
            "status": run.status,
            "user_id": run.user_id,
            "workspace_id": run.workspace_id,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "duration_seconds": run.duration_seconds,
            "total_steps": run.total_steps,
            "completed_steps": run.completed_steps,
            "failed_steps": run.failed_steps,
            "skipped_steps": run.skipped_steps,
            "retry_count": run.retry_count,
            "trigger_type": run.trigger_type,
            "last_heartbeat_at": run.last_heartbeat_at,
            "has_error": run.error is not None,
            "error": _sanitize_dict(run.error),
        }

    def _base_metadata(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        run_id: Optional[str] = None,
        step_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return standard response metadata."""

        return {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "file": FILE_NAME,
            "schema_version": SCHEMA_VERSION,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "run_id": run_id,
            "step_id": step_id,
            "timestamp": _iso_now(),
        }

    @staticmethod
    def _safe_ratio(numerator: Union[int, float], denominator: Union[int, float]) -> float:
        """Return safe rounded ratio."""

        if not denominator:
            return 0.0

        try:
            return round(float(numerator) / float(denominator), 4)
        except Exception:
            return 0.0

    @staticmethod
    def _stats(values: Iterable[Union[int, float]]) -> Dict[str, Optional[float]]:
        """Return basic stats for numeric values."""

        numeric = [float(value) for value in values if isinstance(value, (int, float))]

        if not numeric:
            return {
                "count": 0,
                "min": None,
                "max": None,
                "avg": None,
                "median": None,
                "p95": None,
            }

        sorted_values = sorted(numeric)
        p95_index = min(len(sorted_values) - 1, int(round((len(sorted_values) - 1) * 0.95)))

        return {
            "count": len(sorted_values),
            "min": round(min(sorted_values), 4),
            "max": round(max(sorted_values), 4),
            "avg": round(sum(sorted_values) / len(sorted_values), 4),
            "median": round(statistics.median(sorted_values), 4),
            "p95": round(sorted_values[p95_index], 4),
        }


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "WorkflowMonitor",
    "MonitorConfig",
    "WorkflowRunStatus",
    "WorkflowStepStatus",
    "MonitorEventType",
    "FailureSeverity",
    "WorkflowRunRecord",
    "WorkflowStepRecord",
    "WorkflowMonitorEvent",
    "InMemoryWorkflowMonitorStore",
]