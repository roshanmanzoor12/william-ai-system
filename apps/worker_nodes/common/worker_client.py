"""
apps/worker_nodes/common/worker_client.py

Shared Worker Client for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Connect device worker nodes to the backend safely.

Responsibilities:
    - Device registration
    - Heartbeat reporting
    - Task polling
    - User/workspace isolation checks
    - Worker permission checks
    - Subscription/plan/role compatibility hooks
    - Stop/resume/pause control
    - Safe action reports
    - Structured API responses
    - Audit, Security Agent, Memory Agent, and Verification Agent payload compatibility

Design:
    - Import-safe even if future backend files do not exist yet.
    - No hardcoded secrets.
    - Reads backend URL/API token/device info from environment when not passed directly.
    - Uses only Python standard library by default.
    - Optional requests support if installed.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - safe optional import
    requests = None


JSONDict = Dict[str, Any]


class WorkerClientStatus(str, Enum):
    CREATED = "created"
    REGISTERED = "registered"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


class WorkerTaskStatus(str, Enum):
    RECEIVED = "received"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    NEEDS_SECURITY_APPROVAL = "needs_security_approval"


class WorkerRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkerActionType(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    SYSTEM = "system"
    BROWSER = "browser"
    FILE = "file"
    MEMORY = "memory"
    FINANCE = "finance"
    CALL = "call"
    UNKNOWN = "unknown"


@dataclass
class WorkerClientConfig:
    """
    Runtime configuration for the worker client.

    Environment fallbacks:
        WILLIAM_BACKEND_URL
        WILLIAM_WORKER_API_TOKEN
        WILLIAM_WORKER_DEVICE_ID
        WILLIAM_WORKER_DEVICE_NAME
        WILLIAM_WORKER_USER_ID
        WILLIAM_WORKER_WORKSPACE_ID
    """

    backend_url: str = field(default_factory=lambda: os.getenv("WILLIAM_BACKEND_URL", "http://127.0.0.1:8000"))
    api_token: str = field(default_factory=lambda: os.getenv("WILLIAM_WORKER_API_TOKEN", ""))
    device_id: str = field(default_factory=lambda: os.getenv("WILLIAM_WORKER_DEVICE_ID", ""))
    device_name: str = field(default_factory=lambda: os.getenv("WILLIAM_WORKER_DEVICE_NAME", ""))
    user_id: str = field(default_factory=lambda: os.getenv("WILLIAM_WORKER_USER_ID", ""))
    workspace_id: str = field(default_factory=lambda: os.getenv("WILLIAM_WORKER_WORKSPACE_ID", ""))
    worker_type: str = "device_worker"
    worker_version: str = "1.0.0"
    heartbeat_interval_seconds: int = 30
    poll_interval_seconds: int = 5
    request_timeout_seconds: int = 20
    max_task_batch_size: int = 3
    verify_tls: bool = True
    use_requests_if_available: bool = True
    allow_unregistered_polling: bool = False
    allowed_agents: Tuple[str, ...] = (
        "system",
        "browser",
        "code",
        "voice",
        "visual",
        "workflow",
        "verification",
    )
    allowed_action_types: Tuple[str, ...] = (
        WorkerActionType.READ.value,
        WorkerActionType.WRITE.value,
        WorkerActionType.EXECUTE.value,
        WorkerActionType.BROWSER.value,
        WorkerActionType.FILE.value,
    )
    metadata: JSONDict = field(default_factory=dict)

    def normalize(self) -> "WorkerClientConfig":
        backend_url = str(self.backend_url or "").strip()
        if backend_url and not backend_url.endswith("/"):
            backend_url += "/"

        device_id = self.device_id or self._generate_stable_device_id()
        device_name = self.device_name or self._generate_device_name()

        return WorkerClientConfig(
            backend_url=backend_url,
            api_token=self.api_token,
            device_id=device_id,
            device_name=device_name,
            user_id=str(self.user_id or "").strip(),
            workspace_id=str(self.workspace_id or "").strip(),
            worker_type=self.worker_type,
            worker_version=self.worker_version,
            heartbeat_interval_seconds=max(5, int(self.heartbeat_interval_seconds)),
            poll_interval_seconds=max(1, int(self.poll_interval_seconds)),
            request_timeout_seconds=max(3, int(self.request_timeout_seconds)),
            max_task_batch_size=max(1, int(self.max_task_batch_size)),
            verify_tls=bool(self.verify_tls),
            use_requests_if_available=bool(self.use_requests_if_available),
            allow_unregistered_polling=bool(self.allow_unregistered_polling),
            allowed_agents=tuple(self.allowed_agents or ()),
            allowed_action_types=tuple(self.allowed_action_types or ()),
            metadata=dict(self.metadata or {}),
        )

    @staticmethod
    def _generate_device_name() -> str:
        hostname = socket.gethostname() or "unknown-host"
        system = platform.system() or "unknown-os"
        return f"{system}-{hostname}"

    @staticmethod
    def _generate_stable_device_id() -> str:
        hostname = socket.gethostname() or "unknown-host"
        system = platform.system() or "unknown-os"
        machine = platform.machine() or "unknown-machine"
        seed = f"{system}:{hostname}:{machine}"
        return f"device-{uuid.uuid5(uuid.NAMESPACE_DNS, seed)}"


@dataclass
class WorkerIdentity:
    device_id: str
    device_name: str
    user_id: str
    workspace_id: str
    worker_type: str
    worker_version: str
    hostname: str
    os_name: str
    os_version: str
    machine: str
    python_version: str
    capabilities: List[str]
    allowed_agents: List[str]
    allowed_action_types: List[str]
    metadata: JSONDict = field(default_factory=dict)

    def to_dict(self) -> JSONDict:
        return asdict(self)


@dataclass
class WorkerTask:
    task_id: str
    user_id: str
    workspace_id: str
    agent: str
    action: str
    action_type: str = WorkerActionType.UNKNOWN.value
    payload: JSONDict = field(default_factory=dict)
    permissions_required: List[str] = field(default_factory=list)
    risk_level: str = WorkerRiskLevel.LOW.value
    requires_security_approval: bool = False
    security_approval_id: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: Optional[str] = None
    metadata: JSONDict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkerTask":
        return cls(
            task_id=str(data.get("task_id") or data.get("id") or ""),
            user_id=str(data.get("user_id") or ""),
            workspace_id=str(data.get("workspace_id") or ""),
            agent=str(data.get("agent") or data.get("agent_key") or ""),
            action=str(data.get("action") or ""),
            action_type=str(data.get("action_type") or WorkerActionType.UNKNOWN.value),
            payload=dict(data.get("payload") or {}),
            permissions_required=list(data.get("permissions_required") or []),
            risk_level=str(data.get("risk_level") or WorkerRiskLevel.LOW.value),
            requires_security_approval=bool(data.get("requires_security_approval", False)),
            security_approval_id=data.get("security_approval_id"),
            request_id=str(data.get("request_id") or str(uuid.uuid4())),
            created_at=data.get("created_at"),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> JSONDict:
        return asdict(self)


@dataclass
class WorkerResponse:
    ok: bool
    status: str
    message: str
    data: JSONDict = field(default_factory=dict)
    errors: List[JSONDict] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> JSONDict:
        return asdict(self)


@dataclass
class WorkerActionReport:
    task_id: str
    user_id: str
    workspace_id: str
    device_id: str
    status: WorkerTaskStatus
    message: str
    result: JSONDict = field(default_factory=dict)
    errors: List[JSONDict] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    audit_event: Optional[JSONDict] = None
    memory_payload: Optional[JSONDict] = None
    verification_payload: Optional[JSONDict] = None
    security_payload: Optional[JSONDict] = None
    metadata: JSONDict = field(default_factory=dict)

    def to_dict(self) -> JSONDict:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class WorkerClient:
    """
    Shared worker client used by device worker nodes.

    Example:
        client = WorkerClient()
        client.register_device()
        client.run_forever(task_handler=my_handler)

    A task handler receives a WorkerTask and must return either:
        - dict result
        - WorkerActionReport
        - WorkerResponse
    """

    MODULE_NAME = "WorkerClient"

    def __init__(
        self,
        config: Optional[WorkerClientConfig] = None,
        audit_logger: Optional[Callable[[JSONDict], Any]] = None,
        security_checker: Optional[Callable[[JSONDict], Any]] = None,
        memory_hook: Optional[Callable[[JSONDict], Any]] = None,
        verification_hook: Optional[Callable[[JSONDict], Any]] = None,
        logger: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.config = (config or WorkerClientConfig()).normalize()
        self.audit_logger = audit_logger
        self.security_checker = security_checker
        self.memory_hook = memory_hook
        self.verification_hook = verification_hook
        self.logger = logger

        self.status = WorkerClientStatus.CREATED
        self.session_id = str(uuid.uuid4())
        self.registered_at: Optional[str] = None
        self.last_heartbeat_at: Optional[str] = None
        self.last_poll_at: Optional[str] = None
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def identity(self) -> WorkerIdentity:
        return WorkerIdentity(
            device_id=self.config.device_id,
            device_name=self.config.device_name,
            user_id=self.config.user_id,
            workspace_id=self.config.workspace_id,
            worker_type=self.config.worker_type,
            worker_version=self.config.worker_version,
            hostname=socket.gethostname() or "unknown-host",
            os_name=platform.system() or "unknown-os",
            os_version=platform.version() or "unknown-version",
            machine=platform.machine() or "unknown-machine",
            python_version=platform.python_version(),
            capabilities=self._default_capabilities(),
            allowed_agents=list(self.config.allowed_agents),
            allowed_action_types=list(self.config.allowed_action_types),
            metadata=dict(self.config.metadata),
        )

    def validate_config(self) -> WorkerResponse:
        errors: List[JSONDict] = []

        if not self.config.backend_url:
            errors.append({"field": "backend_url", "error": "required"})

        if not self.config.device_id:
            errors.append({"field": "device_id", "error": "required"})

        if not self.config.user_id:
            errors.append({"field": "user_id", "error": "required"})

        if not self.config.workspace_id:
            errors.append({"field": "workspace_id", "error": "required"})

        if not self.config.api_token:
            errors.append(
                {
                    "field": "api_token",
                    "error": "required",
                    "detail": "Set WILLIAM_WORKER_API_TOKEN or pass api_token in WorkerClientConfig.",
                }
            )

        if errors:
            return WorkerResponse(
                ok=False,
                status="invalid_config",
                message="Worker client configuration is invalid.",
                errors=errors,
            )

        return WorkerResponse(
            ok=True,
            status="valid_config",
            message="Worker client configuration is valid.",
            data={"identity": self.identity().to_dict()},
        )

    def register_device(self) -> JSONDict:
        validation = self.validate_config()
        if not validation.ok:
            self.status = WorkerClientStatus.ERROR
            return validation.to_dict()

        payload = {
            "identity": self.identity().to_dict(),
            "session_id": self.session_id,
            "registered_at": self.now(),
            "audit_event": self.build_audit_event(
                action="worker.device.register.requested",
                risk_level=WorkerRiskLevel.MEDIUM,
                details={"device_id": self.config.device_id},
            ),
        }

        self._safe_hook(self.audit_logger, payload["audit_event"])

        response = self._request(
            method="POST",
            path="/api/worker/register",
            payload=payload,
        )

        if response.ok:
            with self._lock:
                self.status = WorkerClientStatus.REGISTERED
                self.registered_at = self.now()

            return WorkerResponse(
                ok=True,
                status="registered",
                message="Worker device registered successfully.",
                data={
                    "device_id": self.config.device_id,
                    "session_id": self.session_id,
                    "backend_response": response.data,
                },
            ).to_dict()

        self.status = WorkerClientStatus.ERROR
        return response.to_dict()

    def send_heartbeat(self) -> JSONDict:
        if not self._can_contact_backend():
            return WorkerResponse(
                ok=False,
                status="not_ready",
                message="Worker is not ready to send heartbeat.",
                errors=[{"error": "client_not_registered_or_config_invalid"}],
            ).to_dict()

        payload = {
            "device_id": self.config.device_id,
            "device_name": self.config.device_name,
            "user_id": self.config.user_id,
            "workspace_id": self.config.workspace_id,
            "session_id": self.session_id,
            "status": self.status.value,
            "paused": self.pause_event.is_set(),
            "stopping": self.stop_event.is_set(),
            "timestamp": self.now(),
            "identity": self.identity().to_dict(),
        }

        response = self._request(
            method="POST",
            path="/api/worker/heartbeat",
            payload=payload,
        )

        if response.ok:
            self.last_heartbeat_at = self.now()

        return response.to_dict()

    def poll_tasks(self) -> JSONDict:
        if not self._can_poll():
            return WorkerResponse(
                ok=False,
                status="not_ready",
                message="Worker is not ready to poll tasks.",
                errors=[{"error": "client_not_registered_or_polling_not_allowed"}],
            ).to_dict()

        payload = {
            "device_id": self.config.device_id,
            "user_id": self.config.user_id,
            "workspace_id": self.config.workspace_id,
            "session_id": self.session_id,
            "max_tasks": self.config.max_task_batch_size,
            "allowed_agents": list(self.config.allowed_agents),
            "allowed_action_types": list(self.config.allowed_action_types),
            "timestamp": self.now(),
        }

        response = self._request(
            method="POST",
            path="/api/worker/tasks/poll",
            payload=payload,
        )

        self.last_poll_at = self.now()

        if not response.ok:
            return response.to_dict()

        raw_tasks = response.data.get("tasks", [])
        tasks: List[JSONDict] = []

        if isinstance(raw_tasks, list):
            for item in raw_tasks:
                if isinstance(item, Mapping):
                    task = WorkerTask.from_dict(item)
                    validation = self.validate_task(task)
                    if validation.ok:
                        tasks.append(task.to_dict())
                    else:
                        self.report_task_rejected(
                            task=task,
                            reason="task_validation_failed",
                            errors=validation.errors,
                        )

        return WorkerResponse(
            ok=True,
            status="tasks_polled",
            message="Worker task polling completed.",
            data={
                "tasks": tasks,
                "count": len(tasks),
                "raw_count": len(raw_tasks) if isinstance(raw_tasks, list) else 0,
            },
        ).to_dict()

    def validate_task(self, task: WorkerTask) -> WorkerResponse:
        errors: List[JSONDict] = []

        if not task.task_id:
            errors.append({"field": "task_id", "error": "required"})

        if not task.user_id:
            errors.append({"field": "user_id", "error": "required"})

        if not task.workspace_id:
            errors.append({"field": "workspace_id", "error": "required"})

        if task.user_id != self.config.user_id:
            errors.append(
                {
                    "field": "user_id",
                    "error": "isolation_violation",
                    "detail": "Task user_id does not match worker user_id.",
                }
            )

        if task.workspace_id != self.config.workspace_id:
            errors.append(
                {
                    "field": "workspace_id",
                    "error": "isolation_violation",
                    "detail": "Task workspace_id does not match worker workspace_id.",
                }
            )

        if task.agent not in self.config.allowed_agents:
            errors.append(
                {
                    "field": "agent",
                    "error": "agent_not_allowed_for_worker",
                    "agent": task.agent,
                }
            )

        if task.action_type not in self.config.allowed_action_types:
            errors.append(
                {
                    "field": "action_type",
                    "error": "action_type_not_allowed_for_worker",
                    "action_type": task.action_type,
                }
            )

        if task.requires_security_approval and not task.security_approval_id:
            errors.append(
                {
                    "field": "security_approval_id",
                    "error": "required_for_sensitive_task",
                }
            )

        if task.risk_level in {WorkerRiskLevel.HIGH.value, WorkerRiskLevel.CRITICAL.value}:
            if not task.requires_security_approval:
                errors.append(
                    {
                        "field": "requires_security_approval",
                        "error": "high_risk_task_must_require_security_approval",
                        "risk_level": task.risk_level,
                    }
                )

        if errors:
            return WorkerResponse(
                ok=False,
                status=WorkerTaskStatus.REJECTED.value,
                message="Task failed worker validation.",
                errors=errors,
                data={"task": task.to_dict()},
                request_id=task.request_id,
            )

        security_payload = self.build_security_payload_for_task(task)

        if self.security_checker and task.requires_security_approval:
            decision = self._safe_hook(self.security_checker, security_payload)
            if self._security_denied(decision):
                return WorkerResponse(
                    ok=False,
                    status=WorkerTaskStatus.NEEDS_SECURITY_APPROVAL.value,
                    message="Task was rejected by Security Agent decision.",
                    errors=[{"error": "security_agent_denied_task", "decision": self._safe_json(decision)}],
                    data={"security_payload": security_payload},
                    request_id=task.request_id,
                )

        return WorkerResponse(
            ok=True,
            status=WorkerTaskStatus.ACCEPTED.value,
            message="Task accepted by worker validation.",
            data={
                "task_id": task.task_id,
                "security_payload": security_payload,
            },
            request_id=task.request_id,
        )

    def report_task_started(self, task: WorkerTask) -> JSONDict:
        report = WorkerActionReport(
            task_id=task.task_id,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            device_id=self.config.device_id,
            status=WorkerTaskStatus.RUNNING,
            message="Worker task started.",
            started_at=self.now(),
            audit_event=self.build_audit_event(
                action="worker.task.started",
                risk_level=self._risk_from_task(task),
                details={"task": task.to_dict()},
            ),
            security_payload=self.build_security_payload_for_task(task),
            metadata={"request_id": task.request_id},
        )

        self._safe_hook(self.audit_logger, report.audit_event)
        return self._send_action_report(report).to_dict()

    def report_task_completed(
        self,
        task: WorkerTask,
        result: Optional[JSONDict] = None,
        started_at: Optional[str] = None,
    ) -> JSONDict:
        safe_result = self._redact_sensitive_dict(result or {})

        verification_payload = self.build_verification_payload(
            task=task,
            status=WorkerTaskStatus.COMPLETED,
            result=safe_result,
            errors=[],
        )

        memory_payload = self.build_memory_payload(
            task=task,
            summary="Worker task completed successfully.",
            payload=safe_result,
        )

        audit_event = self.build_audit_event(
            action="worker.task.completed",
            risk_level=self._risk_from_task(task),
            details={
                "task_id": task.task_id,
                "agent": task.agent,
                "action": task.action,
                "action_type": task.action_type,
            },
        )

        report = WorkerActionReport(
            task_id=task.task_id,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            device_id=self.config.device_id,
            status=WorkerTaskStatus.COMPLETED,
            message="Worker task completed.",
            result=safe_result,
            errors=[],
            started_at=started_at,
            finished_at=self.now(),
            audit_event=audit_event,
            memory_payload=memory_payload,
            verification_payload=verification_payload,
            security_payload=self.build_security_payload_for_task(task),
            metadata={"request_id": task.request_id},
        )

        self._safe_hook(self.audit_logger, audit_event)
        self._safe_hook(self.memory_hook, memory_payload)
        self._safe_hook(self.verification_hook, verification_payload)

        return self._send_action_report(report).to_dict()

    def report_task_failed(
        self,
        task: WorkerTask,
        error: Any,
        started_at: Optional[str] = None,
        result: Optional[JSONDict] = None,
    ) -> JSONDict:
        safe_error = self._safe_error(error)

        verification_payload = self.build_verification_payload(
            task=task,
            status=WorkerTaskStatus.FAILED,
            result=result or {},
            errors=[safe_error],
        )

        audit_event = self.build_audit_event(
            action="worker.task.failed",
            risk_level=self._risk_from_task(task),
            details={
                "task_id": task.task_id,
                "agent": task.agent,
                "action": task.action,
                "error": safe_error,
            },
        )

        report = WorkerActionReport(
            task_id=task.task_id,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            device_id=self.config.device_id,
            status=WorkerTaskStatus.FAILED,
            message="Worker task failed safely.",
            result=self._redact_sensitive_dict(result or {}),
            errors=[safe_error],
            started_at=started_at,
            finished_at=self.now(),
            audit_event=audit_event,
            verification_payload=verification_payload,
            security_payload=self.build_security_payload_for_task(task),
            metadata={"request_id": task.request_id},
        )

        self._safe_hook(self.audit_logger, audit_event)
        self._safe_hook(self.verification_hook, verification_payload)

        return self._send_action_report(report).to_dict()

    def report_task_rejected(
        self,
        task: WorkerTask,
        reason: str,
        errors: Optional[List[JSONDict]] = None,
    ) -> JSONDict:
        audit_event = self.build_audit_event(
            action="worker.task.rejected",
            risk_level=self._risk_from_task(task),
            details={
                "task_id": task.task_id,
                "reason": reason,
                "errors": errors or [],
            },
        )

        report = WorkerActionReport(
            task_id=task.task_id or "unknown",
            user_id=task.user_id or self.config.user_id,
            workspace_id=task.workspace_id or self.config.workspace_id,
            device_id=self.config.device_id,
            status=WorkerTaskStatus.REJECTED,
            message=f"Worker rejected task: {reason}",
            errors=errors or [],
            finished_at=self.now(),
            audit_event=audit_event,
            security_payload=self.build_security_payload_for_task(task),
            metadata={"request_id": task.request_id},
        )

        self._safe_hook(self.audit_logger, audit_event)
        return self._send_action_report(report).to_dict()

    def run_once(self, task_handler: Callable[[WorkerTask], Any]) -> JSONDict:
        if self.pause_event.is_set():
            return WorkerResponse(
                ok=True,
                status="paused",
                message="Worker is paused. No tasks processed.",
            ).to_dict()

        polled = self.poll_tasks()
        if not polled.get("ok"):
            return polled

        processed: List[JSONDict] = []
        tasks = polled.get("data", {}).get("tasks", [])

        for raw_task in tasks:
            if self.stop_event.is_set():
                break

            task = WorkerTask.from_dict(raw_task)
            validation = self.validate_task(task)
            if not validation.ok:
                processed.append(
                    self.report_task_rejected(
                        task=task,
                        reason="validation_failed_before_execution",
                        errors=validation.errors,
                    )
                )
                continue

            started_at = self.now()
            self.report_task_started(task)

            try:
                handler_result = task_handler(task)
                normalized_result = self._normalize_handler_result(handler_result)

                if normalized_result.get("status") == WorkerTaskStatus.FAILED.value:
                    processed.append(
                        self.report_task_failed(
                            task=task,
                            error=normalized_result.get("errors") or "Task handler returned failed status.",
                            started_at=started_at,
                            result=normalized_result.get("data") or {},
                        )
                    )
                else:
                    processed.append(
                        self.report_task_completed(
                            task=task,
                            result=normalized_result.get("data") or normalized_result,
                            started_at=started_at,
                        )
                    )

            except Exception as exc:
                processed.append(
                    self.report_task_failed(
                        task=task,
                        error=exc,
                        started_at=started_at,
                    )
                )

        return WorkerResponse(
            ok=True,
            status="run_once_completed",
            message="Worker run cycle completed.",
            data={
                "processed_count": len(processed),
                "processed": processed,
            },
        ).to_dict()

    def run_forever(self, task_handler: Callable[[WorkerTask], Any], auto_register: bool = True) -> JSONDict:
        if auto_register and self.status == WorkerClientStatus.CREATED:
            registration = self.register_device()
            if not registration.get("ok"):
                return registration

        with self._lock:
            self.status = WorkerClientStatus.RUNNING
            self.stop_event.clear()

        self.start_heartbeat_loop()

        while not self.stop_event.is_set():
            if self.pause_event.is_set():
                time.sleep(self.config.poll_interval_seconds)
                continue

            self.run_once(task_handler)
            time.sleep(self.config.poll_interval_seconds)

        with self._lock:
            self.status = WorkerClientStatus.STOPPED

        return WorkerResponse(
            ok=True,
            status="stopped",
            message="Worker stopped cleanly.",
            data={"device_id": self.config.device_id, "session_id": self.session_id},
        ).to_dict()

    def start_background_polling(self, task_handler: Callable[[WorkerTask], Any]) -> JSONDict:
        if self._poll_thread and self._poll_thread.is_alive():
            return WorkerResponse(
                ok=True,
                status="already_running",
                message="Background polling is already running.",
            ).to_dict()

        self.stop_event.clear()

        self._poll_thread = threading.Thread(
            target=self.run_forever,
            kwargs={"task_handler": task_handler, "auto_register": True},
            name=f"WorkerPoll-{self.config.device_id}",
            daemon=True,
        )
        self._poll_thread.start()

        return WorkerResponse(
            ok=True,
            status="background_polling_started",
            message="Background polling started.",
            data={"device_id": self.config.device_id},
        ).to_dict()

    def start_heartbeat_loop(self) -> JSONDict:
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return WorkerResponse(
                ok=True,
                status="already_running",
                message="Heartbeat loop is already running.",
            ).to_dict()

        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"WorkerHeartbeat-{self.config.device_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

        return WorkerResponse(
            ok=True,
            status="heartbeat_started",
            message="Heartbeat loop started.",
            data={"device_id": self.config.device_id},
        ).to_dict()

    def pause(self) -> JSONDict:
        self.pause_event.set()
        with self._lock:
            self.status = WorkerClientStatus.PAUSED

        audit_event = self.build_audit_event(
            action="worker.paused",
            risk_level=WorkerRiskLevel.LOW,
            details={"device_id": self.config.device_id},
        )
        self._safe_hook(self.audit_logger, audit_event)

        return WorkerResponse(
            ok=True,
            status="paused",
            message="Worker paused.",
            data={"device_id": self.config.device_id},
        ).to_dict()

    def resume(self) -> JSONDict:
        self.pause_event.clear()
        with self._lock:
            self.status = WorkerClientStatus.RUNNING

        audit_event = self.build_audit_event(
            action="worker.resumed",
            risk_level=WorkerRiskLevel.LOW,
            details={"device_id": self.config.device_id},
        )
        self._safe_hook(self.audit_logger, audit_event)

        return WorkerResponse(
            ok=True,
            status="running",
            message="Worker resumed.",
            data={"device_id": self.config.device_id},
        ).to_dict()

    def stop(self) -> JSONDict:
        self.stop_event.set()
        with self._lock:
            self.status = WorkerClientStatus.STOPPED

        audit_event = self.build_audit_event(
            action="worker.stopped",
            risk_level=WorkerRiskLevel.MEDIUM,
            details={"device_id": self.config.device_id},
        )
        self._safe_hook(self.audit_logger, audit_event)

        self._request(
            method="POST",
            path="/api/worker/stop",
            payload={
                "device_id": self.config.device_id,
                "user_id": self.config.user_id,
                "workspace_id": self.config.workspace_id,
                "session_id": self.session_id,
                "stopped_at": self.now(),
            },
        )

        return WorkerResponse(
            ok=True,
            status="stopped",
            message="Worker stop requested.",
            data={"device_id": self.config.device_id},
        ).to_dict()

    def build_audit_event(
        self,
        action: str,
        risk_level: WorkerRiskLevel,
        details: Optional[JSONDict] = None,
    ) -> JSONDict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "audit",
            "source": "apps.worker_nodes.common.worker_client",
            "module": self.MODULE_NAME,
            "action": action,
            "risk_level": risk_level.value,
            "device_id": self.config.device_id,
            "device_name": self.config.device_name,
            "session_id": self.session_id,
            "actor_user_id": self.config.user_id,
            "user_id": self.config.user_id,
            "workspace_id": self.config.workspace_id,
            "created_at": self.now(),
            "details": self._redact_sensitive_dict(details or {}),
        }

    def build_security_payload_for_task(self, task: WorkerTask) -> JSONDict:
        return {
            "security_request_id": str(uuid.uuid4()),
            "source": "apps.worker_nodes.common.worker_client",
            "module": self.MODULE_NAME,
            "recommended_agent": "security",
            "device_id": self.config.device_id,
            "session_id": self.session_id,
            "task_id": task.task_id,
            "request_id": task.request_id,
            "user_id": task.user_id,
            "workspace_id": task.workspace_id,
            "agent": task.agent,
            "action": task.action,
            "action_type": task.action_type,
            "risk_level": task.risk_level,
            "requires_security_approval": task.requires_security_approval,
            "security_approval_id": task.security_approval_id,
            "permissions_required": list(task.permissions_required),
            "created_at": self.now(),
            "reason": "Worker task validation and execution safety check.",
        }

    def build_memory_payload(self, task: WorkerTask, summary: str, payload: JSONDict) -> JSONDict:
        return {
            "memory_event_id": str(uuid.uuid4()),
            "source": "apps.worker_nodes.common.worker_client",
            "module": self.MODULE_NAME,
            "recommended_agent": "memory",
            "memory_scope": "workspace",
            "safe_to_store": True,
            "summary": summary,
            "device_id": self.config.device_id,
            "task_id": task.task_id,
            "request_id": task.request_id,
            "user_id": task.user_id,
            "workspace_id": task.workspace_id,
            "created_at": self.now(),
            "payload": self._redact_sensitive_dict(payload),
        }

    def build_verification_payload(
        self,
        task: WorkerTask,
        status: WorkerTaskStatus,
        result: JSONDict,
        errors: List[JSONDict],
    ) -> JSONDict:
        return {
            "verification_id": str(uuid.uuid4()),
            "source": "apps.worker_nodes.common.worker_client",
            "module": self.MODULE_NAME,
            "recommended_agent": "verification",
            "status": status.value,
            "device_id": self.config.device_id,
            "task_id": task.task_id,
            "request_id": task.request_id,
            "user_id": task.user_id,
            "workspace_id": task.workspace_id,
            "created_at": self.now(),
            "checks": {
                "user_id_present": bool(task.user_id),
                "workspace_id_present": bool(task.workspace_id),
                "task_matches_worker_user": task.user_id == self.config.user_id,
                "task_matches_worker_workspace": task.workspace_id == self.config.workspace_id,
                "agent_allowed": task.agent in self.config.allowed_agents,
                "action_type_allowed": task.action_type in self.config.allowed_action_types,
                "audit_payload_prepared": True,
                "security_payload_prepared": True,
                "memory_payload_compatible": True,
            },
            "result": self._redact_sensitive_dict(result),
            "errors": errors,
        }

    def _heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.send_heartbeat()
            except Exception as exc:
                self._log(f"Heartbeat failed safely: {self._safe_error(exc).get('message')}")
            time.sleep(self.config.heartbeat_interval_seconds)

    def _send_action_report(self, report: WorkerActionReport) -> WorkerResponse:
        response = self._request(
            method="POST",
            path="/api/worker/tasks/report",
            payload=report.to_dict(),
        )

        if response.ok:
            return WorkerResponse(
                ok=True,
                status="report_sent",
                message="Worker action report sent.",
                data={
                    "task_id": report.task_id,
                    "backend_response": response.data,
                },
            )

        return response

    def _request(self, method: str, path: str, payload: Optional[JSONDict] = None) -> WorkerResponse:
        url = urljoin(self.config.backend_url, path.lstrip("/"))
        request_id = str(uuid.uuid4())

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Worker-Device-Id": self.config.device_id,
            "X-Worker-Session-Id": self.session_id,
            "X-User-Id": self.config.user_id,
            "X-Workspace-Id": self.config.workspace_id,
            "X-Request-Id": request_id,
        }

        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"

        safe_payload = payload or {}

        try:
            if requests is not None and self.config.use_requests_if_available:
                return self._request_with_requests(
                    method=method,
                    url=url,
                    headers=headers,
                    payload=safe_payload,
                    request_id=request_id,
                )

            return self._request_with_urllib(
                method=method,
                url=url,
                headers=headers,
                payload=safe_payload,
                request_id=request_id,
            )

        except Exception as exc:
            return WorkerResponse(
                ok=False,
                status="request_failed",
                message="Worker backend request failed safely.",
                errors=[self._safe_error(exc)],
                request_id=request_id,
            )

    def _request_with_requests(
        self,
        method: str,
        url: str,
        headers: JSONDict,
        payload: JSONDict,
        request_id: str,
    ) -> WorkerResponse:
        assert requests is not None

        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=payload,
            timeout=self.config.request_timeout_seconds,
            verify=self.config.verify_tls,
        )

        data = self._parse_response_text(response.text)

        if 200 <= response.status_code < 300:
            return WorkerResponse(
                ok=True,
                status="ok",
                message="Backend request completed.",
                data=data,
                request_id=request_id,
            )

        return WorkerResponse(
            ok=False,
            status=f"http_{response.status_code}",
            message="Backend returned an error response.",
            data=data if isinstance(data, dict) else {},
            errors=[
                {
                    "error": "backend_error",
                    "status_code": response.status_code,
                    "detail": self._redact_text(response.text),
                }
            ],
            request_id=request_id,
        )

    def _request_with_urllib(
        self,
        method: str,
        url: str,
        headers: JSONDict,
        payload: JSONDict,
        request_id: str,
    ) -> WorkerResponse:
        body = json.dumps(payload).encode("utf-8")
        request = Request(url=url, data=body, headers=headers, method=method.upper())

        try:
            with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
                data = self._parse_response_text(raw)
                return WorkerResponse(
                    ok=True,
                    status="ok",
                    message="Backend request completed.",
                    data=data,
                    request_id=request_id,
                )

        except HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            data = self._parse_response_text(raw)
            return WorkerResponse(
                ok=False,
                status=f"http_{exc.code}",
                message="Backend returned an error response.",
                data=data if isinstance(data, dict) else {},
                errors=[
                    {
                        "error": "backend_error",
                        "status_code": exc.code,
                        "detail": self._redact_text(raw or str(exc)),
                    }
                ],
                request_id=request_id,
            )

        except URLError as exc:
            return WorkerResponse(
                ok=False,
                status="connection_error",
                message="Could not connect to backend.",
                errors=[self._safe_error(exc)],
                request_id=request_id,
            )

    def _can_contact_backend(self) -> bool:
        validation = self.validate_config()
        return validation.ok

    def _can_poll(self) -> bool:
        if not self._can_contact_backend():
            return False
        if self.config.allow_unregistered_polling:
            return True
        return self.status in {
            WorkerClientStatus.REGISTERED,
            WorkerClientStatus.RUNNING,
            WorkerClientStatus.PAUSED,
        }

    @staticmethod
    def _default_capabilities() -> List[str]:
        system = platform.system().lower()
        capabilities = [
            "heartbeat",
            "device_registration",
            "task_polling",
            "safe_action_reports",
            "pause_resume_stop",
            "user_workspace_isolation",
        ]

        if system == "windows":
            capabilities.extend(["windows_worker_compatible", "local_app_detection"])
        elif system == "linux":
            capabilities.extend(["linux_worker_compatible"])
        elif system == "darwin":
            capabilities.extend(["mac_worker_compatible"])

        return capabilities

    def _normalize_handler_result(self, value: Any) -> JSONDict:
        if isinstance(value, WorkerActionReport):
            return value.to_dict()

        if isinstance(value, WorkerResponse):
            return value.to_dict()

        if isinstance(value, Mapping):
            copied = dict(value)
            if "data" not in copied:
                copied = {"status": WorkerTaskStatus.COMPLETED.value, "data": copied}
            return copied

        return {
            "status": WorkerTaskStatus.COMPLETED.value,
            "data": {"value": value},
        }

    def _risk_from_task(self, task: WorkerTask) -> WorkerRiskLevel:
        try:
            return WorkerRiskLevel(task.risk_level)
        except Exception:
            return WorkerRiskLevel.MEDIUM

    @staticmethod
    def _security_denied(decision: Any) -> bool:
        if decision is None:
            return False

        if isinstance(decision, Mapping):
            status = str(decision.get("status", "")).lower()
            approved = decision.get("approved")
            allowed = decision.get("allowed")

            if status in {"denied", "rejected", "blocked"}:
                return True
            if approved is False:
                return True
            if allowed is False:
                return True

        return False

    def _safe_hook(self, hook: Optional[Callable[[JSONDict], Any]], payload: JSONDict) -> Any:
        if hook is None:
            return None

        try:
            return hook(self._redact_sensitive_dict(payload))
        except Exception as exc:
            self._log(f"Hook failed safely: {self._safe_error(exc).get('message')}")
            return {
                "hook_failed": True,
                "error": self._safe_error(exc),
            }

    @staticmethod
    def _parse_response_text(text: str) -> JSONDict:
        if not text:
            return {}

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except Exception:
            return {"raw": text[:1000]}

    def _safe_error(self, error: Any) -> JSONDict:
        if isinstance(error, list):
            return {
                "error": "multiple_errors",
                "message": self._redact_text(json.dumps(error, default=str))[:2000],
            }

        if isinstance(error, Mapping):
            return self._redact_sensitive_dict(dict(error))

        if isinstance(error, BaseException):
            return {
                "error": error.__class__.__name__,
                "message": self._redact_text(str(error)),
                "trace": self._redact_text(traceback.format_exc(limit=3)),
            }

        return {
            "error": "error",
            "message": self._redact_text(str(error)),
        }

    @classmethod
    def _redact_sensitive_dict(cls, data: JSONDict) -> JSONDict:
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_token",
            "api_key",
            "apikey",
            "authorization",
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
            "cookie",
            "session_cookie",
        }

        def redact(value: Any) -> Any:
            if isinstance(value, Mapping):
                redacted: JSONDict = {}
                for key, nested_value in value.items():
                    key_str = str(key)
                    if key_str.lower() in sensitive_keys:
                        redacted[key_str] = "[redacted]"
                    else:
                        redacted[key_str] = redact(nested_value)
                return redacted

            if isinstance(value, list):
                return [redact(item) for item in value]

            if isinstance(value, tuple):
                return tuple(redact(item) for item in value)

            if isinstance(value, str):
                return cls._redact_text(value)

            return value

        return redact(dict(data))

    @staticmethod
    def _redact_text(text: str) -> str:
        if not text:
            return ""

        redacted = str(text)
        blocked_terms = [
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
            "cookie",
        ]

        for term in blocked_terms:
            redacted = redacted.replace(term, "[redacted]")
            redacted = redacted.replace(term.upper(), "[redacted]")
            redacted = redacted.replace(term.title(), "[redacted]")

        return redacted

    @staticmethod
    def _safe_json(value: Any) -> Any:
        try:
            json.dumps(value, default=str)
            return value
        except Exception:
            return str(value)

    def _log(self, message: str) -> None:
        safe_message = self._redact_text(message)
        if self.logger:
            try:
                self.logger(safe_message)
                return
            except Exception:
                return


def create_worker_client_from_env() -> WorkerClient:
    """
    Convenience factory for worker node entrypoints.
    """
    return WorkerClient(config=WorkerClientConfig())


def default_task_handler(task: WorkerTask) -> JSONDict:
    """
    Safe default task handler.

    Real platform-specific workers should inject their own handler.
    This handler does not execute device/system actions. It returns a safe
    structured response so the worker can be tested without dangerous behavior.
    """
    return {
        "status": WorkerTaskStatus.COMPLETED.value,
        "data": {
            "task_id": task.task_id,
            "agent": task.agent,
            "action": task.action,
            "message": "Default worker handler received task safely. No device action was executed.",
        },
    }


__all__ = [
    "WorkerClient",
    "WorkerClientConfig",
    "WorkerIdentity",
    "WorkerTask",
    "WorkerResponse",
    "WorkerActionReport",
    "WorkerClientStatus",
    "WorkerTaskStatus",
    "WorkerRiskLevel",
    "WorkerActionType",
    "create_worker_client_from_env",
    "default_task_handler",
]