"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Device Worker Model: Windows App Control
File: apps/worker_nodes/windows/app_control.py

Purpose:
    Open, focus, list, and close Windows desktop applications safely from a
    worker node while preserving SaaS isolation, task context, permission checks,
    auditability, Security Agent routing, Verification Agent payloads, and
    Memory Agent compatible summaries.

Design goals:
    - Import safely on non-Windows machines.
    - Do not require pywin32/psutil, but use them when installed.
    - Never execute arbitrary shell strings from user input.
    - Every task requires user_id and workspace_id.
    - Every state-changing action returns audit/security/verification payloads.
    - Dangerous app/process actions are blocked or routed to Security Agent.
    - Worker includes heartbeat, registration, permission, stop/resume,
      and safe action reporting helpers.

Security note:
    This file intentionally avoids raw shell=True execution. App launching uses
    known aliases, explicit paths, or Windows shell open behavior through
    subprocess/os.startfile where available.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None


try:
    import win32con  # type: ignore
    import win32gui  # type: ignore
    import win32process  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    win32con = None
    win32gui = None
    win32process = None


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Return current UTC timestamp as ISO string."""
    return utc_now().isoformat()


def generate_id(prefix: str = "id") -> str:
    """Generate a portable ID string."""
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_text(value: Any, *, max_length: int = 500) -> str:
    """Normalize text safely."""
    if value is None:
        return ""
    cleaned = " ".join(str(value).strip().split())
    return cleaned[:max_length]


def stable_hash(payload: Mapping[str, Any]) -> str:
    """Create deterministic hash from a safe JSON payload."""
    raw = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def json_safe(value: Any, *, depth: int = 0) -> Any:
    """Convert arbitrary values into JSON-safe sanitized values."""
    if depth > 8:
        return "[MAX_DEPTH_REACHED]"

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, enum.Enum):
        return value.value

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    if dataclasses.is_dataclass(value):
        return json_safe(dataclasses.asdict(value), depth=depth + 1)

    if isinstance(value, Mapping):
        blocked = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "session",
            "private_key",
            "access_token",
            "refresh_token",
        }
        output: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower().replace("-", "_").replace(" ", "_")
            if any(term in lowered for term in blocked):
                output[key_text] = "[REDACTED]"
            else:
                output[key_text] = json_safe(item, depth=depth + 1)
        return output

    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item, depth=depth + 1) for item in value]

    return str(value)


class AppAction(str, enum.Enum):
    """Supported app-control actions."""

    OPEN = "open"
    FOCUS = "focus"
    CLOSE = "close"
    LIST_WINDOWS = "list_windows"
    LIST_PROCESSES = "list_processes"
    HEARTBEAT = "heartbeat"
    REGISTER_DEVICE = "register_device"
    STOP = "stop"
    RESUME = "resume"


class ActionStatus(str, enum.Enum):
    """Worker action status."""

    SUCCESS = "success"
    ERROR = "error"
    DENIED = "denied"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"


class AppRiskLevel(str, enum.Enum):
    """Risk level for app-control actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkerState(str, enum.Enum):
    """Local worker state."""

    READY = "ready"
    PAUSED = "paused"
    STOPPED = "stopped"
    BUSY = "busy"
    ERROR = "error"


class CloseMode(str, enum.Enum):
    """Close behavior."""

    GRACEFUL = "graceful"
    FORCE = "force"


class WindowMatchMode(str, enum.Enum):
    """Window matching strategy."""

    CONTAINS = "contains"
    EXACT = "exact"
    STARTS_WITH = "starts_with"
    REGEX = "regex"


@dataclasses.dataclass(frozen=True)
class TaskContext:
    """
    User/workspace/task context required for every device action.
    """

    user_id: str
    workspace_id: str
    task_id: str = ""
    requested_by: str = ""
    role: str = "owner"
    plan: str = "pro"
    agent_name: str = "SystemAgent"
    correlation_id: str = ""

    def validate(self) -> "TaskContext":
        safe_user_id = normalize_text(self.user_id, max_length=128)
        safe_workspace_id = normalize_text(self.workspace_id, max_length=128)

        if not safe_user_id:
            raise ValueError("user_id is required for Windows app control.")
        if not safe_workspace_id:
            raise ValueError("workspace_id is required for Windows app control.")

        return TaskContext(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            task_id=normalize_text(self.task_id, max_length=128) or generate_id("task"),
            requested_by=normalize_text(self.requested_by, max_length=128) or safe_user_id,
            role=normalize_text(self.role, max_length=80) or "owner",
            plan=normalize_text(self.plan, max_length=80) or "pro",
            agent_name=normalize_text(self.agent_name, max_length=120) or "SystemAgent",
            correlation_id=normalize_text(self.correlation_id, max_length=128) or generate_id("corr"),
        )


@dataclasses.dataclass(frozen=True)
class AppTarget:
    """
    Resolved application target.
    """

    requested_name: str
    executable: Optional[str] = None
    command: Optional[List[str]] = None
    app_user_model_id: Optional[str] = None
    process_names: Tuple[str, ...] = ()
    window_keywords: Tuple[str, ...] = ()
    working_directory: Optional[str] = None
    risk_level: AppRiskLevel = AppRiskLevel.LOW
    source: str = "alias"


@dataclasses.dataclass(frozen=True)
class WindowInfo:
    """
    Snapshot of a visible window.
    """

    hwnd: int
    title: str
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    is_visible: bool = True
    is_minimized: bool = False


@dataclasses.dataclass
class WorkerRegistration:
    """
    Device worker registration payload.
    """

    device_id: str
    worker_id: str
    hostname: str
    os_name: str
    os_version: str
    python_version: str
    supported_actions: List[str]
    user_id: str
    workspace_id: str
    registered_at: str
    metadata: Dict[str, Any]


class AppControl:
    """
    Windows application controller for William/Jarvis worker nodes.

    Main methods:
        - open_app()
        - focus_app()
        - close_app()
        - list_windows()
        - list_processes()
        - heartbeat()
        - register_device()
        - poll_task()
        - stop()
        - resume()

    The class works best on Windows. On non-Windows systems it imports safely and
    returns structured unsupported responses instead of crashing.
    """

    DEFAULT_ALLOWED_ROLES = {
        "owner",
        "admin",
        "manager",
        "device_admin",
        "system_operator",
        "developer",
    }

    DEFAULT_ALLOWED_PLANS = {
        "pro",
        "business",
        "enterprise",
        "agency",
        "developer",
        "internal",
    }

    SYSTEM_CRITICAL_PROCESSES = {
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
        "system",
        "registry",
        "dwm.exe",
        "taskhostw.exe",
        "fontdrvhost.exe",
        "securityhealthservice.exe",
    }

    DEFAULT_APP_ALIASES: Dict[str, Dict[str, Any]] = {
        "notepad": {
            "command": ["notepad.exe"],
            "process_names": ["notepad.exe"],
            "window_keywords": ["notepad"],
            "risk_level": "low",
        },
        "calculator": {
            "command": ["calc.exe"],
            "process_names": ["calculatorapp.exe", "calc.exe"],
            "window_keywords": ["calculator"],
            "risk_level": "low",
        },
        "paint": {
            "command": ["mspaint.exe"],
            "process_names": ["mspaint.exe"],
            "window_keywords": ["paint"],
            "risk_level": "low",
        },
        "wordpad": {
            "command": ["write.exe"],
            "process_names": ["write.exe", "wordpad.exe"],
            "window_keywords": ["wordpad"],
            "risk_level": "low",
        },
        "explorer": {
            "command": ["explorer.exe"],
            "process_names": ["explorer.exe"],
            "window_keywords": ["file explorer", "explorer"],
            "risk_level": "medium",
        },
        "cmd": {
            "command": ["cmd.exe"],
            "process_names": ["cmd.exe"],
            "window_keywords": ["command prompt"],
            "risk_level": "high",
        },
        "powershell": {
            "command": ["powershell.exe"],
            "process_names": ["powershell.exe", "pwsh.exe"],
            "window_keywords": ["powershell"],
            "risk_level": "high",
        },
        "terminal": {
            "command": ["wt.exe"],
            "process_names": ["windowsterminal.exe", "wt.exe"],
            "window_keywords": ["terminal"],
            "risk_level": "high",
        },
        "microsoft store": {
            "command": ["cmd.exe", "/c", "start", "", "ms-windows-store:"],
            "process_names": ["winstore.app.exe", "applicationframehost.exe"],
            "window_keywords": ["microsoft store", "store"],
            "risk_level": "medium",
        },
        "store": {
            "command": ["cmd.exe", "/c", "start", "", "ms-windows-store:"],
            "process_names": ["winstore.app.exe", "applicationframehost.exe"],
            "window_keywords": ["microsoft store", "store"],
            "risk_level": "medium",
        },
        "settings": {
            "command": ["cmd.exe", "/c", "start", "", "ms-settings:"],
            "process_names": ["systemsettings.exe", "applicationframehost.exe"],
            "window_keywords": ["settings"],
            "risk_level": "medium",
        },
        "control panel": {
            "command": ["control.exe"],
            "process_names": ["control.exe"],
            "window_keywords": ["control panel"],
            "risk_level": "medium",
        },
        "chrome": {
            "command": ["cmd.exe", "/c", "start", "", "chrome"],
            "process_names": ["chrome.exe"],
            "window_keywords": ["chrome", "google chrome"],
            "risk_level": "medium",
        },
        "edge": {
            "command": ["cmd.exe", "/c", "start", "", "msedge"],
            "process_names": ["msedge.exe"],
            "window_keywords": ["edge", "microsoft edge"],
            "risk_level": "medium",
        },
        "firefox": {
            "command": ["cmd.exe", "/c", "start", "", "firefox"],
            "process_names": ["firefox.exe"],
            "window_keywords": ["firefox"],
            "risk_level": "medium",
        },
        "vscode": {
            "command": ["cmd.exe", "/c", "start", "", "code"],
            "process_names": ["code.exe"],
            "window_keywords": ["visual studio code", "vscode"],
            "risk_level": "medium",
        },
        "visual studio code": {
            "command": ["cmd.exe", "/c", "start", "", "code"],
            "process_names": ["code.exe"],
            "window_keywords": ["visual studio code", "vscode"],
            "risk_level": "medium",
        },
        "task manager": {
            "command": ["taskmgr.exe"],
            "process_names": ["taskmgr.exe"],
            "window_keywords": ["task manager"],
            "risk_level": "high",
        },
    }

    def __init__(
        self,
        *,
        device_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        allowed_roles: Optional[Iterable[str]] = None,
        allowed_plans: Optional[Iterable[str]] = None,
        app_aliases: Optional[Mapping[str, Mapping[str, Any]]] = None,
        allow_direct_paths: Optional[bool] = None,
        allow_force_close: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        report_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.device_id = normalize_text(device_id, max_length=128) or os.getenv("WILLIAM_DEVICE_ID") or generate_id("device")
        self.worker_id = normalize_text(worker_id, max_length=128) or os.getenv("WILLIAM_WORKER_ID") or generate_id("worker")

        self.allowed_roles = {
            normalize_text(role).lower()
            for role in (allowed_roles or self._csv_env("WILLIAM_APP_CONTROL_ALLOWED_ROLES") or self.DEFAULT_ALLOWED_ROLES)
            if normalize_text(role)
        }

        self.allowed_plans = {
            normalize_text(plan).lower()
            for plan in (allowed_plans or self._csv_env("WILLIAM_APP_CONTROL_ALLOWED_PLANS") or self.DEFAULT_ALLOWED_PLANS)
            if normalize_text(plan)
        }

        self.allow_direct_paths = self._env_bool("WILLIAM_APP_CONTROL_ALLOW_DIRECT_PATHS", False) if allow_direct_paths is None else bool(allow_direct_paths)
        self.allow_force_close = self._env_bool("WILLIAM_APP_CONTROL_ALLOW_FORCE_CLOSE", False) if allow_force_close is None else bool(allow_force_close)
        self.dry_run = self._env_bool("WILLIAM_APP_CONTROL_DRY_RUN", False) if dry_run is None else bool(dry_run)

        self.audit_sink = audit_sink
        self.report_sink = report_sink

        self._state = WorkerState.READY
        self._state_lock = threading.RLock()
        self._last_heartbeat_at: Optional[datetime] = None
        self._registered_context: Optional[TaskContext] = None

        merged_aliases = dict(self.DEFAULT_APP_ALIASES)
        merged_aliases.update(self._load_aliases_from_env())
        if app_aliases:
            for key, value in app_aliases.items():
                merged_aliases[normalize_text(key).lower()] = dict(value)

        self.app_aliases = merged_aliases

    @staticmethod
    def _csv_env(name: str) -> List[str]:
        raw = os.getenv(name, "")
        if not raw.strip():
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _load_aliases_from_env(self) -> Dict[str, Dict[str, Any]]:
        """
        Load custom aliases from WILLIAM_APP_CONTROL_ALIASES_JSON.

        Expected format:
            {
                "my app": {
                    "command": ["C:/Path/App.exe"],
                    "process_names": ["App.exe"],
                    "window_keywords": ["My App"],
                    "risk_level": "medium"
                }
            }
        """
        raw = os.getenv("WILLIAM_APP_CONTROL_ALIASES_JSON", "").strip()
        if not raw:
            return {}

        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                return {}
            output: Dict[str, Dict[str, Any]] = {}
            for key, value in parsed.items():
                if isinstance(value, Mapping):
                    output[normalize_text(key).lower()] = dict(json_safe(value))
            return output
        except Exception:
            return {}

    @property
    def is_windows(self) -> bool:
        """Return whether current OS is Windows."""
        return platform.system().lower() == "windows"

    @property
    def state(self) -> WorkerState:
        """Return current worker state."""
        with self._state_lock:
            return self._state

    def register_device(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: str = "owner",
        plan: str = "pro",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register this local worker device for a user/workspace context.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("registration"),
            agent_name="DeviceWorker",
        ).validate()

        access = self._check_permission(context=context, action=AppAction.REGISTER_DEVICE)
        if not access["allowed"]:
            return self._result(
                status=ActionStatus.DENIED,
                action=AppAction.REGISTER_DEVICE,
                context=context,
                message=access["reason"],
                data={"access": access},
            )

        registration = WorkerRegistration(
            device_id=self.device_id,
            worker_id=self.worker_id,
            hostname=socket.gethostname(),
            os_name=platform.system(),
            os_version=platform.version(),
            python_version=sys.version.split()[0],
            supported_actions=[item.value for item in AppAction],
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            registered_at=iso_now(),
            metadata=dict(json_safe(metadata or {})),
        )

        self._registered_context = context
        with self._state_lock:
            if self._state == WorkerState.STOPPED:
                self._state = WorkerState.READY

        return self._result(
            status=ActionStatus.SUCCESS,
            action=AppAction.REGISTER_DEVICE,
            context=context,
            message="Windows app-control worker registered.",
            data={"registration": dataclasses.asdict(registration)},
        )

    def heartbeat(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        """
        Return worker heartbeat payload.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("heartbeat"),
            agent_name="DeviceWorker",
        ).validate()

        access = self._check_permission(context=context, action=AppAction.HEARTBEAT)
        if not access["allowed"]:
            return self._result(
                status=ActionStatus.DENIED,
                action=AppAction.HEARTBEAT,
                context=context,
                message=access["reason"],
                data={"access": access},
            )

        self._last_heartbeat_at = utc_now()

        return self._result(
            status=ActionStatus.SUCCESS,
            action=AppAction.HEARTBEAT,
            context=context,
            message="Worker heartbeat healthy.",
            data={
                "device_id": self.device_id,
                "worker_id": self.worker_id,
                "state": self.state.value,
                "is_windows": self.is_windows,
                "hostname": socket.gethostname(),
                "last_heartbeat_at": self._last_heartbeat_at.isoformat(),
                "pywin32_available": bool(win32gui and win32process and win32con),
                "psutil_available": bool(psutil),
                "dry_run": self.dry_run,
            },
        )

    def stop(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: str = "owner",
        plan: str = "pro",
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pause local worker from executing app-control actions.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("stop"),
            agent_name="DeviceWorker",
        ).validate()

        access = self._check_permission(context=context, action=AppAction.STOP)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.STOP, context, access["reason"], {"access": access})

        with self._state_lock:
            self._state = WorkerState.STOPPED

        return self._result(
            ActionStatus.SUCCESS,
            AppAction.STOP,
            context,
            "Worker stopped safely.",
            {"reason": normalize_text(reason) or None, "state": self.state.value},
        )

    def resume(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: str = "owner",
        plan: str = "pro",
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resume local worker after stop/pause.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("resume"),
            agent_name="DeviceWorker",
        ).validate()

        access = self._check_permission(context=context, action=AppAction.RESUME)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.RESUME, context, access["reason"], {"access": access})

        with self._state_lock:
            self._state = WorkerState.READY

        return self._result(
            ActionStatus.SUCCESS,
            AppAction.RESUME,
            context,
            "Worker resumed safely.",
            {"reason": normalize_text(reason) or None, "state": self.state.value},
        )

    def open_app(
        self,
        app_name: str,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
        agent_name: str = "SystemAgent",
        arguments: Optional[Sequence[str]] = None,
        wait_seconds: float = 1.0,
        focus_after_open: bool = True,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Open a Windows application by alias, executable, Microsoft URI, or approved path.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or generate_id("task"),
            requested_by=requested_by or user_id,
            role=role,
            plan=plan,
            agent_name=agent_name,
        ).validate()

        if not self._is_ready():
            return self._result(
                ActionStatus.SKIPPED,
                AppAction.OPEN,
                context,
                f"Worker is {self.state.value}; action skipped.",
                {"worker_state": self.state.value},
            )

        if not self.is_windows:
            return self._unsupported_result(AppAction.OPEN, context)

        access = self._check_permission(context=context, action=AppAction.OPEN)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.OPEN, context, access["reason"], {"access": access})

        try:
            target = self.resolve_app_target(app_name, arguments=arguments)
        except Exception as exc:
            return self._error_result(AppAction.OPEN, context, exc)

        security = self._security_gate(
            context=context,
            action=AppAction.OPEN,
            target=target,
            security_approved=security_approved,
        )
        if not security["allowed"]:
            return self._result(
                ActionStatus.SECURITY_REVIEW_REQUIRED,
                AppAction.OPEN,
                context,
                security["reason"],
                {"security": security, "target": dataclasses.asdict(target)},
            )

        if self.dry_run:
            return self._result(
                ActionStatus.SUCCESS,
                AppAction.OPEN,
                context,
                "Dry run: app open simulated.",
                {"target": dataclasses.asdict(target), "dry_run": True},
            )

        with self._state_lock:
            self._state = WorkerState.BUSY

        try:
            command = self._build_launch_command(target)
            if not command:
                raise ValueError("No launch command could be resolved for this app.")

            process = subprocess.Popen(
                command,
                cwd=target.working_directory or None,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
            )

            if wait_seconds > 0:
                time.sleep(min(float(wait_seconds), 10.0))

            focus_result: Optional[Dict[str, Any]] = None
            if focus_after_open:
                focus_result = self.focus_app(
                    app_name,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    task_id=context.task_id,
                    requested_by=context.requested_by,
                    role=context.role,
                    plan=context.plan,
                    agent_name=context.agent_name,
                    security_approved=security_approved,
                    emit_report=False,
                )

            return self._result(
                ActionStatus.SUCCESS,
                AppAction.OPEN,
                context,
                "Application opened.",
                {
                    "target": dataclasses.asdict(target),
                    "pid": process.pid,
                    "command": command,
                    "focus_result": focus_result,
                },
            )
        except Exception as exc:
            return self._error_result(AppAction.OPEN, context, exc)
        finally:
            with self._state_lock:
                if self._state == WorkerState.BUSY:
                    self._state = WorkerState.READY

    def focus_app(
        self,
        app_name: str,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
        agent_name: str = "SystemAgent",
        match_mode: WindowMatchMode = WindowMatchMode.CONTAINS,
        security_approved: bool = False,
        emit_report: bool = True,
    ) -> Dict[str, Any]:
        """
        Focus a visible window matching an app alias/title/process.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or generate_id("task"),
            requested_by=requested_by or user_id,
            role=role,
            plan=plan,
            agent_name=agent_name,
        ).validate()

        if not self._is_ready() and self.state != WorkerState.BUSY:
            return self._result(
                ActionStatus.SKIPPED,
                AppAction.FOCUS,
                context,
                f"Worker is {self.state.value}; action skipped.",
                {"worker_state": self.state.value},
                emit_report=emit_report,
            )

        if not self.is_windows:
            return self._unsupported_result(AppAction.FOCUS, context, emit_report=emit_report)

        access = self._check_permission(context=context, action=AppAction.FOCUS)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.FOCUS, context, access["reason"], {"access": access}, emit_report=emit_report)

        try:
            target = self.resolve_app_target(app_name)
        except Exception as exc:
            return self._error_result(AppAction.FOCUS, context, exc, emit_report=emit_report)

        security = self._security_gate(
            context=context,
            action=AppAction.FOCUS,
            target=target,
            security_approved=security_approved,
        )
        if not security["allowed"]:
            return self._result(
                ActionStatus.SECURITY_REVIEW_REQUIRED,
                AppAction.FOCUS,
                context,
                security["reason"],
                {"security": security, "target": dataclasses.asdict(target)},
                emit_report=emit_report,
            )

        if not win32gui:
            return self._result(
                ActionStatus.UNSUPPORTED,
                AppAction.FOCUS,
                context,
                "Focusing windows requires pywin32 on Windows.",
                {"dependency": "pywin32"},
                emit_report=emit_report,
            )

        try:
            windows = self._find_matching_windows(target, match_mode=match_mode)
            if not windows:
                return self._result(
                    ActionStatus.NOT_FOUND,
                    AppAction.FOCUS,
                    context,
                    "No matching visible window found.",
                    {"target": dataclasses.asdict(target), "windows_checked": len(self._enumerate_windows())},
                    emit_report=emit_report,
                )

            selected = windows[0]

            if self.dry_run:
                return self._result(
                    ActionStatus.SUCCESS,
                    AppAction.FOCUS,
                    context,
                    "Dry run: app focus simulated.",
                    {"window": dataclasses.asdict(selected), "dry_run": True},
                    emit_report=emit_report,
                )

            self._focus_window(selected.hwnd)

            return self._result(
                ActionStatus.SUCCESS,
                AppAction.FOCUS,
                context,
                "Application window focused.",
                {"window": dataclasses.asdict(selected), "matches": [dataclasses.asdict(w) for w in windows[:10]]},
                emit_report=emit_report,
            )
        except Exception as exc:
            return self._error_result(AppAction.FOCUS, context, exc, emit_report=emit_report)

    def close_app(
        self,
        app_name: str,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
        agent_name: str = "SystemAgent",
        close_mode: CloseMode = CloseMode.GRACEFUL,
        security_approved: bool = False,
        timeout_seconds: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Close an app by window/process using graceful close by default.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or generate_id("task"),
            requested_by=requested_by or user_id,
            role=role,
            plan=plan,
            agent_name=agent_name,
        ).validate()

        if not self._is_ready():
            return self._result(
                ActionStatus.SKIPPED,
                AppAction.CLOSE,
                context,
                f"Worker is {self.state.value}; action skipped.",
                {"worker_state": self.state.value},
            )

        if not self.is_windows:
            return self._unsupported_result(AppAction.CLOSE, context)

        access = self._check_permission(context=context, action=AppAction.CLOSE)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.CLOSE, context, access["reason"], {"access": access})

        try:
            target = self.resolve_app_target(app_name)
            close_mode = self._coerce_close_mode(close_mode)
        except Exception as exc:
            return self._error_result(AppAction.CLOSE, context, exc)

        if self._is_system_critical_target(target):
            return self._result(
                ActionStatus.DENIED,
                AppAction.CLOSE,
                context,
                "Closing this system-critical process is blocked.",
                {"target": dataclasses.asdict(target)},
            )

        security = self._security_gate(
            context=context,
            action=AppAction.CLOSE,
            target=target,
            security_approved=security_approved,
            close_mode=close_mode,
        )
        if not security["allowed"]:
            return self._result(
                ActionStatus.SECURITY_REVIEW_REQUIRED,
                AppAction.CLOSE,
                context,
                security["reason"],
                {"security": security, "target": dataclasses.asdict(target), "close_mode": close_mode.value},
            )

        if close_mode == CloseMode.FORCE and not self.allow_force_close:
            return self._result(
                ActionStatus.DENIED,
                AppAction.CLOSE,
                context,
                "Force close is disabled by worker policy.",
                {"allow_force_close": self.allow_force_close},
            )

        if self.dry_run:
            return self._result(
                ActionStatus.SUCCESS,
                AppAction.CLOSE,
                context,
                "Dry run: app close simulated.",
                {"target": dataclasses.asdict(target), "close_mode": close_mode.value, "dry_run": True},
            )

        with self._state_lock:
            self._state = WorkerState.BUSY

        try:
            closed_windows: List[Dict[str, Any]] = []
            killed_processes: List[Dict[str, Any]] = []

            if close_mode == CloseMode.GRACEFUL and win32gui:
                windows = self._find_matching_windows(target, match_mode=WindowMatchMode.CONTAINS)
                for window in windows:
                    try:
                        win32gui.PostMessage(window.hwnd, win32con.WM_CLOSE, 0, 0)
                        closed_windows.append(dataclasses.asdict(window))
                    except Exception as exc:
                        closed_windows.append({**dataclasses.asdict(window), "error": str(exc)})

                if windows and timeout_seconds > 0:
                    time.sleep(min(float(timeout_seconds), 20.0))

            remaining = self._find_matching_processes(target)
            if close_mode == CloseMode.FORCE or (close_mode == CloseMode.GRACEFUL and remaining and not closed_windows):
                for proc_info in remaining:
                    process_name = normalize_text(proc_info.get("name")).lower()
                    if process_name in self.SYSTEM_CRITICAL_PROCESSES:
                        continue
                    kill_result = self._terminate_process(proc_info, force=close_mode == CloseMode.FORCE)
                    killed_processes.append(kill_result)

            status = ActionStatus.SUCCESS if closed_windows or killed_processes else ActionStatus.NOT_FOUND
            message = "Application close requested." if status == ActionStatus.SUCCESS else "No matching app process/window found."

            return self._result(
                status,
                AppAction.CLOSE,
                context,
                message,
                {
                    "target": dataclasses.asdict(target),
                    "close_mode": close_mode.value,
                    "closed_windows": closed_windows,
                    "process_results": killed_processes,
                },
            )
        except Exception as exc:
            return self._error_result(AppAction.CLOSE, context, exc)
        finally:
            with self._state_lock:
                if self._state == WorkerState.BUSY:
                    self._state = WorkerState.READY

    def list_windows(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        """
        List visible Windows app windows.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or generate_id("task"),
            requested_by=requested_by or user_id,
            role=role,
            plan=plan,
            agent_name="DeviceWorker",
        ).validate()

        if not self.is_windows:
            return self._unsupported_result(AppAction.LIST_WINDOWS, context)

        access = self._check_permission(context=context, action=AppAction.LIST_WINDOWS)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.LIST_WINDOWS, context, access["reason"], {"access": access})

        if not win32gui:
            return self._result(
                ActionStatus.UNSUPPORTED,
                AppAction.LIST_WINDOWS,
                context,
                "Listing windows requires pywin32 on Windows.",
                {"dependency": "pywin32"},
            )

        try:
            windows = self._enumerate_windows()
            return self._result(
                ActionStatus.SUCCESS,
                AppAction.LIST_WINDOWS,
                context,
                "Visible windows listed.",
                {"windows": [dataclasses.asdict(window) for window in windows]},
            )
        except Exception as exc:
            return self._error_result(AppAction.LIST_WINDOWS, context, exc)

    def list_processes(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        """
        List running user-level processes.
        """
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or generate_id("task"),
            requested_by=requested_by or user_id,
            role=role,
            plan=plan,
            agent_name="DeviceWorker",
        ).validate()

        if not self.is_windows:
            return self._unsupported_result(AppAction.LIST_PROCESSES, context)

        access = self._check_permission(context=context, action=AppAction.LIST_PROCESSES)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, AppAction.LIST_PROCESSES, context, access["reason"], {"access": access})

        processes = self._safe_process_list()

        return self._result(
            ActionStatus.SUCCESS,
            AppAction.LIST_PROCESSES,
            context,
            "Processes listed.",
            {"processes": processes},
        )

    def poll_task(
        self,
        task: Mapping[str, Any],
        *,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute one worker task payload from Master Agent / System Agent.

        Expected task shape:
            {
                "action": "open|focus|close|list_windows|list_processes|heartbeat|stop|resume",
                "app_name": "notepad",
                "user_id": "...",
                "workspace_id": "...",
                "task_id": "...",
                "requested_by": "...",
                "role": "owner",
                "plan": "pro",
                "agent_name": "SystemAgent",
                "arguments": [],
                "close_mode": "graceful"
            }
        """
        safe_task = dict(json_safe(task or {}))
        action = normalize_text(safe_task.get("action")).lower()
        user_id = normalize_text(safe_task.get("user_id"))
        workspace_id = normalize_text(safe_task.get("workspace_id"))
        task_id = normalize_text(safe_task.get("task_id")) or generate_id("task")
        requested_by = normalize_text(safe_task.get("requested_by")) or user_id
        role = normalize_text(safe_task.get("role")) or "owner"
        plan = normalize_text(safe_task.get("plan")) or "pro"
        agent_name = normalize_text(safe_task.get("agent_name")) or "SystemAgent"

        if action == AppAction.OPEN.value:
            return self.open_app(
                normalize_text(safe_task.get("app_name")),
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                requested_by=requested_by,
                role=role,
                plan=plan,
                agent_name=agent_name,
                arguments=safe_task.get("arguments") if isinstance(safe_task.get("arguments"), list) else None,
                focus_after_open=bool(safe_task.get("focus_after_open", True)),
                security_approved=security_approved,
            )

        if action == AppAction.FOCUS.value:
            return self.focus_app(
                normalize_text(safe_task.get("app_name")),
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                requested_by=requested_by,
                role=role,
                plan=plan,
                agent_name=agent_name,
                security_approved=security_approved,
            )

        if action == AppAction.CLOSE.value:
            return self.close_app(
                normalize_text(safe_task.get("app_name")),
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                requested_by=requested_by,
                role=role,
                plan=plan,
                agent_name=agent_name,
                close_mode=self._coerce_close_mode(safe_task.get("close_mode") or CloseMode.GRACEFUL),
                security_approved=security_approved,
            )

        if action == AppAction.LIST_WINDOWS.value:
            return self.list_windows(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan)

        if action == AppAction.LIST_PROCESSES.value:
            return self.list_processes(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan)

        if action == AppAction.HEARTBEAT.value:
            return self.heartbeat(user_id=user_id, workspace_id=workspace_id, role=role, plan=plan)

        if action == AppAction.STOP.value:
            return self.stop(user_id=user_id, workspace_id=workspace_id, role=role, plan=plan, reason=normalize_text(safe_task.get("reason")))

        if action == AppAction.RESUME.value:
            return self.resume(user_id=user_id, workspace_id=workspace_id, role=role, plan=plan, reason=normalize_text(safe_task.get("reason")))

        context = TaskContext(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name=agent_name).validate()
        return self._result(
            ActionStatus.ERROR,
            AppAction.LIST_PROCESSES,
            context,
            "Unsupported app-control task action.",
            {"received_action": action, "supported_actions": [item.value for item in AppAction]},
        )

    def resolve_app_target(self, app_name: str, *, arguments: Optional[Sequence[str]] = None) -> AppTarget:
        """
        Resolve user-facing app name into a safe launch/focus/close target.
        """
        requested = normalize_text(app_name, max_length=260)
        if not requested:
            raise ValueError("app_name is required.")

        key = requested.lower()
        alias = self.app_aliases.get(key)

        if alias:
            risk = self._coerce_risk(alias.get("risk_level", "low"))
            command = alias.get("command")
            executable = alias.get("executable")
            app_user_model_id = alias.get("app_user_model_id")
            process_names = tuple(normalize_text(item).lower() for item in alias.get("process_names", []) if normalize_text(item))
            window_keywords = tuple(normalize_text(item).lower() for item in alias.get("window_keywords", []) if normalize_text(item))
            working_directory = normalize_text(alias.get("working_directory")) or None

            command_list = self._normalize_command(command) if command else None
            if command_list and arguments:
                command_list = command_list + self._sanitize_arguments(arguments)

            return AppTarget(
                requested_name=requested,
                executable=normalize_text(executable) or None,
                command=command_list,
                app_user_model_id=normalize_text(app_user_model_id) or None,
                process_names=process_names,
                window_keywords=window_keywords or (key,),
                working_directory=working_directory,
                risk_level=risk,
                source="alias",
            )

        if self._looks_like_windows_uri(requested):
            return AppTarget(
                requested_name=requested,
                command=["cmd.exe", "/c", "start", "", requested],
                process_names=(),
                window_keywords=(requested.split(":")[0].lower(),),
                risk_level=AppRiskLevel.MEDIUM,
                source="uri",
            )

        path = Path(requested)
        if self.allow_direct_paths and path.suffix.lower() in {".exe", ".bat", ".cmd", ".msc", ".lnk"}:
            command = [str(path)]
            if arguments:
                command += self._sanitize_arguments(arguments)
            return AppTarget(
                requested_name=requested,
                executable=str(path),
                command=command,
                process_names=(path.name.lower(),),
                window_keywords=(path.stem.lower(),),
                risk_level=AppRiskLevel.HIGH,
                source="direct_path",
            )

        if re.fullmatch(r"[a-zA-Z0-9_. -]{1,120}", requested):
            exe_name = requested if requested.lower().endswith(".exe") else f"{requested}.exe"
            risk = AppRiskLevel.MEDIUM
            if exe_name.lower() in {"cmd.exe", "powershell.exe", "pwsh.exe", "taskmgr.exe", "regedit.exe"}:
                risk = AppRiskLevel.HIGH
            return AppTarget(
                requested_name=requested,
                command=[exe_name] + self._sanitize_arguments(arguments or []),
                process_names=(exe_name.lower(),),
                window_keywords=(requested.lower().replace(".exe", ""),),
                risk_level=risk,
                source="safe_executable_name",
            )

        raise ValueError("Unsupported app name or path. Use a known alias or enable direct paths by policy.")

    def _normalize_command(self, command: Any) -> List[str]:
        if isinstance(command, str):
            cleaned = normalize_text(command, max_length=1000)
            if not cleaned:
                raise ValueError("Empty command is not allowed.")
            return [cleaned]

        if isinstance(command, Sequence):
            output = [normalize_text(part, max_length=1000) for part in command if normalize_text(part, max_length=1000)]
            if not output:
                raise ValueError("Empty command is not allowed.")
            return output

        raise ValueError("Command must be a string or sequence of strings.")

    def _sanitize_arguments(self, arguments: Sequence[str]) -> List[str]:
        safe_args: List[str] = []
        for arg in arguments:
            item = normalize_text(arg, max_length=500)
            if not item:
                continue
            if any(blocked in item for blocked in ["&&", "||", "|", ">", "<", "`", "$("]):
                raise ValueError("Unsafe command argument rejected.")
            safe_args.append(item)
        return safe_args

    def _build_launch_command(self, target: AppTarget) -> List[str]:
        if target.command:
            return list(target.command)

        if target.executable:
            return [target.executable]

        if target.app_user_model_id:
            return ["cmd.exe", "/c", "start", "", f"shell:AppsFolder\\{target.app_user_model_id}"]

        raise ValueError("No executable, command, or app user model ID resolved.")

    def _looks_like_windows_uri(self, value: str) -> bool:
        return bool(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.-]{1,40}:.{0,400}", value))

    def _coerce_risk(self, value: Any) -> AppRiskLevel:
        if isinstance(value, AppRiskLevel):
            return value
        text = normalize_text(value).lower()
        for item in AppRiskLevel:
            if item.value == text:
                return item
        return AppRiskLevel.LOW

    def _coerce_close_mode(self, value: Any) -> CloseMode:
        if isinstance(value, CloseMode):
            return value
        text = normalize_text(value).lower()
        for item in CloseMode:
            if item.value == text:
                return item
        raise ValueError("Invalid close mode. Use graceful or force.")

    def _is_ready(self) -> bool:
        return self.state == WorkerState.READY

    def _check_permission(self, *, context: TaskContext, action: AppAction) -> Dict[str, Any]:
        role = context.role.lower()
        plan = context.plan.lower()

        if role not in self.allowed_roles:
            return {
                "allowed": False,
                "reason": f"Role '{context.role}' is not allowed to control Windows apps.",
                "role": context.role,
                "plan": context.plan,
                "action": action.value,
            }

        if plan not in self.allowed_plans:
            return {
                "allowed": False,
                "reason": f"Plan '{context.plan}' is not allowed to use Windows app control.",
                "role": context.role,
                "plan": context.plan,
                "action": action.value,
            }

        return {
            "allowed": True,
            "reason": "Permission granted.",
            "role": context.role,
            "plan": context.plan,
            "action": action.value,
        }

    def _security_gate(
        self,
        *,
        context: TaskContext,
        action: AppAction,
        target: AppTarget,
        security_approved: bool,
        close_mode: Optional[CloseMode] = None,
    ) -> Dict[str, Any]:
        requires_review = False
        reasons: List[str] = []

        if target.risk_level in {AppRiskLevel.HIGH, AppRiskLevel.CRITICAL}:
            requires_review = True
            reasons.append(f"Target risk level is {target.risk_level.value}.")

        if action == AppAction.CLOSE:
            requires_review = True
            reasons.append("Closing applications is a state-changing action.")

        if close_mode == CloseMode.FORCE:
            requires_review = True
            reasons.append("Force close can cause data loss.")

        if self._is_system_critical_target(target):
            return {
                "allowed": False,
                "requires_security_review": True,
                "reason": "System-critical target is blocked.",
                "security_agent_payload": self._security_payload(
                    context=context,
                    action=action,
                    target=target,
                    reasons=["System-critical target blocked."],
                ),
            }

        if requires_review and not security_approved:
            return {
                "allowed": False,
                "requires_security_review": True,
                "reason": "Security Agent approval required: " + " ".join(reasons),
                "security_agent_payload": self._security_payload(
                    context=context,
                    action=action,
                    target=target,
                    reasons=reasons,
                ),
            }

        return {
            "allowed": True,
            "requires_security_review": requires_review,
            "reason": "Security gate passed.",
            "security_agent_payload": None,
        }

    def _security_payload(
        self,
        *,
        context: TaskContext,
        action: AppAction,
        target: AppTarget,
        reasons: Sequence[str],
    ) -> Dict[str, Any]:
        return {
            "event": "security.review.device_worker.app_control",
            "device_id": self.device_id,
            "worker_id": self.worker_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "correlation_id": context.correlation_id,
            "requested_by": context.requested_by,
            "agent_name": context.agent_name,
            "action": action.value,
            "target": dataclasses.asdict(target),
            "risk_level": target.risk_level.value,
            "reasons": list(reasons),
            "timestamp": iso_now(),
        }

    def _is_system_critical_target(self, target: AppTarget) -> bool:
        for name in target.process_names:
            if normalize_text(name).lower() in self.SYSTEM_CRITICAL_PROCESSES:
                return True
        command = " ".join(target.command or []).lower()
        return any(proc in command for proc in self.SYSTEM_CRITICAL_PROCESSES)

    def _enumerate_windows(self) -> List[WindowInfo]:
        if not win32gui:
            return []

        windows: List[WindowInfo] = []

        def callback(hwnd: int, _: Any) -> bool:
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                title = normalize_text(win32gui.GetWindowText(hwnd), max_length=500)
                if not title:
                    return True

                process_id: Optional[int] = None
                process_name: Optional[str] = None

                if win32process:
                    try:
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        process_id = int(pid)
                        process_name = self._process_name_by_pid(process_id)
                    except Exception:
                        process_id = None

                is_minimized = bool(win32gui.IsIconic(hwnd))
                windows.append(
                    WindowInfo(
                        hwnd=int(hwnd),
                        title=title,
                        process_id=process_id,
                        process_name=process_name,
                        is_visible=True,
                        is_minimized=is_minimized,
                    )
                )
            except Exception:
                return True
            return True

        win32gui.EnumWindows(callback, None)
        return windows

    def _find_matching_windows(self, target: AppTarget, *, match_mode: WindowMatchMode) -> List[WindowInfo]:
        windows = self._enumerate_windows()
        keywords = [item.lower() for item in target.window_keywords if item]
        process_names = {item.lower() for item in target.process_names if item}

        matches: List[WindowInfo] = []

        for window in windows:
            title = window.title.lower()
            process_name = (window.process_name or "").lower()

            title_match = any(self._match_text(title, keyword, match_mode) for keyword in keywords)
            process_match = bool(process_name and process_name in process_names)

            if title_match or process_match:
                matches.append(window)

        return matches

    def _match_text(self, text: str, pattern: str, mode: WindowMatchMode) -> bool:
        if mode == WindowMatchMode.EXACT:
            return text == pattern
        if mode == WindowMatchMode.STARTS_WITH:
            return text.startswith(pattern)
        if mode == WindowMatchMode.REGEX:
            try:
                return bool(re.search(pattern, text, flags=re.IGNORECASE))
            except re.error:
                return False
        return pattern in text

    def _focus_window(self, hwnd: int) -> None:
        if not win32gui or not win32con:
            raise RuntimeError("pywin32 is required to focus windows.")

        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        else:
            win32gui.ShowWindow(hwnd, win32con.SW_SHOW)

        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            win32gui.BringWindowToTop(hwnd)
            win32gui.SetActiveWindow(hwnd)

    def _safe_process_list(self) -> List[Dict[str, Any]]:
        processes: List[Dict[str, Any]] = []

        if psutil:
            for proc in psutil.process_iter(["pid", "name", "exe", "username", "status", "create_time"]):
                try:
                    info = proc.info
                    name = normalize_text(info.get("name"))
                    if not name:
                        continue
                    processes.append(
                        {
                            "pid": info.get("pid"),
                            "name": name,
                            "exe": info.get("exe"),
                            "username": info.get("username"),
                            "status": info.get("status"),
                            "create_time": info.get("create_time"),
                        }
                    )
                except Exception:
                    continue
            return processes

        try:
            completed = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            if completed.returncode != 0:
                return []

            for line in completed.stdout.splitlines():
                parts = self._parse_tasklist_csv_line(line)
                if len(parts) >= 2:
                    processes.append({"name": parts[0], "pid": self._safe_int(parts[1])})
        except Exception:
            return []

        return processes

    def _parse_tasklist_csv_line(self, line: str) -> List[str]:
        output: List[str] = []
        current = ""
        in_quotes = False

        for char in line:
            if char == '"':
                in_quotes = not in_quotes
                continue
            if char == "," and not in_quotes:
                output.append(current)
                current = ""
                continue
            current += char

        output.append(current)
        return output

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        try:
            return int(value)
        except Exception:
            return None

    def _process_name_by_pid(self, pid: int) -> Optional[str]:
        if not pid:
            return None

        if psutil:
            try:
                return normalize_text(psutil.Process(pid).name()) or None
            except Exception:
                return None

        for item in self._safe_process_list():
            if item.get("pid") == pid:
                return normalize_text(item.get("name")) or None

        return None

    def _find_matching_processes(self, target: AppTarget) -> List[Dict[str, Any]]:
        process_names = {item.lower() for item in target.process_names if item}
        if not process_names:
            return []

        matches = []
        for proc in self._safe_process_list():
            name = normalize_text(proc.get("name")).lower()
            if name in process_names:
                matches.append(proc)
        return matches

    def _terminate_process(self, proc_info: Mapping[str, Any], *, force: bool) -> Dict[str, Any]:
        pid = self._safe_int(proc_info.get("pid"))
        name = normalize_text(proc_info.get("name"))

        if not pid:
            return {"ok": False, "name": name, "pid": None, "error": "Missing PID."}

        if name.lower() in self.SYSTEM_CRITICAL_PROCESSES:
            return {"ok": False, "name": name, "pid": pid, "error": "System-critical process blocked."}

        if psutil:
            try:
                proc = psutil.Process(pid)
                if force:
                    proc.kill()
                else:
                    proc.terminate()
                return {"ok": True, "name": name, "pid": pid, "force": force}
            except Exception as exc:
                return {"ok": False, "name": name, "pid": pid, "force": force, "error": str(exc)}

        try:
            args = ["taskkill", "/PID", str(pid)]
            if force:
                args.append("/F")
            completed = subprocess.run(args, capture_output=True, text=True, timeout=10, shell=False)
            return {
                "ok": completed.returncode == 0,
                "name": name,
                "pid": pid,
                "force": force,
                "stdout": completed.stdout[-500:],
                "stderr": completed.stderr[-500:],
            }
        except Exception as exc:
            return {"ok": False, "name": name, "pid": pid, "force": force, "error": str(exc)}

    def _unsupported_result(
        self,
        action: AppAction,
        context: TaskContext,
        *,
        emit_report: bool = True,
    ) -> Dict[str, Any]:
        return self._result(
            ActionStatus.UNSUPPORTED,
            action,
            context,
            "Windows app control is only supported on Windows.",
            {"current_os": platform.system()},
            emit_report=emit_report,
        )

    def _error_result(
        self,
        action: AppAction,
        context: TaskContext,
        exc: Exception,
        *,
        emit_report: bool = True,
    ) -> Dict[str, Any]:
        with self._state_lock:
            if self._state == WorkerState.BUSY:
                self._state = WorkerState.ERROR

        return self._result(
            ActionStatus.ERROR,
            action,
            context,
            "Windows app-control action failed.",
            {
                "error_type": exc.__class__.__name__,
                "error": normalize_text(str(exc), max_length=1000),
            },
            emit_report=emit_report,
        )

    def _result(
        self,
        status: ActionStatus,
        action: AppAction,
        context: TaskContext,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        *,
        emit_report: bool = True,
    ) -> Dict[str, Any]:
        context = context.validate()
        payload_data = dict(json_safe(data or {}))

        result = {
            "success": status == ActionStatus.SUCCESS,
            "status": status.value,
            "message": normalize_text(message, max_length=1000),
            "action": action.value,
            "device": {
                "device_id": self.device_id,
                "worker_id": self.worker_id,
                "hostname": socket.gethostname(),
                "state": self.state.value,
                "is_windows": self.is_windows,
            },
            "context": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "requested_by": context.requested_by,
                "role": context.role,
                "plan": context.plan,
                "agent_name": context.agent_name,
                "correlation_id": context.correlation_id,
            },
            "data": payload_data,
            "audit_payload": self._audit_payload(status=status, action=action, context=context, data=payload_data),
            "memory_payload": self._memory_payload(status=status, action=action, context=context, message=message, data=payload_data),
            "verification_payload": self._verification_payload(status=status, action=action, context=context, data=payload_data),
            "timestamp": iso_now(),
        }

        result["result_hash"] = stable_hash(result)

        self._emit_audit(result["audit_payload"])

        if emit_report:
            self._emit_report(result)

        return result

    def _audit_payload(
        self,
        *,
        status: ActionStatus,
        action: AppAction,
        context: TaskContext,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return {
            "event": "device_worker.app_control.audit",
            "device_id": self.device_id,
            "worker_id": self.worker_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "correlation_id": context.correlation_id,
            "requested_by": context.requested_by,
            "agent_name": context.agent_name,
            "action": action.value,
            "status": status.value,
            "data_hash": stable_hash(json_safe(data)),
            "timestamp": iso_now(),
        }

    def _memory_payload(
        self,
        *,
        status: ActionStatus,
        action: AppAction,
        context: TaskContext,
        message: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        target = data.get("target") if isinstance(data.get("target"), Mapping) else {}
        return {
            "source": "windows_app_control_worker",
            "type": "device_action",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "title": f"Windows app action: {action.value}",
            "summary": {
                "action": action.value,
                "status": status.value,
                "message": normalize_text(message),
                "app": target.get("requested_name") if isinstance(target, Mapping) else None,
                "worker_id": self.worker_id,
                "device_id": self.device_id,
            },
            "created_at": iso_now(),
        }

    def _verification_payload(
        self,
        *,
        status: ActionStatus,
        action: AppAction,
        context: TaskContext,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return {
            "event": "verification.device_worker.app_control",
            "verification_id": generate_id("ver"),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "correlation_id": context.correlation_id,
            "action": action.value,
            "status": status.value,
            "success": status == ActionStatus.SUCCESS,
            "device_id": self.device_id,
            "worker_id": self.worker_id,
            "evidence_hash": stable_hash(json_safe(data)),
            "prepared_at": iso_now(),
        }

    def _emit_audit(self, payload: Dict[str, Any]) -> None:
        if self.audit_sink:
            try:
                self.audit_sink(dict(json_safe(payload)))
            except Exception:
                return

    def _emit_report(self, payload: Dict[str, Any]) -> None:
        if self.report_sink:
            try:
                self.report_sink(dict(json_safe(payload)))
            except Exception:
                return


__all__ = [
    "AppControl",
    "AppAction",
    "ActionStatus",
    "AppRiskLevel",
    "WorkerState",
    "CloseMode",
    "WindowMatchMode",
    "TaskContext",
    "AppTarget",
    "WindowInfo",
    "WorkerRegistration",
]
