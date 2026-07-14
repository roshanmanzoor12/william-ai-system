"""
apps/worker_nodes/windows/windows_worker.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Windows app/file/browser/system automation worker.

Required class/component:
    WindowsWorker

This worker is designed to connect later with:
    - Master Agent
    - Security Agent
    - Verification Agent
    - Memory Agent
    - Worker registry
    - SaaS task router
    - Audit logs
    - Dashboard analytics

Core safety rules:
    - Every task must include user_id and workspace_id.
    - The worker must never mix task scope across users/workspaces.
    - Sensitive actions are blocked unless Security Agent approval metadata is present.
    - No secrets are hardcoded.
    - All actions return structured safe responses.
    - All completed actions prepare verification and memory-compatible payloads.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import queue
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Return current UTC time as ISO string."""
    return utc_now().isoformat()


def generate_id(prefix: str) -> str:
    """Generate a compact prefixed UUID."""
    return f"{prefix}_{uuid.uuid4().hex}"


class DeviceAuthError(RuntimeError):
    """Raised specifically for a 401 response -- an invalid, expired, or
    revoked token. Distinct from a generic RuntimeError (network/backend
    errors) so run_forever() can tell "stop retrying, the credential is
    dead" apart from "keep retrying, the backend is just unreachable right
    now"."""


class WorkerStatus(str, Enum):
    """Worker runtime status."""

    STARTING = "starting"
    ONLINE = "online"
    IDLE = "idle"
    BUSY = "busy"
    PAUSED = "paused"
    STOPPING = "stopping"
    OFFLINE = "offline"
    ERROR = "error"


class TaskStatus(str, Enum):
    """Task processing status."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    RUNNING = "running"
    WAITING_SECURITY = "waiting_security"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class ActionType(str, Enum):
    """Supported Windows worker actions."""

    OPEN_APP = "open_app"
    OPEN_FILE = "open_file"
    OPEN_FOLDER = "open_folder"
    OPEN_URL = "open_url"
    SEARCH_WEB = "search_web"
    RUN_COMMAND = "run_command"
    LIST_DIRECTORY = "list_directory"
    CREATE_FOLDER = "create_folder"
    WRITE_TEXT_FILE = "write_text_file"
    READ_TEXT_FILE = "read_text_file"
    COPY_FILE = "copy_file"
    MOVE_FILE = "move_file"
    DELETE_FILE = "delete_file"
    SYSTEM_INFO = "system_info"
    SCREEN_LOCK = "screen_lock"
    SHUTDOWN = "shutdown"
    RESTART = "restart"
    SLEEP = "sleep"
    HEARTBEAT = "heartbeat"
    NOOP = "noop"

    # Real task-dispatch protocol action names (apps/api/routes/
    # system_worker.py::WORKER_MVP_ACTIONS) -- these exact string values
    # must match the server's action_type vocabulary byte-for-byte, since
    # coerce_action() below matches on value, not name. OPEN_FILE/
    # OPEN_FOLDER above already match the server's "open_file"/"open_folder"
    # 1:1, so no new members were needed for those two.
    OPEN_MICROSOFT_STORE = "open_microsoft_store"
    OPEN_CHROME = "open_chrome"
    OPEN_VSCODE = "open_vscode"
    OPEN_NOTEPAD = "open_notepad"
    OPEN_EXPLORER = "open_explorer"
    OPEN_DOWNLOADS_FOLDER = "open_downloads_folder"
    DOWNLOAD_GENERATED_FILE_TO_DOWNLOADS = "download_generated_file_to_downloads"
    SHOW_SYSTEM_INFO = "show_system_info"


class RiskLevel(str, Enum):
    """Action risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkerEventType(str, Enum):
    """Worker event type for audit reports."""

    DEVICE_REGISTERED = "device_registered"
    HEARTBEAT_SENT = "heartbeat_sent"
    TASK_POLLED = "task_polled"
    TASK_ACCEPTED = "task_accepted"
    TASK_REJECTED = "task_rejected"
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    SECURITY_REQUIRED = "security_required"
    PERMISSION_DENIED = "permission_denied"
    WORKER_PAUSED = "worker_paused"
    WORKER_RESUMED = "worker_resumed"
    WORKER_STOPPED = "worker_stopped"
    ERROR = "error"


@dataclass(slots=True)
class WorkerConfig:
    """
    Runtime configuration.

    Values are read from environment variables by default so secrets and URLs
    are not hardcoded.
    """

    api_base_url: str = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_API_BASE_URL", "").rstrip("/")
    )
    worker_token: str = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_TOKEN", "")
    )
    # An installed worker (apps/worker_nodes/windows/install_windows_worker.ps1
    # style setup) authenticates with this instead of worker_token (a full
    # user JWT). Both end up in the same Authorization: Bearer header --
    # apps/api/routes/device_setup.py::get_worker_auth_context tells them
    # apart server-side by hash lookup, not the worker.
    device_token: str = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_DEVICE_TOKEN", "")
    )
    # Set via --config; when present, config-file values are applied as
    # overrides in main() with lower priority than explicit CLI flags,
    # matching --token/--api-base-url/--device-name's existing precedence.
    config_path: Optional[str] = field(default=None)
    retry_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("WILLIAM_WORKER_RETRY_INTERVAL", "15"))
    )
    worker_id: str = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_ID", generate_id("win_worker"))
    )
    device_name: str = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_DEVICE_NAME", socket.gethostname())
    )
    environment: str = field(
        default_factory=lambda: os.getenv("WILLIAM_ENV", os.getenv("APP_ENV", "development"))
    )
    poll_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("WILLIAM_WORKER_POLL_INTERVAL", "5"))
    )
    heartbeat_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("WILLIAM_WORKER_HEARTBEAT_INTERVAL", "30"))
    )
    request_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("WILLIAM_WORKER_REQUEST_TIMEOUT", "20"))
    )
    command_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("WILLIAM_WORKER_COMMAND_TIMEOUT", "60"))
    )
    dry_run: bool = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_DRY_RUN", "false").lower()
        in {"1", "true", "yes", "on"}
    )
    allow_shell_commands: bool = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_ALLOW_SHELL", "false").lower()
        in {"1", "true", "yes", "on"}
    )
    allow_destructive_actions: bool = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_ALLOW_DESTRUCTIVE", "false").lower()
        in {"1", "true", "yes", "on"}
    )
    allow_power_actions: bool = field(
        default_factory=lambda: os.getenv("WILLIAM_WORKER_ALLOW_POWER", "false").lower()
        in {"1", "true", "yes", "on"}
    )
    allowed_root_dirs: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            item.strip()
            for item in os.getenv(
                "WILLIAM_WORKER_ALLOWED_ROOTS",
                str(Path.home()),
            ).split(";")
            if item.strip()
        )
    )
    max_text_read_bytes: int = field(
        default_factory=lambda: int(os.getenv("WILLIAM_WORKER_MAX_TEXT_READ_BYTES", "200000"))
    )
    max_text_write_bytes: int = field(
        default_factory=lambda: int(os.getenv("WILLIAM_WORKER_MAX_TEXT_WRITE_BYTES", "200000"))
    )
    user_agent: str = "WilliamJarvisWindowsWorker/1.0"


@dataclass(slots=True)
class WorkerTask:
    """Normalized task envelope."""

    task_id: str
    user_id: str
    workspace_id: str
    action: ActionType
    payload: dict[str, Any]
    requested_by: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: generate_id("corr"))
    raw: dict[str, Any] = field(default_factory=dict)


class WindowsWorker:
    """
    Windows device worker.

    Responsibilities:
        - Device registration
        - Heartbeat
        - Task polling
        - Scope isolation
        - Permission checks
        - Security approval checks
        - Safe Windows automation
        - Stop/resume controls
        - Audit-friendly reports
        - Memory and verification payload preparation
    """

    VERSION = "1.0.0"

    SECRET_REDACTION = "[REDACTED]"

    SENSITIVE_KEYS = {
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
        "openai_api_key",
        "database_url",
        "connection_string",
        "card_number",
        "cvv",
        "cvc",
    }

    ACTION_RISK: dict[ActionType, RiskLevel] = {
        ActionType.NOOP: RiskLevel.LOW,
        ActionType.HEARTBEAT: RiskLevel.LOW,
        ActionType.SYSTEM_INFO: RiskLevel.LOW,
        ActionType.OPEN_APP: RiskLevel.MEDIUM,
        ActionType.OPEN_FILE: RiskLevel.MEDIUM,
        ActionType.OPEN_FOLDER: RiskLevel.MEDIUM,
        ActionType.OPEN_URL: RiskLevel.MEDIUM,
        ActionType.SEARCH_WEB: RiskLevel.MEDIUM,
        ActionType.LIST_DIRECTORY: RiskLevel.MEDIUM,
        ActionType.READ_TEXT_FILE: RiskLevel.MEDIUM,
        ActionType.CREATE_FOLDER: RiskLevel.HIGH,
        ActionType.WRITE_TEXT_FILE: RiskLevel.HIGH,
        ActionType.COPY_FILE: RiskLevel.HIGH,
        ActionType.MOVE_FILE: RiskLevel.HIGH,
        ActionType.DELETE_FILE: RiskLevel.CRITICAL,
        ActionType.RUN_COMMAND: RiskLevel.CRITICAL,
        ActionType.SCREEN_LOCK: RiskLevel.HIGH,
        ActionType.SHUTDOWN: RiskLevel.CRITICAL,
        ActionType.RESTART: RiskLevel.CRITICAL,
        ActionType.SLEEP: RiskLevel.HIGH,
        ActionType.OPEN_MICROSOFT_STORE: RiskLevel.LOW,
        ActionType.OPEN_CHROME: RiskLevel.LOW,
        ActionType.OPEN_VSCODE: RiskLevel.LOW,
        ActionType.OPEN_NOTEPAD: RiskLevel.LOW,
        ActionType.OPEN_EXPLORER: RiskLevel.LOW,
        ActionType.OPEN_DOWNLOADS_FOLDER: RiskLevel.LOW,
        ActionType.DOWNLOAD_GENERATED_FILE_TO_DOWNLOADS: RiskLevel.LOW,
        ActionType.SHOW_SYSTEM_INFO: RiskLevel.LOW,
    }

    SAFE_APP_ALIASES: dict[str, list[str]] = {
        "notepad": ["notepad.exe"],
        "calculator": ["calc.exe"],
        "calc": ["calc.exe"],
        "paint": ["mspaint.exe"],
        "cmd": ["cmd.exe"],
        "powershell": ["powershell.exe"],
        "explorer": ["explorer.exe"],
        "edge": ["msedge.exe"],
        "chrome": ["chrome.exe"],
        "firefox": ["firefox.exe"],
        "wordpad": ["write.exe"],
        "store": ["ms-windows-store:"],
        "microsoft_store": ["ms-windows-store:"],
        "vscode": ["code"],
    }

    SAFE_TEXT_EXTENSIONS = {
        ".txt",
        ".md",
        ".json",
        ".csv",
        ".log",
        ".py",
        ".js",
        ".ts",
        ".html",
        ".css",
        ".xml",
        ".yaml",
        ".yml",
        ".ini",
        ".env.example",
    }

    def __init__(
        self,
        config: Optional[WorkerConfig] = None,
        http_client: Optional[Callable[..., dict[str, Any]]] = None,
    ) -> None:
        self.config = config or WorkerConfig()
        self.http_client = http_client
        self.status = WorkerStatus.STARTING
        self.device_id = self.config.worker_id
        self.session_id = generate_id("session")
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.current_task_id: Optional[str] = None
        self.task_queue: queue.Queue[WorkerTask] = queue.Queue()
        self.audit_events: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._last_heartbeat_at: Optional[datetime] = None
        self._registered = False

        self.handlers: dict[ActionType, Callable[[WorkerTask], dict[str, Any]]] = {
            ActionType.NOOP: self._handle_noop,
            ActionType.HEARTBEAT: self._handle_heartbeat_action,
            ActionType.SYSTEM_INFO: self._handle_system_info,
            ActionType.OPEN_APP: self._handle_open_app,
            ActionType.OPEN_FILE: self._handle_open_file,
            ActionType.OPEN_FOLDER: self._handle_open_folder,
            ActionType.OPEN_URL: self._handle_open_url,
            ActionType.SEARCH_WEB: self._handle_search_web,
            ActionType.RUN_COMMAND: self._handle_run_command,
            ActionType.LIST_DIRECTORY: self._handle_list_directory,
            ActionType.CREATE_FOLDER: self._handle_create_folder,
            ActionType.WRITE_TEXT_FILE: self._handle_write_text_file,
            ActionType.READ_TEXT_FILE: self._handle_read_text_file,
            ActionType.COPY_FILE: self._handle_copy_file,
            ActionType.MOVE_FILE: self._handle_move_file,
            ActionType.DELETE_FILE: self._handle_delete_file,
            ActionType.SCREEN_LOCK: self._handle_screen_lock,
            ActionType.SHUTDOWN: self._handle_shutdown,
            ActionType.RESTART: self._handle_restart,
            ActionType.SLEEP: self._handle_sleep,
            ActionType.OPEN_MICROSOFT_STORE: self._handle_open_microsoft_store,
            ActionType.OPEN_CHROME: self._handle_open_chrome,
            ActionType.OPEN_VSCODE: self._handle_open_vscode,
            ActionType.OPEN_NOTEPAD: self._handle_open_notepad,
            ActionType.OPEN_EXPLORER: self._handle_open_explorer,
            ActionType.OPEN_DOWNLOADS_FOLDER: self._handle_open_downloads_folder,
            ActionType.DOWNLOAD_GENERATED_FILE_TO_DOWNLOADS: self._handle_download_generated_file,
            ActionType.SHOW_SYSTEM_INFO: self._handle_system_info,
        }

    # -------------------------------------------------------------------------
    # Public lifecycle
    # -------------------------------------------------------------------------

    # Real server-side allowlist (apps/api/routes/system_worker.py::
    # WORKER_MVP_ACTIONS) this worker actually implements -- sent on every
    # heartbeat so the dashboard can show what this specific worker build
    # supports.
    SUPPORTED_SERVER_ACTIONS: list[str] = [
        "open_microsoft_store", "open_chrome", "open_vscode", "open_notepad",
        "open_explorer", "open_folder", "open_file",
        "download_generated_file_to_downloads", "open_downloads_folder",
        "show_system_info",
    ]

    def _heartbeat_payload(self) -> dict[str, Any]:
        return {
            "platform": "windows",
            "device_name": self.config.device_name,
            "supported_actions": self.SUPPORTED_SERVER_ACTIONS,
        }

    def register_device(self) -> dict[str, Any]:
        """A worker's first heartbeat IS its registration -- the real
        backend route (POST /system/worker/heartbeat) upserts the
        presence row on every call, so there is no separate register
        endpoint to hit."""
        response = self._post("/system/worker/heartbeat", self._heartbeat_payload())
        self._registered = bool(response.get("ok", True))
        self.status = WorkerStatus.ONLINE if self._registered else WorkerStatus.ERROR

        self.record_event(
            WorkerEventType.DEVICE_REGISTERED,
            {
                "registered": self._registered,
                "response": response,
            },
        )

        return self.success_response(
            message="Windows worker registered.",
            data={
                "worker_id": self.device_id,
                "session_id": self.session_id,
                "registered": self._registered,
            },
        )

    def heartbeat(self) -> dict[str, Any]:
        """Send heartbeat to control plane."""
        self._last_heartbeat_at = utc_now()

        response = self._post("/system/worker/heartbeat", self._heartbeat_payload())

        self.record_event(
            WorkerEventType.HEARTBEAT_SENT,
            {
                "status": self.status.value,
                "response_ok": response.get("ok", True),
            },
        )

        return self.success_response(
            message="Heartbeat sent.",
            data={
                "worker_id": self.device_id,
                "status": self.status.value,
                "heartbeat_at": self._last_heartbeat_at.isoformat(),
            },
        )

    def poll_task(self) -> Optional[WorkerTask]:
        """Poll one task from the control plane. The real backend route
        (GET /system/worker/tasks) returns up to `limit` queued tasks in
        one list, workspace-scoped by the caller's JWT -- this worker only
        ever executes one at a time, so it takes the first and leaves the
        rest queued for the next poll."""
        response = self._get("/system/worker/tasks", query={"limit": 1})

        tasks = response.get("tasks") or []
        raw_task = tasks[0] if tasks else None

        self.record_event(
            WorkerEventType.TASK_POLLED,
            {
                "response_ok": response.get("ok", True),
                "has_task": bool(raw_task),
            },
        )

        if not raw_task:
            return None

        try:
            return self.normalize_task(raw_task)
        except Exception as exc:
            self.record_event(
                WorkerEventType.TASK_REJECTED,
                {
                    "reason": "invalid_task_payload",
                    "error": str(exc),
                },
            )
            return None

    def run_forever(self) -> None:
        """
        Main worker loop.

        This method blocks until stop() is called, the process receives a
        stop signal, or the device token is revoked (see DeviceAuthError --
        that case stops the loop deliberately rather than retrying forever,
        since retrying a dead credential can never succeed on its own; a
        network/backend-unreachable error is the opposite case and always
        retries, every retry_interval_seconds, without crashing).
        """
        self.install_signal_handlers()
        self.status = WorkerStatus.STARTING
        print(f"[worker] connecting to {self.config.api_base_url or '(no backend configured)'} as \"{self.config.device_name}\"...", flush=True)

        revoked = False
        while not self.stop_event.is_set():
            try:
                self.register_device()
                break
            except DeviceAuthError:
                print("[worker] Device token revoked. Please re-enable worker from dashboard.", flush=True)
                self.status = WorkerStatus.ERROR
                revoked = True
                break
            except Exception as exc:
                print(f"[worker] connection error, retrying in {self.config.retry_interval_seconds:.0f}s: {exc}", flush=True)
                if self.stop_event.wait(self.config.retry_interval_seconds):
                    break

        if revoked or self.stop_event.is_set():
            return

        print(f"[worker] connected. device_id={self.device_id}", flush=True)

        next_heartbeat = 0.0

        while not self.stop_event.is_set():
            now = time.time()

            if self.pause_event.is_set():
                self.status = WorkerStatus.PAUSED
                if now >= next_heartbeat:
                    try:
                        self.heartbeat()
                        print("[worker] heartbeat sent (paused)", flush=True)
                        next_heartbeat = now + self.config.heartbeat_interval_seconds
                    except DeviceAuthError:
                        print("[worker] Device token revoked. Please re-enable worker from dashboard.", flush=True)
                        self.status = WorkerStatus.ERROR
                        revoked = True
                        break
                    except Exception as exc:
                        print(f"[worker] connection error, retrying in {self.config.retry_interval_seconds:.0f}s: {exc}", flush=True)
                        next_heartbeat = now + self.config.retry_interval_seconds
                time.sleep(1)
                continue

            if now >= next_heartbeat:
                self.status = WorkerStatus.IDLE if not self.current_task_id else WorkerStatus.BUSY
                try:
                    self.heartbeat()
                    print(f"[worker] heartbeat sent | status={self.status.value}", flush=True)
                    next_heartbeat = now + self.config.heartbeat_interval_seconds
                except DeviceAuthError:
                    print("[worker] Device token revoked. Please re-enable worker from dashboard.", flush=True)
                    self.status = WorkerStatus.ERROR
                    revoked = True
                    break
                except Exception as exc:
                    print(f"[worker] connection error, retrying in {self.config.retry_interval_seconds:.0f}s: {exc}", flush=True)
                    next_heartbeat = now + min(self.config.retry_interval_seconds, self.config.heartbeat_interval_seconds)
                    time.sleep(min(self.config.retry_interval_seconds, self.config.poll_interval_seconds))
                    continue

            try:
                task = self.poll_task()
            except Exception as exc:
                print(f"[worker] error polling for tasks: {exc}", flush=True)
                task = None

            if task:
                print(f"[worker] task received: {task.action.value} ({task.task_id})", flush=True)
                print(f"[worker] executing {task.action.value}...", flush=True)
                result = self.execute_task(task)
                print(f"[worker] result: {'OK' if result.get('ok') else 'FAILED'} - {result.get('message')}", flush=True)
                print("[worker] result reported to backend", flush=True)
            else:
                print("[worker] waiting for tasks...", flush=True)

            time.sleep(self.config.poll_interval_seconds)

        self.status = WorkerStatus.OFFLINE
        self.record_event(WorkerEventType.WORKER_STOPPED, {"stopped_at": iso_now()})
        print("[worker] shutting down", flush=True)

        if revoked:
            # The device token is already known-dead -- reporting offline
            # with it would just be another 401. Skip straight to return
            # (no matching /worker/offline route exists server-side yet
            # anyway; see the try/except below for the non-revoked path).
            return
        try:
            # No matching /worker/offline route exists server-side yet
            # (out of scope for this MVP -- the presence heartbeat's own
            # WORKER_STALE_AFTER_SECONDS staleness window already makes a
            # worker look offline again on its own once heartbeats stop).
            # This call is best-effort only; a graceful-shutdown signal
            # isn't required for correctness.
            self._post(
                "/system/worker/offline",
                {"worker_id": self.device_id, "session_id": self.session_id, "offline_at": iso_now()},
                fail_silently=True,
            )
        except Exception:
            pass

    def stop(self) -> dict[str, Any]:
        """Stop worker safely."""
        self.status = WorkerStatus.STOPPING
        self.stop_event.set()
        self.record_event(WorkerEventType.WORKER_STOPPED, {"requested_at": iso_now()})
        return self.success_response("Worker stop requested.", {"worker_id": self.device_id})

    def pause(self) -> dict[str, Any]:
        """Pause task polling/execution."""
        self.pause_event.set()
        self.status = WorkerStatus.PAUSED
        self.record_event(WorkerEventType.WORKER_PAUSED, {"paused_at": iso_now()})
        return self.success_response("Worker paused.", {"worker_id": self.device_id})

    def resume(self) -> dict[str, Any]:
        """Resume task polling/execution."""
        self.pause_event.clear()
        self.status = WorkerStatus.ONLINE
        self.record_event(WorkerEventType.WORKER_RESUMED, {"resumed_at": iso_now()})
        return self.success_response("Worker resumed.", {"worker_id": self.device_id})

    # -------------------------------------------------------------------------
    # Task execution
    # -------------------------------------------------------------------------

    def execute_task(self, task: WorkerTask) -> dict[str, Any]:
        """Execute one normalized task."""
        with self._lock:
            self.current_task_id = task.task_id
            self.status = WorkerStatus.BUSY

        start_time = utc_now()

        try:
            self.validate_task_scope(task)
            permission_result = self.check_permissions(task)
            if not permission_result["allowed"]:
                result = self.safe_error_response(
                    code="permission_denied",
                    message=permission_result["reason"],
                    task_id=task.task_id,
                    correlation_id=task.correlation_id,
                )
                self.report_task_result(task, TaskStatus.REJECTED, result)
                self.record_event(
                    WorkerEventType.PERMISSION_DENIED,
                    {
                        "task_id": task.task_id,
                        "action": task.action.value,
                        "reason": permission_result["reason"],
                    },
                )
                return result

            security_result = self.check_security(task)
            if not security_result["allowed"]:
                result = self.safe_error_response(
                    code="security_review_required",
                    message=security_result["reason"],
                    task_id=task.task_id,
                    correlation_id=task.correlation_id,
                    data={
                        "risk_level": self.action_risk(task.action).value,
                        "security_payload": self.prepare_security_payload(task),
                    },
                )
                self.report_task_result(task, TaskStatus.WAITING_SECURITY, result)
                self.record_event(
                    WorkerEventType.SECURITY_REQUIRED,
                    {
                        "task_id": task.task_id,
                        "action": task.action.value,
                        "risk_level": self.action_risk(task.action).value,
                    },
                )
                return result

            self.record_event(
                WorkerEventType.TASK_STARTED,
                {
                    "task_id": task.task_id,
                    "user_id": task.user_id,
                    "workspace_id": task.workspace_id,
                    "action": task.action.value,
                },
            )

            handler = self.handlers.get(task.action)
            if handler is None:
                raise ValueError(f"Unsupported action: {task.action.value}")

            result = handler(task)
            result.setdefault("ok", True)
            result.setdefault("task_id", task.task_id)
            result.setdefault("correlation_id", task.correlation_id)
            result.setdefault("verification_payload", self.prepare_verification_payload(task, result))
            result.setdefault("memory_context", self.prepare_memory_context(task, result))
            result.setdefault("audit_payload", self.prepare_audit_payload(task, result, start_time))

            self.report_task_result(task, TaskStatus.COMPLETED, result)
            self.record_event(
                WorkerEventType.TASK_COMPLETED,
                {
                    "task_id": task.task_id,
                    "action": task.action.value,
                    "duration_ms": self.duration_ms(start_time),
                },
            )
            return result

        except PermissionError as exc:
            result = self.safe_error_response(
                code="permission_error",
                message=str(exc),
                task_id=task.task_id,
                correlation_id=task.correlation_id,
            )
            self.report_task_result(task, TaskStatus.REJECTED, result)
            return result

        except Exception as exc:
            result = self.safe_error_response(
                code="task_failed",
                message=str(exc),
                task_id=task.task_id,
                correlation_id=task.correlation_id,
            )
            result["audit_payload"] = self.prepare_audit_payload(task, result, start_time)
            self.report_task_result(task, TaskStatus.FAILED, result)
            self.record_event(
                WorkerEventType.TASK_FAILED,
                {
                    "task_id": task.task_id,
                    "action": task.action.value,
                    "error": str(exc),
                },
            )
            return result

        finally:
            with self._lock:
                self.current_task_id = None
                self.status = WorkerStatus.IDLE

    def cancel_current_task(self, reason: str = "Cancelled by control plane.") -> dict[str, Any]:
        """
        Mark current task as cancelled.

        This worker executes most actions synchronously. Long-running command actions
        use subprocess timeout. Future integration can add per-task cancellation tokens.
        """
        current = self.current_task_id
        self.record_event(
            WorkerEventType.TASK_CANCELLED,
            {
                "task_id": current,
                "reason": reason,
                "cancelled_at": iso_now(),
            },
        )
        return self.success_response(
            "Current task cancellation requested.",
            {
                "task_id": current,
                "reason": reason,
            },
        )

    # -------------------------------------------------------------------------
    # Normalization, validation, permissions, security
    # -------------------------------------------------------------------------

    def normalize_task(self, raw: Mapping[str, Any]) -> WorkerTask:
        """Convert raw control-plane task into WorkerTask."""
        task_id = str(raw.get("task_id") or raw.get("id") or "").strip()
        user_id = str(raw.get("user_id") or "").strip()
        workspace_id = str(raw.get("workspace_id") or "").strip()
        # Real backend rows (database/models/worker_task.py::WorkerTask.to_dict())
        # use "action_type"/"action_payload"; "action"/"payload" kept as a
        # fallback for any other hypothetical raw task shape.
        action_raw = str(raw.get("action_type") or raw.get("action") or "").strip()

        if not task_id:
            raise ValueError("task_id is required.")
        if not user_id:
            raise ValueError("user_id is required.")
        if not workspace_id:
            raise ValueError("workspace_id is required.")
        if not action_raw:
            raise ValueError("action is required.")

        action = self.coerce_action(action_raw)

        return WorkerTask(
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            payload=self.sanitize_payload(raw.get("action_payload") or raw.get("payload") or {}),
            requested_by=raw.get("requested_by"),
            role=raw.get("role"),
            subscription_plan=raw.get("subscription_plan"),
            permissions=self.sanitize_payload(raw.get("permissions") or {}),
            security=self.sanitize_payload(raw.get("security") or {}),
            correlation_id=str(raw.get("correlation_id") or generate_id("corr")),
            raw=self.sanitize_payload(dict(raw)),
        )

    @staticmethod
    def coerce_action(action: str) -> ActionType:
        """Parse action string into ActionType."""
        normalized = action.strip().lower()
        for item in ActionType:
            if item.value == normalized:
                return item
        raise ValueError(f"Unsupported action: {action}")

    def validate_task_scope(self, task: WorkerTask) -> None:
        """Enforce required SaaS isolation fields."""
        if not task.user_id or not task.workspace_id:
            raise PermissionError("Task must include user_id and workspace_id.")

        raw_user_id = str(task.raw.get("user_id") or "")
        raw_workspace_id = str(task.raw.get("workspace_id") or "")

        if raw_user_id and raw_user_id != task.user_id:
            raise PermissionError("Task user scope mismatch.")

        if raw_workspace_id and raw_workspace_id != task.workspace_id:
            raise PermissionError("Task workspace scope mismatch.")

    def check_permissions(self, task: WorkerTask) -> dict[str, Any]:
        """
        Local permission gate.

        Final permission authority should live in SaaS API / Security Agent.
        This local check prevents obvious unsafe actions from running if the
        control-plane payload is incomplete or wrong.
        """
        role = str(task.role or "").lower().strip()
        permissions = task.permissions or {}
        allowed_actions = permissions.get("allowed_actions")
        denied_actions = permissions.get("denied_actions") or []

        if task.action.value in denied_actions:
            return {"allowed": False, "reason": f"Action denied by policy: {task.action.value}"}

        if allowed_actions and task.action.value not in allowed_actions:
            return {"allowed": False, "reason": f"Action not in allowed_actions: {task.action.value}"}

        if task.action == ActionType.RUN_COMMAND and not self.config.allow_shell_commands:
            return {
                "allowed": False,
                "reason": "Shell commands are disabled on this worker. Set WILLIAM_WORKER_ALLOW_SHELL=true only on trusted devices.",
            }

        if task.action in {ActionType.DELETE_FILE, ActionType.MOVE_FILE} and not self.config.allow_destructive_actions:
            return {
                "allowed": False,
                "reason": "Destructive file actions are disabled. Set WILLIAM_WORKER_ALLOW_DESTRUCTIVE=true only on trusted devices.",
            }

        if task.action in {ActionType.SHUTDOWN, ActionType.RESTART, ActionType.SLEEP} and not self.config.allow_power_actions:
            return {
                "allowed": False,
                "reason": "Power actions are disabled. Set WILLIAM_WORKER_ALLOW_POWER=true only on trusted devices.",
            }

        if role in {"viewer", "read_only"} and self.action_risk(task.action) in {
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        }:
            return {
                "allowed": False,
                "reason": "Viewer/read-only role cannot execute high-risk Windows actions.",
            }

        return {"allowed": True, "reason": "Permission check passed."}

    def check_security(self, task: WorkerTask) -> dict[str, Any]:
        """
        Security Agent approval gate.

        High and critical risk actions require security.approved == True.
        """
        risk = self.action_risk(task.action)
        security = task.security or {}

        if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            if not security.get("approved"):
                return {
                    "allowed": False,
                    "reason": f"{risk.value} risk action requires Security Agent approval.",
                }

            approved_scope = security.get("scope") or {}
            if approved_scope:
                if approved_scope.get("user_id") and approved_scope.get("user_id") != task.user_id:
                    return {"allowed": False, "reason": "Security approval user scope mismatch."}
                if approved_scope.get("workspace_id") and approved_scope.get("workspace_id") != task.workspace_id:
                    return {"allowed": False, "reason": "Security approval workspace scope mismatch."}
                if approved_scope.get("task_id") and approved_scope.get("task_id") != task.task_id:
                    return {"allowed": False, "reason": "Security approval task scope mismatch."}

        return {"allowed": True, "reason": "Security check passed."}

    def action_risk(self, action: ActionType) -> RiskLevel:
        """Return risk level for action."""
        return self.ACTION_RISK.get(action, RiskLevel.HIGH)

    # -------------------------------------------------------------------------
    # Action handlers
    # -------------------------------------------------------------------------

    def _handle_noop(self, task: WorkerTask) -> dict[str, Any]:
        return self.success_response(
            "No operation executed.",
            {
                "action": task.action.value,
                "dry_run": self.config.dry_run,
            },
        )

    def _handle_heartbeat_action(self, task: WorkerTask) -> dict[str, Any]:
        return self.heartbeat()

    def _handle_system_info(self, task: WorkerTask) -> dict[str, Any]:
        return self.success_response(
            "System info collected.",
            {
                "platform": self.platform_info(),
                "capabilities": self.capabilities(),
                "worker_id": self.device_id,
                "session_id": self.session_id,
                "status": self.status.value,
            },
        )

    def _handle_open_app(self, task: WorkerTask) -> dict[str, Any]:
        app = str(task.payload.get("app") or task.payload.get("name") or "").strip()
        args = task.payload.get("args") or []

        if not app:
            raise ValueError("payload.app is required.")

        command = self.resolve_app_command(app, args)

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: app open skipped.",
                {
                    "command": command,
                    "app": app,
                },
            )

        if len(command) == 1 and command[0].endswith(":"):
            os.startfile(command[0])  # type: ignore[attr-defined]
            return self.success_response("Windows protocol app opened.", {"app": app, "command": command})

        subprocess.Popen(command, shell=False)
        return self.success_response("App opened.", {"app": app, "command": command})

    def _handle_open_file(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path"))
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")

        if self.config.dry_run:
            return self.success_response("Dry-run: file open skipped.", {"path": str(path)})

        os.startfile(str(path))  # type: ignore[attr-defined]
        return self.success_response("File opened.", {"path": str(path)})

    def _handle_open_folder(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path"))
        if not path.exists():
            raise FileNotFoundError(f"Folder not found: {path}")

        if not path.is_dir():
            raise ValueError(f"Path is not a folder: {path}")

        if self.config.dry_run:
            return self.success_response("Dry-run: folder open skipped.", {"path": str(path)})

        os.startfile(str(path))  # type: ignore[attr-defined]
        return self.success_response("Folder opened.", {"path": str(path)})

    def _handle_aliased_open_app(self, task: WorkerTask, *, alias: str, args: Optional[list[str]] = None) -> dict[str, Any]:
        """Shared by the OPEN_MICROSOFT_STORE/OPEN_CHROME/OPEN_VSCODE/
        OPEN_NOTEPAD/OPEN_EXPLORER handlers below -- injects the known
        SAFE_APP_ALIASES key into the task's own payload, then reuses
        _handle_open_app's existing, already-tested resolve/launch logic
        rather than duplicating it per app."""
        task.payload["app"] = alias
        if args:
            task.payload["args"] = args
        return self._handle_open_app(task)

    def _handle_open_microsoft_store(self, task: WorkerTask) -> dict[str, Any]:
        return self._handle_aliased_open_app(task, alias="store")

    def _handle_open_chrome(self, task: WorkerTask) -> dict[str, Any]:
        return self._handle_aliased_open_app(task, alias="chrome")

    def _handle_open_vscode(self, task: WorkerTask) -> dict[str, Any]:
        return self._handle_aliased_open_app(task, alias="vscode", args=["."])

    def _handle_open_notepad(self, task: WorkerTask) -> dict[str, Any]:
        return self._handle_aliased_open_app(task, alias="notepad")

    def _handle_open_explorer(self, task: WorkerTask) -> dict[str, Any]:
        return self._handle_aliased_open_app(task, alias="explorer")

    def _handle_open_downloads_folder(self, task: WorkerTask) -> dict[str, Any]:
        task.payload["path"] = str(Path.home() / "Downloads")
        return self._handle_open_folder(task)

    def _handle_download_generated_file(self, task: WorkerTask) -> dict[str, Any]:
        """Honest failure when nothing real is reachable -- real file
        generation isn't built yet (a later phase), so this never fakes a
        successful download; it only ever succeeds once a real,
        server-populated download_url is actually present and fetchable."""
        download_url = task.payload.get("download_url")
        if not download_url:
            raise ValueError("No generated file is available to download yet.")

        filename = task.payload.get("filename") or Path(urlparse(download_url).path).name or "download"
        destination = Path.home() / "Downloads" / filename

        if self.config.dry_run:
            return self.success_response("Dry-run: download skipped.", {"download_url": download_url, "destination": str(destination)})

        request = Request(download_url, headers=self._headers(), method="GET")
        with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
            destination.write_bytes(response.read())

        return self.success_response("File downloaded.", {"download_url": download_url, "destination": str(destination)})

    def _handle_open_url(self, task: WorkerTask) -> dict[str, Any]:
        url = self.safe_url(task.payload.get("url"))
        browser = task.payload.get("browser")

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: URL open skipped.",
                {
                    "url": url,
                    "browser": browser,
                },
            )

        if browser:
            command = self.resolve_app_command(str(browser), [url])
            subprocess.Popen(command, shell=False)
        else:
            webbrowser.open(url, new=2)

        return self.success_response("URL opened.", {"url": url, "browser": browser})

    def _handle_search_web(self, task: WorkerTask) -> dict[str, Any]:
        query = str(task.payload.get("query") or "").strip()
        if not query:
            raise ValueError("payload.query is required.")

        engine = str(task.payload.get("engine") or "google").strip().lower()
        if engine == "bing":
            url = "https://www.bing.com/search?q=" + query.replace(" ", "+")
        elif engine == "duckduckgo":
            url = "https://duckduckgo.com/?q=" + query.replace(" ", "+")
        else:
            url = "https://www.google.com/search?q=" + query.replace(" ", "+")

        return self._handle_open_url(
            WorkerTask(
                task_id=task.task_id,
                user_id=task.user_id,
                workspace_id=task.workspace_id,
                action=ActionType.OPEN_URL,
                payload={"url": url},
                requested_by=task.requested_by,
                role=task.role,
                subscription_plan=task.subscription_plan,
                permissions=task.permissions,
                security=task.security,
                correlation_id=task.correlation_id,
                raw=task.raw,
            )
        )

    def _handle_run_command(self, task: WorkerTask) -> dict[str, Any]:
        command = task.payload.get("command")
        cwd_raw = task.payload.get("cwd")
        timeout = float(task.payload.get("timeout_seconds") or self.config.command_timeout_seconds)

        if not command:
            raise ValueError("payload.command is required.")

        if isinstance(command, str):
            command_list = command.strip().split()
        elif isinstance(command, list):
            command_list = [str(part) for part in command]
        else:
            raise ValueError("payload.command must be a string or list.")

        if not command_list:
            raise ValueError("Command cannot be empty.")

        cwd = self.safe_path(cwd_raw) if cwd_raw else None
        if cwd and not cwd.is_dir():
            raise ValueError("payload.cwd must be a directory.")

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: command execution skipped.",
                {
                    "command": command_list,
                    "cwd": str(cwd) if cwd else None,
                },
            )

        completed = subprocess.run(
            command_list,
            cwd=str(cwd) if cwd else None,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return {
            "ok": completed.returncode == 0,
            "message": "Command completed." if completed.returncode == 0 else "Command failed.",
            "returncode": completed.returncode,
            "stdout": completed.stdout[-8000:],
            "stderr": completed.stderr[-8000:],
            "command": command_list,
            "cwd": str(cwd) if cwd else None,
        }

    def _handle_list_directory(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path") or str(Path.home()))
        include_hidden = bool(task.payload.get("include_hidden", False))
        max_items = int(task.payload.get("max_items") or 200)

        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {path}")

        items: list[dict[str, Any]] = []

        for index, child in enumerate(path.iterdir()):
            if index >= max_items:
                break

            if not include_hidden and child.name.startswith("."):
                continue

            try:
                stat = child.stat()
                items.append(
                    {
                        "name": child.name,
                        "path": str(child),
                        "type": "directory" if child.is_dir() else "file",
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    }
                )
            except OSError:
                items.append(
                    {
                        "name": child.name,
                        "path": str(child),
                        "type": "unknown",
                        "error": "Could not read metadata.",
                    }
                )

        return self.success_response(
            "Directory listed.",
            {
                "path": str(path),
                "items": items,
                "count": len(items),
            },
        )

    def _handle_create_folder(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path"))
        parents = bool(task.payload.get("parents", True))
        exist_ok = bool(task.payload.get("exist_ok", True))

        if self.config.dry_run:
            return self.success_response("Dry-run: folder creation skipped.", {"path": str(path)})

        path.mkdir(parents=parents, exist_ok=exist_ok)
        return self.success_response("Folder created.", {"path": str(path)})

    def _handle_write_text_file(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path"))
        content = str(task.payload.get("content") or "")
        encoding = str(task.payload.get("encoding") or "utf-8")
        overwrite = bool(task.payload.get("overwrite", False))

        self.ensure_safe_text_file(path)

        size = len(content.encode(encoding, errors="ignore"))
        if size > self.config.max_text_write_bytes:
            raise ValueError("Text content exceeds max write size.")

        if path.exists() and not overwrite:
            raise FileExistsError("File already exists and overwrite=false.")

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: text file write skipped.",
                {
                    "path": str(path),
                    "size_bytes": size,
                    "overwrite": overwrite,
                },
            )

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding)
        return self.success_response(
            "Text file written.",
            {
                "path": str(path),
                "size_bytes": size,
            },
        )

    def _handle_read_text_file(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path"))
        encoding = str(task.payload.get("encoding") or "utf-8")

        self.ensure_safe_text_file(path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not path.is_file():
            raise ValueError("Path is not a file.")

        size = path.stat().st_size
        if size > self.config.max_text_read_bytes:
            raise ValueError("File exceeds max read size.")

        content = path.read_text(encoding=encoding, errors="replace")
        return self.success_response(
            "Text file read.",
            {
                "path": str(path),
                "size_bytes": size,
                "content": content,
            },
        )

    def _handle_copy_file(self, task: WorkerTask) -> dict[str, Any]:
        source = self.safe_path(task.payload.get("source"))
        destination = self.safe_path(task.payload.get("destination"))
        overwrite = bool(task.payload.get("overwrite", False))

        if not source.exists() or not source.is_file():
            raise FileNotFoundError(f"Source file not found: {source}")

        if destination.exists() and not overwrite:
            raise FileExistsError("Destination exists and overwrite=false.")

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: copy skipped.",
                {
                    "source": str(source),
                    "destination": str(destination),
                    "overwrite": overwrite,
                },
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return self.success_response(
            "File copied.",
            {
                "source": str(source),
                "destination": str(destination),
            },
        )

    def _handle_move_file(self, task: WorkerTask) -> dict[str, Any]:
        source = self.safe_path(task.payload.get("source"))
        destination = self.safe_path(task.payload.get("destination"))
        overwrite = bool(task.payload.get("overwrite", False))

        if not source.exists():
            raise FileNotFoundError(f"Source not found: {source}")

        if destination.exists() and not overwrite:
            raise FileExistsError("Destination exists and overwrite=false.")

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: move skipped.",
                {
                    "source": str(source),
                    "destination": str(destination),
                    "overwrite": overwrite,
                },
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        return self.success_response(
            "File moved.",
            {
                "source": str(source),
                "destination": str(destination),
            },
        )

    def _handle_delete_file(self, task: WorkerTask) -> dict[str, Any]:
        path = self.safe_path(task.payload.get("path"))
        recursive = bool(task.payload.get("recursive", False))

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        if self.config.dry_run:
            return self.success_response(
                "Dry-run: delete skipped.",
                {
                    "path": str(path),
                    "recursive": recursive,
                },
            )

        if path.is_dir():
            if not recursive:
                raise ValueError("Directory deletion requires recursive=true.")
            shutil.rmtree(path)
        else:
            path.unlink()

        return self.success_response("Path deleted.", {"path": str(path), "recursive": recursive})

    def _handle_screen_lock(self, task: WorkerTask) -> dict[str, Any]:
        if self.config.dry_run:
            return self.success_response("Dry-run: screen lock skipped.", {})

        ctypes.windll.user32.LockWorkStation()
        return self.success_response("Windows screen locked.", {})

    def _handle_shutdown(self, task: WorkerTask) -> dict[str, Any]:
        delay = int(task.payload.get("delay_seconds") or 30)
        if self.config.dry_run:
            return self.success_response("Dry-run: shutdown skipped.", {"delay_seconds": delay})

        subprocess.Popen(["shutdown", "/s", "/t", str(delay)], shell=False)
        return self.success_response("Shutdown scheduled.", {"delay_seconds": delay})

    def _handle_restart(self, task: WorkerTask) -> dict[str, Any]:
        delay = int(task.payload.get("delay_seconds") or 30)
        if self.config.dry_run:
            return self.success_response("Dry-run: restart skipped.", {"delay_seconds": delay})

        subprocess.Popen(["shutdown", "/r", "/t", str(delay)], shell=False)
        return self.success_response("Restart scheduled.", {"delay_seconds": delay})

    def _handle_sleep(self, task: WorkerTask) -> dict[str, Any]:
        if self.config.dry_run:
            return self.success_response("Dry-run: sleep skipped.", {})

        ctypes.windll.PowrProf.SetSuspendState(False, True, False)
        return self.success_response("Sleep requested.", {})

    # -------------------------------------------------------------------------
    # Path, app, URL safety
    # -------------------------------------------------------------------------

    def safe_path(self, value: Any) -> Path:
        """Resolve and validate path inside allowed roots."""
        if not value:
            raise ValueError("Path is required.")

        path = Path(str(value)).expanduser().resolve()

        allowed_roots = [Path(root).expanduser().resolve() for root in self.config.allowed_root_dirs]
        if not allowed_roots:
            raise PermissionError("No allowed root directories configured.")

        if not any(self.is_relative_to(path, root) for root in allowed_roots):
            raise PermissionError(
                f"Path is outside allowed roots. Configure WILLIAM_WORKER_ALLOWED_ROOTS if needed. Path: {path}"
            )

        return path

    @staticmethod
    def is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def ensure_safe_text_file(self, path: Path) -> None:
        """Allow only common text files for read/write text operations."""
        suffix = path.suffix.lower()

        if path.name.lower().endswith(".env.example"):
            return

        if suffix not in self.SAFE_TEXT_EXTENSIONS:
            raise PermissionError(f"Unsupported text file extension: {suffix or '[none]'}")

    def safe_url(self, value: Any) -> str:
        """Validate URL before opening."""
        url = str(value or "").strip()
        if not url:
            raise ValueError("URL is required.")

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise PermissionError("Only http/https URLs are allowed.")

        if not parsed.netloc:
            raise ValueError("URL must include a host.")

        return url

    def resolve_app_command(self, app: str, args: Any = None) -> list[str]:
        """Resolve app alias or executable into a subprocess command."""
        args_list = [str(item) for item in args] if isinstance(args, list) else []

        normalized = app.strip().lower()
        alias = self.SAFE_APP_ALIASES.get(normalized)

        if alias:
            return alias + args_list

        if app.lower().endswith(".exe"):
            executable = shutil.which(app)
            if executable:
                return [executable] + args_list

        raise PermissionError(
            f"App is not in safe aliases or PATH: {app}. Add a safe alias in WindowsWorker.SAFE_APP_ALIASES."
        )

    # -------------------------------------------------------------------------
    # Reports and payloads
    # -------------------------------------------------------------------------

    def report_task_result(
        self,
        task: WorkerTask,
        status: TaskStatus,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Send task result to control plane. The real backend route only
        understands two outcomes (completed/failed) -- every other
        WorkerTask-local status (rejected/waiting_security/cancelled/
        skipped) is honestly reported as failed with a real error_code
        explaining why, never silently dropped or reported as completed."""
        is_completed = status == TaskStatus.COMPLETED
        sanitized_result = self.sanitize_payload(result)

        payload: dict[str, Any] = {
            "status": "completed" if is_completed else "failed",
            "device_id": self.device_id,
        }
        if is_completed:
            payload["result_message"] = sanitized_result.get("message") or "Action completed."
        else:
            payload["error_code"] = status.value
            payload["error_details"] = sanitized_result.get("message") or json.dumps(sanitized_result)[:2000]

        return self._post(f"/system/worker/tasks/{task.task_id}/result", payload)

    def prepare_security_payload(self, task: WorkerTask) -> dict[str, Any]:
        """Prepare Security Agent review payload."""
        return self.sanitize_payload(
            {
                "worker_id": self.device_id,
                "session_id": self.session_id,
                "task_id": task.task_id,
                "user_id": task.user_id,
                "workspace_id": task.workspace_id,
                "action": task.action.value,
                "risk_level": self.action_risk(task.action).value,
                "payload_summary": task.payload,
                "requested_by": task.requested_by,
                "role": task.role,
                "correlation_id": task.correlation_id,
                "reason": "Windows worker action requires Security Agent approval.",
                "created_at": iso_now(),
            }
        )

    def prepare_verification_payload(
        self,
        task: WorkerTask,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prepare Verification Agent confirmation payload."""
        return self.sanitize_payload(
            {
                "verification_id": generate_id("ver"),
                "worker_id": self.device_id,
                "session_id": self.session_id,
                "task_id": task.task_id,
                "user_id": task.user_id,
                "workspace_id": task.workspace_id,
                "action": task.action.value,
                "risk_level": self.action_risk(task.action).value,
                "result_ok": bool(result.get("ok")),
                "result_hash": self.compute_hash(result),
                "correlation_id": task.correlation_id,
                "completed_at": iso_now(),
            }
        )

    def prepare_memory_context(
        self,
        task: WorkerTask,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prepare Memory Agent-compatible context."""
        return self.sanitize_payload(
            {
                "type": "windows_worker_action",
                "worker_id": self.device_id,
                "task_id": task.task_id,
                "user_id": task.user_id,
                "workspace_id": task.workspace_id,
                "action": task.action.value,
                "risk_level": self.action_risk(task.action).value,
                "result_ok": bool(result.get("ok")),
                "summary": result.get("message"),
                "correlation_id": task.correlation_id,
                "created_at": iso_now(),
            }
        )

    def prepare_audit_payload(
        self,
        task: WorkerTask,
        result: Mapping[str, Any],
        started_at: datetime,
    ) -> dict[str, Any]:
        """Prepare audit-friendly payload."""
        return self.sanitize_payload(
            {
                "worker_id": self.device_id,
                "session_id": self.session_id,
                "device_name": self.config.device_name,
                "task_id": task.task_id,
                "user_id": task.user_id,
                "workspace_id": task.workspace_id,
                "action": task.action.value,
                "risk_level": self.action_risk(task.action).value,
                "requested_by": task.requested_by,
                "role": task.role,
                "subscription_plan": task.subscription_plan,
                "correlation_id": task.correlation_id,
                "result_ok": bool(result.get("ok")),
                "result_hash": self.compute_hash(result),
                "dry_run": self.config.dry_run,
                "started_at": started_at.isoformat(),
                "completed_at": iso_now(),
                "duration_ms": self.duration_ms(started_at),
            }
        )

    def record_event(
        self,
        event_type: WorkerEventType,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Record local audit event and optionally send it to control plane."""
        event = self.sanitize_payload(
            {
                "event_id": generate_id("wevt"),
                "worker_id": self.device_id,
                "session_id": self.session_id,
                "event_type": event_type.value,
                "status": self.status.value,
                "payload": payload or {},
                "created_at": iso_now(),
            }
        )

        self.audit_events.append(event)
        if len(self.audit_events) > 500:
            self.audit_events = self.audit_events[-500:]

        try:
            self._post("/system/worker/events", event, fail_silently=True)
        except Exception:
            pass

        return event

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": self.config.user_agent,
            "X-Worker-ID": self.device_id,
            "X-Worker-Session-ID": self.session_id,
        }

        # An installed worker's device_token (durable, revocable) takes
        # priority over a dev-mode user JWT (worker_token) if somehow both
        # are set -- the backend tells them apart by hash lookup either way
        # (apps/api/routes/device_setup.py::get_worker_auth_context), but
        # preferring the device token here matches "installed worker mode"
        # being the intended steady state once setup is done.
        effective_token = self.config.device_token or self.config.worker_token
        if effective_token:
            headers["Authorization"] = f"Bearer {effective_token}"

        return headers

    def _post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        fail_silently: bool = False,
    ) -> dict[str, Any]:
        if self.http_client:
            return self._unwrap_envelope(self.http_client("POST", path, payload))

        if not self.config.api_base_url:
            return {
                "ok": True,
                "offline_mode": True,
                "message": "No API base URL configured. Skipped POST.",
                "path": path,
            }

        url = f"{self.config.api_base_url}{path}"
        body = json.dumps(self.sanitize_payload(payload)).encode("utf-8")
        request = Request(url, data=body, headers=self._headers(), method="POST")

        try:
            with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                return self._decode_http_response(response.read())
        except HTTPError as exc:
            if fail_silently:
                return {"ok": False, "error": str(exc)}
            if exc.code == 401:
                raise DeviceAuthError(f"POST {path} failed: {exc}") from exc
            raise RuntimeError(f"POST {path} failed: {exc}") from exc
        except (URLError, TimeoutError) as exc:
            if fail_silently:
                return {"ok": False, "error": str(exc)}
            raise RuntimeError(f"POST {path} failed: {exc}") from exc

    def _get(
        self,
        path: str,
        *,
        query: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        if self.http_client:
            return self._unwrap_envelope(self.http_client("GET", path, query or {}))

        if not self.config.api_base_url:
            return {
                "ok": True,
                "offline_mode": True,
                "message": "No API base URL configured. Skipped GET.",
                "path": path,
                "task": None,
            }

        query_string = ""
        if query:
            query_string = "?" + "&".join(f"{key}={value}" for key, value in query.items())

        url = f"{self.config.api_base_url}{path}{query_string}"
        request = Request(url, headers=self._headers(), method="GET")

        try:
            with urlopen(request, timeout=self.config.request_timeout_seconds) as response:
                return self._decode_http_response(response.read())
        except HTTPError as exc:
            if exc.code == 401:
                raise DeviceAuthError(f"GET {path} failed: {exc}") from exc
            raise RuntimeError(f"GET {path} failed: {exc}") from exc
        except (URLError, TimeoutError) as exc:
            raise RuntimeError(f"GET {path} failed: {exc}") from exc

    @staticmethod
    def _decode_http_response(raw: bytes) -> dict[str, Any]:
        if not raw:
            return {"ok": True}
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {"ok": True, "raw": raw.decode("utf-8", errors="replace")}

        if not isinstance(decoded, dict):
            return {"ok": True, "data": decoded}

        return WindowsWorker._unwrap_envelope(decoded)

    @staticmethod
    def _unwrap_envelope(decoded: Mapping[str, Any]) -> dict[str, Any]:
        """Real backend routes (apps/api/routes/system_worker.py) always
        answer with the William/Jarvis {success, message, data, error,
        metadata} envelope, not the {ok, ...} shape the rest of this file
        was originally written against. Called from BOTH the real urlopen
        path (_decode_http_response) AND the http_client test-injection
        path in _post/_get, so a test double returning a real envelope
        (matching what the actual backend sends) behaves identically to a
        live network call -- every other method (poll_task/
        register_device/heartbeat/report_task_result) keeps using
        response.get("ok")/response.get(field) unchanged, while still
        reading real values out of "data"."""
        if not isinstance(decoded, dict) or "success" not in decoded:
            return dict(decoded) if isinstance(decoded, dict) else {"ok": True, "data": decoded}

        unwrapped: dict[str, Any] = {"ok": bool(decoded.get("success"))}
        data = decoded.get("data")
        if isinstance(data, dict):
            unwrapped.update(data)
        if not decoded.get("success"):
            error = decoded.get("error") or {}
            unwrapped["error"] = (error.get("code") if isinstance(error, dict) else None) or decoded.get("message")
        unwrapped["_envelope"] = decoded
        return unwrapped

    # -------------------------------------------------------------------------
    # Utility helpers
    # -------------------------------------------------------------------------

    @classmethod
    def sanitize_payload(cls, payload: Any, depth: int = 0) -> Any:
        """Redact secrets and make payload JSON-safe."""
        if depth > 8:
            return "[MAX_DEPTH_REACHED]"

        if payload is None or isinstance(payload, (str, int, float, bool)):
            return payload

        if isinstance(payload, datetime):
            return payload.isoformat()

        if isinstance(payload, Enum):
            return payload.value

        if isinstance(payload, Mapping):
            safe: dict[str, Any] = {}
            for raw_key, raw_value in payload.items():
                key = str(raw_key)
                normalized = key.lower().replace("-", "_").replace(" ", "_")
                if normalized in cls.SENSITIVE_KEYS or any(item in normalized for item in cls.SENSITIVE_KEYS):
                    safe[key] = cls.SECRET_REDACTION
                else:
                    safe[key] = cls.sanitize_payload(raw_value, depth + 1)
            return safe

        if isinstance(payload, (list, tuple, set, frozenset)):
            return [cls.sanitize_payload(item, depth + 1) for item in payload]

        return str(payload)

    @classmethod
    def compute_hash(cls, payload: Any) -> str:
        safe = cls.sanitize_payload(payload)
        serialized = json.dumps(safe, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def duration_ms(started_at: datetime) -> int:
        return int((utc_now() - started_at).total_seconds() * 1000)

    def platform_info(self) -> dict[str, Any]:
        """Return safe platform details."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "hostname": socket.gethostname(),
            "is_windows": platform.system().lower() == "windows",
            "is_admin": self.is_admin(),
        }

    @staticmethod
    def is_admin() -> bool:
        """Return whether current process has Windows admin rights."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def capabilities(self) -> dict[str, Any]:
        """Return worker capabilities."""
        return {
            "actions": [action.value for action in ActionType],
            "dry_run": self.config.dry_run,
            "allow_shell_commands": self.config.allow_shell_commands,
            "allow_destructive_actions": self.config.allow_destructive_actions,
            "allow_power_actions": self.config.allow_power_actions,
            "allowed_root_dirs": list(self.config.allowed_root_dirs),
            "max_text_read_bytes": self.config.max_text_read_bytes,
            "max_text_write_bytes": self.config.max_text_write_bytes,
            "safe_app_aliases": sorted(self.SAFE_APP_ALIASES.keys()),
            "safe_text_extensions": sorted(self.SAFE_TEXT_EXTENSIONS),
        }

    @classmethod
    def safe_error_response(
        cls,
        *,
        code: str,
        message: str,
        task_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        response = {
            "ok": False,
            "error": {
                "code": code,
                "message": message,
                "task_id": task_id,
                "correlation_id": correlation_id,
            },
        }
        if data:
            response["data"] = cls.sanitize_payload(data)
        return response

    @classmethod
    def success_response(
        cls,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        return {
            "ok": True,
            "message": message,
            "data": cls.sanitize_payload(data or {}),
        }

    def install_signal_handlers(self) -> None:
        """Install Ctrl+C / termination handlers."""

        def _handler(signum: int, frame: Any) -> None:
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except Exception:
            pass


def build_demo_task(action: str, payload: Mapping[str, Any]) -> WorkerTask:
    """Create a local demo task for CLI testing."""
    return WorkerTask(
        task_id=generate_id("task"),
        user_id="demo_user",
        workspace_id="demo_workspace",
        action=WindowsWorker.coerce_action(action),
        payload=WindowsWorker.sanitize_payload(payload),
        requested_by="local_cli",
        role="owner",
        subscription_plan="dev",
        permissions={"allowed_actions": [item.value for item in ActionType]},
        security={
            "approved": True,
            "scope": {
                "user_id": "demo_user",
                "workspace_id": "demo_workspace",
            },
        },
        correlation_id=generate_id("corr"),
        raw={
            "source": "local_cli",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "action": action,
            "payload": payload,
        },
    )


def main() -> int:
    """CLI entrypoint for local testing."""
    parser = argparse.ArgumentParser(description="William/Jarvis Windows Worker")
    parser.add_argument("--run", action="store_true", help="Run polling worker loop.")
    parser.add_argument("--register", action="store_true", help="Register device and exit.")
    parser.add_argument("--heartbeat", action="store_true", help="Send heartbeat and exit.")
    parser.add_argument("--demo-action", type=str, help="Run one local demo action.")
    parser.add_argument("--payload-json", type=str, default="{}", help="JSON payload for demo action.")
    parser.add_argument("--dry-run", action="store_true", help="Force dry-run mode.")
    parser.add_argument("--token", type=str, default=None, help="Real JWT access token (overrides WILLIAM_WORKER_TOKEN).")
    parser.add_argument("--device-token", type=str, default=None, help="Installed-worker device token from POST /system/device/register (overrides WILLIAM_WORKER_DEVICE_TOKEN).")
    parser.add_argument("--api-base-url", type=str, default=None, help="Backend API base URL, e.g. http://localhost:8001/api/v1 (overrides WILLIAM_WORKER_API_BASE_URL).")
    parser.add_argument("--device-name", type=str, default=None, help='Display name for this device, e.g. "Roshan Windows Laptop" (overrides WILLIAM_WORKER_DEVICE_NAME).')
    parser.add_argument("--config", type=str, default=None, help='Path to a JSON config file (scripts/windows/install_windows_worker.ps1 writes one to %%USERPROFILE%%\\.william\\windows_worker.json) with api_base_url/device_id/device_token/device_name.')
    args = parser.parse_args()

    config = WorkerConfig()

    # Config-file values apply first (lowest priority) -- explicit CLI
    # flags below always override them, matching --token/--api-base-url/
    # --device-name's existing precedence over env vars.
    if args.config:
        config.config_path = args.config
        try:
            with open(args.config, "r", encoding="utf-8") as config_file:
                file_config = json.load(config_file)
            if not isinstance(file_config, dict):
                raise ValueError("Config file must contain a JSON object.")
            if file_config.get("api_base_url"):
                config.api_base_url = str(file_config["api_base_url"]).rstrip("/")
            if file_config.get("device_token"):
                config.device_token = str(file_config["device_token"])
            if file_config.get("device_name"):
                config.device_name = str(file_config["device_name"])
            if file_config.get("device_id"):
                config.worker_id = str(file_config["device_id"])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"[worker] could not read config file {args.config}: {exc}", flush=True)
            return 1

    if args.dry_run:
        config.dry_run = True
    if args.token:
        config.worker_token = args.token
    if args.device_token:
        config.device_token = args.device_token
    if args.api_base_url:
        config.api_base_url = args.api_base_url.rstrip("/")
    if args.device_name:
        config.device_name = args.device_name

    worker = WindowsWorker(config=config)

    if args.register:
        print(json.dumps(worker.register_device(), indent=2))
        return 0

    if args.heartbeat:
        print(json.dumps(worker.heartbeat(), indent=2))
        return 0

    if args.demo_action:
        try:
            payload = json.loads(args.payload_json)
            if not isinstance(payload, dict):
                raise ValueError("payload-json must decode to an object.")
            task = build_demo_task(args.demo_action, payload)
            print(json.dumps(worker.execute_task(task), indent=2))
            return 0
        except Exception as exc:
            print(
                json.dumps(
                    WindowsWorker.safe_error_response(
                        code="demo_action_failed",
                        message=str(exc),
                    ),
                    indent=2,
                )
            )
            return 1

    # A real token (JWT dev mode OR an installed worker's device token) +
    # api-base-url with no other explicit one-shot flag means "run live" --
    # matches the documented dev command:
    #   python -m apps.worker_nodes.windows.windows_worker --token <JWT>
    #     --api-base-url http://localhost:8001/api/v1 --device-name "..."
    # as well as the installed-worker command:
    #   python -m apps.worker_nodes.windows.windows_worker --config <path>
    # (no --run needed in either case).
    should_run = args.run or (
        (bool(config.worker_token) or bool(config.device_token)) and bool(config.api_base_url)
    )

    if should_run:
        worker.run_forever()
        return 0

    print(json.dumps(worker.success_response("WindowsWorker ready.", worker.capabilities()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())