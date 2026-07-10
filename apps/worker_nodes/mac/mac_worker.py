"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Device Worker: macOS Worker
File: apps/worker_nodes/mac/mac_worker.py

Purpose:
    macOS device worker with AppleScript / automation hooks for safe local actions.

Capabilities:
    - Register macOS worker device
    - Heartbeat and health payloads
    - Stop / resume local worker execution
    - Poll and execute task payloads
    - Open, focus, quit macOS apps
    - List running apps
    - List visible windows via System Events
    - Run approved AppleScript templates
    - Prepare Security Agent approval payloads
    - Prepare Verification Agent completion payloads
    - Prepare Memory Agent compatible summaries
    - Emit audit-safe structured action reports

Security design:
    - Every task requires user_id and workspace_id.
    - No cross-user/workspace execution context is allowed.
    - Raw arbitrary AppleScript execution is disabled by default.
    - Sensitive automation actions route to Security Agent.
    - Commands are executed with shell=False.
    - No secrets are hardcoded.
    - Payloads are sanitized before returning/logging.
    - This file imports safely on non-macOS systems.

Environment variables:
    WILLIAM_MAC_WORKER_ALLOWED_ROLES
    WILLIAM_MAC_WORKER_ALLOWED_PLANS
    WILLIAM_MAC_WORKER_ALLOW_RAW_APPLESCRIPT
    WILLIAM_MAC_WORKER_DRY_RUN
    WILLIAM_MAC_WORKER_APP_ALIASES_JSON
    WILLIAM_MAC_WORKER_SCRIPT_TEMPLATES_JSON
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


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Return current UTC timestamp as ISO string."""
    return utc_now().isoformat()


def generate_id(prefix: str = "id") -> str:
    """Return a unique portable ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_text(value: Any, *, max_length: int = 1000) -> str:
    """Normalize user / worker text safely."""
    if value is None:
        return ""
    cleaned = " ".join(str(value).strip().split())
    return cleaned[:max_length]


def json_safe(value: Any, *, depth: int = 0) -> Any:
    """Convert arbitrary data into JSON-safe sanitized values."""
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
        safe: Dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower().replace("-", "_").replace(" ", "_")
            if any(term in lowered for term in blocked):
                safe[key] = "[REDACTED]"
            else:
                safe[key] = json_safe(raw_value, depth=depth + 1)
        return safe

    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item, depth=depth + 1) for item in value]

    return str(value)


def stable_hash(payload: Mapping[str, Any]) -> str:
    """Create a deterministic SHA-256 hash for audit/evidence payloads."""
    raw = json.dumps(json_safe(payload), sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def applescript_quote(value: Any) -> str:
    """
    Quote a value for AppleScript string usage.

    This is not used for arbitrary shell construction. It is only used inside
    fixed AppleScript templates.
    """
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


class MacAction(str, enum.Enum):
    """Supported mac worker actions."""

    REGISTER_DEVICE = "register_device"
    HEARTBEAT = "heartbeat"
    STOP = "stop"
    RESUME = "resume"
    OPEN_APP = "open_app"
    FOCUS_APP = "focus_app"
    QUIT_APP = "quit_app"
    LIST_APPS = "list_apps"
    LIST_WINDOWS = "list_windows"
    RUN_TEMPLATE = "run_template"
    RUN_APPLESCRIPT = "run_applescript"


class ActionStatus(str, enum.Enum):
    """Worker action status."""

    SUCCESS = "success"
    ERROR = "error"
    DENIED = "denied"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    UNSUPPORTED = "unsupported"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"


class WorkerState(str, enum.Enum):
    """Local worker lifecycle state."""

    READY = "ready"
    BUSY = "busy"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


class RiskLevel(str, enum.Enum):
    """Risk level for local automation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScriptKind(str, enum.Enum):
    """AppleScript execution mode."""

    TEMPLATE = "template"
    RAW = "raw"


@dataclasses.dataclass(frozen=True)
class TaskContext:
    """Required tenant/task context for every worker action."""

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
            raise ValueError("user_id is required for macOS worker actions.")
        if not safe_workspace_id:
            raise ValueError("workspace_id is required for macOS worker actions.")

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
class MacAppTarget:
    """Resolved macOS application target."""

    requested_name: str
    app_name: str
    bundle_id: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.LOW
    source: str = "alias"


@dataclasses.dataclass(frozen=True)
class AppleScriptResult:
    """AppleScript execution result."""

    ok: bool
    stdout: str
    stderr: str
    returncode: int
    elapsed_ms: int
    script_hash: str


@dataclasses.dataclass(frozen=True)
class WorkerRegistration:
    """Device registration payload."""

    device_id: str
    worker_id: str
    hostname: str
    os_name: str
    os_version: str
    machine: str
    python_version: str
    supported_actions: List[str]
    user_id: str
    workspace_id: str
    registered_at: str
    metadata: Dict[str, Any]


class MacWorker:
    """
    macOS worker node with safe AppleScript / automation hooks.

    Main methods:
        - register_device()
        - heartbeat()
        - stop()
        - resume()
        - open_app()
        - focus_app()
        - quit_app()
        - list_running_apps()
        - list_windows()
        - run_template()
        - run_applescript()
        - poll_task()

    Raw AppleScript is disabled by default and should only be enabled for trusted
    local development or after Security Agent approval.
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

    DEFAULT_APP_ALIASES: Dict[str, Dict[str, Any]] = {
        "finder": {"app_name": "Finder", "bundle_id": "com.apple.finder", "risk_level": "medium"},
        "safari": {"app_name": "Safari", "bundle_id": "com.apple.Safari", "risk_level": "medium"},
        "chrome": {"app_name": "Google Chrome", "bundle_id": "com.google.Chrome", "risk_level": "medium"},
        "google chrome": {"app_name": "Google Chrome", "bundle_id": "com.google.Chrome", "risk_level": "medium"},
        "firefox": {"app_name": "Firefox", "bundle_id": "org.mozilla.firefox", "risk_level": "medium"},
        "terminal": {"app_name": "Terminal", "bundle_id": "com.apple.Terminal", "risk_level": "high"},
        "iterm": {"app_name": "iTerm", "bundle_id": "com.googlecode.iterm2", "risk_level": "high"},
        "iterm2": {"app_name": "iTerm", "bundle_id": "com.googlecode.iterm2", "risk_level": "high"},
        "vscode": {"app_name": "Visual Studio Code", "bundle_id": "com.microsoft.VSCode", "risk_level": "medium"},
        "visual studio code": {"app_name": "Visual Studio Code", "bundle_id": "com.microsoft.VSCode", "risk_level": "medium"},
        "textedit": {"app_name": "TextEdit", "bundle_id": "com.apple.TextEdit", "risk_level": "low"},
        "notes": {"app_name": "Notes", "bundle_id": "com.apple.Notes", "risk_level": "medium"},
        "calendar": {"app_name": "Calendar", "bundle_id": "com.apple.iCal", "risk_level": "medium"},
        "mail": {"app_name": "Mail", "bundle_id": "com.apple.mail", "risk_level": "high"},
        "messages": {"app_name": "Messages", "bundle_id": "com.apple.MobileSMS", "risk_level": "high"},
        "system settings": {"app_name": "System Settings", "bundle_id": "com.apple.systempreferences", "risk_level": "high"},
        "settings": {"app_name": "System Settings", "bundle_id": "com.apple.systempreferences", "risk_level": "high"},
        "activity monitor": {"app_name": "Activity Monitor", "bundle_id": "com.apple.ActivityMonitor", "risk_level": "high"},
        "preview": {"app_name": "Preview", "bundle_id": "com.apple.Preview", "risk_level": "low"},
        "photos": {"app_name": "Photos", "bundle_id": "com.apple.Photos", "risk_level": "medium"},
        "music": {"app_name": "Music", "bundle_id": "com.apple.Music", "risk_level": "medium"},
    }

    DEFAULT_SCRIPT_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "say_text": {
            "risk_level": "low",
            "description": "Speak text using macOS say command through AppleScript.",
            "required_params": ["text"],
            "script": 'say {text}',
        },
        "show_notification": {
            "risk_level": "low",
            "description": "Show a macOS notification.",
            "required_params": ["title", "message"],
            "script": 'display notification {message} with title {title}',
        },
        "open_url": {
            "risk_level": "medium",
            "description": "Open a URL in the default browser.",
            "required_params": ["url"],
            "script": 'open location {url}',
        },
        "new_textedit_document": {
            "risk_level": "medium",
            "description": "Create a new TextEdit document with safe text.",
            "required_params": ["text"],
            "script": (
                'tell application "TextEdit"\n'
                "activate\n"
                "make new document\n"
                "set text of front document to {text}\n"
                "end tell"
            ),
        },
        "get_front_app": {
            "risk_level": "low",
            "description": "Return frontmost application name.",
            "required_params": [],
            "script": (
                'tell application "System Events"\n'
                'set frontApp to name of first application process whose frontmost is true\n'
                "end tell\n"
                "return frontApp"
            ),
        },
    }

    HIGH_RISK_APPS = {
        "terminal",
        "iterm",
        "iterm2",
        "mail",
        "messages",
        "system settings",
        "settings",
        "activity monitor",
        "keychain access",
        "script editor",
        "automator",
    }

    def __init__(
        self,
        *,
        device_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        allowed_roles: Optional[Iterable[str]] = None,
        allowed_plans: Optional[Iterable[str]] = None,
        app_aliases: Optional[Mapping[str, Mapping[str, Any]]] = None,
        script_templates: Optional[Mapping[str, Mapping[str, Any]]] = None,
        allow_raw_applescript: Optional[bool] = None,
        dry_run: Optional[bool] = None,
        applescript_timeout_seconds: Optional[int] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        report_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.device_id = normalize_text(device_id, max_length=128) or os.getenv("WILLIAM_MAC_DEVICE_ID") or generate_id("mac_device")
        self.worker_id = normalize_text(worker_id, max_length=128) or os.getenv("WILLIAM_MAC_WORKER_ID") or generate_id("mac_worker")

        self.allowed_roles = {
            normalize_text(role).lower()
            for role in (allowed_roles or self._csv_env("WILLIAM_MAC_WORKER_ALLOWED_ROLES") or self.DEFAULT_ALLOWED_ROLES)
            if normalize_text(role)
        }

        self.allowed_plans = {
            normalize_text(plan).lower()
            for plan in (allowed_plans or self._csv_env("WILLIAM_MAC_WORKER_ALLOWED_PLANS") or self.DEFAULT_ALLOWED_PLANS)
            if normalize_text(plan)
        }

        self.allow_raw_applescript = (
            self._env_bool("WILLIAM_MAC_WORKER_ALLOW_RAW_APPLESCRIPT", False)
            if allow_raw_applescript is None
            else bool(allow_raw_applescript)
        )
        self.dry_run = (
            self._env_bool("WILLIAM_MAC_WORKER_DRY_RUN", False)
            if dry_run is None
            else bool(dry_run)
        )
        self.applescript_timeout_seconds = int(
            applescript_timeout_seconds
            if applescript_timeout_seconds is not None
            else os.getenv("WILLIAM_MAC_WORKER_APPLESCRIPT_TIMEOUT", "30")
        )

        self.audit_sink = audit_sink
        self.report_sink = report_sink

        merged_aliases = dict(self.DEFAULT_APP_ALIASES)
        merged_aliases.update(self._load_json_env("WILLIAM_MAC_WORKER_APP_ALIASES_JSON"))
        if app_aliases:
            for key, value in app_aliases.items():
                merged_aliases[normalize_text(key).lower()] = dict(value)
        self.app_aliases = merged_aliases

        merged_templates = dict(self.DEFAULT_SCRIPT_TEMPLATES)
        merged_templates.update(self._load_json_env("WILLIAM_MAC_WORKER_SCRIPT_TEMPLATES_JSON"))
        if script_templates:
            for key, value in script_templates.items():
                merged_templates[normalize_text(key).lower()] = dict(value)
        self.script_templates = merged_templates

        self._state = WorkerState.READY
        self._state_lock = threading.RLock()
        self._last_heartbeat_at: Optional[datetime] = None
        self._registered_context: Optional[TaskContext] = None

    @staticmethod
    def _csv_env(name: str) -> List[str]:
        raw = os.getenv(name, "")
        if not raw.strip():
            return []
        return [part.strip() for part in raw.split(",") if part.strip()]

    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _load_json_env(self, name: str) -> Dict[str, Dict[str, Any]]:
        raw = os.getenv(name, "").strip()
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
    def is_macos(self) -> bool:
        """Return True when running on macOS."""
        return platform.system().lower() == "darwin"

    @property
    def state(self) -> WorkerState:
        """Return local worker state."""
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
        """Register this macOS worker device for a user/workspace."""
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("registration"),
            agent_name="MacWorker",
        ).validate()

        access = self._check_permission(context=context, action=MacAction.REGISTER_DEVICE)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.REGISTER_DEVICE, context, access["reason"], {"access": access})

        registration = WorkerRegistration(
            device_id=self.device_id,
            worker_id=self.worker_id,
            hostname=socket.gethostname(),
            os_name=platform.system(),
            os_version=platform.version(),
            machine=platform.machine(),
            python_version=sys.version.split()[0],
            supported_actions=[item.value for item in MacAction],
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
            ActionStatus.SUCCESS,
            MacAction.REGISTER_DEVICE,
            context,
            "macOS worker registered.",
            {"registration": dataclasses.asdict(registration)},
        )

    def heartbeat(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        """Return a worker heartbeat payload."""
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("heartbeat"),
            agent_name="MacWorker",
        ).validate()

        access = self._check_permission(context=context, action=MacAction.HEARTBEAT)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.HEARTBEAT, context, access["reason"], {"access": access})

        self._last_heartbeat_at = utc_now()

        return self._result(
            ActionStatus.SUCCESS,
            MacAction.HEARTBEAT,
            context,
            "macOS worker heartbeat healthy.",
            {
                "device_id": self.device_id,
                "worker_id": self.worker_id,
                "state": self.state.value,
                "is_macos": self.is_macos,
                "hostname": socket.gethostname(),
                "last_heartbeat_at": self._last_heartbeat_at.isoformat(),
                "dry_run": self.dry_run,
                "allow_raw_applescript": self.allow_raw_applescript,
                "osascript_available": self._osascript_available(),
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
        """Stop local worker execution."""
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("stop"),
            agent_name="MacWorker",
        ).validate()

        access = self._check_permission(context=context, action=MacAction.STOP)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.STOP, context, access["reason"], {"access": access})

        with self._state_lock:
            self._state = WorkerState.STOPPED

        return self._result(
            ActionStatus.SUCCESS,
            MacAction.STOP,
            context,
            "macOS worker stopped safely.",
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
        """Resume local worker execution."""
        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            task_id=generate_id("resume"),
            agent_name="MacWorker",
        ).validate()

        access = self._check_permission(context=context, action=MacAction.RESUME)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.RESUME, context, access["reason"], {"access": access})

        with self._state_lock:
            self._state = WorkerState.READY

        return self._result(
            ActionStatus.SUCCESS,
            MacAction.RESUME,
            context,
            "macOS worker resumed safely.",
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
        security_approved: bool = False,
        wait_seconds: float = 0.5,
    ) -> Dict[str, Any]:
        """Open a macOS application by alias or name."""
        context = self._context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            requested_by=requested_by,
            role=role,
            plan=plan,
            agent_name=agent_name,
        )

        if not self._is_ready():
            return self._result(ActionStatus.SKIPPED, MacAction.OPEN_APP, context, f"Worker is {self.state.value}; action skipped.", {"worker_state": self.state.value})

        unsupported = self._platform_guard(MacAction.OPEN_APP, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.OPEN_APP)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.OPEN_APP, context, access["reason"], {"access": access})

        try:
            target = self.resolve_app_target(app_name)
        except Exception as exc:
            return self._error_result(MacAction.OPEN_APP, context, exc)

        security = self._security_gate(context=context, action=MacAction.OPEN_APP, target=target, security_approved=security_approved)
        if not security["allowed"]:
            return self._result(ActionStatus.SECURITY_REVIEW_REQUIRED, MacAction.OPEN_APP, context, security["reason"], {"security": security, "target": dataclasses.asdict(target)})

        if self.dry_run:
            return self._result(ActionStatus.SUCCESS, MacAction.OPEN_APP, context, "Dry run: app open simulated.", {"target": dataclasses.asdict(target), "dry_run": True})

        with self._state_lock:
            self._state = WorkerState.BUSY

        try:
            command = ["open"]
            if target.bundle_id:
                command += ["-b", target.bundle_id]
            else:
                command += ["-a", target.app_name]

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
                shell=False,
            )

            if wait_seconds > 0:
                time.sleep(min(float(wait_seconds), 10.0))

            if completed.returncode != 0:
                return self._result(
                    ActionStatus.ERROR,
                    MacAction.OPEN_APP,
                    context,
                    "Failed to open macOS application.",
                    {
                        "target": dataclasses.asdict(target),
                        "command": command,
                        "stderr": completed.stderr[-1000:],
                        "stdout": completed.stdout[-1000:],
                    },
                )

            return self._result(
                ActionStatus.SUCCESS,
                MacAction.OPEN_APP,
                context,
                "macOS application opened.",
                {
                    "target": dataclasses.asdict(target),
                    "command": command,
                    "stdout": completed.stdout[-1000:],
                },
            )
        except Exception as exc:
            return self._error_result(MacAction.OPEN_APP, context, exc)
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
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Bring a macOS application to the front."""
        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name=agent_name)

        if not self._is_ready():
            return self._result(ActionStatus.SKIPPED, MacAction.FOCUS_APP, context, f"Worker is {self.state.value}; action skipped.", {"worker_state": self.state.value})

        unsupported = self._platform_guard(MacAction.FOCUS_APP, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.FOCUS_APP)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.FOCUS_APP, context, access["reason"], {"access": access})

        try:
            target = self.resolve_app_target(app_name)
        except Exception as exc:
            return self._error_result(MacAction.FOCUS_APP, context, exc)

        security = self._security_gate(context=context, action=MacAction.FOCUS_APP, target=target, security_approved=security_approved)
        if not security["allowed"]:
            return self._result(ActionStatus.SECURITY_REVIEW_REQUIRED, MacAction.FOCUS_APP, context, security["reason"], {"security": security, "target": dataclasses.asdict(target)})

        script = f'tell application {applescript_quote(target.app_name)} to activate'

        if self.dry_run:
            return self._result(ActionStatus.SUCCESS, MacAction.FOCUS_APP, context, "Dry run: app focus simulated.", {"target": dataclasses.asdict(target), "script_hash": stable_hash({"script": script}), "dry_run": True})

        result = self._run_osascript(script)

        status = ActionStatus.SUCCESS if result.ok else ActionStatus.ERROR
        message = "macOS application focused." if result.ok else "Failed to focus macOS application."

        return self._result(
            status,
            MacAction.FOCUS_APP,
            context,
            message,
            {
                "target": dataclasses.asdict(target),
                "applescript": dataclasses.asdict(result),
            },
        )

    def quit_app(
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
        security_approved: bool = False,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Quit a macOS application. Force quit requires stronger review."""
        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name=agent_name)

        if not self._is_ready():
            return self._result(ActionStatus.SKIPPED, MacAction.QUIT_APP, context, f"Worker is {self.state.value}; action skipped.", {"worker_state": self.state.value})

        unsupported = self._platform_guard(MacAction.QUIT_APP, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.QUIT_APP)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.QUIT_APP, context, access["reason"], {"access": access})

        try:
            target = self.resolve_app_target(app_name)
        except Exception as exc:
            return self._error_result(MacAction.QUIT_APP, context, exc)

        security = self._security_gate(context=context, action=MacAction.QUIT_APP, target=target, security_approved=security_approved, force=force)
        if not security["allowed"]:
            return self._result(ActionStatus.SECURITY_REVIEW_REQUIRED, MacAction.QUIT_APP, context, security["reason"], {"security": security, "target": dataclasses.asdict(target), "force": force})

        if self.dry_run:
            return self._result(ActionStatus.SUCCESS, MacAction.QUIT_APP, context, "Dry run: app quit simulated.", {"target": dataclasses.asdict(target), "force": force, "dry_run": True})

        if force:
            command = ["pkill", "-x", target.app_name]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=20, shell=False)
                return self._result(
                    ActionStatus.SUCCESS if completed.returncode == 0 else ActionStatus.ERROR,
                    MacAction.QUIT_APP,
                    context,
                    "macOS application force quit requested." if completed.returncode == 0 else "Failed to force quit app.",
                    {"target": dataclasses.asdict(target), "command": command, "stdout": completed.stdout[-1000:], "stderr": completed.stderr[-1000:]},
                )
            except Exception as exc:
                return self._error_result(MacAction.QUIT_APP, context, exc)

        script = f'tell application {applescript_quote(target.app_name)} to quit'
        result = self._run_osascript(script)

        return self._result(
            ActionStatus.SUCCESS if result.ok else ActionStatus.ERROR,
            MacAction.QUIT_APP,
            context,
            "macOS application quit requested." if result.ok else "Failed to quit macOS application.",
            {"target": dataclasses.asdict(target), "applescript": dataclasses.asdict(result)},
        )

    def list_running_apps(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        """List running macOS app process names."""
        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name="MacWorker")

        unsupported = self._platform_guard(MacAction.LIST_APPS, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.LIST_APPS)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.LIST_APPS, context, access["reason"], {"access": access})

        script = (
            'tell application "System Events"\n'
            'set appNames to name of every application process whose background only is false\n'
            'return appNames\n'
            'end tell'
        )
        result = self._run_osascript(script)

        apps: List[str] = []
        if result.ok and result.stdout:
            apps = [normalize_text(item) for item in result.stdout.split(",") if normalize_text(item)]

        return self._result(
            ActionStatus.SUCCESS if result.ok else ActionStatus.ERROR,
            MacAction.LIST_APPS,
            context,
            "Running apps listed." if result.ok else "Failed to list running apps.",
            {"apps": apps, "applescript": dataclasses.asdict(result)},
        )

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
        """List visible windows from System Events."""
        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name="MacWorker")

        unsupported = self._platform_guard(MacAction.LIST_WINDOWS, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.LIST_WINDOWS)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.LIST_WINDOWS, context, access["reason"], {"access": access})

        script = (
            'tell application "System Events"\n'
            'set outputText to ""\n'
            'repeat with proc in application processes whose background only is false\n'
            'set procName to name of proc\n'
            'try\n'
            'repeat with win in windows of proc\n'
            'set winName to name of win\n'
            'if winName is not "" then set outputText to outputText & procName & "||" & winName & linefeed\n'
            'end repeat\n'
            'end try\n'
            'end repeat\n'
            'return outputText\n'
            'end tell'
        )
        result = self._run_osascript(script)

        windows: List[Dict[str, str]] = []
        if result.ok and result.stdout:
            for line in result.stdout.splitlines():
                if "||" in line:
                    app, title = line.split("||", 1)
                    windows.append({"app": normalize_text(app), "title": normalize_text(title)})

        return self._result(
            ActionStatus.SUCCESS if result.ok else ActionStatus.ERROR,
            MacAction.LIST_WINDOWS,
            context,
            "Visible windows listed." if result.ok else "Failed to list visible windows.",
            {"windows": windows, "applescript": dataclasses.asdict(result)},
        )

    def run_template(
        self,
        template_name: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
        agent_name: str = "SystemAgent",
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Run an allowlisted AppleScript template."""
        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name=agent_name)

        if not self._is_ready():
            return self._result(ActionStatus.SKIPPED, MacAction.RUN_TEMPLATE, context, f"Worker is {self.state.value}; action skipped.", {"worker_state": self.state.value})

        unsupported = self._platform_guard(MacAction.RUN_TEMPLATE, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.RUN_TEMPLATE)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.RUN_TEMPLATE, context, access["reason"], {"access": access})

        template_key = normalize_text(template_name).lower()
        template = self.script_templates.get(template_key)
        if not template:
            return self._result(
                ActionStatus.NOT_FOUND,
                MacAction.RUN_TEMPLATE,
                context,
                "AppleScript template not found.",
                {"template_name": template_name, "available_templates": sorted(self.script_templates.keys())},
            )

        template_risk = self._coerce_risk(template.get("risk_level", "medium"))
        security = self._security_gate(context=context, action=MacAction.RUN_TEMPLATE, script_kind=ScriptKind.TEMPLATE, template_name=template_key, risk_level=template_risk, security_approved=security_approved)
        if not security["allowed"]:
            return self._result(ActionStatus.SECURITY_REVIEW_REQUIRED, MacAction.RUN_TEMPLATE, context, security["reason"], {"security": security, "template_name": template_key})

        try:
            script = self._render_template(template_key, template, params or {})
        except Exception as exc:
            return self._error_result(MacAction.RUN_TEMPLATE, context, exc)

        if self.dry_run:
            return self._result(
                ActionStatus.SUCCESS,
                MacAction.RUN_TEMPLATE,
                context,
                "Dry run: AppleScript template execution simulated.",
                {"template_name": template_key, "script_hash": stable_hash({"script": script}), "dry_run": True},
            )

        with self._state_lock:
            self._state = WorkerState.BUSY

        try:
            result = self._run_osascript(script)
            return self._result(
                ActionStatus.SUCCESS if result.ok else ActionStatus.ERROR,
                MacAction.RUN_TEMPLATE,
                context,
                "AppleScript template executed." if result.ok else "AppleScript template failed.",
                {"template_name": template_key, "applescript": dataclasses.asdict(result)},
            )
        finally:
            with self._state_lock:
                if self._state == WorkerState.BUSY:
                    self._state = WorkerState.READY

    def run_applescript(
        self,
        script: str,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        role: str = "owner",
        plan: str = "pro",
        agent_name: str = "SystemAgent",
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Run raw AppleScript only when explicitly enabled and approved.

        Safer production pattern:
            Use run_template() instead of raw script execution.
        """
        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name=agent_name)

        if not self._is_ready():
            return self._result(ActionStatus.SKIPPED, MacAction.RUN_APPLESCRIPT, context, f"Worker is {self.state.value}; action skipped.", {"worker_state": self.state.value})

        unsupported = self._platform_guard(MacAction.RUN_APPLESCRIPT, context)
        if unsupported:
            return unsupported

        access = self._check_permission(context=context, action=MacAction.RUN_APPLESCRIPT)
        if not access["allowed"]:
            return self._result(ActionStatus.DENIED, MacAction.RUN_APPLESCRIPT, context, access["reason"], {"access": access})

        clean_script = str(script or "").strip()
        if not clean_script:
            return self._result(ActionStatus.ERROR, MacAction.RUN_APPLESCRIPT, context, "AppleScript cannot be empty.", {})

        if not self.allow_raw_applescript:
            security = self._security_gate(context=context, action=MacAction.RUN_APPLESCRIPT, script_kind=ScriptKind.RAW, risk_level=RiskLevel.CRITICAL, security_approved=security_approved)
            return self._result(
                ActionStatus.SECURITY_REVIEW_REQUIRED,
                MacAction.RUN_APPLESCRIPT,
                context,
                "Raw AppleScript is disabled by worker policy and requires explicit enablement plus Security Agent approval.",
                {"security": security, "script_hash": stable_hash({"script": clean_script})},
            )

        security = self._security_gate(context=context, action=MacAction.RUN_APPLESCRIPT, script_kind=ScriptKind.RAW, risk_level=RiskLevel.CRITICAL, security_approved=security_approved)
        if not security["allowed"]:
            return self._result(ActionStatus.SECURITY_REVIEW_REQUIRED, MacAction.RUN_APPLESCRIPT, context, security["reason"], {"security": security, "script_hash": stable_hash({"script": clean_script})})

        if self.dry_run:
            return self._result(ActionStatus.SUCCESS, MacAction.RUN_APPLESCRIPT, context, "Dry run: raw AppleScript execution simulated.", {"script_hash": stable_hash({"script": clean_script}), "dry_run": True})

        with self._state_lock:
            self._state = WorkerState.BUSY

        try:
            result = self._run_osascript(clean_script)
            return self._result(
                ActionStatus.SUCCESS if result.ok else ActionStatus.ERROR,
                MacAction.RUN_APPLESCRIPT,
                context,
                "Raw AppleScript executed." if result.ok else "Raw AppleScript failed.",
                {"applescript": dataclasses.asdict(result)},
            )
        finally:
            with self._state_lock:
                if self._state == WorkerState.BUSY:
                    self._state = WorkerState.READY

    def poll_task(self, task: Mapping[str, Any], *, security_approved: bool = False) -> Dict[str, Any]:
        """
        Execute one task payload from Master Agent / System Agent.

        Expected shape:
            {
                "action": "open_app|focus_app|quit_app|list_apps|list_windows|run_template|heartbeat|stop|resume",
                "app_name": "Safari",
                "template_name": "show_notification",
                "params": {"title": "William", "message": "Done"},
                "user_id": "...",
                "workspace_id": "...",
                "task_id": "...",
                "requested_by": "...",
                "role": "owner",
                "plan": "pro",
                "agent_name": "SystemAgent"
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

        if action == MacAction.OPEN_APP.value:
            return self.open_app(
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

        if action == MacAction.FOCUS_APP.value:
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

        if action == MacAction.QUIT_APP.value:
            return self.quit_app(
                normalize_text(safe_task.get("app_name")),
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                requested_by=requested_by,
                role=role,
                plan=plan,
                agent_name=agent_name,
                security_approved=security_approved,
                force=bool(safe_task.get("force", False)),
            )

        if action == MacAction.LIST_APPS.value:
            return self.list_running_apps(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan)

        if action == MacAction.LIST_WINDOWS.value:
            return self.list_windows(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan)

        if action == MacAction.RUN_TEMPLATE.value:
            params = safe_task.get("params") if isinstance(safe_task.get("params"), Mapping) else {}
            return self.run_template(
                normalize_text(safe_task.get("template_name")),
                params=params,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                requested_by=requested_by,
                role=role,
                plan=plan,
                agent_name=agent_name,
                security_approved=security_approved,
            )

        if action == MacAction.RUN_APPLESCRIPT.value:
            return self.run_applescript(
                str(safe_task.get("script") or ""),
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                requested_by=requested_by,
                role=role,
                plan=plan,
                agent_name=agent_name,
                security_approved=security_approved,
            )

        if action == MacAction.HEARTBEAT.value:
            return self.heartbeat(user_id=user_id, workspace_id=workspace_id, role=role, plan=plan)

        if action == MacAction.STOP.value:
            return self.stop(user_id=user_id, workspace_id=workspace_id, role=role, plan=plan, reason=normalize_text(safe_task.get("reason")))

        if action == MacAction.RESUME.value:
            return self.resume(user_id=user_id, workspace_id=workspace_id, role=role, plan=plan, reason=normalize_text(safe_task.get("reason")))

        context = self._context(user_id=user_id, workspace_id=workspace_id, task_id=task_id, requested_by=requested_by, role=role, plan=plan, agent_name=agent_name)
        return self._result(
            ActionStatus.ERROR,
            MacAction.HEARTBEAT,
            context,
            "Unsupported macOS worker task action.",
            {"received_action": action, "supported_actions": [item.value for item in MacAction]},
        )

    def resolve_app_target(self, app_name: str) -> MacAppTarget:
        """Resolve user-facing app name into a macOS app target."""
        requested = normalize_text(app_name, max_length=260)
        if not requested:
            raise ValueError("app_name is required.")

        key = requested.lower()
        alias = self.app_aliases.get(key)

        if alias:
            return MacAppTarget(
                requested_name=requested,
                app_name=normalize_text(alias.get("app_name")) or requested,
                bundle_id=normalize_text(alias.get("bundle_id")) or None,
                risk_level=self._coerce_risk(alias.get("risk_level", "low")),
                source="alias",
            )

        if re.fullmatch(r"[a-zA-Z0-9 ._()&+-]{1,120}", requested):
            risk = RiskLevel.HIGH if key in self.HIGH_RISK_APPS else RiskLevel.MEDIUM
            return MacAppTarget(
                requested_name=requested,
                app_name=requested,
                bundle_id=None,
                risk_level=risk,
                source="safe_app_name",
            )

        raise ValueError("Unsupported macOS app name. Use a known alias or simple app name.")

    def _render_template(self, template_name: str, template: Mapping[str, Any], params: Mapping[str, Any]) -> str:
        required = template.get("required_params") or []
        if not isinstance(required, Sequence):
            required = []

        safe_params = dict(json_safe(params))
        missing = [name for name in required if normalize_text(safe_params.get(name)) == ""]
        if missing:
            raise ValueError(f"Missing required template params: {', '.join(missing)}")

        script = str(template.get("script") or "").strip()
        if not script:
            raise ValueError(f"AppleScript template '{template_name}' has no script.")

        replacements: Dict[str, str] = {}
        for key, value in safe_params.items():
            replacements[str(key)] = applescript_quote(value)

        for key, value in replacements.items():
            script = script.replace("{" + key + "}", value)

        unresolved = re.findall(r"\{([a-zA-Z0-9_]+)\}", script)
        if unresolved:
            raise ValueError(f"Unresolved template params: {', '.join(sorted(set(unresolved)))}")

        return script

    def _run_osascript(self, script: str) -> AppleScriptResult:
        """Run AppleScript through osascript with shell disabled."""
        start = time.time()
        script_text = str(script or "").strip()
        script_hash = stable_hash({"script": script_text})

        if not script_text:
            return AppleScriptResult(
                ok=False,
                stdout="",
                stderr="AppleScript is empty.",
                returncode=1,
                elapsed_ms=0,
                script_hash=script_hash,
            )

        if not self._osascript_available():
            return AppleScriptResult(
                ok=False,
                stdout="",
                stderr="osascript is not available on this system.",
                returncode=127,
                elapsed_ms=int((time.time() - start) * 1000),
                script_hash=script_hash,
            )

        try:
            completed = subprocess.run(
                ["osascript", "-e", script_text],
                capture_output=True,
                text=True,
                timeout=max(1, self.applescript_timeout_seconds),
                shell=False,
            )
            elapsed_ms = int((time.time() - start) * 1000)
            return AppleScriptResult(
                ok=completed.returncode == 0,
                stdout=(completed.stdout or "").strip()[-5000:],
                stderr=(completed.stderr or "").strip()[-5000:],
                returncode=completed.returncode,
                elapsed_ms=elapsed_ms,
                script_hash=script_hash,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed_ms = int((time.time() - start) * 1000)
            return AppleScriptResult(
                ok=False,
                stdout=(exc.stdout or "")[-5000:] if isinstance(exc.stdout, str) else "",
                stderr="AppleScript execution timed out.",
                returncode=124,
                elapsed_ms=elapsed_ms,
                script_hash=script_hash,
            )
        except Exception as exc:
            elapsed_ms = int((time.time() - start) * 1000)
            return AppleScriptResult(
                ok=False,
                stdout="",
                stderr=str(exc),
                returncode=1,
                elapsed_ms=elapsed_ms,
                script_hash=script_hash,
            )

    def _osascript_available(self) -> bool:
        if not self.is_macos:
            return False
        try:
            completed = subprocess.run(
                ["which", "osascript"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            return completed.returncode == 0 and bool(completed.stdout.strip())
        except Exception:
            return False

    def _coerce_risk(self, value: Any) -> RiskLevel:
        if isinstance(value, RiskLevel):
            return value
        text = normalize_text(value).lower()
        for item in RiskLevel:
            if item.value == text:
                return item
        return RiskLevel.LOW

    def _context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        requested_by: Optional[str],
        role: str,
        plan: str,
        agent_name: str,
    ) -> TaskContext:
        return TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or generate_id("task"),
            requested_by=requested_by or user_id,
            role=role,
            plan=plan,
            agent_name=agent_name,
        ).validate()

    def _is_ready(self) -> bool:
        return self.state == WorkerState.READY

    def _platform_guard(self, action: MacAction, context: TaskContext) -> Optional[Dict[str, Any]]:
        if self.is_macos:
            return None
        return self._result(
            ActionStatus.UNSUPPORTED,
            action,
            context,
            "macOS worker actions are only supported on macOS.",
            {"current_os": platform.system()},
        )

    def _check_permission(self, *, context: TaskContext, action: MacAction) -> Dict[str, Any]:
        role = context.role.lower()
        plan = context.plan.lower()

        if role not in self.allowed_roles:
            return {
                "allowed": False,
                "reason": f"Role '{context.role}' is not allowed to use macOS worker automation.",
                "role": context.role,
                "plan": context.plan,
                "action": action.value,
            }

        if plan not in self.allowed_plans:
            return {
                "allowed": False,
                "reason": f"Plan '{context.plan}' is not allowed to use macOS worker automation.",
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
        action: MacAction,
        target: Optional[MacAppTarget] = None,
        script_kind: Optional[ScriptKind] = None,
        template_name: Optional[str] = None,
        risk_level: Optional[RiskLevel] = None,
        security_approved: bool,
        force: bool = False,
    ) -> Dict[str, Any]:
        effective_risk = risk_level or (target.risk_level if target else RiskLevel.LOW)
        reasons: List[str] = []
        requires_review = False

        if effective_risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            requires_review = True
            reasons.append(f"Risk level is {effective_risk.value}.")

        if action in {MacAction.QUIT_APP, MacAction.RUN_APPLESCRIPT}:
            requires_review = True
            reasons.append(f"{action.value} is sensitive or state-changing.")

        if force:
            requires_review = True
            reasons.append("Force quit can cause data loss.")

        if script_kind == ScriptKind.RAW:
            requires_review = True
            reasons.append("Raw AppleScript execution is high risk.")

        if requires_review and not security_approved:
            return {
                "allowed": False,
                "requires_security_review": True,
                "reason": "Security Agent approval required: " + " ".join(reasons),
                "security_agent_payload": self._security_payload(
                    context=context,
                    action=action,
                    target=target,
                    risk_level=effective_risk,
                    reasons=reasons,
                    script_kind=script_kind,
                    template_name=template_name,
                    force=force,
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
        action: MacAction,
        risk_level: RiskLevel,
        reasons: Sequence[str],
        target: Optional[MacAppTarget] = None,
        script_kind: Optional[ScriptKind] = None,
        template_name: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        return {
            "event": "security.review.device_worker.mac_worker",
            "device_id": self.device_id,
            "worker_id": self.worker_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "correlation_id": context.correlation_id,
            "requested_by": context.requested_by,
            "agent_name": context.agent_name,
            "action": action.value,
            "target": dataclasses.asdict(target) if target else None,
            "script_kind": script_kind.value if script_kind else None,
            "template_name": template_name,
            "force": force,
            "risk_level": risk_level.value,
            "reasons": list(reasons),
            "timestamp": iso_now(),
        }

    def _result(
        self,
        status: ActionStatus,
        action: MacAction,
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
                "is_macos": self.is_macos,
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

    def _error_result(self, action: MacAction, context: TaskContext, exc: Exception) -> Dict[str, Any]:
        with self._state_lock:
            if self._state == WorkerState.BUSY:
                self._state = WorkerState.ERROR

        return self._result(
            ActionStatus.ERROR,
            action,
            context,
            "macOS worker action failed.",
            {
                "error_type": exc.__class__.__name__,
                "error": normalize_text(str(exc), max_length=1000),
            },
        )

    def _audit_payload(
        self,
        *,
        status: ActionStatus,
        action: MacAction,
        context: TaskContext,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return {
            "event": "device_worker.mac_worker.audit",
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
        action: MacAction,
        context: TaskContext,
        message: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        target = data.get("target") if isinstance(data.get("target"), Mapping) else {}
        return {
            "source": "mac_worker",
            "type": "device_action",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "title": f"macOS worker action: {action.value}",
            "summary": {
                "action": action.value,
                "status": status.value,
                "message": normalize_text(message),
                "app": target.get("app_name") if isinstance(target, Mapping) else None,
                "worker_id": self.worker_id,
                "device_id": self.device_id,
            },
            "created_at": iso_now(),
        }

    def _verification_payload(
        self,
        *,
        status: ActionStatus,
        action: MacAction,
        context: TaskContext,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return {
            "event": "verification.device_worker.mac_worker",
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
    "MacWorker",
    "MacAction",
    "ActionStatus",
    "WorkerState",
    "RiskLevel",
    "ScriptKind",
    "TaskContext",
    "MacAppTarget",
    "AppleScriptResult",
    "WorkerRegistration",
]
