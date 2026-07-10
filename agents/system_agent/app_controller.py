"""
agents/system_agent/app_controller.py

William / Jarvis Multi-Agent AI SaaS System
System Agent - App Controller

Purpose:
    Safely open, close, focus, switch, minimize, maximize, and restart desktop
    applications while preserving SaaS user/workspace isolation and compatibility
    with Master Agent routing, Security Agent approvals, Verification Agent payloads,
    Memory Agent payloads, audit logging, dashboards, and future plugin-style agents.

Design notes:
    - Import-safe: this file can be imported even if the wider William project has
      not been fully generated yet.
    - Safety-first: sensitive app actions are routed through permission/security hooks.
    - SaaS isolation: every user-scoped operation validates user_id and workspace_id.
    - Structured results: every public method returns a dict with success, message,
      data, error, and metadata keys.
    - Cross-platform: supports Windows, macOS, and Linux with safe best-effort behavior.
    - Testable: supports dry_run mode and dependency injection for command execution.

This controller is intended to be used by:
    - SystemAgent for local OS/application control tasks.
    - MasterAgent through Agent Router task dispatch.
    - SecurityAgent for action approval.
    - VerificationAgent for post-action verification payloads.
    - MemoryAgent for useful context retention.
    - Dashboard/API layer for audit logs, analytics, and task history.
"""

from __future__ import annotations

import os
import sys
import shlex
import shutil
import signal
import logging
import platform
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional project imports with safe fallbacks.
# This keeps the file import-safe even before other William files exist.
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early generation stages
    class BaseAgent:  # type: ignore
        """Fallback BaseAgent stub used only when the real BaseAgent is unavailable."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


try:
    from core.agent_events import AgentEventEmitter  # type: ignore
except Exception:  # pragma: no cover
    AgentEventEmitter = None  # type: ignore


try:
    from core.audit import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants and type aliases
# ---------------------------------------------------------------------------

JSONDict = Dict[str, Any]
CommandRunner = Callable[..., subprocess.CompletedProcess]

DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_RESTART_DELAY_SECONDS = 1.5
SAFE_APP_NAME_MAX_LENGTH = 180
SAFE_ARGUMENT_MAX_LENGTH = 500


class AppAction(str, Enum):
    """Supported application control actions."""

    OPEN = "open"
    CLOSE = "close"
    FOCUS = "focus"
    SWITCH = "switch"
    MINIMIZE = "minimize"
    MAXIMIZE = "maximize"
    RESTART = "restart"


class SecurityLevel(str, Enum):
    """Action sensitivity levels for Security Agent and audit routing."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExecutionStatus(str, Enum):
    """Normalized execution statuses used in structured results."""

    PLANNED = "planned"
    EXECUTED = "executed"
    BLOCKED = "blocked"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class AppControllerConfig:
    """
    Runtime configuration for AppController.

    Attributes:
        dry_run:
            When True, methods return the command plan but do not execute commands.
        allow_execution:
            When False, all OS-changing actions are blocked unless a custom
            security callback explicitly allows execution.
        command_timeout_seconds:
            Timeout for OS commands.
        restart_delay_seconds:
            Delay between close and open during restart.
        allow_unknown_apps:
            If False, only registered app_profiles can be controlled.
        enable_audit_log:
            Enables local audit logging hook.
        enable_agent_events:
            Enables agent event hook.
        enable_memory_payloads:
            Enables memory payload preparation.
        enable_verification_payloads:
            Enables verification payload preparation.
        permitted_actions:
            Optional allow-list of actions. If empty, all supported actions are allowed
            subject to security approval.
        blocked_apps:
            App names that must never be controlled by this file.
        protected_apps:
            Apps that require high-sensitivity approval before close/restart.
    """

    dry_run: bool = True
    allow_execution: bool = False
    command_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    restart_delay_seconds: float = DEFAULT_RESTART_DELAY_SECONDS
    allow_unknown_apps: bool = True
    enable_audit_log: bool = True
    enable_agent_events: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True
    permitted_actions: List[str] = field(default_factory=list)
    blocked_apps: List[str] = field(
        default_factory=lambda: [
            "system",
            "kernel",
            "launchd",
            "init",
            "systemd",
            "winlogon",
            "csrss",
            "lsass",
            "services",
            "securityhealthservice",
        ]
    )
    protected_apps: List[str] = field(
        default_factory=lambda: [
            "terminal",
            "cmd",
            "powershell",
            "windows terminal",
            "iterm",
            "gnome-terminal",
            "konsole",
            "alacritty",
            "wezterm",
            "ssh",
            "vpn",
            "password manager",
            "1password",
            "bitwarden",
            "keepass",
            "keychain",
            "settings",
            "system settings",
            "control panel",
            "registry editor",
            "regedit",
        ]
    )


@dataclass
class AppProfile:
    """
    Optional app profile for known applications.

    This can later be loaded from agents/system_agent/app_profiles.py or a database.
    The controller works without profiles, but profiles improve reliability.
    """

    name: str
    executable: Optional[str] = None
    process_names: List[str] = field(default_factory=list)
    bundle_id: Optional[str] = None
    window_title: Optional[str] = None
    launch_args: List[str] = field(default_factory=list)
    working_directory: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    metadata: JSONDict = field(default_factory=dict)


@dataclass
class AppCommandPlan:
    """Internal representation of an OS command plan."""

    action: AppAction
    app_name: str
    command: List[str]
    platform_name: str
    shell: bool = False
    cwd: Optional[str] = None
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    metadata: JSONDict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# AppController
# ---------------------------------------------------------------------------

class AppController(BaseAgent):
    """
    Production-ready app control helper for William/Jarvis System Agent.

    Public methods:
        - open_app()
        - close_app()
        - focus_app()
        - switch_app()
        - minimize_app()
        - maximize_app()
        - restart_app()
        - handle_task()

    Each method accepts user_id and workspace_id so that future API/dashboard
    layers can keep actions, logs, analytics, and permissions isolated per tenant.
    """

    def __init__(
        self,
        config: Optional[AppControllerConfig] = None,
        app_profiles: Optional[Union[Mapping[str, Union[AppProfile, Mapping[str, Any]]], Iterable[Union[AppProfile, Mapping[str, Any]]]]] = None,
        security_approval_callback: Optional[Callable[[JSONDict], Union[bool, JSONDict]]] = None,
        audit_callback: Optional[Callable[[JSONDict], None]] = None,
        event_callback: Optional[Callable[[JSONDict], None]] = None,
        command_runner: Optional[CommandRunner] = None,
        logger: Optional[logging.Logger] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, agent_name="SystemAgent.AppController", **kwargs)
        self.config = config or AppControllerConfig()
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.command_runner = command_runner or subprocess.run
        self.logger = logger or logging.getLogger("William.SystemAgent.AppController")
        self.platform_name = platform.system().lower()
        self.app_profiles: Dict[str, AppProfile] = {}
        self._register_default_profiles()
        self._load_app_profiles(app_profiles)

    # ------------------------------------------------------------------
    # Public action methods
    # ------------------------------------------------------------------

    def open_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        app_path: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        wait: bool = False,
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Open/launch an application safely."""

        context = self._build_task_context(
            action=AppAction.OPEN,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
            extra={"app_path": app_path, "args": list(args or []), "wait": wait},
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        plan_result = self._create_command_plan(
            action=AppAction.OPEN,
            app_name=app_name,
            app_path=app_path,
            args=args,
            wait=wait,
            context=context,
        )
        if not plan_result["success"]:
            return plan_result

        return self._execute_plan(plan_result["data"]["plan"], context)

    def close_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        force: bool = False,
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Close an application safely. Force close requires stronger approval."""

        context = self._build_task_context(
            action=AppAction.CLOSE,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
            extra={"force": force},
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        plan_result = self._create_command_plan(
            action=AppAction.CLOSE,
            app_name=app_name,
            force=force,
            context=context,
        )
        if not plan_result["success"]:
            return plan_result

        return self._execute_plan(plan_result["data"]["plan"], context)

    def focus_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Bring an application window to the foreground."""

        context = self._build_task_context(
            action=AppAction.FOCUS,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        plan_result = self._create_command_plan(
            action=AppAction.FOCUS,
            app_name=app_name,
            context=context,
        )
        if not plan_result["success"]:
            return plan_result

        return self._execute_plan(plan_result["data"]["plan"], context)

    def switch_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """
        Switch to an app.

        In this controller, switch_app is intentionally equivalent to focus_app
        because window switching is app-focused and should remain deterministic.
        """

        context = self._build_task_context(
            action=AppAction.SWITCH,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        plan_result = self._create_command_plan(
            action=AppAction.SWITCH,
            app_name=app_name,
            context=context,
        )
        if not plan_result["success"]:
            return plan_result

        return self._execute_plan(plan_result["data"]["plan"], context)

    def minimize_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Minimize an app window when supported by the host OS."""

        context = self._build_task_context(
            action=AppAction.MINIMIZE,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        plan_result = self._create_command_plan(
            action=AppAction.MINIMIZE,
            app_name=app_name,
            context=context,
        )
        if not plan_result["success"]:
            return plan_result

        return self._execute_plan(plan_result["data"]["plan"], context)

    def maximize_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Maximize an app window when supported by the host OS."""

        context = self._build_task_context(
            action=AppAction.MAXIMIZE,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        plan_result = self._create_command_plan(
            action=AppAction.MAXIMIZE,
            app_name=app_name,
            context=context,
        )
        if not plan_result["success"]:
            return plan_result

        return self._execute_plan(plan_result["data"]["plan"], context)

    def restart_app(
        self,
        app_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        app_path: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        force_close: bool = False,
        request_metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Restart an application by safely closing it and then opening it."""

        context = self._build_task_context(
            action=AppAction.RESTART,
            app_name=app_name,
            user_id=user_id,
            workspace_id=workspace_id,
            request_metadata=request_metadata,
            extra={"app_path": app_path, "args": list(args or []), "force_close": force_close},
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        close_plan_result = self._create_command_plan(
            action=AppAction.CLOSE,
            app_name=app_name,
            force=force_close,
            context=context,
        )
        if not close_plan_result["success"]:
            return close_plan_result

        open_plan_result = self._create_command_plan(
            action=AppAction.OPEN,
            app_name=app_name,
            app_path=app_path,
            args=args,
            wait=False,
            context=context,
        )
        if not open_plan_result["success"]:
            return open_plan_result

        restart_plan = {
            "close_plan": close_plan_result["data"]["plan"],
            "open_plan": open_plan_result["data"]["plan"],
            "restart_delay_seconds": self.config.restart_delay_seconds,
        }

        approval = self._request_security_approval(context, restart_plan)
        if not approval["success"]:
            return approval

        self._emit_agent_event("app_restart_started", context, {"restart_plan": self._serialize_restart_plan(restart_plan)})
        self._log_audit_event("app_restart_requested", context, {"restart_plan": self._serialize_restart_plan(restart_plan)})

        if self.config.dry_run or not self.config.allow_execution:
            data = {
                "status": ExecutionStatus.PLANNED.value,
                "dry_run": self.config.dry_run,
                "allow_execution": self.config.allow_execution,
                "restart_plan": self._serialize_restart_plan(restart_plan),
                "verification_payload": self._prepare_verification_payload(context, restart_plan),
                "memory_payload": self._prepare_memory_payload(context, restart_plan),
            }
            return self._safe_result(
                message="Restart plan prepared. Execution is disabled or dry_run is enabled.",
                data=data,
                metadata=self._result_metadata(context),
            )

        close_result = self._run_command_plan(close_plan_result["data"]["plan"])
        if not close_result["success"]:
            return close_result

        self._sleep_restart_delay()

        open_result = self._run_command_plan(open_plan_result["data"]["plan"])
        combined_data = {
            "status": ExecutionStatus.EXECUTED.value if open_result["success"] else ExecutionStatus.FAILED.value,
            "close_result": close_result,
            "open_result": open_result,
            "restart_plan": self._serialize_restart_plan(restart_plan),
            "verification_payload": self._prepare_verification_payload(context, restart_plan),
            "memory_payload": self._prepare_memory_payload(context, restart_plan),
        }

        if open_result["success"]:
            self._emit_agent_event("app_restart_completed", context, combined_data)
            self._log_audit_event("app_restart_completed", context, combined_data)
            return self._safe_result(
                message=f"Application restart completed for '{app_name}'.",
                data=combined_data,
                metadata=self._result_metadata(context),
            )

        self._emit_agent_event("app_restart_failed", context, combined_data)
        self._log_audit_event("app_restart_failed", context, combined_data)
        return self._error_result(
            message=f"Application restart failed for '{app_name}'.",
            error=open_result.get("error") or "Open step failed after close step.",
            data=combined_data,
            metadata=self._result_metadata(context),
        )

    def register_app_profile(self, profile: Union[AppProfile, Mapping[str, Any]]) -> JSONDict:
        """Register or update an app profile at runtime."""

        try:
            normalized = self._normalize_profile(profile)
            keys = {normalized.name, *normalized.aliases, *normalized.process_names}
            for key in keys:
                if key:
                    self.app_profiles[self._normalize_key(key)] = normalized

            return self._safe_result(
                message=f"App profile registered for '{normalized.name}'.",
                data={"profile": asdict(normalized)},
                metadata={"registered_keys": sorted(self._normalize_key(k) for k in keys if k)},
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to register app profile.",
                error=str(exc),
                metadata={"profile_type": type(profile).__name__},
            )

    def get_app_profile(self, app_name: str) -> Optional[AppProfile]:
        """Return a registered app profile by app name, alias, or process name."""

        return self.app_profiles.get(self._normalize_key(app_name))

    def list_app_profiles(self) -> JSONDict:
        """List currently registered app profiles."""

        unique_profiles: Dict[str, AppProfile] = {}
        for profile in self.app_profiles.values():
            unique_profiles[self._normalize_key(profile.name)] = profile

        return self._safe_result(
            message="Registered app profiles loaded.",
            data={"profiles": [asdict(profile) for profile in unique_profiles.values()]},
            metadata={"count": len(unique_profiles)},
        )

    def handle_task(self, task: Mapping[str, Any]) -> JSONDict:
        """
        MasterAgent/Router-compatible task entry point.

        Expected task shape:
            {
                "action": "open|close|focus|switch|minimize|maximize|restart",
                "app_name": "Chrome",
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "args": [],
                "force": false,
                "metadata": {}
            }
        """

        try:
            action = str(task.get("action", "")).strip().lower()
            app_name = str(task.get("app_name") or task.get("application") or "").strip()
            user_id = task.get("user_id")
            workspace_id = task.get("workspace_id")
            metadata = task.get("metadata") if isinstance(task.get("metadata"), Mapping) else {}

            if not action:
                return self._error_result("Missing action.", "Task requires an action field.")
            if not app_name:
                return self._error_result("Missing app_name.", "Task requires an app_name field.")

            common_kwargs = {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "request_metadata": metadata,
            }

            if action == AppAction.OPEN.value:
                return self.open_app(
                    app_name,
                    app_path=task.get("app_path"),
                    args=task.get("args") if isinstance(task.get("args"), Sequence) and not isinstance(task.get("args"), str) else None,
                    wait=bool(task.get("wait", False)),
                    **common_kwargs,
                )
            if action == AppAction.CLOSE.value:
                return self.close_app(app_name, force=bool(task.get("force", False)), **common_kwargs)
            if action == AppAction.FOCUS.value:
                return self.focus_app(app_name, **common_kwargs)
            if action == AppAction.SWITCH.value:
                return self.switch_app(app_name, **common_kwargs)
            if action == AppAction.MINIMIZE.value:
                return self.minimize_app(app_name, **common_kwargs)
            if action == AppAction.MAXIMIZE.value:
                return self.maximize_app(app_name, **common_kwargs)
            if action == AppAction.RESTART.value:
                return self.restart_app(
                    app_name,
                    app_path=task.get("app_path"),
                    args=task.get("args") if isinstance(task.get("args"), Sequence) and not isinstance(task.get("args"), str) else None,
                    force_close=bool(task.get("force", False)),
                    **common_kwargs,
                )

            return self._error_result(
                message=f"Unsupported app action '{action}'.",
                error="Unsupported action.",
                metadata={"supported_actions": [item.value for item in AppAction]},
            )
        except Exception as exc:
            self.logger.exception("AppController.handle_task failed")
            return self._error_result(
                message="AppController task handling failed.",
                error=str(exc),
                metadata={"task_keys": sorted(str(k) for k in task.keys())},
            )

    async def run(self, task: Mapping[str, Any]) -> JSONDict:
        """Async-compatible BaseAgent entry point."""

        return self.handle_task(task)

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> JSONDict:
        """
        Validate SaaS and safety context.

        This is required by the William/Jarvis architecture so every app action
        has a user_id and workspace_id before touching the host OS.
        """

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")
        app_name = str(context.get("app_name") or "").strip()
        action = str(context.get("action") or "").strip().lower()

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing user_id.",
                error="AppController requires user_id for SaaS isolation.",
                metadata={"context_action": action},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing workspace_id.",
                error="AppController requires workspace_id for workspace isolation.",
                metadata={"context_action": action, "user_id": str(user_id)},
            )

        if not app_name:
            return self._error_result(
                message="Missing application name.",
                error="AppController requires a non-empty app_name.",
                metadata={"context_action": action},
            )

        if len(app_name) > SAFE_APP_NAME_MAX_LENGTH:
            return self._error_result(
                message="Application name is too long.",
                error=f"app_name exceeds {SAFE_APP_NAME_MAX_LENGTH} characters.",
                metadata={"app_name_length": len(app_name)},
            )

        if action not in {item.value for item in AppAction}:
            return self._error_result(
                message=f"Unsupported application action '{action}'.",
                error="Unsupported action.",
                metadata={"supported_actions": [item.value for item in AppAction]},
            )

        if self.config.permitted_actions and action not in set(self.config.permitted_actions):
            return self._error_result(
                message=f"Action '{action}' is not permitted by AppController config.",
                error="Action blocked by configuration.",
                metadata={"permitted_actions": self.config.permitted_actions},
            )

        if self._is_blocked_app(app_name):
            return self._error_result(
                message=f"App '{app_name}' is blocked by safety policy.",
                error="Blocked app.",
                metadata={"blocked_apps": self.config.blocked_apps},
            )

        if not self.config.allow_unknown_apps and self.get_app_profile(app_name) is None:
            return self._error_result(
                message=f"App '{app_name}' is not registered in app profiles.",
                error="Unknown app blocked by configuration.",
                metadata={"allow_unknown_apps": self.config.allow_unknown_apps},
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context": dict(context)},
            metadata=self._result_metadata(context),
        )

    def _requires_security_check(self, context: Mapping[str, Any]) -> bool:
        """Return True when an action must be approved by Security Agent."""

        action = str(context.get("action") or "").lower()
        app_name = str(context.get("app_name") or "").lower()
        extra = context.get("extra") if isinstance(context.get("extra"), Mapping) else {}

        if action in {AppAction.CLOSE.value, AppAction.RESTART.value}:
            return True

        if action in {AppAction.OPEN.value, AppAction.FOCUS.value, AppAction.SWITCH.value, AppAction.MINIMIZE.value, AppAction.MAXIMIZE.value}:
            return True

        if bool(extra.get("force")) or bool(extra.get("force_close")):
            return True

        if self._is_protected_app(app_name):
            return True

        return False

    def _request_security_approval(self, context: Mapping[str, Any], plan: Any) -> JSONDict:
        """
        Request approval for a planned action.

        If a security_approval_callback is provided, this method delegates the
        decision to that callback. Otherwise it uses safe local defaults:
        - dry_run mode allows planning.
        - execution mode requires config.allow_execution=True.
        """

        approval_payload = {
            "agent": "SystemAgent.AppController",
            "action": context.get("action"),
            "app_name": context.get("app_name"),
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "requires_security_check": self._requires_security_check(context),
            "security_level": self._estimate_security_level(context).value,
            "dry_run": self.config.dry_run,
            "allow_execution": self.config.allow_execution,
            "plan": self._serialize_any_plan(plan),
            "requested_at": self._utc_now(),
        }

        if self.security_approval_callback:
            try:
                decision = self.security_approval_callback(approval_payload)
                if isinstance(decision, Mapping):
                    approved = bool(decision.get("approved") or decision.get("success"))
                    if approved:
                        return self._safe_result(
                            message="Security approval granted.",
                            data={"approval": dict(decision), "approval_payload": approval_payload},
                            metadata=self._result_metadata(context),
                        )
                    return self._error_result(
                        message="Security approval denied.",
                        error=decision.get("error") or decision.get("message") or "Denied by security callback.",
                        data={"approval": dict(decision), "approval_payload": approval_payload},
                        metadata=self._result_metadata(context),
                    )

                if bool(decision):
                    return self._safe_result(
                        message="Security approval granted.",
                        data={"approval": {"approved": True}, "approval_payload": approval_payload},
                        metadata=self._result_metadata(context),
                    )

                return self._error_result(
                    message="Security approval denied.",
                    error="Denied by security callback.",
                    data={"approval": {"approved": False}, "approval_payload": approval_payload},
                    metadata=self._result_metadata(context),
                )
            except Exception as exc:
                return self._error_result(
                    message="Security approval callback failed.",
                    error=str(exc),
                    data={"approval_payload": approval_payload},
                    metadata=self._result_metadata(context),
                )

        if self.config.dry_run:
            return self._safe_result(
                message="Security approval not required for dry_run planning.",
                data={"approval": {"approved": True, "mode": "dry_run"}, "approval_payload": approval_payload},
                metadata=self._result_metadata(context),
            )

        if not self.config.allow_execution:
            return self._error_result(
                message="Execution is disabled by AppController config.",
                error="Set allow_execution=True and provide Security Agent approval to execute OS actions.",
                data={"approval": {"approved": False, "mode": "execution_disabled"}, "approval_payload": approval_payload},
                metadata=self._result_metadata(context),
            )

        return self._safe_result(
            message="Local execution approval granted by configuration.",
            data={"approval": {"approved": True, "mode": "local_config"}, "approval_payload": approval_payload},
            metadata=self._result_metadata(context),
        )

    def _prepare_verification_payload(self, context: Mapping[str, Any], plan: Any, execution: Optional[Mapping[str, Any]] = None) -> JSONDict:
        """
        Prepare Verification Agent payload.

        The Verification Agent can later inspect app process/window state and
        compare it with this expected action.
        """

        return {
            "agent": "VerificationAgent",
            "source_agent": "SystemAgent.AppController",
            "verification_type": "app_control_action",
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "expected_action": context.get("action"),
            "app_name": context.get("app_name"),
            "plan": self._serialize_any_plan(plan),
            "execution": dict(execution or {}),
            "created_at": self._utc_now(),
            "metadata": dict(context.get("request_metadata") or {}),
        }

    def _prepare_memory_payload(self, context: Mapping[str, Any], plan: Any, execution: Optional[Mapping[str, Any]] = None) -> JSONDict:
        """
        Prepare Memory Agent payload.

        Only non-sensitive operational context is included. Secrets, raw user files,
        and cross-workspace data are never included.
        """

        if not self.config.enable_memory_payloads:
            return {}

        return {
            "agent": "MemoryAgent",
            "source_agent": "SystemAgent.AppController",
            "memory_type": "system_app_action_summary",
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "summary": f"{context.get('action')} requested for app '{context.get('app_name')}'.",
            "facts": {
                "action": context.get("action"),
                "app_name": context.get("app_name"),
                "platform": self.platform_name,
                "dry_run": self.config.dry_run,
                "executed": bool(execution and execution.get("status") == ExecutionStatus.EXECUTED.value),
            },
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(self, event_name: str, context: Mapping[str, Any], data: Optional[Mapping[str, Any]] = None) -> None:
        """
        Emit event for dashboard/API/task-history integrations.

        A future AgentEventEmitter can be injected or imported. Until then this
        method safely logs events and calls event_callback if provided.
        """

        if not self.config.enable_agent_events:
            return

        event = {
            "event": event_name,
            "agent": "SystemAgent.AppController",
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "action": context.get("action"),
            "app_name": context.get("app_name"),
            "data": dict(data or {}),
            "created_at": self._utc_now(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
            else:
                self.logger.debug("Agent event: %s", event)
        except Exception:
            self.logger.exception("Failed to emit AppController agent event")

    def _log_audit_event(self, event_name: str, context: Mapping[str, Any], data: Optional[Mapping[str, Any]] = None) -> None:
        """
        Log audit event with SaaS user/workspace context.

        This hook intentionally avoids global state so future DB-backed audit logs
        can be injected without changing public methods.
        """

        if not self.config.enable_audit_log:
            return

        audit_event = {
            "event": event_name,
            "agent": "SystemAgent.AppController",
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "action": context.get("action"),
            "app_name": context.get("app_name"),
            "security_level": self._estimate_security_level(context).value,
            "data": dict(data or {}),
            "created_at": self._utc_now(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit_event)
            else:
                self.logger.info("Audit event: %s", audit_event)
        except Exception:
            self.logger.exception("Failed to write AppController audit event")

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Return normalized success result."""

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Return normalized error result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": str(error) if error is not None else "Unknown error",
            "metadata": dict(metadata or {}),
        }

    # ------------------------------------------------------------------
    # Command planning
    # ------------------------------------------------------------------

    def _create_command_plan(
        self,
        *,
        action: AppAction,
        app_name: str,
        context: Mapping[str, Any],
        app_path: Optional[str] = None,
        args: Optional[Sequence[str]] = None,
        force: bool = False,
        wait: bool = False,
    ) -> JSONDict:
        """Create a cross-platform command plan for an app action."""

        try:
            sanitized_app_name = self._sanitize_app_name(app_name)
            sanitized_args = self._sanitize_args(args or [])
            profile = self.get_app_profile(sanitized_app_name)
            security_level = self._estimate_security_level(context)

            if self.platform_name.startswith("win"):
                plan = self._create_windows_plan(
                    action=action,
                    app_name=sanitized_app_name,
                    profile=profile,
                    app_path=app_path,
                    args=sanitized_args,
                    force=force,
                    wait=wait,
                    security_level=security_level,
                )
            elif self.platform_name == "darwin":
                plan = self._create_macos_plan(
                    action=action,
                    app_name=sanitized_app_name,
                    profile=profile,
                    app_path=app_path,
                    args=sanitized_args,
                    force=force,
                    wait=wait,
                    security_level=security_level,
                )
            elif self.platform_name.startswith("linux"):
                plan = self._create_linux_plan(
                    action=action,
                    app_name=sanitized_app_name,
                    profile=profile,
                    app_path=app_path,
                    args=sanitized_args,
                    force=force,
                    wait=wait,
                    security_level=security_level,
                )
            else:
                return self._error_result(
                    message=f"Unsupported platform '{self.platform_name}'.",
                    error="Unsupported platform.",
                    metadata={"platform": self.platform_name, "action": action.value},
                )

            return self._safe_result(
                message=f"Command plan created for {action.value} '{sanitized_app_name}'.",
                data={"plan": plan},
                metadata={
                    "platform": self.platform_name,
                    "action": action.value,
                    "security_level": security_level.value,
                    "profile_found": profile is not None,
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to create command plan")
            return self._error_result(
                message="Failed to create app command plan.",
                error=str(exc),
                metadata={"action": action.value, "app_name": app_name, "platform": self.platform_name},
            )

    def _create_windows_plan(
        self,
        *,
        action: AppAction,
        app_name: str,
        profile: Optional[AppProfile],
        app_path: Optional[str],
        args: Sequence[str],
        force: bool,
        wait: bool,
        security_level: SecurityLevel,
    ) -> AppCommandPlan:
        """Create Windows command plan."""

        executable = self._resolve_executable(app_name, profile, app_path)
        process_name = self._resolve_process_name(app_name, profile, executable)

        if action == AppAction.OPEN:
            if executable:
                command = ["cmd", "/c", "start"]
                if wait:
                    command.append("/wait")
                command.extend(["", executable, *args])
            else:
                command = ["cmd", "/c", "start", "", app_name, *args]
            return self._plan(action, app_name, command, security_level=security_level, metadata={"executable": executable, "wait": wait})

        if action == AppAction.CLOSE:
            command = ["taskkill", "/IM", process_name]
            if force:
                command.append("/F")
            return self._plan(action, app_name, command, security_level=SecurityLevel.HIGH if force else security_level, metadata={"process_name": process_name, "force": force})

        if action in {AppAction.FOCUS, AppAction.SWITCH}:
            ps = (
                "$wshell = New-Object -ComObject wscript.shell; "
                f"$wshell.AppActivate('{self._escape_powershell_single_quoted(app_name)}') | Out-Null"
            )
            return self._plan(action, app_name, ["powershell", "-NoProfile", "-Command", ps], security_level=security_level)

        if action == AppAction.MINIMIZE:
            ps = self._windows_window_script(app_name, operation="minimize")
            return self._plan(action, app_name, ["powershell", "-NoProfile", "-Command", ps], security_level=security_level)

        if action == AppAction.MAXIMIZE:
            ps = self._windows_window_script(app_name, operation="maximize")
            return self._plan(action, app_name, ["powershell", "-NoProfile", "-Command", ps], security_level=security_level)

        raise ValueError(f"Unsupported Windows action: {action.value}")

    def _create_macos_plan(
        self,
        *,
        action: AppAction,
        app_name: str,
        profile: Optional[AppProfile],
        app_path: Optional[str],
        args: Sequence[str],
        force: bool,
        wait: bool,
        security_level: SecurityLevel,
    ) -> AppCommandPlan:
        """Create macOS command plan."""

        mac_app_name = profile.name if profile else app_name
        bundle_id = profile.bundle_id if profile else None

        if action == AppAction.OPEN:
            if app_path:
                command = ["open", app_path, "--args", *args] if args else ["open", app_path]
            elif bundle_id:
                command = ["open", "-b", bundle_id, "--args", *args] if args else ["open", "-b", bundle_id]
            else:
                command = ["open", "-a", mac_app_name, "--args", *args] if args else ["open", "-a", mac_app_name]
            return self._plan(action, app_name, command, security_level=security_level, metadata={"bundle_id": bundle_id, "wait": wait})

        if action == AppAction.CLOSE:
            if force:
                command = ["osascript", "-e", f'tell application "{self._escape_applescript_string(mac_app_name)}" to quit']
                metadata = {"force": False, "note": "macOS force quit is intentionally not used by default."}
            else:
                command = ["osascript", "-e", f'tell application "{self._escape_applescript_string(mac_app_name)}" to quit']
                metadata = {"force": False}
            return self._plan(action, app_name, command, security_level=SecurityLevel.HIGH if force else security_level, metadata=metadata)

        if action in {AppAction.FOCUS, AppAction.SWITCH}:
            command = ["osascript", "-e", f'tell application "{self._escape_applescript_string(mac_app_name)}" to activate']
            return self._plan(action, app_name, command, security_level=security_level)

        if action == AppAction.MINIMIZE:
            script = (
                f'tell application "System Events" to tell process "{self._escape_applescript_string(mac_app_name)}" '
                'to set miniaturized of windows to true'
            )
            return self._plan(action, app_name, ["osascript", "-e", script], security_level=security_level)

        if action == AppAction.MAXIMIZE:
            script = (
                f'tell application "System Events" to tell process "{self._escape_applescript_string(mac_app_name)}" '
                'to set value of attribute "AXFullScreen" of front window to true'
            )
            return self._plan(action, app_name, ["osascript", "-e", script], security_level=security_level)

        raise ValueError(f"Unsupported macOS action: {action.value}")

    def _create_linux_plan(
        self,
        *,
        action: AppAction,
        app_name: str,
        profile: Optional[AppProfile],
        app_path: Optional[str],
        args: Sequence[str],
        force: bool,
        wait: bool,
        security_level: SecurityLevel,
    ) -> AppCommandPlan:
        """Create Linux command plan."""

        executable = self._resolve_executable(app_name, profile, app_path)
        process_name = self._resolve_process_name(app_name, profile, executable)

        if action == AppAction.OPEN:
            launch_target = executable or app_name
            command = [launch_target, *args]
            return self._plan(action, app_name, command, security_level=security_level, metadata={"executable": executable, "wait": wait})

        if action == AppAction.CLOSE:
            command = ["pkill"]
            if force:
                command.extend(["-9"])
            command.extend(["-f", process_name])
            return self._plan(action, app_name, command, security_level=SecurityLevel.HIGH if force else security_level, metadata={"process_name": process_name, "force": force})

        if action in {AppAction.FOCUS, AppAction.SWITCH}:
            if shutil.which("wmctrl"):
                command = ["wmctrl", "-a", self._window_title_for(app_name, profile)]
            else:
                command = ["xdotool", "search", "--name", self._window_title_for(app_name, profile), "windowactivate"]
            return self._plan(action, app_name, command, security_level=security_level, metadata={"requires": "wmctrl or xdotool"})

        if action == AppAction.MINIMIZE:
            if shutil.which("xdotool"):
                command = ["sh", "-c", f"xdotool search --name {shlex.quote(self._window_title_for(app_name, profile))} windowminimize"]
            else:
                command = ["wmctrl", "-r", self._window_title_for(app_name, profile), "-b", "add,hidden"]
            return self._plan(action, app_name, command, security_level=security_level, metadata={"requires": "xdotool or wmctrl"})

        if action == AppAction.MAXIMIZE:
            command = ["wmctrl", "-r", self._window_title_for(app_name, profile), "-b", "add,maximized_vert,maximized_horz"]
            return self._plan(action, app_name, command, security_level=security_level, metadata={"requires": "wmctrl"})

        raise ValueError(f"Unsupported Linux action: {action.value}")

    def _plan(
        self,
        action: AppAction,
        app_name: str,
        command: List[str],
        *,
        security_level: SecurityLevel,
        shell: bool = False,
        cwd: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AppCommandPlan:
        """Create AppCommandPlan with default timeout and platform metadata."""

        return AppCommandPlan(
            action=action,
            app_name=app_name,
            command=command,
            platform_name=self.platform_name,
            shell=shell,
            cwd=cwd,
            timeout=self.config.command_timeout_seconds,
            security_level=security_level,
            metadata=dict(metadata or {}),
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute_plan(self, plan: AppCommandPlan, context: Mapping[str, Any]) -> JSONDict:
        """Run a command plan after security approval and audit logging."""

        approval = self._request_security_approval(context, plan)
        if not approval["success"]:
            self._emit_agent_event("app_action_blocked", context, {"plan": self._serialize_plan(plan), "approval": approval})
            self._log_audit_event("app_action_blocked", context, {"plan": self._serialize_plan(plan), "approval": approval})
            return approval

        self._emit_agent_event("app_action_requested", context, {"plan": self._serialize_plan(plan)})
        self._log_audit_event("app_action_requested", context, {"plan": self._serialize_plan(plan)})

        if self.config.dry_run or not self.config.allow_execution:
            data = {
                "status": ExecutionStatus.PLANNED.value,
                "dry_run": self.config.dry_run,
                "allow_execution": self.config.allow_execution,
                "plan": self._serialize_plan(plan),
                "verification_payload": self._prepare_verification_payload(context, plan),
                "memory_payload": self._prepare_memory_payload(context, plan),
            }
            return self._safe_result(
                message=f"Command plan prepared for {plan.action.value} '{plan.app_name}'. Execution is disabled or dry_run is enabled.",
                data=data,
                metadata=self._result_metadata(context),
            )

        execution = self._run_command_plan(plan)
        execution_data = dict(execution.get("data") or {})
        execution_data["verification_payload"] = self._prepare_verification_payload(context, plan, execution_data)
        execution_data["memory_payload"] = self._prepare_memory_payload(context, plan, execution_data)

        if execution["success"]:
            self._emit_agent_event("app_action_completed", context, execution_data)
            self._log_audit_event("app_action_completed", context, execution_data)
            return self._safe_result(
                message=f"App action '{plan.action.value}' completed for '{plan.app_name}'.",
                data=execution_data,
                metadata=self._result_metadata(context),
            )

        self._emit_agent_event("app_action_failed", context, execution_data)
        self._log_audit_event("app_action_failed", context, execution_data)
        return self._error_result(
            message=f"App action '{plan.action.value}' failed for '{plan.app_name}'.",
            error=execution.get("error") or "Command execution failed.",
            data=execution_data,
            metadata=self._result_metadata(context),
        )

    def _run_command_plan(self, plan: AppCommandPlan) -> JSONDict:
        """Execute a command plan safely with timeout and output capture."""

        try:
            command = plan.command
            if not command:
                return self._error_result(
                    message="Cannot execute empty command plan.",
                    error="Empty command.",
                    metadata={"action": plan.action.value, "app_name": plan.app_name},
                )

            # For Linux app launch, do not block on GUI apps longer than needed.
            if plan.action == AppAction.OPEN and self.platform_name.startswith("linux"):
                process = subprocess.Popen(
                    command,
                    cwd=plan.cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                data = {
                    "status": ExecutionStatus.EXECUTED.value,
                    "plan": self._serialize_plan(plan),
                    "pid": process.pid,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "",
                }
                return self._safe_result(
                    message=f"Application launch command started for '{plan.app_name}'.",
                    data=data,
                    metadata={"pid": process.pid},
                )

            completed = self.command_runner(
                command,
                shell=plan.shell,
                cwd=plan.cwd,
                capture_output=True,
                text=True,
                timeout=plan.timeout,
                check=False,
            )

            stdout = (completed.stdout or "").strip()
            stderr = (completed.stderr or "").strip()
            data = {
                "status": ExecutionStatus.EXECUTED.value if completed.returncode == 0 else ExecutionStatus.FAILED.value,
                "plan": self._serialize_plan(plan),
                "returncode": completed.returncode,
                "stdout": stdout[-4000:],
                "stderr": stderr[-4000:],
            }

            if completed.returncode == 0:
                return self._safe_result(
                    message=f"Command executed for '{plan.app_name}'.",
                    data=data,
                    metadata={"returncode": completed.returncode},
                )

            return self._error_result(
                message=f"Command failed for '{plan.app_name}'.",
                error=stderr or f"Command returned non-zero exit code {completed.returncode}.",
                data=data,
                metadata={"returncode": completed.returncode},
            )

        except subprocess.TimeoutExpired as exc:
            return self._error_result(
                message=f"Command timed out for '{plan.app_name}'.",
                error=f"Timeout after {plan.timeout} seconds.",
                data={"status": ExecutionStatus.FAILED.value, "plan": self._serialize_plan(plan)},
                metadata={"timeout": plan.timeout, "cmd": getattr(exc, "cmd", None)},
            )
        except FileNotFoundError as exc:
            return self._error_result(
                message=f"Required command was not found for '{plan.app_name}'.",
                error=str(exc),
                data={"status": ExecutionStatus.FAILED.value, "plan": self._serialize_plan(plan)},
                metadata={"platform": self.platform_name},
            )
        except Exception as exc:
            self.logger.exception("Command execution failed")
            return self._error_result(
                message=f"Command execution error for '{plan.app_name}'.",
                error=str(exc),
                data={"status": ExecutionStatus.FAILED.value, "plan": self._serialize_plan(plan)},
                metadata={"platform": self.platform_name},
            )

    # ------------------------------------------------------------------
    # Profile loading and defaults
    # ------------------------------------------------------------------

    def _register_default_profiles(self) -> None:
        """Register common app profiles for better cross-platform matching."""

        defaults = [
            AppProfile(
                name="Chrome",
                executable=self._first_existing_executable(["chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]),
                process_names=["chrome.exe", "chrome", "google-chrome", "Google Chrome"],
                bundle_id="com.google.Chrome",
                window_title="Chrome",
                aliases=["google chrome", "browser chrome"],
            ),
            AppProfile(
                name="Firefox",
                executable=self._first_existing_executable(["firefox"]),
                process_names=["firefox.exe", "firefox", "Firefox"],
                bundle_id="org.mozilla.firefox",
                window_title="Firefox",
                aliases=["mozilla firefox"],
            ),
            AppProfile(
                name="Edge",
                executable=self._first_existing_executable(["msedge", "microsoft-edge", "microsoft-edge-stable"]),
                process_names=["msedge.exe", "msedge", "Microsoft Edge"],
                bundle_id="com.microsoft.edgemac",
                window_title="Edge",
                aliases=["microsoft edge"],
            ),
            AppProfile(
                name="Notepad",
                executable="notepad.exe" if self.platform_name.startswith("win") else None,
                process_names=["notepad.exe", "notepad"],
                window_title="Notepad",
                aliases=["windows notepad"],
            ),
            AppProfile(
                name="TextEdit",
                process_names=["TextEdit"],
                bundle_id="com.apple.TextEdit",
                window_title="TextEdit",
                aliases=["text edit"],
            ),
            AppProfile(
                name="Terminal",
                process_names=["Terminal", "terminal", "gnome-terminal", "konsole"],
                bundle_id="com.apple.Terminal",
                window_title="Terminal",
                aliases=["cmd", "command prompt", "powershell", "shell"],
            ),
            AppProfile(
                name="VS Code",
                executable=self._first_existing_executable(["code"]),
                process_names=["Code.exe", "code", "Visual Studio Code"],
                bundle_id="com.microsoft.VSCode",
                window_title="Visual Studio Code",
                aliases=["vscode", "visual studio code", "code editor"],
            ),
        ]

        for profile in defaults:
            self.register_app_profile(profile)

    def _load_app_profiles(
        self,
        app_profiles: Optional[Union[Mapping[str, Union[AppProfile, Mapping[str, Any]]], Iterable[Union[AppProfile, Mapping[str, Any]]]]],
    ) -> None:
        """Load custom app profiles from mapping or iterable."""

        if not app_profiles:
            return

        if isinstance(app_profiles, Mapping):
            for key, value in app_profiles.items():
                if isinstance(value, AppProfile):
                    profile = value
                else:
                    profile_data = dict(value)
                    profile_data.setdefault("name", str(key))
                    profile = self._normalize_profile(profile_data)
                self.register_app_profile(profile)
            return

        for item in app_profiles:
            self.register_app_profile(item)

    def _normalize_profile(self, profile: Union[AppProfile, Mapping[str, Any]]) -> AppProfile:
        """Convert dict-style profile to AppProfile."""

        if isinstance(profile, AppProfile):
            return profile

        data = dict(profile)
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("App profile requires a non-empty name.")

        return AppProfile(
            name=name,
            executable=data.get("executable"),
            process_names=list(data.get("process_names") or []),
            bundle_id=data.get("bundle_id"),
            window_title=data.get("window_title"),
            launch_args=list(data.get("launch_args") or []),
            working_directory=data.get("working_directory"),
            aliases=list(data.get("aliases") or []),
            metadata=dict(data.get("metadata") or {}),
        )

    # ------------------------------------------------------------------
    # Safety helpers
    # ------------------------------------------------------------------

    def _sanitize_app_name(self, app_name: str) -> str:
        """Validate and normalize app names without allowing shell injection."""

        value = str(app_name or "").strip()
        if not value:
            raise ValueError("app_name cannot be empty.")
        if len(value) > SAFE_APP_NAME_MAX_LENGTH:
            raise ValueError(f"app_name exceeds {SAFE_APP_NAME_MAX_LENGTH} characters.")
        disallowed = ["\x00", "\n", "\r"]
        if any(item in value for item in disallowed):
            raise ValueError("app_name contains invalid control characters.")
        return value

    def _sanitize_args(self, args: Sequence[str]) -> List[str]:
        """Sanitize optional launch arguments."""

        sanitized: List[str] = []
        for arg in args:
            value = str(arg)
            if len(value) > SAFE_ARGUMENT_MAX_LENGTH:
                raise ValueError(f"Launch argument exceeds {SAFE_ARGUMENT_MAX_LENGTH} characters.")
            if "\x00" in value:
                raise ValueError("Launch argument contains invalid null byte.")
            sanitized.append(value)
        return sanitized

    def _is_blocked_app(self, app_name: str) -> bool:
        """Return True if app name matches blocked safety list."""

        key = self._normalize_key(app_name)
        return any(key == self._normalize_key(item) or key in self._normalize_key(item) for item in self.config.blocked_apps)

    def _is_protected_app(self, app_name: str) -> bool:
        """Return True if app name matches protected app list."""

        key = self._normalize_key(app_name)
        profile = self.get_app_profile(app_name)
        profile_values: List[str] = []
        if profile:
            profile_values.extend([profile.name, profile.executable or "", profile.bundle_id or "", profile.window_title or ""])
            profile_values.extend(profile.process_names)
            profile_values.extend(profile.aliases)

        keys = {key, *(self._normalize_key(value) for value in profile_values if value)}
        protected = {self._normalize_key(item) for item in self.config.protected_apps}
        return any(any(protected_item in value or value in protected_item for value in keys) for protected_item in protected)

    def _estimate_security_level(self, context: Mapping[str, Any]) -> SecurityLevel:
        """Estimate action sensitivity for audit/security routing."""

        action = str(context.get("action") or "").lower()
        app_name = str(context.get("app_name") or "")
        extra = context.get("extra") if isinstance(context.get("extra"), Mapping) else {}

        if bool(extra.get("force")) or bool(extra.get("force_close")):
            return SecurityLevel.HIGH

        if action in {AppAction.CLOSE.value, AppAction.RESTART.value}:
            return SecurityLevel.HIGH if self._is_protected_app(app_name) else SecurityLevel.MEDIUM

        if self._is_protected_app(app_name):
            return SecurityLevel.MEDIUM

        return SecurityLevel.LOW

    # ------------------------------------------------------------------
    # Resolve helpers
    # ------------------------------------------------------------------

    def _resolve_executable(self, app_name: str, profile: Optional[AppProfile], app_path: Optional[str]) -> Optional[str]:
        """Resolve executable from explicit path, profile, PATH, or app name."""

        if app_path:
            return str(app_path)

        if profile and profile.executable:
            return profile.executable

        candidates = [app_name]
        if profile:
            candidates.extend(profile.process_names)
            candidates.extend(profile.aliases)

        for candidate in candidates:
            if not candidate:
                continue
            found = shutil.which(candidate)
            if found:
                return found

        return None

    def _resolve_process_name(self, app_name: str, profile: Optional[AppProfile], executable: Optional[str]) -> str:
        """Resolve process name for close commands."""

        if profile and profile.process_names:
            return profile.process_names[0]

        if executable:
            return Path(executable).name

        return app_name

    def _window_title_for(self, app_name: str, profile: Optional[AppProfile]) -> str:
        """Return best-known window title for focus/minimize/maximize."""

        if profile and profile.window_title:
            return profile.window_title
        if profile:
            return profile.name
        return app_name

    def _first_existing_executable(self, candidates: Sequence[str]) -> Optional[str]:
        """Return first executable found in PATH."""

        for candidate in candidates:
            found = shutil.which(candidate)
            if found:
                return found
        return None

    # ------------------------------------------------------------------
    # Serialization and result metadata
    # ------------------------------------------------------------------

    def _serialize_plan(self, plan: AppCommandPlan) -> JSONDict:
        """Serialize AppCommandPlan to dict while avoiding secret exposure."""

        return {
            "action": plan.action.value,
            "app_name": plan.app_name,
            "command": list(plan.command),
            "platform_name": plan.platform_name,
            "shell": plan.shell,
            "cwd": plan.cwd,
            "timeout": plan.timeout,
            "security_level": plan.security_level.value,
            "metadata": dict(plan.metadata),
        }

    def _serialize_restart_plan(self, restart_plan: Mapping[str, Any]) -> JSONDict:
        """Serialize restart plan containing two AppCommandPlan objects."""

        return {
            "close_plan": self._serialize_any_plan(restart_plan.get("close_plan")),
            "open_plan": self._serialize_any_plan(restart_plan.get("open_plan")),
            "restart_delay_seconds": restart_plan.get("restart_delay_seconds"),
        }

    def _serialize_any_plan(self, plan: Any) -> Any:
        """Safely serialize any plan-like object."""

        if isinstance(plan, AppCommandPlan):
            return self._serialize_plan(plan)
        if isinstance(plan, Mapping):
            return {str(k): self._serialize_any_plan(v) for k, v in plan.items()}
        if isinstance(plan, list):
            return [self._serialize_any_plan(item) for item in plan]
        if isinstance(plan, tuple):
            return [self._serialize_any_plan(item) for item in plan]
        return plan

    def _result_metadata(self, context: Mapping[str, Any]) -> JSONDict:
        """Standard metadata for every result."""

        return {
            "agent": "SystemAgent.AppController",
            "user_id": str(context.get("user_id")) if context.get("user_id") is not None else None,
            "workspace_id": str(context.get("workspace_id")) if context.get("workspace_id") is not None else None,
            "action": context.get("action"),
            "app_name": context.get("app_name"),
            "platform": self.platform_name,
            "timestamp": self._utc_now(),
        }

    def _build_task_context(
        self,
        *,
        action: AppAction,
        app_name: str,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        request_metadata: Optional[Mapping[str, Any]] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> JSONDict:
        """Create normalized context shared across hooks."""

        return {
            "agent": "SystemAgent.AppController",
            "action": action.value,
            "app_name": app_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "request_metadata": dict(request_metadata or {}),
            "extra": dict(extra or {}),
            "platform": self.platform_name,
            "created_at": self._utc_now(),
        }

    # ------------------------------------------------------------------
    # Platform-specific script helpers
    # ------------------------------------------------------------------

    def _windows_window_script(self, app_name: str, *, operation: str) -> str:
        """
        Create a PowerShell window operation script.

        Uses Win32 APIs through Add-Type. This avoids third-party dependencies and
        keeps behavior best-effort. It targets windows whose title contains app_name.
        """

        escaped = self._escape_powershell_single_quoted(app_name)
        show_cmd = "6" if operation == "minimize" else "3"
        return f"""
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinApi {{
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}}
"@
$target = '{escaped}'
$matched = $false
[WinApi]::EnumWindows({{
    param([IntPtr]$hWnd, [IntPtr]$lParam)
    $builder = New-Object System.Text.StringBuilder 512
    [void][WinApi]::GetWindowText($hWnd, $builder, $builder.Capacity)
    $title = $builder.ToString()
    if ([WinApi]::IsWindowVisible($hWnd) -and $title.ToLower().Contains($target.ToLower())) {{
        [void][WinApi]::ShowWindow($hWnd, {show_cmd})
        $script:matched = $true
    }}
    return $true
}}, [IntPtr]::Zero) | Out-Null
if (-not $matched) {{ exit 2 }} else {{ exit 0 }}
""".strip()

    def _escape_powershell_single_quoted(self, value: str) -> str:
        """Escape string for PowerShell single-quoted string."""

        return value.replace("'", "''")

    def _escape_applescript_string(self, value: str) -> str:
        """Escape app name for AppleScript double-quoted string."""

        return value.replace("\\", "\\\\").replace('"', '\\"')

    # ------------------------------------------------------------------
    # Small utilities
    # ------------------------------------------------------------------

    def _normalize_key(self, value: str) -> str:
        """Normalize names for profile lookup and safety matching."""

        return " ".join(str(value or "").strip().lower().replace("_", " ").replace("-", " ").split())

    def _utc_now(self) -> str:
        """Return ISO UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()

    def _sleep_restart_delay(self) -> None:
        """Sleep between close/open for restart. Isolated for test patching."""

        import time

        delay = max(0.0, float(self.config.restart_delay_seconds))
        if delay:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Optional convenience factory
# ---------------------------------------------------------------------------

def create_app_controller(
    *,
    dry_run: bool = True,
    allow_execution: bool = False,
    app_profiles: Optional[Union[Mapping[str, Union[AppProfile, Mapping[str, Any]]], Iterable[Union[AppProfile, Mapping[str, Any]]]]] = None,
    security_approval_callback: Optional[Callable[[JSONDict], Union[bool, JSONDict]]] = None,
    audit_callback: Optional[Callable[[JSONDict], None]] = None,
    event_callback: Optional[Callable[[JSONDict], None]] = None,
) -> AppController:
    """
    Factory helper for API routes, dashboard services, tests, and SystemAgent.

    Example:
        controller = create_app_controller(dry_run=True)
        result = controller.open_app("Chrome", user_id="u1", workspace_id="w1")
    """

    config = AppControllerConfig(dry_run=dry_run, allow_execution=allow_execution)
    return AppController(
        config=config,
        app_profiles=app_profiles,
        security_approval_callback=security_approval_callback,
        audit_callback=audit_callback,
        event_callback=event_callback,
    )


__all__ = [
    "AppAction",
    "SecurityLevel",
    "ExecutionStatus",
    "AppControllerConfig",
    "AppProfile",
    "AppCommandPlan",
    "AppController",
    "create_app_controller",
]
