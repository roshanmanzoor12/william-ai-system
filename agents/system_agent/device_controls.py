"""
agents/system_agent/device_controls.py

William / Jarvis Multi-Agent AI SaaS System - System Agent Device Controls

Purpose:
    Safely control device-level settings and power actions:
    WiFi, Bluetooth, volume, brightness, battery saver, screen lock, sleep,
    restart, and shutdown.

Design goals:
    - Import-safe even when the rest of William/Jarvis is not created yet.
    - Compatible with Master Agent routing, Agent Registry, BaseAgent patterns,
      Security Agent approval, Verification Agent payloads, Memory Agent context,
      audit logs, dashboard/API integration, and SaaS user/workspace isolation.
    - Never execute sensitive or destructive system actions unless permission
      checks pass.
    - Return structured dict/JSON-style results:
      {
          "success": bool,
          "message": str,
          "data": dict,
          "error": str | None,
          "metadata": dict
      }

Important:
    Device-level controls are OS-specific. This file uses safe command discovery,
    dry-run support, and explicit security gating for sensitive operations.
    It does not hardcode secrets and does not assume privileged access.
"""

from __future__ import annotations

import dataclasses
import getpass
import json
import logging
import os
import platform
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with fallback stubs
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis
        agents.base_agent module exists. The real project BaseAgent can replace
        this without changing this file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.name = kwargs.get("name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__.lower())

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() was called.",
                "data": {},
                "error": "base_agent_not_available",
                "metadata": {},
            }


try:
    from core.agent_events import emit_agent_event as william_emit_agent_event  # type: ignore
except Exception:  # pragma: no cover
    william_emit_agent_event = None


try:
    from core.audit import log_audit_event as william_log_audit_event  # type: ignore
except Exception:  # pragma: no cover
    william_log_audit_event = None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.system_agent.device_controls")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class DeviceControlAction(str, Enum):
    """Supported public action names for routing and dashboards."""

    SET_WIFI = "set_wifi"
    GET_WIFI_STATUS = "get_wifi_status"
    SET_BLUETOOTH = "set_bluetooth"
    GET_BLUETOOTH_STATUS = "get_bluetooth_status"
    SET_VOLUME = "set_volume"
    GET_VOLUME = "get_volume"
    SET_BRIGHTNESS = "set_brightness"
    GET_BRIGHTNESS = "get_brightness"
    SET_BATTERY_SAVER = "set_battery_saver"
    GET_BATTERY_SAVER_STATUS = "get_battery_saver_status"
    LOCK_SCREEN = "lock_screen"
    SLEEP = "sleep"
    RESTART = "restart"
    SHUTDOWN = "shutdown"
    GET_DEVICE_STATUS = "get_device_status"


class SecurityLevel(str, Enum):
    """Internal security levels used by permission checks."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OperatingSystem(str, Enum):
    """Normalized OS names."""

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class DeviceCommand:
    """
    OS command description.

    Args:
        executable: Main executable name.
        args: Command arguments excluding executable.
        shell: Whether to run using shell. Defaults to False for safety.
        timeout_seconds: Process timeout.
        sensitive: Whether the command requires security approval.
        description: Human-readable description for logs/audit.
    """

    executable: str
    args: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    shell: bool = False
    timeout_seconds: int = 20
    sensitive: bool = True
    description: str = ""


@dataclasses.dataclass
class DeviceControlConfig:
    """
    Runtime configuration for DeviceControls.

    dry_run:
        When True, commands are validated and returned but not executed.
        Recommended default for SaaS/dashboard testing.

    allow_real_execution:
        Must be True before any real OS command is executed.

    require_security_approval:
        If True, sensitive actions require _request_security_approval().

    audit_enabled/event_enabled:
        Enable audit/event hooks. These hooks are safe and no-op when the real
        infrastructure does not exist yet.

    command_timeout_seconds:
        Default timeout for command execution.

    allowed_actions:
        Optional allow-list. Empty means every known action can be considered,
        subject to security checks.

    denied_actions:
        Optional deny-list. Denied actions always fail.
    """

    dry_run: bool = True
    allow_real_execution: bool = False
    require_security_approval: bool = True
    audit_enabled: bool = True
    event_enabled: bool = True
    command_timeout_seconds: int = 20
    allowed_actions: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    denied_actions: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    default_volume_step: int = 5
    default_brightness_step: int = 10
    linux_prefer_systemctl: bool = True
    macos_use_osascript: bool = True
    windows_use_powershell: bool = True


@dataclasses.dataclass
class ExecutionContext:
    """
    SaaS-safe context object for every device-control request.

    user_id and workspace_id are required for user-specific execution.
    request_id is generated when missing for traceability.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    role: Optional[str] = None
    request_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "system_agent"
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "role": self.role,
            "request_id": self.request_id,
            "source": self.source,
            "context_metadata": dict(self.metadata or {}),
        }


@dataclasses.dataclass
class CommandExecutionResult:
    """Normalized command execution result."""

    executed: bool
    return_code: Optional[int]
    stdout: str
    stderr: str
    command: List[str]
    dry_run: bool
    started_at: str
    finished_at: str
    duration_ms: int


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return timezone-aware ISO timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _normalize_os(system_name: Optional[str] = None) -> OperatingSystem:
    """Normalize platform.system() values."""

    raw = (system_name or platform.system() or "").strip().lower()
    if raw.startswith("win"):
        return OperatingSystem.WINDOWS
    if raw in {"darwin", "mac", "macos", "osx"}:
        return OperatingSystem.MACOS
    if raw == "linux":
        return OperatingSystem.LINUX
    return OperatingSystem.UNKNOWN


def _as_bool(value: Any) -> Optional[bool]:
    """
    Convert common boolean-like values to bool.

    Returns None for invalid values so public methods can report validation
    errors cleanly.
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if cleaned in {"1", "true", "yes", "on", "enable", "enabled"}:
            return True
        if cleaned in {"0", "false", "no", "off", "disable", "disabled"}:
            return False
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
    return None


def _clamp_int(value: Any, minimum: int = 0, maximum: int = 100) -> Optional[int]:
    """Convert and clamp an integer percentage."""

    try:
        number = int(value)
    except Exception:
        return None
    return max(minimum, min(maximum, number))


def _safe_join_command(command: Sequence[str]) -> str:
    """Create a safe readable command string for metadata."""

    return " ".join(str(part) for part in command)


def _available(executable: str) -> bool:
    """Return True when executable exists on PATH."""

    return shutil.which(executable) is not None


# ---------------------------------------------------------------------------
# Main DeviceControls class
# ---------------------------------------------------------------------------

class DeviceControls(BaseAgent):
    """
    Production-ready System Agent helper for safe device controls.

    This class is intentionally conservative. It can be used in three ways:

    1. Dry-run mode:
        Validate actions and generate the exact command without executing it.

    2. Real execution mode:
        Requires config.allow_real_execution=True and passing security approval
        for sensitive actions.

    3. Master Agent routing:
        Use run_task() with an action string and parameters:
            controller.run_task("set_volume", {"level": 60}, user_id="u1", workspace_id="w1")

    Connections:
        - Master Agent / Router:
            Public methods and run_task() return structured results.
        - Security Agent:
            _requires_security_check() and _request_security_approval() gate
            sensitive operations.
        - Verification Agent:
            _prepare_verification_payload() describes expected outcome.
        - Memory Agent:
            _prepare_memory_payload() provides safe useful context.
        - Dashboard/API:
            Every result includes metadata, request_id, timestamps and dry-run
            execution data.
        - Audit/Event:
            _log_audit_event() and _emit_agent_event() no-op safely when the
            real project hooks are not available.
    """

    agent_name = "System Agent Device Controls"
    agent_slug = "system_agent.device_controls"
    agent_version = "1.0.0"

    def __init__(
        self,
        config: Optional[DeviceControlConfig] = None,
        security_approval_callback: Optional[
            Callable[[str, SecurityLevel, ExecutionContext, Dict[str, Any]], bool]
        ] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize DeviceControls.

        Args:
            config: Runtime safety and execution configuration.
            security_approval_callback:
                Optional callable used to integrate with Security Agent.
            event_callback:
                Optional callable for agent events.
            audit_callback:
                Optional callable for audit logs.
            logger: Optional logger override.
            **kwargs: Extra args passed to BaseAgent fallback/real class.
        """

        try:
            super().__init__(name=self.agent_name, agent_id=self.agent_slug, **kwargs)
        except TypeError:
            try:
                super().__init__(**kwargs)
            except Exception:
                pass

        self.config = config or DeviceControlConfig()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.logger = logger or LOGGER
        self.os_name = _normalize_os()
        self.created_at = _utc_now()

        self._action_security_levels: Dict[str, SecurityLevel] = {
            DeviceControlAction.SET_WIFI.value: SecurityLevel.MEDIUM,
            DeviceControlAction.GET_WIFI_STATUS.value: SecurityLevel.LOW,
            DeviceControlAction.SET_BLUETOOTH.value: SecurityLevel.MEDIUM,
            DeviceControlAction.GET_BLUETOOTH_STATUS.value: SecurityLevel.LOW,
            DeviceControlAction.SET_VOLUME.value: SecurityLevel.LOW,
            DeviceControlAction.GET_VOLUME.value: SecurityLevel.LOW,
            DeviceControlAction.SET_BRIGHTNESS.value: SecurityLevel.MEDIUM,
            DeviceControlAction.GET_BRIGHTNESS.value: SecurityLevel.LOW,
            DeviceControlAction.SET_BATTERY_SAVER.value: SecurityLevel.MEDIUM,
            DeviceControlAction.GET_BATTERY_SAVER_STATUS.value: SecurityLevel.LOW,
            DeviceControlAction.LOCK_SCREEN.value: SecurityLevel.HIGH,
            DeviceControlAction.SLEEP.value: SecurityLevel.HIGH,
            DeviceControlAction.RESTART.value: SecurityLevel.CRITICAL,
            DeviceControlAction.SHUTDOWN.value: SecurityLevel.CRITICAL,
            DeviceControlAction.GET_DEVICE_STATUS.value: SecurityLevel.LOW,
        }

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[Optional[ExecutionContext], Optional[Dict[str, Any]]]:
        """
        Validate SaaS user/workspace isolation context.

        Device control actions must always be traceable to a user and workspace.
        This prevents mixed audit logs, task history, analytics, and permissions.
        """

        if user_id is None or str(user_id).strip() == "":
            return None, self._error_result(
                message="Missing required user_id for device control action.",
                error="missing_user_id",
                metadata={"validation": "context"},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return None, self._error_result(
                message="Missing required workspace_id for device control action.",
                error="missing_workspace_id",
                metadata={"validation": "context"},
            )

        context = ExecutionContext(
            user_id=str(user_id).strip(),
            workspace_id=str(workspace_id).strip(),
            actor_id=str(actor_id).strip() if actor_id is not None and str(actor_id).strip() else None,
            role=role,
            request_id=request_id or str(uuid.uuid4()),
            source=self.agent_slug,
            metadata=dict(metadata or {}),
        )
        return context, None

    def _requires_security_check(self, action: str, data: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide whether action requires Security Agent approval.

        Most mutating controls are sensitive. Critical power actions are always
        sensitive. Status reads are low-risk but still audited.
        """

        level = self._action_security_levels.get(action, SecurityLevel.HIGH)
        if level in {SecurityLevel.MEDIUM, SecurityLevel.HIGH, SecurityLevel.CRITICAL}:
            return True

        data = data or {}
        if data.get("force") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        level: SecurityLevel,
        context: ExecutionContext,
        data: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Request approval from Security Agent or callback.

        Conservative fallback behavior:
            - Dry-run mode passes approval because no command executes.
            - Real execution without callback fails for sensitive actions.
        """

        payload = {
            "agent": self.agent_slug,
            "action": action,
            "security_level": level.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "data": dict(data or {}),
            "dry_run": self.config.dry_run,
            "allow_real_execution": self.config.allow_real_execution,
            "timestamp": _utc_now(),
        }

        if self.config.dry_run:
            self.logger.debug("Security approval auto-approved for dry-run: %s", payload)
            return True

        if not self.config.require_security_approval:
            return True

        if self.security_approval_callback:
            try:
                return bool(self.security_approval_callback(action, level, context, payload))
            except Exception as exc:
                self.logger.exception("Security approval callback failed: %s", exc)
                return False

        self.logger.warning(
            "Security approval denied: no Security Agent callback configured for action=%s level=%s",
            action,
            level.value,
        )
        return False

    def _prepare_verification_payload(
        self,
        action: str,
        context: ExecutionContext,
        data: Optional[Mapping[str, Any]] = None,
        execution: Optional[CommandExecutionResult] = None,
    ) -> Dict[str, Any]:
        """
        Create a Verification Agent compatible payload.

        Verification Agent can later use this to check if the device state
        changed as expected.
        """

        return {
            "verification_type": "device_control",
            "agent": self.agent_slug,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "expected_state": dict(data or {}),
            "execution": dataclasses.asdict(execution) if execution else None,
            "created_at": _utc_now(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: ExecutionContext,
        data: Optional[Mapping[str, Any]] = None,
        result_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a Memory Agent compatible context payload.

        This does not store secrets. It only captures useful operational context
        such as device preference changes or dry-run action history.
        """

        safe_data = dict(data or {})
        for key in list(safe_data.keys()):
            if "token" in key.lower() or "secret" in key.lower() or "password" in key.lower():
                safe_data[key] = "[REDACTED]"

        return {
            "memory_type": "system_device_control",
            "agent": self.agent_slug,
            "action": action,
            "summary": result_summary or f"Device control action processed: {action}",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "safe_context": safe_data,
            "created_at": _utc_now(),
        }

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit event for dashboard/task history.

        Safe no-op when event infrastructure does not exist.
        """

        if not self.config.event_enabled:
            return

        event_payload = dict(payload)
        event_payload.setdefault("agent", self.agent_slug)
        event_payload.setdefault("timestamp", _utc_now())

        if self.event_callback:
            try:
                self.event_callback(event_name, event_payload)
            except Exception:
                self.logger.exception("DeviceControls event_callback failed")
            return

        if william_emit_agent_event:
            try:
                william_emit_agent_event(event_name, event_payload)
            except Exception:
                self.logger.exception("William emit_agent_event hook failed")
            return

        self.logger.debug("Agent event: %s %s", event_name, event_payload)

    def _log_audit_event(self, payload: Mapping[str, Any]) -> None:
        """
        Log audit event with SaaS context.

        Safe no-op/log-only when the real audit module does not exist yet.
        """

        if not self.config.audit_enabled:
            return

        audit_payload = dict(payload)
        audit_payload.setdefault("agent", self.agent_slug)
        audit_payload.setdefault("timestamp", _utc_now())

        if self.audit_callback:
            try:
                self.audit_callback(audit_payload)
            except Exception:
                self.logger.exception("DeviceControls audit_callback failed")
            return

        if william_log_audit_event:
            try:
                william_log_audit_event(audit_payload)
            except Exception:
                self.logger.exception("William log_audit_event hook failed")
            return

        self.logger.info("Audit event: %s", json.dumps(audit_payload, default=str))

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard successful structured result."""

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent": self.agent_slug,
                "agent_version": self.agent_version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard failed structured result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": str(error),
            "metadata": {
                "agent": self.agent_slug,
                "agent_version": self.agent_version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Public routing interface
    # ------------------------------------------------------------------

    def run_task(
        self,
        action: str,
        parameters: Optional[Mapping[str, Any]] = None,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Master Agent / Router compatible task entrypoint.

        Example:
            controller.run_task(
                "set_volume",
                {"level": 60},
                user_id="u1",
                workspace_id="w1"
            )
        """

        params = dict(parameters or {})
        normalized_action = str(action or "").strip().lower()

        action_map: Dict[str, Callable[..., Dict[str, Any]]] = {
            DeviceControlAction.SET_WIFI.value: self.set_wifi,
            DeviceControlAction.GET_WIFI_STATUS.value: self.get_wifi_status,
            DeviceControlAction.SET_BLUETOOTH.value: self.set_bluetooth,
            DeviceControlAction.GET_BLUETOOTH_STATUS.value: self.get_bluetooth_status,
            DeviceControlAction.SET_VOLUME.value: self.set_volume,
            DeviceControlAction.GET_VOLUME.value: self.get_volume,
            DeviceControlAction.SET_BRIGHTNESS.value: self.set_brightness,
            DeviceControlAction.GET_BRIGHTNESS.value: self.get_brightness,
            DeviceControlAction.SET_BATTERY_SAVER.value: self.set_battery_saver,
            DeviceControlAction.GET_BATTERY_SAVER_STATUS.value: self.get_battery_saver_status,
            DeviceControlAction.LOCK_SCREEN.value: self.lock_screen,
            DeviceControlAction.SLEEP.value: self.sleep_device,
            DeviceControlAction.RESTART.value: self.restart_device,
            DeviceControlAction.SHUTDOWN.value: self.shutdown_device,
            DeviceControlAction.GET_DEVICE_STATUS.value: self.get_device_status,
        }

        if normalized_action not in action_map:
            return self._error_result(
                message=f"Unsupported device control action: {action}",
                error="unsupported_action",
                metadata={
                    "supported_actions": sorted(action_map.keys()),
                    "request_id": request_id,
                },
            )

        common_kwargs = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "role": role,
            "request_id": request_id,
            "metadata": metadata,
        }

        try:
            return action_map[normalized_action](**params, **common_kwargs)
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid parameters for action {normalized_action}.",
                error=exc,
                metadata={
                    "action": normalized_action,
                    "parameters": params,
                    "request_id": request_id,
                },
            )
        except Exception as exc:
            self.logger.exception("DeviceControls.run_task failed")
            return self._error_result(
                message=f"Device control action failed: {normalized_action}",
                error=exc,
                metadata={
                    "action": normalized_action,
                    "request_id": request_id,
                },
            )

    async def arun_task(
        self,
        action: str,
        parameters: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Async wrapper for agent frameworks that expect async calls."""

        return self.run_task(action, parameters, **kwargs)

    # ------------------------------------------------------------------
    # Public action methods
    # ------------------------------------------------------------------

    def set_wifi(
        self,
        enabled: Union[bool, str, int],
        *,
        interface_name: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Enable or disable WiFi where supported by the operating system."""

        bool_enabled = _as_bool(enabled)
        if bool_enabled is None:
            return self._error_result(
                message="Invalid enabled value for WiFi control.",
                error="invalid_enabled_value",
                metadata={"received": enabled},
            )

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        action = DeviceControlAction.SET_WIFI.value
        data = {"enabled": bool_enabled, "interface_name": interface_name}

        command_result = self._perform_action(
            action=action,
            context=context,
            data=data,
            command_factory=lambda: self._build_wifi_command(bool_enabled, interface_name),
        )
        return command_result

    def get_wifi_status(
        self,
        *,
        interface_name: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return WiFi status using available OS tools."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        action = DeviceControlAction.GET_WIFI_STATUS.value
        data = {"interface_name": interface_name}

        return self._perform_action(
            action=action,
            context=context,
            data=data,
            command_factory=lambda: self._build_wifi_status_command(interface_name),
            read_only=True,
        )

    def set_bluetooth(
        self,
        enabled: Union[bool, str, int],
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Enable or disable Bluetooth where supported by the operating system."""

        bool_enabled = _as_bool(enabled)
        if bool_enabled is None:
            return self._error_result(
                message="Invalid enabled value for Bluetooth control.",
                error="invalid_enabled_value",
                metadata={"received": enabled},
            )

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        action = DeviceControlAction.SET_BLUETOOTH.value
        data = {"enabled": bool_enabled}

        return self._perform_action(
            action=action,
            context=context,
            data=data,
            command_factory=lambda: self._build_bluetooth_command(bool_enabled),
        )

    def get_bluetooth_status(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return Bluetooth status using available OS tools."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.GET_BLUETOOTH_STATUS.value,
            context=context,
            data={},
            command_factory=self._build_bluetooth_status_command,
            read_only=True,
        )

    def set_volume(
        self,
        level: Union[int, str, float],
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Set system volume percentage from 0 to 100 where supported."""

        volume = _clamp_int(level, 0, 100)
        if volume is None:
            return self._error_result(
                message="Invalid volume level. Expected integer 0-100.",
                error="invalid_volume_level",
                metadata={"received": level},
            )

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.SET_VOLUME.value,
            context=context,
            data={"level": volume},
            command_factory=lambda: self._build_volume_command(volume),
        )

    def get_volume(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Get current system volume where supported."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.GET_VOLUME.value,
            context=context,
            data={},
            command_factory=self._build_volume_status_command,
            read_only=True,
        )

    def set_brightness(
        self,
        level: Union[int, str, float],
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Set screen brightness percentage from 0 to 100 where supported."""

        brightness = _clamp_int(level, 0, 100)
        if brightness is None:
            return self._error_result(
                message="Invalid brightness level. Expected integer 0-100.",
                error="invalid_brightness_level",
                metadata={"received": level},
            )

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.SET_BRIGHTNESS.value,
            context=context,
            data={"level": brightness},
            command_factory=lambda: self._build_brightness_command(brightness),
        )

    def get_brightness(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Get current screen brightness where supported."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.GET_BRIGHTNESS.value,
            context=context,
            data={},
            command_factory=self._build_brightness_status_command,
            read_only=True,
        )

    def set_battery_saver(
        self,
        enabled: Union[bool, str, int],
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Enable or disable battery saver / low power mode where supported."""

        bool_enabled = _as_bool(enabled)
        if bool_enabled is None:
            return self._error_result(
                message="Invalid enabled value for battery saver control.",
                error="invalid_enabled_value",
                metadata={"received": enabled},
            )

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.SET_BATTERY_SAVER.value,
            context=context,
            data={"enabled": bool_enabled},
            command_factory=lambda: self._build_battery_saver_command(bool_enabled),
        )

    def get_battery_saver_status(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return battery saver / low power mode status where supported."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.GET_BATTERY_SAVER_STATUS.value,
            context=context,
            data={},
            command_factory=self._build_battery_saver_status_command,
            read_only=True,
        )

    def lock_screen(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Lock the current desktop session where supported."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.LOCK_SCREEN.value,
            context=context,
            data={"target": "current_session"},
            command_factory=self._build_lock_command,
        )

    def sleep_device(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Put the device to sleep/suspend where supported."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.SLEEP.value,
            context=context,
            data={"target": "device"},
            command_factory=self._build_sleep_command,
        )

    def restart_device(
        self,
        *,
        delay_seconds: int = 0,
        confirmation: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Restart the device.

        Requires confirmation="RESTART" unless dry-run is enabled.
        """

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        if not self.config.dry_run and confirmation != "RESTART":
            return self._error_result(
                message='Restart requires confirmation="RESTART" when dry_run is disabled.',
                error="missing_restart_confirmation",
                metadata={"request_id": context.request_id if context else request_id},
            )

        safe_delay = max(0, int(delay_seconds or 0))
        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.RESTART.value,
            context=context,
            data={"delay_seconds": safe_delay, "confirmation_present": confirmation == "RESTART"},
            command_factory=lambda: self._build_restart_command(safe_delay),
        )

    def shutdown_device(
        self,
        *,
        delay_seconds: int = 0,
        confirmation: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Shutdown the device.

        Requires confirmation="SHUTDOWN" unless dry-run is enabled.
        """

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        if not self.config.dry_run and confirmation != "SHUTDOWN":
            return self._error_result(
                message='Shutdown requires confirmation="SHUTDOWN" when dry_run is disabled.',
                error="missing_shutdown_confirmation",
                metadata={"request_id": context.request_id if context else request_id},
            )

        safe_delay = max(0, int(delay_seconds or 0))
        assert context is not None
        return self._perform_action(
            action=DeviceControlAction.SHUTDOWN.value,
            context=context,
            data={"delay_seconds": safe_delay, "confirmation_present": confirmation == "SHUTDOWN"},
            command_factory=lambda: self._build_shutdown_command(safe_delay),
        )

    def get_device_status(
        self,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        actor_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return general device status useful for dashboards."""

        context, error = self._validate_task_context(user_id, workspace_id, actor_id, role, request_id, metadata)
        if error:
            return error

        assert context is not None
        data = {
            "os": self.os_name.value,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": platform.node(),
            "current_user": getpass.getuser(),
            "python_version": platform.python_version(),
            "dry_run": self.config.dry_run,
            "allow_real_execution": self.config.allow_real_execution,
            "available_tools": self._detect_available_tools(),
        }

        verification_payload = self._prepare_verification_payload(
            DeviceControlAction.GET_DEVICE_STATUS.value,
            context,
            data,
        )
        memory_payload = self._prepare_memory_payload(
            DeviceControlAction.GET_DEVICE_STATUS.value,
            context,
            data,
            "Device status was requested.",
        )

        self._emit_agent_event("device_status_requested", {**context.to_metadata(), "data": data})
        self._log_audit_event(
            {
                **context.to_metadata(),
                "action": DeviceControlAction.GET_DEVICE_STATUS.value,
                "security_level": SecurityLevel.LOW.value,
                "success": True,
            }
        )

        return self._safe_result(
            message="Device status prepared successfully.",
            data={
                "status": data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata=context.to_metadata(),
        )

    # ------------------------------------------------------------------
    # Internal action pipeline
    # ------------------------------------------------------------------

    def _perform_action(
        self,
        *,
        action: str,
        context: ExecutionContext,
        data: Mapping[str, Any],
        command_factory: Callable[[], Union[DeviceCommand, List[DeviceCommand], Tuple[DeviceCommand, ...], None]],
        read_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Common validation, security, execution, audit and result pipeline.
        """

        if self.config.allowed_actions and action not in self.config.allowed_actions:
            return self._error_result(
                message=f"Action is not allowed by DeviceControls config: {action}",
                error="action_not_allowed",
                metadata={**context.to_metadata(), "action": action},
            )

        if action in self.config.denied_actions:
            return self._error_result(
                message=f"Action is denied by DeviceControls config: {action}",
                error="action_denied",
                metadata={**context.to_metadata(), "action": action},
            )

        level = self._action_security_levels.get(action, SecurityLevel.HIGH)
        security_required = self._requires_security_check(action, data)

        self._emit_agent_event(
            "device_control_requested",
            {
                **context.to_metadata(),
                "action": action,
                "security_level": level.value,
                "security_required": security_required,
                "data": dict(data),
                "dry_run": self.config.dry_run,
            },
        )

        if security_required:
            approved = self._request_security_approval(action, level, context, data)
            if not approved:
                self._log_audit_event(
                    {
                        **context.to_metadata(),
                        "action": action,
                        "security_level": level.value,
                        "success": False,
                        "error": "security_approval_denied",
                        "data": dict(data),
                    }
                )
                return self._error_result(
                    message=f"Security approval denied for action: {action}",
                    error="security_approval_denied",
                    data={"action": action, "security_level": level.value},
                    metadata=context.to_metadata(),
                )

        try:
            command_or_commands = command_factory()
        except Exception as exc:
            self.logger.exception("Command factory failed for action=%s", action)
            return self._error_result(
                message=f"Could not prepare command for action: {action}",
                error=exc,
                data={"action": action, "input": dict(data)},
                metadata=context.to_metadata(),
            )

        if command_or_commands is None:
            return self._error_result(
                message=f"Action is not supported on this operating system or required tools are missing: {action}",
                error="unsupported_or_missing_tool",
                data={"action": action, "os": self.os_name.value, "available_tools": self._detect_available_tools()},
                metadata=context.to_metadata(),
            )

        commands: List[DeviceCommand]
        if isinstance(command_or_commands, DeviceCommand):
            commands = [command_or_commands]
        else:
            commands = list(command_or_commands)

        if not commands:
            return self._error_result(
                message=f"No command prepared for action: {action}",
                error="empty_command",
                metadata=context.to_metadata(),
            )

        executions: List[CommandExecutionResult] = []
        for command in commands:
            execution = self._execute_device_command(command, read_only=read_only)
            executions.append(execution)

            if execution.return_code not in (0, None) and not execution.dry_run:
                break

        all_success = all(
            ex.dry_run or ex.return_code == 0 or (read_only and ex.return_code == 0)
            for ex in executions
        )

        verification_payload = self._prepare_verification_payload(
            action=action,
            context=context,
            data=data,
            execution=executions[-1] if executions else None,
        )
        memory_payload = self._prepare_memory_payload(
            action=action,
            context=context,
            data=data,
            result_summary=f"Device control action {action} {'prepared' if self.config.dry_run else 'executed'}.",
        )

        audit_payload = {
            **context.to_metadata(),
            "action": action,
            "security_level": level.value,
            "success": bool(all_success),
            "dry_run": self.config.dry_run,
            "read_only": read_only,
            "commands": [ex.command for ex in executions],
            "data": dict(data),
            "errors": [ex.stderr for ex in executions if ex.stderr],
        }
        self._log_audit_event(audit_payload)
        self._emit_agent_event(
            "device_control_completed" if all_success else "device_control_failed",
            audit_payload,
        )

        result_data = {
            "action": action,
            "input": dict(data),
            "os": self.os_name.value,
            "dry_run": self.config.dry_run,
            "read_only": read_only,
            "executions": [dataclasses.asdict(ex) for ex in executions],
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
        }

        if all_success:
            return self._safe_result(
                message=(
                    f"Device control action prepared safely: {action}"
                    if self.config.dry_run
                    else f"Device control action completed: {action}"
                ),
                data=result_data,
                metadata=context.to_metadata(),
            )

        return self._error_result(
            message=f"Device control action failed: {action}",
            error="command_failed",
            data=result_data,
            metadata=context.to_metadata(),
        )

    def _execute_device_command(self, command: DeviceCommand, *, read_only: bool = False) -> CommandExecutionResult:
        """
        Execute an OS command safely.

        Real execution requires:
            - config.dry_run is False
            - config.allow_real_execution is True
            - executable is available unless command uses shell
        """

        started_at = _utc_now()
        start_time = time.monotonic()
        command_list = [command.executable, *command.args]

        if self.config.dry_run or not self.config.allow_real_execution:
            finished_at = _utc_now()
            return CommandExecutionResult(
                executed=False,
                return_code=None,
                stdout="",
                stderr="",
                command=command_list,
                dry_run=True,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        if not command.shell and not _available(command.executable):
            finished_at = _utc_now()
            return CommandExecutionResult(
                executed=False,
                return_code=127,
                stdout="",
                stderr=f"Executable not found: {command.executable}",
                command=command_list,
                dry_run=False,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        timeout = command.timeout_seconds or self.config.command_timeout_seconds

        try:
            if command.shell:
                completed = subprocess.run(
                    _safe_join_command(command_list),
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            else:
                completed = subprocess.run(
                    command_list,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )

            finished_at = _utc_now()
            return CommandExecutionResult(
                executed=True,
                return_code=completed.returncode,
                stdout=(completed.stdout or "").strip(),
                stderr=(completed.stderr or "").strip(),
                command=command_list,
                dry_run=False,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        except subprocess.TimeoutExpired as exc:
            finished_at = _utc_now()
            return CommandExecutionResult(
                executed=True,
                return_code=124,
                stdout=(exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
                stderr=f"Command timed out after {timeout}s.",
                command=command_list,
                dry_run=False,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
        except Exception as exc:
            finished_at = _utc_now()
            return CommandExecutionResult(
                executed=False,
                return_code=1,
                stdout="",
                stderr=str(exc),
                command=command_list,
                dry_run=False,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

    # ------------------------------------------------------------------
    # OS command builders
    # ------------------------------------------------------------------

    def _build_wifi_command(self, enabled: bool, interface_name: Optional[str]) -> Optional[DeviceCommand]:
        """Build OS-specific WiFi enable/disable command."""

        if self.os_name == OperatingSystem.WINDOWS:
            interface = interface_name or "Wi-Fi"
            args = (
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                f'netsh interface set interface name="{interface}" admin={"enabled" if enabled else "disabled"}',
            )
            return DeviceCommand(
                executable="powershell",
                args=args,
                description=f"{'Enable' if enabled else 'Disable'} Windows WiFi interface",
            )

        if self.os_name == OperatingSystem.MACOS:
            interface = interface_name or "en0"
            return DeviceCommand(
                executable="networksetup",
                args=("-setairportpower", interface, "on" if enabled else "off"),
                description=f"{'Enable' if enabled else 'Disable'} macOS WiFi",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("nmcli"):
                return DeviceCommand(
                    executable="nmcli",
                    args=("radio", "wifi", "on" if enabled else "off"),
                    description=f"{'Enable' if enabled else 'Disable'} Linux WiFi using nmcli",
                )
            if _available("rfkill"):
                return DeviceCommand(
                    executable="rfkill",
                    args=("unblock" if enabled else "block", "wifi"),
                    description=f"{'Enable' if enabled else 'Disable'} Linux WiFi using rfkill",
                )

        return None

    def _build_wifi_status_command(self, interface_name: Optional[str]) -> Optional[DeviceCommand]:
        """Build OS-specific WiFi status command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="netsh",
                args=("wlan", "show", "interfaces"),
                sensitive=False,
                description="Get Windows WiFi status",
            )

        if self.os_name == OperatingSystem.MACOS:
            interface = interface_name or "en0"
            return DeviceCommand(
                executable="networksetup",
                args=("-getairportpower", interface),
                sensitive=False,
                description="Get macOS WiFi status",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("nmcli"):
                return DeviceCommand(
                    executable="nmcli",
                    args=("radio", "wifi"),
                    sensitive=False,
                    description="Get Linux WiFi status using nmcli",
                )
            if _available("rfkill"):
                return DeviceCommand(
                    executable="rfkill",
                    args=("list", "wifi"),
                    sensitive=False,
                    description="Get Linux WiFi status using rfkill",
                )

        return None

    def _build_bluetooth_command(self, enabled: bool) -> Optional[DeviceCommand]:
        """Build OS-specific Bluetooth enable/disable command."""

        if self.os_name == OperatingSystem.WINDOWS:
            # Windows Bluetooth adapter management varies by driver. This command
            # is intentionally conservative and uses PowerShell PnpDevice where available.
            state_cmd = "Enable-PnpDevice" if enabled else "Disable-PnpDevice"
            confirm = "-Confirm:$false"
            script = (
                f'Get-PnpDevice -Class Bluetooth | '
                f'Where-Object {{$_.Status -ne "Unknown"}} | '
                f'ForEach-Object {{ {state_cmd} -InstanceId $_.InstanceId {confirm} }}'
            )
            return DeviceCommand(
                executable="powershell",
                args=("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script),
                description=f"{'Enable' if enabled else 'Disable'} Windows Bluetooth devices",
            )

        if self.os_name == OperatingSystem.MACOS:
            if _available("blueutil"):
                return DeviceCommand(
                    executable="blueutil",
                    args=("--power", "1" if enabled else "0"),
                    description=f"{'Enable' if enabled else 'Disable'} macOS Bluetooth using blueutil",
                )
            return None

        if self.os_name == OperatingSystem.LINUX:
            if _available("bluetoothctl"):
                return DeviceCommand(
                    executable="bluetoothctl",
                    args=("power", "on" if enabled else "off"),
                    description=f"{'Enable' if enabled else 'Disable'} Linux Bluetooth using bluetoothctl",
                )
            if _available("rfkill"):
                return DeviceCommand(
                    executable="rfkill",
                    args=("unblock" if enabled else "block", "bluetooth"),
                    description=f"{'Enable' if enabled else 'Disable'} Linux Bluetooth using rfkill",
                )

        return None

    def _build_bluetooth_status_command(self) -> Optional[DeviceCommand]:
        """Build OS-specific Bluetooth status command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="powershell",
                args=(
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "Get-PnpDevice -Class Bluetooth | Select-Object FriendlyName,Status,InstanceId",
                ),
                sensitive=False,
                description="Get Windows Bluetooth status",
            )

        if self.os_name == OperatingSystem.MACOS:
            if _available("blueutil"):
                return DeviceCommand(
                    executable="blueutil",
                    args=("--power",),
                    sensitive=False,
                    description="Get macOS Bluetooth status using blueutil",
                )
            return None

        if self.os_name == OperatingSystem.LINUX:
            if _available("bluetoothctl"):
                return DeviceCommand(
                    executable="bluetoothctl",
                    args=("show",),
                    sensitive=False,
                    description="Get Linux Bluetooth status using bluetoothctl",
                )
            if _available("rfkill"):
                return DeviceCommand(
                    executable="rfkill",
                    args=("list", "bluetooth"),
                    sensitive=False,
                    description="Get Linux Bluetooth status using rfkill",
                )

        return None

    def _build_volume_command(self, level: int) -> Optional[DeviceCommand]:
        """Build OS-specific volume set command."""

        if self.os_name == OperatingSystem.WINDOWS:
            # Native Windows volume control is limited without external libs.
            # This uses PowerShell + Windows audio endpoint COM when available.
            # It is wrapped as a command and remains dry-run safe by default.
            script = (
                "$obj = New-Object -ComObject WScript.Shell; "
                "$target = "
                + str(level)
                + "; "
                "$obj.SendKeys([char]173); Start-Sleep -Milliseconds 100; "
                "$obj.SendKeys([char]173); "
                "for ($i=0; $i -lt 50; $i++) { $obj.SendKeys([char]174) }; "
                "$steps = [Math]::Round($target / 2); "
                "for ($i=0; $i -lt $steps; $i++) { $obj.SendKeys([char]175) }"
            )
            return DeviceCommand(
                executable="powershell",
                args=("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script),
                description="Set Windows volume using media key events",
            )

        if self.os_name == OperatingSystem.MACOS:
            apple_volume = round(level / 100 * 7)
            return DeviceCommand(
                executable="osascript",
                args=("-e", f"set volume output volume {level}", "-e", f"set volume {apple_volume}"),
                description="Set macOS volume",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("pactl"):
                return DeviceCommand(
                    executable="pactl",
                    args=("set-sink-volume", "@DEFAULT_SINK@", f"{level}%"),
                    description="Set Linux volume using pactl",
                )
            if _available("amixer"):
                return DeviceCommand(
                    executable="amixer",
                    args=("sset", "Master", f"{level}%"),
                    description="Set Linux volume using amixer",
                )

        return None

    def _build_volume_status_command(self) -> Optional[DeviceCommand]:
        """Build OS-specific volume status command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="powershell",
                args=(
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "Write-Output 'Volume status requires Windows audio API integration.'",
                ),
                sensitive=False,
                description="Get Windows volume status message",
            )

        if self.os_name == OperatingSystem.MACOS:
            return DeviceCommand(
                executable="osascript",
                args=("-e", "output volume of (get volume settings)"),
                sensitive=False,
                description="Get macOS volume",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("pactl"):
                return DeviceCommand(
                    executable="pactl",
                    args=("get-sink-volume", "@DEFAULT_SINK@"),
                    sensitive=False,
                    description="Get Linux volume using pactl",
                )
            if _available("amixer"):
                return DeviceCommand(
                    executable="amixer",
                    args=("get", "Master"),
                    sensitive=False,
                    description="Get Linux volume using amixer",
                )

        return None

    def _build_brightness_command(self, level: int) -> Optional[DeviceCommand]:
        """Build OS-specific brightness set command."""

        if self.os_name == OperatingSystem.WINDOWS:
            script = (
                f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods)"
                f".WmiSetBrightness(1,{level})"
            )
            return DeviceCommand(
                executable="powershell",
                args=("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script),
                description="Set Windows brightness using WMI",
            )

        if self.os_name == OperatingSystem.MACOS:
            if _available("brightness"):
                return DeviceCommand(
                    executable="brightness",
                    args=(str(level / 100),),
                    description="Set macOS brightness using brightness CLI",
                )
            return None

        if self.os_name == OperatingSystem.LINUX:
            if _available("brightnessctl"):
                return DeviceCommand(
                    executable="brightnessctl",
                    args=("set", f"{level}%"),
                    description="Set Linux brightness using brightnessctl",
                )
            if _available("xbacklight"):
                return DeviceCommand(
                    executable="xbacklight",
                    args=("-set", str(level)),
                    description="Set Linux brightness using xbacklight",
                )

        return None

    def _build_brightness_status_command(self) -> Optional[DeviceCommand]:
        """Build OS-specific brightness status command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="powershell",
                args=(
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness",
                ),
                sensitive=False,
                description="Get Windows brightness using WMI",
            )

        if self.os_name == OperatingSystem.MACOS:
            if _available("brightness"):
                return DeviceCommand(
                    executable="brightness",
                    args=("-l",),
                    sensitive=False,
                    description="Get macOS brightness using brightness CLI",
                )
            return None

        if self.os_name == OperatingSystem.LINUX:
            if _available("brightnessctl"):
                return DeviceCommand(
                    executable="brightnessctl",
                    args=("g",),
                    sensitive=False,
                    description="Get Linux brightness using brightnessctl",
                )
            if _available("xbacklight"):
                return DeviceCommand(
                    executable="xbacklight",
                    args=("-get",),
                    sensitive=False,
                    description="Get Linux brightness using xbacklight",
                )

        return None

    def _build_battery_saver_command(self, enabled: bool) -> Optional[DeviceCommand]:
        """Build OS-specific battery saver / low power mode command."""

        if self.os_name == OperatingSystem.WINDOWS:
            # 1 = enabled, 0 = disabled for Energy Saver policy on supported versions.
            # powercfg setdcvalueindex is safer than registry editing.
            value = "1" if enabled else "0"
            script = (
                "powercfg /setdcvalueindex scheme_current sub_energysaver esbattthreshold "
                + ("100" if enabled else "0")
                + "; powercfg /setactive scheme_current; "
                + f'Write-Output "battery_saver_requested={value}"'
            )
            return DeviceCommand(
                executable="powershell",
                args=("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script),
                description=f"{'Enable' if enabled else 'Disable'} Windows battery saver policy",
            )

        if self.os_name == OperatingSystem.MACOS:
            # macOS lowpowermode: 1 enabled, 0 disabled. Usually may require sudo.
            return DeviceCommand(
                executable="pmset",
                args=("-a", "lowpowermode", "1" if enabled else "0"),
                description=f"{'Enable' if enabled else 'Disable'} macOS low power mode",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("powerprofilesctl"):
                return DeviceCommand(
                    executable="powerprofilesctl",
                    args=("set", "power-saver" if enabled else "balanced"),
                    description=f"{'Enable' if enabled else 'Disable'} Linux power saver profile",
                )
            return None

        return None

    def _build_battery_saver_status_command(self) -> Optional[DeviceCommand]:
        """Build OS-specific battery saver status command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="powershell",
                args=(
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "powercfg /query scheme_current sub_energysaver esbattthreshold",
                ),
                sensitive=False,
                description="Get Windows battery saver policy",
            )

        if self.os_name == OperatingSystem.MACOS:
            return DeviceCommand(
                executable="pmset",
                args=("-g",),
                sensitive=False,
                description="Get macOS power settings",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("powerprofilesctl"):
                return DeviceCommand(
                    executable="powerprofilesctl",
                    args=("get",),
                    sensitive=False,
                    description="Get Linux power profile",
                )
            if _available("upower"):
                return DeviceCommand(
                    executable="upower",
                    args=("-d",),
                    sensitive=False,
                    description="Get Linux power status using upower",
                )

        return None

    def _build_lock_command(self) -> Optional[DeviceCommand]:
        """Build OS-specific lock screen command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="rundll32.exe",
                args=("user32.dll,LockWorkStation",),
                description="Lock Windows workstation",
            )

        if self.os_name == OperatingSystem.MACOS:
            return DeviceCommand(
                executable="pmset",
                args=("displaysleepnow",),
                description="Lock/sleep macOS display",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("loginctl"):
                return DeviceCommand(
                    executable="loginctl",
                    args=("lock-session",),
                    description="Lock Linux session using loginctl",
                )
            if _available("xdg-screensaver"):
                return DeviceCommand(
                    executable="xdg-screensaver",
                    args=("lock",),
                    description="Lock Linux session using xdg-screensaver",
                )
            if _available("gnome-screensaver-command"):
                return DeviceCommand(
                    executable="gnome-screensaver-command",
                    args=("-l",),
                    description="Lock Linux session using gnome-screensaver-command",
                )

        return None

    def _build_sleep_command(self) -> Optional[DeviceCommand]:
        """Build OS-specific sleep/suspend command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="rundll32.exe",
                args=("powrprof.dll,SetSuspendState", "0,1,0"),
                description="Put Windows device to sleep",
            )

        if self.os_name == OperatingSystem.MACOS:
            return DeviceCommand(
                executable="pmset",
                args=("sleepnow",),
                description="Put macOS device to sleep",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("systemctl"):
                return DeviceCommand(
                    executable="systemctl",
                    args=("suspend",),
                    description="Suspend Linux device using systemctl",
                )
            if _available("loginctl"):
                return DeviceCommand(
                    executable="loginctl",
                    args=("suspend",),
                    description="Suspend Linux device using loginctl",
                )

        return None

    def _build_restart_command(self, delay_seconds: int = 0) -> Optional[DeviceCommand]:
        """Build OS-specific restart command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="shutdown",
                args=("/r", "/t", str(max(0, int(delay_seconds)))),
                timeout_seconds=5,
                description="Restart Windows device",
            )

        if self.os_name == OperatingSystem.MACOS:
            if delay_seconds > 0:
                return DeviceCommand(
                    executable="sh",
                    args=("-c", f"sleep {int(delay_seconds)} && osascript -e 'tell app \"System Events\" to restart'"),
                    timeout_seconds=5,
                    description="Delayed restart macOS device",
                )
            return DeviceCommand(
                executable="osascript",
                args=("-e", 'tell app "System Events" to restart'),
                timeout_seconds=5,
                description="Restart macOS device",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("systemctl"):
                return DeviceCommand(
                    executable="systemctl",
                    args=("reboot",),
                    timeout_seconds=5,
                    description="Restart Linux device using systemctl",
                )
            if _available("shutdown"):
                minutes = max(0, int(delay_seconds)) // 60
                return DeviceCommand(
                    executable="shutdown",
                    args=("-r", f"+{minutes}"),
                    timeout_seconds=5,
                    description="Restart Linux device using shutdown",
                )

        return None

    def _build_shutdown_command(self, delay_seconds: int = 0) -> Optional[DeviceCommand]:
        """Build OS-specific shutdown command."""

        if self.os_name == OperatingSystem.WINDOWS:
            return DeviceCommand(
                executable="shutdown",
                args=("/s", "/t", str(max(0, int(delay_seconds)))),
                timeout_seconds=5,
                description="Shutdown Windows device",
            )

        if self.os_name == OperatingSystem.MACOS:
            if delay_seconds > 0:
                return DeviceCommand(
                    executable="sh",
                    args=("-c", f"sleep {int(delay_seconds)} && osascript -e 'tell app \"System Events\" to shut down'"),
                    timeout_seconds=5,
                    description="Delayed shutdown macOS device",
                )
            return DeviceCommand(
                executable="osascript",
                args=("-e", 'tell app "System Events" to shut down'),
                timeout_seconds=5,
                description="Shutdown macOS device",
            )

        if self.os_name == OperatingSystem.LINUX:
            if _available("systemctl"):
                return DeviceCommand(
                    executable="systemctl",
                    args=("poweroff",),
                    timeout_seconds=5,
                    description="Shutdown Linux device using systemctl",
                )
            if _available("shutdown"):
                minutes = max(0, int(delay_seconds)) // 60
                return DeviceCommand(
                    executable="shutdown",
                    args=("-h", f"+{minutes}"),
                    timeout_seconds=5,
                    description="Shutdown Linux device using shutdown",
                )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _detect_available_tools(self) -> Dict[str, bool]:
        """Return supported command-line tools availability for diagnostics."""

        tools = [
            "powershell",
            "netsh",
            "shutdown",
            "rundll32.exe",
            "networksetup",
            "osascript",
            "pmset",
            "blueutil",
            "brightness",
            "nmcli",
            "rfkill",
            "bluetoothctl",
            "pactl",
            "amixer",
            "brightnessctl",
            "xbacklight",
            "powerprofilesctl",
            "upower",
            "loginctl",
            "xdg-screensaver",
            "gnome-screensaver-command",
            "systemctl",
        ]
        return {tool: _available(tool) for tool in tools}

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return a static/detected capability map for dashboard display.

        This method does not require user/workspace context because it is
        metadata about the agent module, not user-specific execution.
        """

        tools = self._detect_available_tools()
        capabilities = {
            "agent": self.agent_slug,
            "agent_version": self.agent_version,
            "os": self.os_name.value,
            "dry_run": self.config.dry_run,
            "allow_real_execution": self.config.allow_real_execution,
            "actions": [action.value for action in DeviceControlAction],
            "available_tools": tools,
            "supports": {
                "wifi": self._build_wifi_status_command(None) is not None or self._build_wifi_command(True, None) is not None,
                "bluetooth": self._build_bluetooth_status_command() is not None or self._build_bluetooth_command(True) is not None,
                "volume": self._build_volume_status_command() is not None or self._build_volume_command(50) is not None,
                "brightness": self._build_brightness_status_command() is not None or self._build_brightness_command(50) is not None,
                "battery_saver": self._build_battery_saver_status_command() is not None or self._build_battery_saver_command(True) is not None,
                "lock_screen": self._build_lock_command() is not None,
                "sleep": self._build_sleep_command() is not None,
                "restart": self._build_restart_command(0) is not None,
                "shutdown": self._build_shutdown_command(0) is not None,
            },
            "created_at": self.created_at,
            "checked_at": _utc_now(),
        }
        return capabilities

    def update_config(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Update runtime config safely.

        Useful for dashboard toggles. Unknown fields are rejected.
        """

        allowed_fields = {field.name for field in dataclasses.fields(DeviceControlConfig)}
        rejected = sorted(set(kwargs.keys()) - allowed_fields)
        if rejected:
            return self._error_result(
                message="Unsupported DeviceControlConfig fields.",
                error="unsupported_config_fields",
                data={"rejected": rejected, "allowed": sorted(allowed_fields)},
            )

        config_dict = dataclasses.asdict(self.config)
        config_dict.update(kwargs)

        tuple_fields = {"allowed_actions", "denied_actions"}
        for field_name in tuple_fields:
            if field_name in config_dict and not isinstance(config_dict[field_name], tuple):
                config_dict[field_name] = tuple(config_dict[field_name] or ())

        self.config = DeviceControlConfig(**config_dict)
        return self._safe_result(
            message="DeviceControls config updated.",
            data={"config": dataclasses.asdict(self.config)},
        )


# ---------------------------------------------------------------------------
# Factory and module exports
# ---------------------------------------------------------------------------

def create_device_controls(
    *,
    dry_run: bool = True,
    allow_real_execution: bool = False,
    require_security_approval: bool = True,
    security_approval_callback: Optional[
        Callable[[str, SecurityLevel, ExecutionContext, Dict[str, Any]], bool]
    ] = None,
    event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    **config_overrides: Any,
) -> DeviceControls:
    """
    Factory used by Agent Loader / Registry.

    Example:
        controller = create_device_controls(dry_run=True)
    """

    config_data = {
        "dry_run": dry_run,
        "allow_real_execution": allow_real_execution,
        "require_security_approval": require_security_approval,
        **config_overrides,
    }
    config = DeviceControlConfig(**config_data)
    return DeviceControls(
        config=config,
        security_approval_callback=security_approval_callback,
        event_callback=event_callback,
        audit_callback=audit_callback,
    )


def get_agent_manifest() -> Dict[str, Any]:
    """
    Registry-compatible manifest for plugin-style loading.
    """

    return {
        "agent": DeviceControls.agent_slug,
        "name": DeviceControls.agent_name,
        "version": DeviceControls.agent_version,
        "class_name": "DeviceControls",
        "factory": "create_device_controls",
        "module": "agents.system_agent.device_controls",
        "description": "Controls WiFi, Bluetooth, volume, brightness, battery saver, lock, sleep, restart, and shutdown safely.",
        "actions": [action.value for action in DeviceControlAction],
        "requires_user_context": True,
        "requires_workspace_context": True,
        "security_gated": True,
        "safe_import": True,
        "default_dry_run": True,
    }


__all__ = [
    "DeviceControls",
    "DeviceControlConfig",
    "DeviceControlAction",
    "DeviceCommand",
    "ExecutionContext",
    "CommandExecutionResult",
    "SecurityLevel",
    "OperatingSystem",
    "create_device_controls",
    "get_agent_manifest",
]


if __name__ == "__main__":
    # Safe manual smoke test. This does NOT execute real system commands.
    controller = create_device_controls(dry_run=True)
    print(json.dumps(controller.get_capabilities(), indent=2, default=str))
    print(
        json.dumps(
            controller.run_task(
                "set_volume",
                {"level": 50},
                user_id="demo_user",
                workspace_id="demo_workspace",
            ),
            indent=2,
            default=str,
        )
    )
