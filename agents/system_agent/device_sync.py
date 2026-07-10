"""
agents/system_agent/device_sync.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Multi-device routing and sync for laptop, phone, desktop, server, watch, glasses.

This module provides the DeviceSync class for the System Agent. It handles:
    - SaaS-safe device registration
    - User/workspace-isolated device state
    - Heartbeat tracking
    - Online/offline detection
    - Capability-based device routing
    - Task routing to the best device
    - Multi-device sync snapshots
    - Audit, memory, verification, and event payload preparation

Architecture compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - Master Agent compatible
    - Security Agent approval compatible
    - Memory Agent payload compatible
    - Verification Agent payload compatible
    - Dashboard/API ready

Security:
    This file does not perform real destructive device actions.
    Sensitive routing and sync operations pass through permission/security hooks.
"""

from __future__ import annotations

import copy
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# -------------------------------------------------------------------------
# Safe optional BaseAgent import
# -------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # fallback stub for import-safety
        """
        Fallback BaseAgent stub.

        This allows device_sync.py to import safely even if the real William/Jarvis
        BaseAgent has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "system")
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": None,
                "metadata": {},
            }


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

logger = logging.getLogger("DeviceSync")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# -------------------------------------------------------------------------
# Enums and constants
# -------------------------------------------------------------------------

class DeviceType(str, Enum):
    LAPTOP = "laptop"
    PHONE = "phone"
    DESKTOP = "desktop"
    SERVER = "server"
    WATCH = "watch"
    GLASSES = "glasses"
    TABLET = "tablet"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    IDLE = "idle"
    BUSY = "busy"
    SYNCING = "syncing"
    ERROR = "error"
    DISABLED = "disabled"


class RoutePriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class SyncDirection(str, Enum):
    PUSH = "push"
    PULL = "pull"
    BIDIRECTIONAL = "bidirectional"


DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 90
DEFAULT_MAX_EVENT_LOG = 500
DEFAULT_MAX_AUDIT_LOG = 500
DEFAULT_MAX_TASK_HISTORY = 500

SUPPORTED_DEVICE_TYPES = {
    DeviceType.LAPTOP.value,
    DeviceType.PHONE.value,
    DeviceType.DESKTOP.value,
    DeviceType.SERVER.value,
    DeviceType.WATCH.value,
    DeviceType.GLASSES.value,
    DeviceType.TABLET.value,
    DeviceType.UNKNOWN.value,
}

DEFAULT_CAPABILITIES_BY_TYPE = {
    DeviceType.LAPTOP.value: [
        "browser",
        "files",
        "voice",
        "screen",
        "notifications",
        "desktop_apps",
        "code",
    ],
    DeviceType.DESKTOP.value: [
        "browser",
        "files",
        "voice",
        "screen",
        "notifications",
        "desktop_apps",
        "code",
        "heavy_compute",
    ],
    DeviceType.PHONE.value: [
        "calls",
        "messages",
        "notifications",
        "mobile_apps",
        "gps",
        "camera",
        "microphone",
    ],
    DeviceType.SERVER.value: [
        "api",
        "background_jobs",
        "storage",
        "heavy_compute",
        "scheduled_tasks",
        "webhooks",
    ],
    DeviceType.WATCH.value: [
        "notifications",
        "health_events",
        "quick_actions",
        "microphone",
    ],
    DeviceType.GLASSES.value: [
        "camera",
        "visual_context",
        "voice",
        "ar_display",
        "microphone",
    ],
    DeviceType.TABLET.value: [
        "browser",
        "files",
        "screen",
        "mobile_apps",
        "camera",
        "microphone",
    ],
    DeviceType.UNKNOWN.value: [],
}


# -------------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------------

@dataclass
class DeviceIdentity:
    """
    Identity information for one device.

    user_id and workspace_id are mandatory for SaaS isolation.
    device_id is unique within the DeviceSync store.
    """

    user_id: str
    workspace_id: str
    device_id: str
    device_name: str
    device_type: str = DeviceType.UNKNOWN.value
    owner_label: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    app_version: Optional[str] = None


@dataclass
class DeviceRuntime:
    """
    Runtime state for a device.
    """

    status: str = DeviceStatus.OFFLINE.value
    capabilities: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    registered_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    current_task_id: Optional[str] = None
    current_task_type: Optional[str] = None
    load_score: float = 0.0
    battery_percent: Optional[int] = None
    network_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceRecord:
    """
    Complete device record.
    """

    identity: DeviceIdentity
    runtime: DeviceRuntime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity": asdict(self.identity),
            "runtime": asdict(self.runtime),
        }


@dataclass
class RoutedTask:
    """
    Internal task routing record.
    """

    task_id: str
    user_id: str
    workspace_id: str
    task_type: str
    target_device_id: str
    priority: str = RoutePriority.NORMAL.value
    payload: Dict[str, Any] = field(default_factory=dict)
    routed_at: float = field(default_factory=time.time)
    status: str = "routed"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SyncSnapshot:
    """
    Sync state payload for device-to-device or device-to-server sync.
    """

    sync_id: str
    user_id: str
    workspace_id: str
    source_device_id: str
    target_device_ids: List[str]
    direction: str = SyncDirection.BIDIRECTIONAL.value
    state: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


# -------------------------------------------------------------------------
# DeviceSync
# -------------------------------------------------------------------------

class DeviceSync(BaseAgent):
    """
    DeviceSync handles multi-device registration, routing, heartbeat, and sync.

    Master Agent:
        Can call route_task_to_device() to select the best target device.

    Security Agent:
        Sensitive operations pass through _request_security_approval().

    Memory Agent:
        Useful device context is prepared using _prepare_memory_payload().

    Verification Agent:
        Completed actions prepare payloads via _prepare_verification_payload().

    Dashboard/API:
        Methods return structured dict results suitable for FastAPI/Flask responses.

    Registry/Router:
        Public methods are stable and structured for agent routing.
    """

    def __init__(
        self,
        agent_name: str = "DeviceSync",
        heartbeat_timeout_seconds: int = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        max_event_log: int = DEFAULT_MAX_EVENT_LOG,
        max_audit_log: int = DEFAULT_MAX_AUDIT_LOG,
        max_task_history: int = DEFAULT_MAX_TASK_HISTORY,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_type="system", **kwargs)

        self.agent_name = agent_name
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self.max_event_log = max_event_log
        self.max_audit_log = max_audit_log
        self.max_task_history = max_task_history

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self._lock = threading.RLock()

        # Main isolated storage:
        # key = (user_id, workspace_id, device_id)
        self._devices: Dict[Tuple[str, str, str], DeviceRecord] = {}

        # Routed task storage:
        # key = task_id
        self._task_history: Dict[str, RoutedTask] = {}

        # Sync snapshots:
        # key = sync_id
        self._sync_snapshots: Dict[str, SyncSnapshot] = {}

        self._event_log: List[Dict[str, Any]] = []
        self._audit_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # BaseAgent-compatible entrypoint
    # ------------------------------------------------------------------

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Generic router-friendly run method.

        Supported actions:
            - register_device
            - update_device_status
            - heartbeat
            - list_devices
            - get_device
            - remove_device
            - route_task
            - sync_state
            - broadcast_sync
            - mark_stale_offline
        """

        task = task or {}
        action = task.get("action") or kwargs.get("action")

        if not action:
            return self._error_result(
                message="No action provided for DeviceSync.",
                error_code="missing_action",
                metadata={"supported_actions": self.supported_actions()},
            )

        payload = task.get("payload") or kwargs.get("payload") or {}
        context = task.get("context") or kwargs.get("context") or {}

        action_map = {
            "register_device": self.register_device,
            "update_device_status": self.update_device_status,
            "heartbeat": self.heartbeat,
            "list_devices": self.list_devices,
            "get_device": self.get_device,
            "remove_device": self.remove_device,
            "route_task": self.route_task_to_device,
            "sync_state": self.sync_state,
            "broadcast_sync": self.broadcast_sync,
            "mark_stale_offline": self.mark_stale_devices_offline,
        }

        handler = action_map.get(str(action))
        if not handler:
            return self._error_result(
                message=f"Unsupported DeviceSync action: {action}",
                error_code="unsupported_action",
                metadata={"supported_actions": self.supported_actions()},
            )

        try:
            return handler(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid payload for action '{action}'.",
                error=str(exc),
                error_code="invalid_payload",
            )
        except Exception as exc:
            logger.exception("DeviceSync run() failed.")
            return self._error_result(
                message=f"DeviceSync action '{action}' failed.",
                error=str(exc),
                error_code="action_failed",
            )

    def supported_actions(self) -> List[str]:
        return [
            "register_device",
            "update_device_status",
            "heartbeat",
            "list_devices",
            "get_device",
            "remove_device",
            "route_task",
            "sync_state",
            "broadcast_sync",
            "mark_stale_offline",
        ]

    # ------------------------------------------------------------------
    # Public API: device registration and lifecycle
    # ------------------------------------------------------------------

    def register_device(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        device_type: str = DeviceType.UNKNOWN.value,
        capabilities: Optional[List[str]] = None,
        platform: Optional[str] = None,
        os_version: Optional[str] = None,
        app_version: Optional[str] = None,
        owner_label: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register or update one device in a user/workspace isolated way.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        safe_device_type = self._normalize_device_type(device_type)
        safe_device_id = device_id or self._generate_device_id(safe_device_type)
        safe_device_name = device_name or f"{safe_device_type}-{safe_device_id[-6:]}"

        requested_capabilities = capabilities
        if requested_capabilities is None:
            requested_capabilities = DEFAULT_CAPABILITIES_BY_TYPE.get(safe_device_type, [])

        cleaned_capabilities = self._clean_capabilities(requested_capabilities)
        now = time.time()

        operation = "register_device"
        if self._requires_security_check(operation=operation, device_type=safe_device_type):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "device_id": safe_device_id,
                    "device_type": safe_device_type,
                    "capabilities": cleaned_capabilities,
                },
            )
            if not approval["success"]:
                return approval

        with self._lock:
            key = self._device_key(user_id, workspace_id, safe_device_id)
            existing = self._devices.get(key)

            identity = DeviceIdentity(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                device_id=safe_device_id,
                device_name=safe_device_name,
                device_type=safe_device_type,
                owner_label=owner_label,
                platform=platform,
                os_version=os_version,
                app_version=app_version,
            )

            if existing:
                runtime = existing.runtime
                runtime.status = DeviceStatus.ONLINE.value
                runtime.capabilities = cleaned_capabilities
                runtime.last_seen = now
                runtime.updated_at = now
                runtime.metadata.update(metadata or {})
                record = DeviceRecord(identity=identity, runtime=runtime)
                message = "Device updated successfully."
            else:
                runtime = DeviceRuntime(
                    status=DeviceStatus.ONLINE.value,
                    capabilities=cleaned_capabilities,
                    last_seen=now,
                    registered_at=now,
                    updated_at=now,
                    metadata=metadata or {},
                )
                record = DeviceRecord(identity=identity, runtime=runtime)
                message = "Device registered successfully."

            self._devices[key] = record

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=safe_device_id,
            details={
                "device_type": safe_device_type,
                "device_name": safe_device_name,
                "capabilities": cleaned_capabilities,
            },
        )

        event = self._emit_agent_event(
            event_type="device.registered",
            user_id=user_id,
            workspace_id=workspace_id,
            data=record.to_dict(),
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data=record.to_dict(),
        )

        memory = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="device_context",
            content={
                "device_id": safe_device_id,
                "device_name": safe_device_name,
                "device_type": safe_device_type,
                "capabilities": cleaned_capabilities,
            },
        )

        return self._safe_result(
            message=message,
            data={
                "device": record.to_dict(),
                "verification_payload": verification,
                "memory_payload": memory,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "device_id": safe_device_id,
            },
        )

    def update_device_status(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        status: str = DeviceStatus.ONLINE.value,
        current_task_id: Optional[str] = None,
        current_task_type: Optional[str] = None,
        load_score: Optional[float] = None,
        battery_percent: Optional[int] = None,
        network_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update status/runtime metadata for a registered device.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not device_id:
            return self._error_result(
                message="device_id is required.",
                error_code="missing_device_id",
            )

        safe_status = self._normalize_status(status)
        now = time.time()

        with self._lock:
            key = self._device_key(user_id, workspace_id, device_id)
            record = self._devices.get(key)

            if not record:
                return self._error_result(
                    message="Device not found for this user/workspace.",
                    error_code="device_not_found",
                    metadata={
                        "user_id": str(user_id),
                        "workspace_id": str(workspace_id),
                        "device_id": device_id,
                    },
                )

            record.runtime.status = safe_status
            record.runtime.updated_at = now
            record.runtime.last_seen = now

            if current_task_id is not None:
                record.runtime.current_task_id = current_task_id

            if current_task_type is not None:
                record.runtime.current_task_type = current_task_type

            if load_score is not None:
                record.runtime.load_score = self._safe_float(load_score, default=0.0)

            if battery_percent is not None:
                record.runtime.battery_percent = self._normalize_percent(battery_percent)

            if network_type is not None:
                record.runtime.network_type = str(network_type)

            if metadata:
                record.runtime.metadata.update(metadata)

            updated_device = record.to_dict()

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action="update_device_status",
            resource_id=device_id,
            details={"status": safe_status},
        )

        event = self._emit_agent_event(
            event_type="device.status_updated",
            user_id=user_id,
            workspace_id=workspace_id,
            data=updated_device,
        )

        verification = self._prepare_verification_payload(
            operation="update_device_status",
            user_id=user_id,
            workspace_id=workspace_id,
            data=updated_device,
        )

        return self._safe_result(
            message="Device status updated successfully.",
            data={
                "device": updated_device,
                "verification_payload": verification,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "device_id": device_id,
            },
        )

    def heartbeat(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        status: str = DeviceStatus.ONLINE.value,
        load_score: Optional[float] = None,
        battery_percent: Optional[int] = None,
        network_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update heartbeat for an existing device.
        """

        return self.update_device_status(
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            status=status,
            load_score=load_score,
            battery_percent=battery_percent,
            network_type=network_type,
            metadata=metadata,
            context=context,
        )

    def remove_device(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remove a device from this workspace.

        This is a sensitive operation because removing a device can affect routing.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not device_id:
            return self._error_result(
                message="device_id is required.",
                error_code="missing_device_id",
            )

        operation = "remove_device"
        if self._requires_security_check(operation=operation):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={"device_id": device_id},
            )
            if not approval["success"]:
                return approval

        with self._lock:
            key = self._device_key(user_id, workspace_id, device_id)
            record = self._devices.pop(key, None)

        if not record:
            return self._error_result(
                message="Device not found for this user/workspace.",
                error_code="device_not_found",
                metadata={
                    "user_id": str(user_id),
                    "workspace_id": str(workspace_id),
                    "device_id": device_id,
                },
            )

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=device_id,
            details={"removed_device": record.to_dict()},
        )

        event = self._emit_agent_event(
            event_type="device.removed",
            user_id=user_id,
            workspace_id=workspace_id,
            data={"device_id": device_id},
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data={"device_id": device_id},
        )

        return self._safe_result(
            message="Device removed successfully.",
            data={
                "removed_device": record.to_dict(),
                "verification_payload": verification,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "device_id": device_id,
            },
        )

    # ------------------------------------------------------------------
    # Public API: listing and lookup
    # ------------------------------------------------------------------

    def list_devices(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_type: Optional[str] = None,
        status: Optional[str] = None,
        capability: Optional[str] = None,
        include_offline_update: bool = True,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List devices for one user/workspace only.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if include_offline_update:
            self.mark_stale_devices_offline(
                user_id=user_id,
                workspace_id=workspace_id,
                context=context,
            )

        safe_device_type = self._normalize_device_type(device_type) if device_type else None
        safe_status = self._normalize_status(status) if status else None
        safe_capability = str(capability).strip().lower() if capability else None

        with self._lock:
            devices = []
            for (uid, wid, _device_id), record in self._devices.items():
                if uid != str(user_id) or wid != str(workspace_id):
                    continue

                if safe_device_type and record.identity.device_type != safe_device_type:
                    continue

                if safe_status and record.runtime.status != safe_status:
                    continue

                if safe_capability and safe_capability not in record.runtime.capabilities:
                    continue

                devices.append(record.to_dict())

        devices.sort(
            key=lambda item: (
                item["runtime"].get("status") != DeviceStatus.ONLINE.value,
                item["identity"].get("device_type", ""),
                item["identity"].get("device_name", ""),
            )
        )

        return self._safe_result(
            message="Devices listed successfully.",
            data={
                "devices": devices,
                "count": len(devices),
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "filters": {
                    "device_type": safe_device_type,
                    "status": safe_status,
                    "capability": safe_capability,
                },
            },
        )

    def get_device(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get one device by ID within user/workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not device_id:
            return self._error_result(
                message="device_id is required.",
                error_code="missing_device_id",
            )

        with self._lock:
            record = self._devices.get(self._device_key(user_id, workspace_id, device_id))

        if not record:
            return self._error_result(
                message="Device not found for this user/workspace.",
                error_code="device_not_found",
                metadata={
                    "user_id": str(user_id),
                    "workspace_id": str(workspace_id),
                    "device_id": device_id,
                },
            )

        return self._safe_result(
            message="Device found.",
            data={"device": record.to_dict()},
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "device_id": device_id,
            },
        )

    def get_online_devices(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        capability: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for fetching online devices.
        """

        return self.list_devices(
            user_id=user_id,
            workspace_id=workspace_id,
            status=DeviceStatus.ONLINE.value,
            capability=capability,
            context=context,
        )

    # ------------------------------------------------------------------
    # Public API: routing
    # ------------------------------------------------------------------

    def route_task_to_device(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        task_type: Optional[str] = None,
        required_capabilities: Optional[List[str]] = None,
        preferred_device_id: Optional[str] = None,
        preferred_device_type: Optional[str] = None,
        priority: str = RoutePriority.NORMAL.value,
        payload: Optional[Dict[str, Any]] = None,
        allow_busy: bool = False,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Select the best device for a task and create a routed task record.

        This does not execute the task directly. It prepares safe routing metadata
        that Master Agent, Router, Dashboard/API, or device workers can consume.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not task_type:
            return self._error_result(
                message="task_type is required.",
                error_code="missing_task_type",
            )

        cleaned_required = self._clean_capabilities(required_capabilities or [])
        safe_priority = self._normalize_priority(priority)
        safe_preferred_type = (
            self._normalize_device_type(preferred_device_type)
            if preferred_device_type
            else None
        )

        operation = "route_task_to_device"
        if self._requires_security_check(operation=operation, task_type=task_type):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "task_type": task_type,
                    "required_capabilities": cleaned_required,
                    "preferred_device_id": preferred_device_id,
                    "preferred_device_type": safe_preferred_type,
                    "priority": safe_priority,
                },
            )
            if not approval["success"]:
                return approval

        self.mark_stale_devices_offline(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        with self._lock:
            candidates = self._find_route_candidates(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                required_capabilities=cleaned_required,
                preferred_device_id=preferred_device_id,
                preferred_device_type=safe_preferred_type,
                allow_busy=allow_busy,
            )

            if not candidates:
                return self._error_result(
                    message="No suitable device found for this task.",
                    error_code="no_device_available",
                    metadata={
                        "user_id": str(user_id),
                        "workspace_id": str(workspace_id),
                        "task_type": task_type,
                        "required_capabilities": cleaned_required,
                        "preferred_device_id": preferred_device_id,
                        "preferred_device_type": safe_preferred_type,
                        "allow_busy": allow_busy,
                    },
                )

            best_device = self._select_best_device(candidates)
            task_id = self._generate_task_id()
            routed = RoutedTask(
                task_id=task_id,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                task_type=str(task_type),
                target_device_id=best_device.identity.device_id,
                priority=safe_priority,
                payload=payload or {},
                metadata={
                    "required_capabilities": cleaned_required,
                    "preferred_device_id": preferred_device_id,
                    "preferred_device_type": safe_preferred_type,
                    "selected_device_type": best_device.identity.device_type,
                    "selected_device_name": best_device.identity.device_name,
                },
            )

            best_device.runtime.status = DeviceStatus.BUSY.value
            best_device.runtime.current_task_id = task_id
            best_device.runtime.current_task_type = str(task_type)
            best_device.runtime.updated_at = time.time()

            self._task_history[task_id] = routed
            self._trim_task_history_locked()

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=task_id,
            details={
                "task_type": task_type,
                "target_device_id": best_device.identity.device_id,
                "priority": safe_priority,
            },
        )

        event = self._emit_agent_event(
            event_type="device.task_routed",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "task": asdict(routed),
                "device": best_device.to_dict(),
            },
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "task": asdict(routed),
                "device": best_device.to_dict(),
            },
        )

        memory = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="device_routing_context",
            content={
                "task_type": task_type,
                "target_device_id": best_device.identity.device_id,
                "target_device_type": best_device.identity.device_type,
                "required_capabilities": cleaned_required,
            },
        )

        return self._safe_result(
            message="Task routed to device successfully.",
            data={
                "task": asdict(routed),
                "target_device": best_device.to_dict(),
                "verification_payload": verification,
                "memory_payload": memory,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "task_id": task_id,
                "target_device_id": best_device.identity.device_id,
            },
        )

    def complete_routed_task(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: str,
        success: bool = True,
        result_data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mark a routed task complete and release the target device.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            routed = self._task_history.get(task_id)
            if not routed:
                return self._error_result(
                    message="Routed task not found.",
                    error_code="task_not_found",
                    metadata={"task_id": task_id},
                )

            if routed.user_id != str(user_id) or routed.workspace_id != str(workspace_id):
                return self._error_result(
                    message="Task does not belong to this user/workspace.",
                    error_code="task_scope_mismatch",
                )

            routed.status = "completed" if success else "failed"
            routed.metadata["completed_at"] = time.time()
            routed.metadata["result_data"] = result_data or {}
            routed.metadata["error"] = error

            device_key = self._device_key(user_id, workspace_id, routed.target_device_id)
            device = self._devices.get(device_key)
            if device:
                device.runtime.current_task_id = None
                device.runtime.current_task_type = None
                device.runtime.status = DeviceStatus.ONLINE.value if success else DeviceStatus.ERROR.value
                device.runtime.updated_at = time.time()

        verification = self._prepare_verification_payload(
            operation="complete_routed_task",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "task_id": task_id,
                "success": success,
                "result_data": result_data or {},
                "error": error,
            },
        )

        self._emit_agent_event(
            event_type="device.task_completed",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "task_id": task_id,
                "success": success,
                "target_device_id": routed.target_device_id,
            },
        )

        return self._safe_result(
            message="Routed task completion recorded.",
            data={
                "task": asdict(routed),
                "verification_payload": verification,
            },
            metadata={
                "task_id": task_id,
                "target_device_id": routed.target_device_id,
            },
        )

    # ------------------------------------------------------------------
    # Public API: sync
    # ------------------------------------------------------------------

    def sync_state(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        source_device_id: Optional[str] = None,
        target_device_ids: Optional[List[str]] = None,
        state: Optional[Dict[str, Any]] = None,
        direction: str = SyncDirection.BIDIRECTIONAL.value,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a sync snapshot between devices.

        This does not directly push to physical devices. It creates a structured
        sync payload that API/websocket/device workers can consume.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not source_device_id:
            return self._error_result(
                message="source_device_id is required.",
                error_code="missing_source_device_id",
            )

        safe_direction = self._normalize_sync_direction(direction)
        safe_state = self._sanitize_sync_state(state or {})

        operation = "sync_state"
        if self._requires_security_check(operation=operation):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "source_device_id": source_device_id,
                    "target_device_ids": target_device_ids or [],
                    "direction": safe_direction,
                },
            )
            if not approval["success"]:
                return approval

        with self._lock:
            source_key = self._device_key(user_id, workspace_id, source_device_id)
            source = self._devices.get(source_key)

            if not source:
                return self._error_result(
                    message="Source device not found.",
                    error_code="source_device_not_found",
                    metadata={"source_device_id": source_device_id},
                )

            if not target_device_ids:
                target_device_ids = [
                    device_id
                    for uid, wid, device_id in self._devices.keys()
                    if uid == str(user_id)
                    and wid == str(workspace_id)
                    and device_id != source_device_id
                ]

            valid_targets = []
            missing_targets = []

            for target_id in target_device_ids:
                target_key = self._device_key(user_id, workspace_id, target_id)
                if self._devices.get(target_key):
                    valid_targets.append(target_id)
                else:
                    missing_targets.append(target_id)

            sync_id = self._generate_sync_id()
            snapshot = SyncSnapshot(
                sync_id=sync_id,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                source_device_id=source_device_id,
                target_device_ids=valid_targets,
                direction=safe_direction,
                state=safe_state,
                metadata={
                    **(metadata or {}),
                    "missing_targets": missing_targets,
                },
            )
            self._sync_snapshots[sync_id] = snapshot

            source.runtime.status = DeviceStatus.SYNCING.value
            source.runtime.updated_at = time.time()

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=sync_id,
            details={
                "source_device_id": source_device_id,
                "target_device_ids": valid_targets,
                "direction": safe_direction,
                "missing_targets": missing_targets,
            },
        )

        event = self._emit_agent_event(
            event_type="device.sync_created",
            user_id=user_id,
            workspace_id=workspace_id,
            data=asdict(snapshot),
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data=asdict(snapshot),
        )

        memory = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="device_sync_context",
            content={
                "sync_id": sync_id,
                "source_device_id": source_device_id,
                "target_device_ids": valid_targets,
                "direction": safe_direction,
            },
        )

        return self._safe_result(
            message="Device sync snapshot created successfully.",
            data={
                "sync_snapshot": asdict(snapshot),
                "verification_payload": verification,
                "memory_payload": memory,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "sync_id": sync_id,
                "missing_targets": missing_targets,
            },
        )

    def broadcast_sync(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        source_device_id: Optional[str] = None,
        state: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Broadcast a sync state from one source device to all other devices in the workspace.
        """

        return self.sync_state(
            user_id=user_id,
            workspace_id=workspace_id,
            source_device_id=source_device_id,
            target_device_ids=None,
            state=state,
            direction=SyncDirection.BIDIRECTIONAL.value,
            metadata=metadata,
            context=context,
        )

    def get_sync_snapshot(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        sync_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch a sync snapshot by ID with user/workspace isolation.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            snapshot = self._sync_snapshots.get(sync_id)

        if not snapshot:
            return self._error_result(
                message="Sync snapshot not found.",
                error_code="sync_snapshot_not_found",
                metadata={"sync_id": sync_id},
            )

        if snapshot.user_id != str(user_id) or snapshot.workspace_id != str(workspace_id):
            return self._error_result(
                message="Sync snapshot does not belong to this user/workspace.",
                error_code="sync_scope_mismatch",
            )

        return self._safe_result(
            message="Sync snapshot found.",
            data={"sync_snapshot": asdict(snapshot)},
            metadata={"sync_id": sync_id},
        )

    # ------------------------------------------------------------------
    # Public API: health and stale handling
    # ------------------------------------------------------------------

    def mark_stale_devices_offline(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        timeout_seconds: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mark devices offline if heartbeat is stale.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        timeout = timeout_seconds or self.heartbeat_timeout_seconds
        now = time.time()
        marked = []

        with self._lock:
            for (uid, wid, device_id), record in self._devices.items():
                if uid != str(user_id) or wid != str(workspace_id):
                    continue

                if record.runtime.status == DeviceStatus.DISABLED.value:
                    continue

                age = now - record.runtime.last_seen
                if age > timeout and record.runtime.status != DeviceStatus.OFFLINE.value:
                    record.runtime.status = DeviceStatus.OFFLINE.value
                    record.runtime.updated_at = now
                    marked.append({
                        "device_id": device_id,
                        "last_seen_age_seconds": round(age, 2),
                    })

        if marked:
            self._emit_agent_event(
                event_type="device.marked_offline",
                user_id=user_id,
                workspace_id=workspace_id,
                data={"devices": marked},
            )

        return self._safe_result(
            message="Stale device check completed.",
            data={
                "marked_offline": marked,
                "count": len(marked),
            },
            metadata={
                "timeout_seconds": timeout,
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def workspace_health(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return device health summary for a workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        self.mark_stale_devices_offline(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        summary = {
            "total": 0,
            "online": 0,
            "offline": 0,
            "busy": 0,
            "syncing": 0,
            "error": 0,
            "disabled": 0,
            "by_type": {},
        }

        with self._lock:
            for (uid, wid, _device_id), record in self._devices.items():
                if uid != str(user_id) or wid != str(workspace_id):
                    continue

                summary["total"] += 1
                status = record.runtime.status
                dtype = record.identity.device_type

                if status in summary:
                    summary[status] += 1

                summary["by_type"].setdefault(dtype, 0)
                summary["by_type"][dtype] += 1

        return self._safe_result(
            message="Workspace device health generated.",
            data={"health": summary},
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    # ------------------------------------------------------------------
    # Compatibility hooks required by prompt bible
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation fields.

        Every user-specific device operation must include user_id and workspace_id.
        """

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for DeviceSync operations.",
                error_code="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for DeviceSync operations.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        operation: str,
        device_type: Optional[str] = None,
        task_type: Optional[str] = None,
        **_: Any,
    ) -> bool:
        """
        Decide whether an operation needs Security Agent approval.

        This is intentionally conservative for operations that affect routing,
        sync, or device removal.
        """

        sensitive_operations = {
            "remove_device",
            "route_task_to_device",
            "sync_state",
        }

        sensitive_task_keywords = {
            "call",
            "message",
            "file",
            "browser",
            "system",
            "notification",
            "automation",
            "payment",
            "finance",
        }

        if operation in sensitive_operations:
            return True

        if device_type in {
            DeviceType.PHONE.value,
            DeviceType.SERVER.value,
            DeviceType.GLASSES.value,
        }:
            return True

        if task_type:
            normalized_task = str(task_type).lower()
            if any(keyword in normalized_task for keyword in sensitive_task_keywords):
                return True

        return False

    def _request_security_approval(
        self,
        operation: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a real security_agent exists, this method attempts to call it safely.
        Otherwise, it returns a safe default approval with metadata.
        """

        approval_payload = {
            "operation": operation,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "payload": payload or {},
            "agent": self.agent_name,
            "timestamp": time.time(),
        }

        if self.security_agent:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    result = self.security_agent.approve_action(approval_payload)
                elif hasattr(self.security_agent, "run"):
                    result = self.security_agent.run({
                        "action": "approve_action",
                        "payload": approval_payload,
                    })
                else:
                    result = None

                if isinstance(result, dict):
                    if result.get("success") is False:
                        return self._error_result(
                            message="Security Agent denied the operation.",
                            error=result.get("error"),
                            error_code="security_denied",
                            metadata={"approval_payload": approval_payload},
                        )

                    return self._safe_result(
                        message="Security Agent approved the operation.",
                        data={"approval": result},
                        metadata={"approval_payload": approval_payload},
                    )
            except Exception as exc:
                logger.warning("Security Agent approval failed: %s", exc)
                return self._error_result(
                    message="Security Agent approval failed.",
                    error=str(exc),
                    error_code="security_agent_error",
                    metadata={"approval_payload": approval_payload},
                )

        return self._safe_result(
            message="Security approval passed by safe default policy.",
            data={"approved": True},
            metadata={
                "approval_payload": approval_payload,
                "approval_mode": "safe_default_no_security_agent_attached",
            },
        )

    def _prepare_verification_payload(
        self,
        operation: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.
        """

        payload = {
            "verification_id": f"verify_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "operation": operation,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "data": copy.deepcopy(data or {}),
            "created_at": time.time(),
            "status": "prepared",
        }

        if self.verification_agent:
            try:
                if hasattr(self.verification_agent, "prepare"):
                    self.verification_agent.prepare(payload)
                elif hasattr(self.verification_agent, "run"):
                    self.verification_agent.run({
                        "action": "prepare_verification",
                        "payload": payload,
                    })
            except Exception as exc:
                payload["verification_agent_error"] = str(exc)

        return payload

    def _prepare_memory_payload(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: str,
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.
        """

        payload = {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "memory_type": memory_type,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "content": copy.deepcopy(content),
            "created_at": time.time(),
            "safe_to_store": True,
        }

        if self.memory_agent:
            try:
                if hasattr(self.memory_agent, "prepare_memory"):
                    self.memory_agent.prepare_memory(payload)
                elif hasattr(self.memory_agent, "run"):
                    self.memory_agent.run({
                        "action": "prepare_memory",
                        "payload": payload,
                    })
            except Exception as exc:
                payload["memory_agent_error"] = str(exc)

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an internal agent event for dashboard/API/event bus.
        """

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "data": copy.deepcopy(data or {}),
            "created_at": time.time(),
        }

        with self._lock:
            self._event_log.append(event)
            if len(self._event_log) > self.max_event_log:
                self._event_log = self._event_log[-self.max_event_log:]

        if self.event_bus:
            try:
                if hasattr(self.event_bus, "emit"):
                    self.event_bus.emit(event_type, event)
                elif hasattr(self.event_bus, "publish"):
                    self.event_bus.publish(event)
            except Exception as exc:
                event["event_bus_error"] = str(exc)

        return event

    def _log_audit_event(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log a SaaS-safe audit event.
        """

        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "resource_id": resource_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "details": copy.deepcopy(details or {}),
            "created_at": time.time(),
        }

        with self._lock:
            self._audit_log.append(audit_event)
            if len(self._audit_log) > self.max_audit_log:
                self._audit_log = self._audit_log[-self.max_audit_log:]

        if self.audit_logger:
            try:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit_event)
                elif hasattr(self.audit_logger, "write"):
                    self.audit_logger.write(audit_event)
            except Exception as exc:
                audit_event["audit_logger_error"] = str(exc)

        return audit_event

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response format.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[str] = None,
        error_code: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response format.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code or "device_sync_error",
                "detail": error or message,
            },
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _device_key(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        device_id: str,
    ) -> Tuple[str, str, str]:
        return (str(user_id), str(workspace_id), str(device_id))

    def _coalesce_id(
        self,
        primary: Optional[Union[str, int]],
        fallback: Optional[Union[str, int]],
    ) -> Optional[Union[str, int]]:
        if primary is not None and str(primary).strip() != "":
            return primary
        if fallback is not None and str(fallback).strip() != "":
            return fallback
        return None

    def _generate_device_id(self, device_type: str) -> str:
        safe_type = self._normalize_device_type(device_type)
        return f"{safe_type}_{uuid.uuid4().hex}"

    def _generate_task_id(self) -> str:
        return f"task_{uuid.uuid4().hex}"

    def _generate_sync_id(self) -> str:
        return f"sync_{uuid.uuid4().hex}"

    def _normalize_device_type(self, device_type: Optional[str]) -> str:
        value = str(device_type or DeviceType.UNKNOWN.value).strip().lower()
        if value not in SUPPORTED_DEVICE_TYPES:
            return DeviceType.UNKNOWN.value
        return value

    def _normalize_status(self, status: Optional[str]) -> str:
        value = str(status or DeviceStatus.OFFLINE.value).strip().lower()
        valid = {item.value for item in DeviceStatus}
        if value not in valid:
            return DeviceStatus.ERROR.value
        return value

    def _normalize_priority(self, priority: Optional[str]) -> str:
        value = str(priority or RoutePriority.NORMAL.value).strip().lower()
        valid = {item.value for item in RoutePriority}
        if value not in valid:
            return RoutePriority.NORMAL.value
        return value

    def _normalize_sync_direction(self, direction: Optional[str]) -> str:
        value = str(direction or SyncDirection.BIDIRECTIONAL.value).strip().lower()
        valid = {item.value for item in SyncDirection}
        if value not in valid:
            return SyncDirection.BIDIRECTIONAL.value
        return value

    def _clean_capabilities(self, capabilities: List[str]) -> List[str]:
        cleaned = []
        for item in capabilities:
            value = str(item).strip().lower()
            if not value:
                continue
            if value not in cleaned:
                cleaned.append(value)
        return cleaned

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        try:
            number = float(value)
        except Exception:
            return default

        if number < 0:
            return 0.0

        return number

    def _normalize_percent(self, value: Any) -> int:
        try:
            number = int(value)
        except Exception:
            return 0
        return max(0, min(100, number))

    def _sanitize_sync_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize sync state before storing.

        Removes obviously secret-looking keys while keeping sync useful.
        """

        blocked_terms = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "access_token",
            "refresh_token",
        }

        def clean(obj: Any) -> Any:
            if isinstance(obj, dict):
                safe_dict = {}
                for key, value in obj.items():
                    lower_key = str(key).lower()
                    if any(term in lower_key for term in blocked_terms):
                        safe_dict[key] = "[REDACTED]"
                    else:
                        safe_dict[key] = clean(value)
                return safe_dict

            if isinstance(obj, list):
                return [clean(item) for item in obj]

            return obj

        return clean(copy.deepcopy(state))

    def _find_route_candidates(
        self,
        user_id: str,
        workspace_id: str,
        required_capabilities: List[str],
        preferred_device_id: Optional[str],
        preferred_device_type: Optional[str],
        allow_busy: bool,
    ) -> List[DeviceRecord]:
        candidates: List[DeviceRecord] = []

        for (uid, wid, device_id), record in self._devices.items():
            if uid != user_id or wid != workspace_id:
                continue

            if record.runtime.status == DeviceStatus.DISABLED.value:
                continue

            if record.runtime.status == DeviceStatus.OFFLINE.value:
                continue

            if record.runtime.status == DeviceStatus.ERROR.value:
                continue

            if not allow_busy and record.runtime.status == DeviceStatus.BUSY.value:
                continue

            if preferred_device_id and device_id != preferred_device_id:
                continue

            if preferred_device_type and record.identity.device_type != preferred_device_type:
                continue

            if required_capabilities:
                capabilities = set(record.runtime.capabilities)
                if not set(required_capabilities).issubset(capabilities):
                    continue

            candidates.append(record)

        return candidates

    def _select_best_device(self, candidates: List[DeviceRecord]) -> DeviceRecord:
        """
        Select best device by status, load score, heartbeat freshness, and type.

        Server/desktop/laptop are preferred for heavy workloads.
        Phone/watch/glasses are preferred only when capabilities demand it.
        """

        def score(record: DeviceRecord) -> Tuple[int, float, float, int]:
            status_rank = {
                DeviceStatus.ONLINE.value: 0,
                DeviceStatus.IDLE.value: 1,
                DeviceStatus.SYNCING.value: 2,
                DeviceStatus.BUSY.value: 3,
            }.get(record.runtime.status, 9)

            load_score = record.runtime.load_score
            last_seen_age = time.time() - record.runtime.last_seen

            type_rank = {
                DeviceType.SERVER.value: 0,
                DeviceType.DESKTOP.value: 1,
                DeviceType.LAPTOP.value: 2,
                DeviceType.TABLET.value: 3,
                DeviceType.PHONE.value: 4,
                DeviceType.GLASSES.value: 5,
                DeviceType.WATCH.value: 6,
                DeviceType.UNKNOWN.value: 9,
            }.get(record.identity.device_type, 9)

            return (status_rank, load_score, last_seen_age, type_rank)

        return sorted(candidates, key=score)[0]

    def _trim_task_history_locked(self) -> None:
        if len(self._task_history) <= self.max_task_history:
            return

        sorted_items = sorted(
            self._task_history.items(),
            key=lambda item: item[1].routed_at,
        )
        keep_items = sorted_items[-self.max_task_history:]
        self._task_history = dict(keep_items)

    # ------------------------------------------------------------------
    # Dashboard/debug helpers
    # ------------------------------------------------------------------

    def export_workspace_snapshot(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export a safe dashboard-ready snapshot for one workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            devices = [
                record.to_dict()
                for (uid, wid, _device_id), record in self._devices.items()
                if uid == str(user_id) and wid == str(workspace_id)
            ]

            tasks = [
                asdict(task)
                for task in self._task_history.values()
                if task.user_id == str(user_id) and task.workspace_id == str(workspace_id)
            ]

            syncs = [
                asdict(snapshot)
                for snapshot in self._sync_snapshots.values()
                if snapshot.user_id == str(user_id)
                and snapshot.workspace_id == str(workspace_id)
            ]

        return self._safe_result(
            message="Workspace device snapshot exported.",
            data={
                "devices": devices,
                "tasks": tasks,
                "sync_snapshots": syncs,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "device_count": len(devices),
                "task_count": len(tasks),
                "sync_count": len(syncs),
            },
        )

    def get_event_log(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return recent agent events, optionally scoped to user/workspace.
        """

        safe_limit = max(1, min(int(limit), self.max_event_log))

        with self._lock:
            events = list(self._event_log)

        if user_id is not None:
            events = [item for item in events if item.get("user_id") == str(user_id)]

        if workspace_id is not None:
            events = [item for item in events if item.get("workspace_id") == str(workspace_id)]

        events = events[-safe_limit:]

        return self._safe_result(
            message="Event log returned.",
            data={
                "events": events,
                "count": len(events),
            },
        )

    def get_audit_log(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return recent audit events, optionally scoped to user/workspace.
        """

        safe_limit = max(1, min(int(limit), self.max_audit_log))

        with self._lock:
            events = list(self._audit_log)

        if user_id is not None:
            events = [item for item in events if item.get("user_id") == str(user_id)]

        if workspace_id is not None:
            events = [item for item in events if item.get("workspace_id") == str(workspace_id)]

        events = events[-safe_limit:]

        return self._safe_result(
            message="Audit log returned.",
            data={
                "audit_events": events,
                "count": len(events),
            },
        )


# -------------------------------------------------------------------------
# Standalone smoke test
# -------------------------------------------------------------------------

if __name__ == "__main__":
    sync = DeviceSync()

    ctx = {
        "user_id": "user_1",
        "workspace_id": "workspace_1",
    }

    laptop = sync.register_device(
        context=ctx,
        device_id="laptop_001",
        device_name="Roshan Laptop",
        device_type="laptop",
    )
    print("REGISTER LAPTOP:", laptop)

    phone = sync.register_device(
        context=ctx,
        device_id="phone_001",
        device_name="Roshan Phone",
        device_type="phone",
    )
    print("REGISTER PHONE:", phone)

    devices = sync.list_devices(context=ctx)
    print("DEVICES:", devices)

    routed = sync.route_task_to_device(
        context=ctx,
        task_type="browser_research",
        required_capabilities=["browser"],
        payload={"query": "William system status"},
    )
    print("ROUTED:", routed)

    snapshot = sync.broadcast_sync(
        context=ctx,
        source_device_id="laptop_001",
        state={
            "active_task": "browser_research",
            "safe_note": "Syncing task state.",
            "access_token": "should_be_redacted",
        },
    )
    print("SYNC:", snapshot)

    health = sync.workspace_health(context=ctx, user_id=None, workspace_id=None)
    print("HEALTH:", health)

    print("FILE COMPLETE")