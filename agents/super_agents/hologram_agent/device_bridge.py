"""
agents/super_agents/hologram_agent/device_bridge.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Hologram Agent - Device Bridge

Purpose:
    Connects glasses/watch/phone/laptop streams and controls.

Responsibilities:
    - Register and manage user/workspace-isolated hologram devices.
    - Connect/disconnect glasses, smartwatch, phone, and laptop sessions.
    - Start/stop device streams such as camera, microphone, display, sensor,
      notification, location, and control channels.
    - Send safe control commands to connected devices.
    - Track telemetry, stream health, device capabilities, and connection state.
    - Prepare Verification Agent and Memory Agent payloads after useful actions.
    - Emit dashboard/API friendly events and audit logs.
    - Stay import-safe even if future William/Jarvis modules do not exist yet.

Safety:
    - No real OS/device/browser/camera/microphone action is executed directly.
    - Real external device SDK integrations must be added through adapters and
      protected by the Security Agent hooks.
    - Every user-specific operation requires user_id and workspace_id.
    - Device state is tenant-isolated by user_id + workspace_id.
    - Sensitive stream/control operations require security approval by policy.

Architecture Compatibility:
    - BaseAgent compatible with fallback stub.
    - Master Agent / Agent Router compatible through clear public methods.
    - Agent Registry / Agent Loader compatible through metadata factory helpers.
    - Security Agent compatible through _requires_security_check and
      _request_security_approval.
    - Verification Agent compatible through _prepare_verification_payload.
    - Memory Agent compatible through _prepare_memory_payload.
    - Dashboard/API compatible through structured result dictionaries.

Result Format:
    {
        "success": bool,
        "message": str,
        "data": dict,
        "error": dict | None,
        "metadata": dict
    }
"""

from __future__ import annotations

import copy
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe during early project development before
        the real William/Jarvis BaseAgent is available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "hologram_agent")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit_event(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback audit_event: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums / Constants
# ---------------------------------------------------------------------------

class HologramDeviceType(str, Enum):
    """Supported device categories for Hologram Agent bridging."""

    GLASSES = "glasses"
    WATCH = "watch"
    PHONE = "phone"
    LAPTOP = "laptop"
    TABLET = "tablet"
    UNKNOWN = "unknown"


class HologramDeviceStatus(str, Enum):
    """Device connection lifecycle status."""

    REGISTERED = "registered"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    BLOCKED = "blocked"


class HologramStreamType(str, Enum):
    """Supported stream types."""

    CAMERA = "camera"
    MICROPHONE = "microphone"
    DISPLAY = "display"
    SENSOR = "sensor"
    LOCATION = "location"
    NOTIFICATION = "notification"
    CONTROL = "control"
    BIOMETRIC = "biometric"
    GESTURE = "gesture"
    SPATIAL = "spatial"


class HologramStreamStatus(str, Enum):
    """Stream lifecycle status."""

    CREATED = "created"
    STARTING = "starting"
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    BLOCKED = "blocked"


class HologramControlCommand(str, Enum):
    """Common safe control commands."""

    SHOW_OVERLAY = "show_overlay"
    HIDE_OVERLAY = "hide_overlay"
    UPDATE_OVERLAY = "update_overlay"
    VIBRATE = "vibrate"
    PLAY_SOUND = "play_sound"
    SET_BRIGHTNESS = "set_brightness"
    SET_VOLUME = "set_volume"
    START_NAVIGATION = "start_navigation"
    STOP_NAVIGATION = "stop_navigation"
    REQUEST_FRAME = "request_frame"
    REQUEST_SENSOR_SNAPSHOT = "request_sensor_snapshot"
    SYNC_CONTEXT = "sync_context"
    PING = "ping"


class HologramBridgeAction(str, Enum):
    """Actions exposed to Master Agent / Agent Router."""

    REGISTER_DEVICE = "register_device"
    UPDATE_DEVICE = "update_device"
    REMOVE_DEVICE = "remove_device"
    CONNECT_DEVICE = "connect_device"
    DISCONNECT_DEVICE = "disconnect_device"
    START_STREAM = "start_stream"
    STOP_STREAM = "stop_stream"
    PAUSE_STREAM = "pause_stream"
    RESUME_STREAM = "resume_stream"
    SEND_CONTROL = "send_control"
    INGEST_TELEMETRY = "ingest_telemetry"
    GET_DEVICE = "get_device"
    LIST_DEVICES = "list_devices"
    GET_STREAM = "get_stream"
    LIST_STREAMS = "list_streams"
    GET_BRIDGE_STATUS = "get_bridge_status"


SENSITIVE_STREAM_TYPES = {
    HologramStreamType.CAMERA.value,
    HologramStreamType.MICROPHONE.value,
    HologramStreamType.LOCATION.value,
    HologramStreamType.BIOMETRIC.value,
    HologramStreamType.DISPLAY.value,
}

SENSITIVE_COMMANDS = {
    HologramControlCommand.PLAY_SOUND.value,
    HologramControlCommand.SET_BRIGHTNESS.value,
    HologramControlCommand.SET_VOLUME.value,
    HologramControlCommand.START_NAVIGATION.value,
    HologramControlCommand.REQUEST_FRAME.value,
    HologramControlCommand.REQUEST_SENSOR_SNAPSHOT.value,
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC datetime in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Create a stable readable ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _normalize_text(value: Any) -> str:
    """Normalize text values safely."""
    if value is None:
        return ""
    return str(value).strip()


def _deepcopy(value: Any) -> Any:
    """Deep copy JSON-like data to avoid leaking mutable internal state."""
    return copy.deepcopy(value)


def _clean_dict(data: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Convert mapping to dict and remove None values."""
    if not data:
        return {}
    return {str(k): v for k, v in dict(data).items() if v is not None}


def _listify(value: Optional[Union[str, Iterable[str]]]) -> List[str]:
    """Normalize a value into a clean unique list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        raw_values = [value]
    else:
        raw_values = list(value)

    output: List[str] = []
    seen = set()
    for item in raw_values:
        text = _normalize_text(item)
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def _safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """Convert a value to float safely."""
    if value is None or value == "":
        return default
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to int safely."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HologramTaskContext:
    """
    SaaS execution context.

    Every user/workspace-specific operation must carry this context to prevent
    cross-tenant device, stream, telemetry, audit, memory, and analytics mixing.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_id: Optional[str] = None
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    source_agent: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HologramDevice:
    """Registered device record."""

    id: str
    user_id: str
    workspace_id: str
    device_type: str
    name: str
    status: str = HologramDeviceStatus.REGISTERED.value
    model: str = ""
    os_name: str = ""
    os_version: str = ""
    app_version: str = ""
    connection_mode: str = "simulated"
    adapter_name: str = "simulated"
    capabilities: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    last_seen_at: Optional[str] = None
    last_error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class HologramStream:
    """Device stream record."""

    id: str
    user_id: str
    workspace_id: str
    device_id: str
    stream_type: str
    status: str = HologramStreamStatus.CREATED.value
    label: str = ""
    quality: str = "balanced"
    sample_rate: Optional[int] = None
    frame_rate: Optional[int] = None
    resolution: Optional[str] = None
    encrypted: bool = True
    muted: bool = False
    paused: bool = False
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    last_packet_at: Optional[str] = None
    last_error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class HologramTelemetry:
    """Telemetry snapshot from a device."""

    id: str
    user_id: str
    workspace_id: str
    device_id: str
    battery_percent: Optional[float] = None
    signal_strength: Optional[float] = None
    temperature_celsius: Optional[float] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    storage_percent: Optional[float] = None
    network_type: str = ""
    is_charging: Optional[bool] = None
    sensor_summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)


@dataclass
class HologramControlReceipt:
    """Control command receipt."""

    id: str
    user_id: str
    workspace_id: str
    device_id: str
    command: str
    accepted: bool
    simulated: bool = True
    message: str = ""
    payload_summary: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Thread-safe in-memory bridge store
# ---------------------------------------------------------------------------

class InMemoryDeviceBridgeStore:
    """
    Thread-safe in-memory state store.

    This gives the Hologram Agent a real testable bridge state before physical
    device SDKs are connected. All records are isolated by user_id + workspace_id.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._store: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}

    @staticmethod
    def tenant_key(user_id: str, workspace_id: str) -> str:
        return f"{user_id}::{workspace_id}"

    def _tenant(self, user_id: str, workspace_id: str) -> Dict[str, Dict[str, Dict[str, Any]]]:
        key = self.tenant_key(user_id, workspace_id)
        if key not in self._store:
            self._store[key] = {
                "devices": {},
                "streams": {},
                "telemetry": {},
                "control_receipts": {},
            }
        return self._store[key]

    def save(
        self,
        user_id: str,
        workspace_id: str,
        bucket: str,
        record: Mapping[str, Any],
    ) -> Dict[str, Any]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            payload = _deepcopy(dict(record))
            tenant[bucket][payload["id"]] = payload
            return _deepcopy(payload)

    def get(
        self,
        user_id: str,
        workspace_id: str,
        bucket: str,
        record_id: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            record = tenant[bucket].get(record_id)
            return _deepcopy(record) if record else None

    def update(
        self,
        user_id: str,
        workspace_id: str,
        bucket: str,
        record_id: str,
        updates: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            current = tenant[bucket].get(record_id)
            if not current:
                return None

            cleaned = _clean_dict(updates)
            current.update(cleaned)
            current["updated_at"] = _utc_now()
            tenant[bucket][record_id] = current
            return _deepcopy(current)

    def delete(
        self,
        user_id: str,
        workspace_id: str,
        bucket: str,
        record_id: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            deleted = tenant[bucket].pop(record_id, None)
            return _deepcopy(deleted) if deleted else None

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        bucket: str,
        filters: Optional[Mapping[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            filters = _clean_dict(filters)
            tenant = self._tenant(user_id, workspace_id)
            records = list(tenant[bucket].values())

            def passes(record: Mapping[str, Any]) -> bool:
                for key, expected in filters.items():
                    if record.get(key) != expected:
                        return False
                return True

            output = [_deepcopy(record) for record in records if passes(record)]
            output.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
            return output

    def find_one(
        self,
        user_id: str,
        workspace_id: str,
        bucket: str,
        predicate: Callable[[Dict[str, Any]], bool],
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            records = self.list_records(user_id, workspace_id, bucket)
            for record in records:
                if predicate(record):
                    return record
            return None


# ---------------------------------------------------------------------------
# Simulated device adapter
# ---------------------------------------------------------------------------

class SimulatedDeviceAdapter:
    """
    Safe adapter used by default.

    It does not access real hardware. It returns deterministic structured
    responses so API/dashboard workflows can be tested before real device
    providers are integrated.
    """

    adapter_name = "simulated"

    def connect(self, device: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "accepted": True,
            "message": "Simulated device connection established.",
            "data": {
                "adapter_name": self.adapter_name,
                "device_id": device.get("id"),
                "connected_at": _utc_now(),
            },
        }

    def disconnect(self, device: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "accepted": True,
            "message": "Simulated device disconnected.",
            "data": {
                "adapter_name": self.adapter_name,
                "device_id": device.get("id"),
                "disconnected_at": _utc_now(),
            },
        }

    def start_stream(self, device: Mapping[str, Any], stream: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "accepted": True,
            "message": "Simulated stream started.",
            "data": {
                "adapter_name": self.adapter_name,
                "device_id": device.get("id"),
                "stream_id": stream.get("id"),
                "stream_type": stream.get("stream_type"),
                "started_at": _utc_now(),
            },
        }

    def stop_stream(self, device: Mapping[str, Any], stream: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "accepted": True,
            "message": "Simulated stream stopped.",
            "data": {
                "adapter_name": self.adapter_name,
                "device_id": device.get("id"),
                "stream_id": stream.get("id"),
                "stream_type": stream.get("stream_type"),
                "stopped_at": _utc_now(),
            },
        }

    def send_control(
        self,
        device: Mapping[str, Any],
        command: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return {
            "accepted": True,
            "message": f"Simulated control command accepted: {command}",
            "data": {
                "adapter_name": self.adapter_name,
                "device_id": device.get("id"),
                "command": command,
                "payload_summary": HologramDeviceBridge._summarize_payload(payload),
                "accepted_at": _utc_now(),
            },
        }


# ---------------------------------------------------------------------------
# Main Hologram Device Bridge
# ---------------------------------------------------------------------------

class HologramDeviceBridge(BaseAgent):
    """
    Connects glasses/watch/phone/laptop streams and controls for Hologram Agent.

    Master Agent / Agent Router can call this class to:
        - Register device endpoints.
        - Connect/disconnect device sessions.
        - Start/stop camera/mic/display/sensor streams.
        - Send safe overlay/control commands.
        - Ingest device telemetry for dashboards and automation.

    Real device SDKs can be added later by injecting adapters into `adapters`.
    """

    agent_name = "hologram_device_bridge"
    agent_type = "hologram_agent"
    module_name = "device_bridge"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        security_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        store: Optional[InMemoryDeviceBridgeStore] = None,
        adapters: Optional[Mapping[str, Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.agent_name,
            agent_type=self.agent_type,
            **kwargs,
        )

        self.config = _clean_dict(config)
        self.security_client = security_client
        self.verification_client = verification_client
        self.memory_client = memory_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.store = store or InMemoryDeviceBridgeStore()
        self.logger = logger_instance or logging.getLogger(
            "william.hologram_agent.device_bridge"
        )

        default_adapters: Dict[str, Any] = {
            "simulated": SimulatedDeviceAdapter(),
            "memory": SimulatedDeviceAdapter(),
        }
        if adapters:
            default_adapters.update(dict(adapters))
        self.adapters = default_adapters

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> HologramTaskContext:
        """
        Validate tenant execution context.

        Raises:
            ValueError if user_id or workspace_id is missing.
        """
        if not isinstance(context, Mapping):
            raise ValueError("context must be a mapping with user_id and workspace_id")

        user_id = _normalize_text(context.get("user_id"))
        workspace_id = _normalize_text(context.get("workspace_id"))

        if not user_id:
            raise ValueError("user_id is required for HologramDeviceBridge operations")
        if not workspace_id:
            raise ValueError("workspace_id is required for HologramDeviceBridge operations")

        permissions = context.get("permissions") or []
        if isinstance(permissions, str):
            permissions = [permissions]

        metadata = context.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            metadata = {"raw_metadata": metadata}

        return HologramTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=_normalize_text(context.get("role")) or None,
            subscription_id=_normalize_text(context.get("subscription_id")) or None,
            request_id=_normalize_text(context.get("request_id")) or None,
            task_id=_normalize_text(context.get("task_id")) or None,
            source_agent=_normalize_text(context.get("source_agent")) or None,
            permissions=[_normalize_text(item) for item in permissions if _normalize_text(item)],
            metadata=dict(metadata),
        )

    def _requires_security_check(
        self,
        action: Union[str, HologramBridgeAction],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide if an action should require Security Agent approval.

        Sensitive operations include camera/microphone/location/biometric/display
        streams and device controls that could affect user experience.
        """
        action_value = action.value if isinstance(action, HologramBridgeAction) else str(action)
        payload = payload or {}

        always_sensitive = {
            HologramBridgeAction.REMOVE_DEVICE.value,
            HologramBridgeAction.CONNECT_DEVICE.value,
            HologramBridgeAction.START_STREAM.value,
            HologramBridgeAction.SEND_CONTROL.value,
        }

        if action_value in always_sensitive:
            if action_value == HologramBridgeAction.START_STREAM.value:
                stream_type = _normalize_text(payload.get("stream_type")).lower()
                return stream_type in SENSITIVE_STREAM_TYPES

            if action_value == HologramBridgeAction.SEND_CONTROL.value:
                command = _normalize_text(payload.get("command")).lower()
                return command in SENSITIVE_COMMANDS

            return True

        if self.config.get("require_security_for_all_device_actions") is True:
            return True

        return False

    def _request_security_approval(
        self,
        ctx: HologramTaskContext,
        action: Union[str, HologramBridgeAction],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent/client for approval.

        If no security client is configured, non-sensitive simulated operations
        are allowed; sensitive actions are denied by default unless
        config.allow_simulated_sensitive_without_security is True.
        """
        action_value = action.value if isinstance(action, HologramBridgeAction) else str(action)
        payload = _clean_dict(payload)

        approval_payload = {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "payload_summary": self._summarize_payload(payload),
            "created_at": _utc_now(),
        }

        if self.security_client and hasattr(self.security_client, "approve_action"):
            try:
                response = self.security_client.approve_action(approval_payload)
                if isinstance(response, Mapping):
                    approved = bool(response.get("approved") or response.get("success"))
                    return {
                        "approved": approved,
                        "message": str(response.get("message") or "Security check completed."),
                        "data": dict(response),
                    }
            except Exception as exc:
                self.logger.exception("Security approval failed: %s", exc)
                return {
                    "approved": False,
                    "message": "Security approval failed.",
                    "data": {"exception": str(exc)},
                }

        if self._requires_security_check(action_value, payload):
            if self.config.get("allow_simulated_sensitive_without_security") is True:
                return {
                    "approved": True,
                    "message": "Sensitive simulated device action allowed by local config.",
                    "data": approval_payload,
                }

            return {
                "approved": False,
                "message": "Security approval required for this device action but no Security Agent/client is configured.",
                "data": approval_payload,
            }

        return {
            "approved": True,
            "message": "Security approval not required for this safe device bridge operation.",
            "data": approval_payload,
        }

    def _prepare_verification_payload(
        self,
        ctx: HologramTaskContext,
        action: Union[str, HologramBridgeAction],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can confirm device_id, stream_id, workspace isolation,
        and whether device/stream state changed as expected.
        """
        action_value = action.value if isinstance(action, HologramBridgeAction) else str(action)
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        return {
            "verification_type": "hologram_device_bridge_operation",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "success": bool(result.get("success")),
            "device_id": data.get("device_id") or data.get("id"),
            "stream_id": data.get("stream_id"),
            "device_type": data.get("device_type"),
            "stream_type": data.get("stream_type"),
            "created_at": _utc_now(),
            "metadata": {
                "message": result.get("message"),
                "error": result.get("error"),
            },
        }

    def _prepare_memory_payload(
        self,
        ctx: HologramTaskContext,
        action: Union[str, HologramBridgeAction],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Stores useful operational context without raw private stream data.
        """
        action_value = action.value if isinstance(action, HologramBridgeAction) else str(action)
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        return {
            "memory_type": "hologram_device_bridge_event",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "summary": result.get("message"),
            "device_id": data.get("device_id") or data.get("id"),
            "stream_id": data.get("stream_id"),
            "device_type": data.get("device_type"),
            "stream_type": data.get("stream_type"),
            "created_at": _utc_now(),
            "metadata": {
                "success": bool(result.get("success")),
                "module_version": self.version,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """Emit dashboard/API/agent event safely."""
        safe_payload = _deepcopy(dict(payload))

        try:
            if self.event_emitter and hasattr(self.event_emitter, "emit"):
                self.event_emitter.emit(event_name, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.debug("Hologram device event emitted: %s | %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit hologram device event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        ctx: HologramTaskContext,
        action: Union[str, HologramBridgeAction],
        payload: Optional[Mapping[str, Any]] = None,
        result: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Log tenant-scoped audit event."""
        action_value = action.value if isinstance(action, HologramBridgeAction) else str(action)

        audit_payload = {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "source_agent": ctx.source_agent,
            "payload_summary": self._summarize_payload(payload or {}),
            "success": bool(result.get("success")) if result else None,
            "message": result.get("message") if result else None,
            "error": result.get("error") if result else None,
            "created_at": _utc_now(),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_payload)
                return

            if hasattr(super(), "log_audit_event"):
                try:
                    super().log_audit_event(audit_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.info("Hologram device audit event: %s", audit_payload)
        except Exception as exc:
            self.logger.warning("Failed to log hologram device audit event: %s", exc)

    def _safe_result(
        self,
        success: bool = True,
        message: str = "Hologram device bridge operation completed.",
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured success/error result."""
        return {
            "success": bool(success),
            "message": message,
            "data": _deepcopy(dict(data or {})),
            "error": _deepcopy(dict(error or {})) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "module": self.module_name,
                "version": self.version,
                "timestamp": _utc_now(),
                **_clean_dict(metadata),
            },
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "hologram_device_bridge_error",
        details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured error result."""
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error={
                "code": error_code,
                "details": _deepcopy(dict(details or {})),
            },
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Public device methods
    # ------------------------------------------------------------------

    def register_device(
        self,
        context: Mapping[str, Any],
        device_type: str,
        name: str,
        model: str = "",
        os_name: str = "",
        os_version: str = "",
        app_version: str = "",
        connection_mode: str = "simulated",
        adapter_name: str = "simulated",
        capabilities: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register glasses/watch/phone/laptop device for a user/workspace."""
        payload = {
            "device_type": device_type,
            "name": name,
            "model": model,
            "os_name": os_name,
            "os_version": os_version,
            "app_version": app_version,
            "connection_mode": connection_mode,
            "adapter_name": adapter_name,
            "capabilities": _listify(capabilities),
            "permissions": _listify(permissions),
            "metadata": _clean_dict(metadata),
        }
        return self._execute(
            context=context,
            action=HologramBridgeAction.REGISTER_DEVICE,
            payload=payload,
            operation=lambda ctx: self._register_device(ctx, payload),
        )

    def update_device(
        self,
        context: Mapping[str, Any],
        device_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update device metadata, permissions, capabilities, or app details."""
        payload = {"device_id": device_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=HologramBridgeAction.UPDATE_DEVICE,
            payload=payload,
            operation=lambda ctx: self._update_device(ctx, device_id, updates),
        )

    def remove_device(
        self,
        context: Mapping[str, Any],
        device_id: str,
    ) -> Dict[str, Any]:
        """
        Remove a registered device from this workspace.

        This is sensitive because it changes device access and stops related
        streams.
        """
        payload = {"device_id": device_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.REMOVE_DEVICE,
            payload=payload,
            operation=lambda ctx: self._remove_device(ctx, device_id),
        )

    def connect_device(
        self,
        context: Mapping[str, Any],
        device_id: str,
    ) -> Dict[str, Any]:
        """Connect a registered device session through its adapter."""
        payload = {"device_id": device_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.CONNECT_DEVICE,
            payload=payload,
            operation=lambda ctx: self._connect_device(ctx, device_id),
        )

    def disconnect_device(
        self,
        context: Mapping[str, Any],
        device_id: str,
    ) -> Dict[str, Any]:
        """Disconnect a device and stop active streams."""
        payload = {"device_id": device_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.DISCONNECT_DEVICE,
            payload=payload,
            operation=lambda ctx: self._disconnect_device(ctx, device_id),
        )

    def get_device(
        self,
        context: Mapping[str, Any],
        device_id: str,
    ) -> Dict[str, Any]:
        """Fetch one device in the current tenant."""
        payload = {"device_id": device_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.GET_DEVICE,
            payload=payload,
            operation=lambda ctx: self._get_device(ctx, device_id),
        )

    def list_devices(
        self,
        context: Mapping[str, Any],
        device_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List devices in the current tenant."""
        payload = {"device_type": device_type, "status": status}
        return self._execute(
            context=context,
            action=HologramBridgeAction.LIST_DEVICES,
            payload=payload,
            operation=lambda ctx: self._list_devices(ctx, device_type=device_type, status=status),
        )

    # ------------------------------------------------------------------
    # Public stream methods
    # ------------------------------------------------------------------

    def start_stream(
        self,
        context: Mapping[str, Any],
        device_id: str,
        stream_type: str,
        label: str = "",
        quality: str = "balanced",
        sample_rate: Optional[int] = None,
        frame_rate: Optional[int] = None,
        resolution: Optional[str] = None,
        encrypted: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Start a stream from a connected device."""
        payload = {
            "device_id": device_id,
            "stream_type": stream_type,
            "label": label,
            "quality": quality,
            "sample_rate": sample_rate,
            "frame_rate": frame_rate,
            "resolution": resolution,
            "encrypted": encrypted,
            "metadata": _clean_dict(metadata),
        }
        return self._execute(
            context=context,
            action=HologramBridgeAction.START_STREAM,
            payload=payload,
            operation=lambda ctx: self._start_stream(ctx, payload),
        )

    def stop_stream(
        self,
        context: Mapping[str, Any],
        stream_id: str,
    ) -> Dict[str, Any]:
        """Stop an active stream."""
        payload = {"stream_id": stream_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.STOP_STREAM,
            payload=payload,
            operation=lambda ctx: self._stop_stream(ctx, stream_id),
        )

    def pause_stream(
        self,
        context: Mapping[str, Any],
        stream_id: str,
    ) -> Dict[str, Any]:
        """Pause an active stream without deleting its state."""
        payload = {"stream_id": stream_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.PAUSE_STREAM,
            payload=payload,
            operation=lambda ctx: self._pause_or_resume_stream(ctx, stream_id, pause=True),
        )

    def resume_stream(
        self,
        context: Mapping[str, Any],
        stream_id: str,
    ) -> Dict[str, Any]:
        """Resume a paused stream."""
        payload = {"stream_id": stream_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.RESUME_STREAM,
            payload=payload,
            operation=lambda ctx: self._pause_or_resume_stream(ctx, stream_id, pause=False),
        )

    def get_stream(
        self,
        context: Mapping[str, Any],
        stream_id: str,
    ) -> Dict[str, Any]:
        """Fetch one stream in the current tenant."""
        payload = {"stream_id": stream_id}
        return self._execute(
            context=context,
            action=HologramBridgeAction.GET_STREAM,
            payload=payload,
            operation=lambda ctx: self._get_stream(ctx, stream_id),
        )

    def list_streams(
        self,
        context: Mapping[str, Any],
        device_id: Optional[str] = None,
        stream_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List streams in the current tenant."""
        payload = {"device_id": device_id, "stream_type": stream_type, "status": status}
        return self._execute(
            context=context,
            action=HologramBridgeAction.LIST_STREAMS,
            payload=payload,
            operation=lambda ctx: self._list_streams(
                ctx,
                device_id=device_id,
                stream_type=stream_type,
                status=status,
            ),
        )

    # ------------------------------------------------------------------
    # Public control / telemetry methods
    # ------------------------------------------------------------------

    def send_control(
        self,
        context: Mapping[str, Any],
        device_id: str,
        command: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a safe control command to a connected device."""
        control_payload = {
            "device_id": device_id,
            "command": command,
            "payload": _clean_dict(payload),
        }
        return self._execute(
            context=context,
            action=HologramBridgeAction.SEND_CONTROL,
            payload=control_payload,
            operation=lambda ctx: self._send_control(ctx, device_id, command, payload or {}),
        )

    def ingest_telemetry(
        self,
        context: Mapping[str, Any],
        device_id: str,
        telemetry: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Ingest device health, battery, signal, and sensor summary."""
        payload = {"device_id": device_id, "telemetry": _clean_dict(telemetry)}
        return self._execute(
            context=context,
            action=HologramBridgeAction.INGEST_TELEMETRY,
            payload=payload,
            operation=lambda ctx: self._ingest_telemetry(ctx, device_id, telemetry),
        )

    def get_bridge_status(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Return dashboard-friendly bridge status for the current workspace."""
        return self._execute(
            context=context,
            action=HologramBridgeAction.GET_BRIDGE_STATUS,
            payload={},
            operation=lambda ctx: self._get_bridge_status(ctx),
        )

    def health_check(self) -> Dict[str, Any]:
        """Return import/runtime health status."""
        return self._safe_result(
            success=True,
            message="HologramDeviceBridge is healthy.",
            data={
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "module": self.module_name,
                "version": self.version,
                "adapters": sorted(self.adapters.keys()),
                "safe_import": True,
            },
            metadata={"operation": "health_check"},
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """Return capability map for Agent Registry / Agent Loader."""
        return self._safe_result(
            success=True,
            message="HologramDeviceBridge capabilities loaded.",
            data={
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "module": self.module_name,
                "version": self.version,
                "device_types": [item.value for item in HologramDeviceType],
                "stream_types": [item.value for item in HologramStreamType],
                "control_commands": [item.value for item in HologramControlCommand],
                "actions": [item.value for item in HologramBridgeAction],
                "requires_context": ["user_id", "workspace_id"],
                "master_agent_routes": [
                    "hologram.device.register",
                    "hologram.device.update",
                    "hologram.device.remove",
                    "hologram.device.connect",
                    "hologram.device.disconnect",
                    "hologram.device.start_stream",
                    "hologram.device.stop_stream",
                    "hologram.device.pause_stream",
                    "hologram.device.resume_stream",
                    "hologram.device.send_control",
                    "hologram.device.ingest_telemetry",
                    "hologram.device.status",
                ],
            },
            metadata={"operation": "get_capabilities"},
        )

    # ------------------------------------------------------------------
    # Execution wrapper
    # ------------------------------------------------------------------

    def _execute(
        self,
        context: Mapping[str, Any],
        action: HologramBridgeAction,
        payload: Mapping[str, Any],
        operation: Callable[[HologramTaskContext], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Shared operation wrapper.

        It ensures every operation goes through:
            - context validation
            - security check
            - action execution
            - verification payload preparation
            - memory payload preparation
            - event emission
            - audit logging
        """
        ctx: Optional[HologramTaskContext] = None

        try:
            ctx = self._validate_task_context(context)

            security = self._request_security_approval(ctx, action, payload)
            if not security.get("approved"):
                result = self._error_result(
                    message=security.get("message", "Security approval denied."),
                    error_code="security_approval_denied",
                    details=security.get("data") if isinstance(security.get("data"), Mapping) else {},
                    metadata={
                        "action": action.value,
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                    },
                )
                self._log_audit_event(ctx, action, payload, result)
                self._emit_agent_event(
                    "hologram.device.security_denied",
                    {
                        "action": action.value,
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "result": result,
                    },
                )
                return result

            result = operation(ctx)

            verification_payload = self._prepare_verification_payload(ctx, action, result)
            memory_payload = self._prepare_memory_payload(ctx, action, result)

            result.setdefault("metadata", {})
            if isinstance(result["metadata"], dict):
                result["metadata"]["verification_payload"] = verification_payload
                result["metadata"]["memory_payload"] = memory_payload

            self._send_optional_verification(verification_payload)
            self._send_optional_memory(memory_payload)

            self._emit_agent_event(
                "hologram.device.operation_completed",
                {
                    "action": action.value,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "success": result.get("success"),
                    "device_id": result.get("data", {}).get("device_id")
                    if isinstance(result.get("data"), Mapping)
                    else None,
                    "stream_id": result.get("data", {}).get("stream_id")
                    if isinstance(result.get("data"), Mapping)
                    else None,
                },
            )
            self._log_audit_event(ctx, action, payload, result)
            return result

        except Exception as exc:
            self.logger.exception("HologramDeviceBridge operation failed: %s", exc)
            result = self._error_result(
                message="Hologram device bridge operation failed.",
                error_code="hologram_device_bridge_operation_failed",
                details={"exception": str(exc), "action": action.value},
                metadata={"action": action.value},
            )

            if ctx is not None:
                self._log_audit_event(ctx, action, payload, result)
                self._emit_agent_event(
                    "hologram.device.operation_failed",
                    {
                        "action": action.value,
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "error": str(exc),
                    },
                )

            return result

    # ------------------------------------------------------------------
    # Internal device operations
    # ------------------------------------------------------------------

    def _register_device(
        self,
        ctx: HologramTaskContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        device_type = self._normalize_device_type(payload.get("device_type"))
        name = _normalize_text(payload.get("name"))

        if not name:
            return self._error_result("Device name is required.", "missing_device_name")

        adapter_name = _normalize_text(payload.get("adapter_name")) or "simulated"
        if adapter_name not in self.adapters:
            return self._error_result(
                "Device adapter is not registered.",
                "adapter_not_registered",
                {"adapter_name": adapter_name, "available_adapters": sorted(self.adapters.keys())},
            )

        existing = self.store.find_one(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            lambda record: (
                _normalize_text(record.get("name")).lower() == name.lower()
                and record.get("device_type") == device_type.value
            ),
        )

        if existing:
            existing["already_registered"] = True
            return self._safe_result(
                success=True,
                message="Hologram device already registered.",
                data=existing,
                metadata={
                    "action": HologramBridgeAction.REGISTER_DEVICE.value,
                    "deduplicated": True,
                },
            )

        device = HologramDevice(
            id=_new_id("holo_device"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            device_type=device_type.value,
            name=name,
            model=_normalize_text(payload.get("model")),
            os_name=_normalize_text(payload.get("os_name")),
            os_version=_normalize_text(payload.get("os_version")),
            app_version=_normalize_text(payload.get("app_version")),
            connection_mode=_normalize_text(payload.get("connection_mode")) or "simulated",
            adapter_name=adapter_name,
            capabilities=_listify(payload.get("capabilities")) or self._default_capabilities_for_device(device_type),
            permissions=_listify(payload.get("permissions")),
            metadata=_clean_dict(payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}),
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, "devices", asdict(device))

        return self._safe_result(
            success=True,
            message="Hologram device registered successfully.",
            data=saved,
            metadata={
                "action": HologramBridgeAction.REGISTER_DEVICE.value,
                "device_id": saved["id"],
            },
        )

    def _update_device(
        self,
        ctx: HologramTaskContext,
        device_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(device_id)
        if not clean_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_id},
            )

        allowed_keys = {
            "name",
            "model",
            "os_name",
            "os_version",
            "app_version",
            "connection_mode",
            "adapter_name",
            "capabilities",
            "permissions",
            "metadata",
            "last_error",
        }

        cleaned = _clean_dict(updates)
        safe_updates: Dict[str, Any] = {}

        for key in allowed_keys:
            if key in cleaned:
                if key in {"capabilities", "permissions"}:
                    safe_updates[key] = _listify(cleaned[key])
                elif key == "metadata":
                    safe_updates[key] = _clean_dict(cleaned[key]) if isinstance(cleaned[key], Mapping) else {}
                elif key == "adapter_name":
                    adapter_name = _normalize_text(cleaned[key])
                    if adapter_name not in self.adapters:
                        return self._error_result(
                            "Device adapter is not registered.",
                            "adapter_not_registered",
                            {"adapter_name": adapter_name, "available_adapters": sorted(self.adapters.keys())},
                        )
                    safe_updates[key] = adapter_name
                else:
                    safe_updates[key] = cleaned[key]

        safe_updates["updated_at"] = _utc_now()

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_id,
            safe_updates,
        )

        if not updated:
            return self._error_result("Device update failed.", "device_update_failed")

        return self._safe_result(
            success=True,
            message="Hologram device updated successfully.",
            data=updated,
            metadata={
                "action": HologramBridgeAction.UPDATE_DEVICE.value,
                "device_id": clean_id,
            },
        )

    def _remove_device(
        self,
        ctx: HologramTaskContext,
        device_id: str,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(device_id)
        if not clean_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_id},
            )

        streams = self.store.list_records(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            filters={"device_id": clean_id},
        )

        stopped_stream_ids: List[str] = []
        for stream in streams:
            if stream.get("status") in {
                HologramStreamStatus.ACTIVE.value,
                HologramStreamStatus.PAUSED.value,
                HologramStreamStatus.STARTING.value,
            }:
                self.store.update(
                    ctx.user_id,
                    ctx.workspace_id,
                    "streams",
                    stream["id"],
                    {
                        "status": HologramStreamStatus.STOPPED.value,
                        "stopped_at": _utc_now(),
                        "last_error": "Stopped because device was removed.",
                    },
                )
                stopped_stream_ids.append(stream["id"])

        deleted = self.store.delete(ctx.user_id, ctx.workspace_id, "devices", clean_id)
        if not deleted:
            return self._error_result("Device removal failed.", "device_remove_failed")

        return self._safe_result(
            success=True,
            message="Hologram device removed successfully.",
            data={
                "device_id": clean_id,
                "removed_device": deleted,
                "stopped_stream_ids": stopped_stream_ids,
            },
            metadata={
                "action": HologramBridgeAction.REMOVE_DEVICE.value,
                "device_id": clean_id,
            },
        )

    def _connect_device(
        self,
        ctx: HologramTaskContext,
        device_id: str,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(device_id)
        if not clean_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_id},
            )

        adapter = self._get_adapter(device)
        self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_id,
            {"status": HologramDeviceStatus.CONNECTING.value, "last_error": None},
        )

        adapter_response = adapter.connect(device)
        accepted = bool(adapter_response.get("accepted"))

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_id,
            {
                "status": HologramDeviceStatus.CONNECTED.value if accepted else HologramDeviceStatus.ERROR.value,
                "last_seen_at": _utc_now() if accepted else device.get("last_seen_at"),
                "last_error": None if accepted else adapter_response.get("message", "Device connection failed."),
            },
        )

        if not accepted:
            return self._error_result(
                "Device connection failed.",
                "device_connection_failed",
                {
                    "device_id": clean_id,
                    "adapter_response": adapter_response,
                },
            )

        data = dict(updated or {})
        data["device_id"] = clean_id
        data["adapter_response"] = adapter_response

        return self._safe_result(
            success=True,
            message="Hologram device connected successfully.",
            data=data,
            metadata={
                "action": HologramBridgeAction.CONNECT_DEVICE.value,
                "device_id": clean_id,
            },
        )

    def _disconnect_device(
        self,
        ctx: HologramTaskContext,
        device_id: str,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(device_id)
        if not clean_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_id},
            )

        adapter = self._get_adapter(device)

        self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_id,
            {"status": HologramDeviceStatus.DISCONNECTING.value},
        )

        active_streams = self.store.list_records(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            filters={"device_id": clean_id},
        )

        stopped_stream_ids: List[str] = []
        for stream in active_streams:
            if stream.get("status") in {
                HologramStreamStatus.ACTIVE.value,
                HologramStreamStatus.PAUSED.value,
                HologramStreamStatus.STARTING.value,
            }:
                adapter.stop_stream(device, stream)
                self.store.update(
                    ctx.user_id,
                    ctx.workspace_id,
                    "streams",
                    stream["id"],
                    {
                        "status": HologramStreamStatus.STOPPED.value,
                        "stopped_at": _utc_now(),
                    },
                )
                stopped_stream_ids.append(stream["id"])

        adapter_response = adapter.disconnect(device)
        accepted = bool(adapter_response.get("accepted"))

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_id,
            {
                "status": HologramDeviceStatus.DISCONNECTED.value if accepted else HologramDeviceStatus.ERROR.value,
                "last_seen_at": _utc_now(),
                "last_error": None if accepted else adapter_response.get("message", "Device disconnect failed."),
            },
        )

        if not accepted:
            return self._error_result(
                "Device disconnect failed.",
                "device_disconnect_failed",
                {
                    "device_id": clean_id,
                    "adapter_response": adapter_response,
                },
            )

        return self._safe_result(
            success=True,
            message="Hologram device disconnected successfully.",
            data={
                "device_id": clean_id,
                "device": updated,
                "stopped_stream_ids": stopped_stream_ids,
                "adapter_response": adapter_response,
            },
            metadata={
                "action": HologramBridgeAction.DISCONNECT_DEVICE.value,
                "device_id": clean_id,
            },
        )

    def _get_device(
        self,
        ctx: HologramTaskContext,
        device_id: str,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(device_id)
        if not clean_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_id},
            )

        streams = self.store.list_records(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            filters={"device_id": clean_id},
        )

        return self._safe_result(
            success=True,
            message="Hologram device fetched successfully.",
            data={
                **device,
                "device_id": clean_id,
                "streams": streams,
            },
            metadata={
                "action": HologramBridgeAction.GET_DEVICE.value,
                "device_id": clean_id,
            },
        )

    def _list_devices(
        self,
        ctx: HologramTaskContext,
        device_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        filters: Dict[str, Any] = {}

        if device_type:
            filters["device_type"] = self._normalize_device_type(device_type).value

        if status:
            filters["status"] = self._normalize_device_status(status).value

        devices = self.store.list_records(ctx.user_id, ctx.workspace_id, "devices", filters=filters)

        return self._safe_result(
            success=True,
            message="Hologram devices listed successfully.",
            data={
                "devices": devices,
                "total": len(devices),
                "filters": filters,
            },
            metadata={"action": HologramBridgeAction.LIST_DEVICES.value},
        )

    # ------------------------------------------------------------------
    # Internal stream operations
    # ------------------------------------------------------------------

    def _start_stream(
        self,
        ctx: HologramTaskContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        device_id = _normalize_text(payload.get("device_id"))
        if not device_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", device_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": device_id},
            )

        if device.get("status") != HologramDeviceStatus.CONNECTED.value:
            return self._error_result(
                "Device must be connected before starting a stream.",
                "device_not_connected",
                {
                    "device_id": device_id,
                    "current_status": device.get("status"),
                },
            )

        stream_type = self._normalize_stream_type(payload.get("stream_type"))
        if stream_type.value not in device.get("capabilities", []):
            return self._error_result(
                "Device does not declare support for this stream type.",
                "unsupported_device_stream",
                {
                    "device_id": device_id,
                    "stream_type": stream_type.value,
                    "capabilities": device.get("capabilities", []),
                },
            )

        existing = self.store.find_one(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            lambda record: (
                record.get("device_id") == device_id
                and record.get("stream_type") == stream_type.value
                and record.get("status") in {
                    HologramStreamStatus.STARTING.value,
                    HologramStreamStatus.ACTIVE.value,
                    HologramStreamStatus.PAUSED.value,
                }
            ),
        )

        if existing:
            return self._safe_result(
                success=True,
                message="Hologram stream is already active.",
                data={
                    **existing,
                    "device_id": device_id,
                    "stream_id": existing["id"],
                },
                metadata={
                    "action": HologramBridgeAction.START_STREAM.value,
                    "deduplicated": True,
                },
            )

        stream = HologramStream(
            id=_new_id("holo_stream"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            device_id=device_id,
            stream_type=stream_type.value,
            status=HologramStreamStatus.STARTING.value,
            label=_normalize_text(payload.get("label")) or f"{device.get('name')} {stream_type.value}",
            quality=_normalize_text(payload.get("quality")) or "balanced",
            sample_rate=_safe_int(payload.get("sample_rate"), 0) or None,
            frame_rate=_safe_int(payload.get("frame_rate"), 0) or None,
            resolution=_normalize_text(payload.get("resolution")) or None,
            encrypted=bool(payload.get("encrypted", True)),
            metadata=_clean_dict(payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}),
        )

        saved_stream = self.store.save(ctx.user_id, ctx.workspace_id, "streams", asdict(stream))
        adapter = self._get_adapter(device)
        adapter_response = adapter.start_stream(device, saved_stream)
        accepted = bool(adapter_response.get("accepted"))

        updated_stream = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            saved_stream["id"],
            {
                "status": HologramStreamStatus.ACTIVE.value if accepted else HologramStreamStatus.ERROR.value,
                "started_at": _utc_now() if accepted else None,
                "last_packet_at": _utc_now() if accepted else None,
                "last_error": None if accepted else adapter_response.get("message", "Stream start failed."),
            },
        )

        self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            device_id,
            {"last_seen_at": _utc_now()},
        )

        if not accepted:
            return self._error_result(
                "Hologram stream failed to start.",
                "stream_start_failed",
                {
                    "device_id": device_id,
                    "stream_id": saved_stream["id"],
                    "adapter_response": adapter_response,
                },
            )

        data = dict(updated_stream or {})
        data["device_id"] = device_id
        data["stream_id"] = saved_stream["id"]
        data["adapter_response"] = adapter_response

        return self._safe_result(
            success=True,
            message="Hologram stream started successfully.",
            data=data,
            metadata={
                "action": HologramBridgeAction.START_STREAM.value,
                "device_id": device_id,
                "stream_id": saved_stream["id"],
                "stream_type": stream_type.value,
            },
        )

    def _stop_stream(
        self,
        ctx: HologramTaskContext,
        stream_id: str,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(stream_id)
        if not clean_id:
            return self._error_result("stream_id is required.", "missing_stream_id")

        stream = self.store.get(ctx.user_id, ctx.workspace_id, "streams", clean_id)
        if not stream:
            return self._error_result(
                "Stream not found in this workspace.",
                "stream_not_found",
                {"stream_id": clean_id},
            )

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", stream["device_id"])
        if not device:
            return self._error_result(
                "Stream device not found in this workspace.",
                "stream_device_not_found",
                {
                    "stream_id": clean_id,
                    "device_id": stream.get("device_id"),
                },
            )

        adapter = self._get_adapter(device)
        adapter_response = adapter.stop_stream(device, stream)
        accepted = bool(adapter_response.get("accepted"))

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            clean_id,
            {
                "status": HologramStreamStatus.STOPPED.value if accepted else HologramStreamStatus.ERROR.value,
                "stopped_at": _utc_now() if accepted else stream.get("stopped_at"),
                "last_error": None if accepted else adapter_response.get("message", "Stream stop failed."),
            },
        )

        if not accepted:
            return self._error_result(
                "Hologram stream failed to stop.",
                "stream_stop_failed",
                {
                    "stream_id": clean_id,
                    "adapter_response": adapter_response,
                },
            )

        return self._safe_result(
            success=True,
            message="Hologram stream stopped successfully.",
            data={
                **(updated or {}),
                "device_id": stream["device_id"],
                "stream_id": clean_id,
                "adapter_response": adapter_response,
            },
            metadata={
                "action": HologramBridgeAction.STOP_STREAM.value,
                "stream_id": clean_id,
            },
        )

    def _pause_or_resume_stream(
        self,
        ctx: HologramTaskContext,
        stream_id: str,
        pause: bool,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(stream_id)
        if not clean_id:
            return self._error_result("stream_id is required.", "missing_stream_id")

        stream = self.store.get(ctx.user_id, ctx.workspace_id, "streams", clean_id)
        if not stream:
            return self._error_result(
                "Stream not found in this workspace.",
                "stream_not_found",
                {"stream_id": clean_id},
            )

        if pause and stream.get("status") != HologramStreamStatus.ACTIVE.value:
            return self._error_result(
                "Only active streams can be paused.",
                "stream_not_active",
                {"stream_id": clean_id, "current_status": stream.get("status")},
            )

        if not pause and stream.get("status") != HologramStreamStatus.PAUSED.value:
            return self._error_result(
                "Only paused streams can be resumed.",
                "stream_not_paused",
                {"stream_id": clean_id, "current_status": stream.get("status")},
            )

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            clean_id,
            {
                "status": HologramStreamStatus.PAUSED.value if pause else HologramStreamStatus.ACTIVE.value,
                "paused": pause,
                "last_packet_at": stream.get("last_packet_at") if pause else _utc_now(),
            },
        )

        action = HologramBridgeAction.PAUSE_STREAM if pause else HologramBridgeAction.RESUME_STREAM

        return self._safe_result(
            success=True,
            message="Hologram stream paused successfully." if pause else "Hologram stream resumed successfully.",
            data={
                **(updated or {}),
                "device_id": stream["device_id"],
                "stream_id": clean_id,
            },
            metadata={
                "action": action.value,
                "stream_id": clean_id,
            },
        )

    def _get_stream(
        self,
        ctx: HologramTaskContext,
        stream_id: str,
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(stream_id)
        if not clean_id:
            return self._error_result("stream_id is required.", "missing_stream_id")

        stream = self.store.get(ctx.user_id, ctx.workspace_id, "streams", clean_id)
        if not stream:
            return self._error_result(
                "Stream not found in this workspace.",
                "stream_not_found",
                {"stream_id": clean_id},
            )

        return self._safe_result(
            success=True,
            message="Hologram stream fetched successfully.",
            data={
                **stream,
                "stream_id": clean_id,
            },
            metadata={
                "action": HologramBridgeAction.GET_STREAM.value,
                "stream_id": clean_id,
            },
        )

    def _list_streams(
        self,
        ctx: HologramTaskContext,
        device_id: Optional[str] = None,
        stream_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        filters: Dict[str, Any] = {}

        if device_id:
            filters["device_id"] = _normalize_text(device_id)
        if stream_type:
            filters["stream_type"] = self._normalize_stream_type(stream_type).value
        if status:
            filters["status"] = self._normalize_stream_status(status).value

        streams = self.store.list_records(ctx.user_id, ctx.workspace_id, "streams", filters=filters)

        for stream in streams:
            stream["stream_id"] = stream.get("id")

        return self._safe_result(
            success=True,
            message="Hologram streams listed successfully.",
            data={
                "streams": streams,
                "total": len(streams),
                "filters": filters,
            },
            metadata={"action": HologramBridgeAction.LIST_STREAMS.value},
        )

    # ------------------------------------------------------------------
    # Internal control / telemetry operations
    # ------------------------------------------------------------------

    def _send_control(
        self,
        ctx: HologramTaskContext,
        device_id: str,
        command: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_device_id = _normalize_text(device_id)
        if not clean_device_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_device_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_device_id},
            )

        if device.get("status") != HologramDeviceStatus.CONNECTED.value:
            return self._error_result(
                "Device must be connected before sending controls.",
                "device_not_connected",
                {
                    "device_id": clean_device_id,
                    "current_status": device.get("status"),
                },
            )

        normalized_command = self._normalize_control_command(command)
        if HologramStreamType.CONTROL.value not in device.get("capabilities", []):
            return self._error_result(
                "Device does not declare control capability.",
                "control_not_supported",
                {
                    "device_id": clean_device_id,
                    "capabilities": device.get("capabilities", []),
                },
            )

        adapter = self._get_adapter(device)
        adapter_response = adapter.send_control(device, normalized_command.value, payload)
        accepted = bool(adapter_response.get("accepted"))

        receipt = HologramControlReceipt(
            id=_new_id("holo_control"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            device_id=clean_device_id,
            command=normalized_command.value,
            accepted=accepted,
            simulated=device.get("adapter_name") in {"simulated", "memory"},
            message=str(adapter_response.get("message") or ""),
            payload_summary=self._summarize_payload(payload),
        )

        saved_receipt = self.store.save(
            ctx.user_id,
            ctx.workspace_id,
            "control_receipts",
            asdict(receipt),
        )

        self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_device_id,
            {
                "last_seen_at": _utc_now(),
                "last_error": None if accepted else adapter_response.get("message", "Control command failed."),
            },
        )

        if not accepted:
            return self._error_result(
                "Hologram device control command failed.",
                "device_control_failed",
                {
                    "device_id": clean_device_id,
                    "command": normalized_command.value,
                    "receipt": saved_receipt,
                    "adapter_response": adapter_response,
                },
            )

        return self._safe_result(
            success=True,
            message="Hologram device control command accepted.",
            data={
                "device_id": clean_device_id,
                "command": normalized_command.value,
                "receipt": saved_receipt,
                "adapter_response": adapter_response,
            },
            metadata={
                "action": HologramBridgeAction.SEND_CONTROL.value,
                "device_id": clean_device_id,
                "command": normalized_command.value,
            },
        )

    def _ingest_telemetry(
        self,
        ctx: HologramTaskContext,
        device_id: str,
        telemetry: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_device_id = _normalize_text(device_id)
        if not clean_device_id:
            return self._error_result("device_id is required.", "missing_device_id")

        device = self.store.get(ctx.user_id, ctx.workspace_id, "devices", clean_device_id)
        if not device:
            return self._error_result(
                "Device not found in this workspace.",
                "device_not_found",
                {"device_id": clean_device_id},
            )

        cleaned = _clean_dict(telemetry)

        snapshot = HologramTelemetry(
            id=_new_id("holo_telemetry"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            device_id=clean_device_id,
            battery_percent=_safe_float(cleaned.get("battery_percent")),
            signal_strength=_safe_float(cleaned.get("signal_strength")),
            temperature_celsius=_safe_float(cleaned.get("temperature_celsius")),
            cpu_percent=_safe_float(cleaned.get("cpu_percent")),
            memory_percent=_safe_float(cleaned.get("memory_percent")),
            storage_percent=_safe_float(cleaned.get("storage_percent")),
            network_type=_normalize_text(cleaned.get("network_type")),
            is_charging=cleaned.get("is_charging") if isinstance(cleaned.get("is_charging"), bool) else None,
            sensor_summary=_clean_dict(cleaned.get("sensor_summary") if isinstance(cleaned.get("sensor_summary"), Mapping) else {}),
            metadata=_clean_dict(cleaned.get("metadata") if isinstance(cleaned.get("metadata"), Mapping) else {}),
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, "telemetry", asdict(snapshot))

        self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            "devices",
            clean_device_id,
            {
                "last_seen_at": _utc_now(),
                "last_error": None,
            },
        )

        active_streams = self.store.list_records(
            ctx.user_id,
            ctx.workspace_id,
            "streams",
            filters={"device_id": clean_device_id},
        )
        for stream in active_streams:
            if stream.get("status") == HologramStreamStatus.ACTIVE.value:
                self.store.update(
                    ctx.user_id,
                    ctx.workspace_id,
                    "streams",
                    stream["id"],
                    {"last_packet_at": _utc_now()},
                )

        return self._safe_result(
            success=True,
            message="Hologram device telemetry ingested successfully.",
            data={
                "device_id": clean_device_id,
                "telemetry": saved,
            },
            metadata={
                "action": HologramBridgeAction.INGEST_TELEMETRY.value,
                "device_id": clean_device_id,
            },
        )

    def _get_bridge_status(
        self,
        ctx: HologramTaskContext,
    ) -> Dict[str, Any]:
        devices = self.store.list_records(ctx.user_id, ctx.workspace_id, "devices")
        streams = self.store.list_records(ctx.user_id, ctx.workspace_id, "streams")
        telemetry = self.store.list_records(ctx.user_id, ctx.workspace_id, "telemetry")
        receipts = self.store.list_records(ctx.user_id, ctx.workspace_id, "control_receipts")

        device_status_counts: Dict[str, int] = {}
        for device in devices:
            status = str(device.get("status") or HologramDeviceStatus.REGISTERED.value)
            device_status_counts[status] = device_status_counts.get(status, 0) + 1

        stream_status_counts: Dict[str, int] = {}
        for stream in streams:
            status = str(stream.get("status") or HologramStreamStatus.CREATED.value)
            stream_status_counts[status] = stream_status_counts.get(status, 0) + 1

        latest_telemetry_by_device: Dict[str, Dict[str, Any]] = {}
        for item in telemetry:
            device_id = str(item.get("device_id"))
            current = latest_telemetry_by_device.get(device_id)
            if not current or str(item.get("created_at")) > str(current.get("created_at")):
                latest_telemetry_by_device[device_id] = item

        return self._safe_result(
            success=True,
            message="Hologram device bridge status loaded successfully.",
            data={
                "total_devices": len(devices),
                "total_streams": len(streams),
                "total_telemetry_snapshots": len(telemetry),
                "total_control_receipts": len(receipts),
                "device_status_counts": device_status_counts,
                "stream_status_counts": stream_status_counts,
                "active_devices": [
                    device for device in devices
                    if device.get("status") == HologramDeviceStatus.CONNECTED.value
                ],
                "active_streams": [
                    stream for stream in streams
                    if stream.get("status") == HologramStreamStatus.ACTIVE.value
                ],
                "latest_telemetry_by_device": latest_telemetry_by_device,
            },
            metadata={
                "action": HologramBridgeAction.GET_BRIDGE_STATUS.value,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    # ------------------------------------------------------------------
    # Normalizers / adapters
    # ------------------------------------------------------------------

    def _get_adapter(self, device: Mapping[str, Any]) -> Any:
        """Resolve device adapter by name with simulated fallback."""
        adapter_name = _normalize_text(device.get("adapter_name")) or "simulated"
        adapter = self.adapters.get(adapter_name)
        if adapter:
            return adapter
        return self.adapters["simulated"]

    @staticmethod
    def _normalize_device_type(value: Any) -> HologramDeviceType:
        raw = _normalize_text(value).lower()
        aliases = {
            "ar_glasses": HologramDeviceType.GLASSES,
            "smart_glasses": HologramDeviceType.GLASSES,
            "glasses": HologramDeviceType.GLASSES,
            "watch": HologramDeviceType.WATCH,
            "smartwatch": HologramDeviceType.WATCH,
            "phone": HologramDeviceType.PHONE,
            "mobile": HologramDeviceType.PHONE,
            "laptop": HologramDeviceType.LAPTOP,
            "notebook": HologramDeviceType.LAPTOP,
            "tablet": HologramDeviceType.TABLET,
        }
        return aliases.get(raw, HologramDeviceType.UNKNOWN)

    @staticmethod
    def _normalize_device_status(value: Any) -> HologramDeviceStatus:
        raw = _normalize_text(value).lower()
        allowed = {item.value: item for item in HologramDeviceStatus}
        if raw not in allowed:
            raise ValueError(f"Unsupported device status: {value}")
        return allowed[raw]

    @staticmethod
    def _normalize_stream_type(value: Any) -> HologramStreamType:
        raw = _normalize_text(value).lower()
        aliases = {
            "cam": HologramStreamType.CAMERA,
            "camera": HologramStreamType.CAMERA,
            "mic": HologramStreamType.MICROPHONE,
            "microphone": HologramStreamType.MICROPHONE,
            "screen": HologramStreamType.DISPLAY,
            "display": HologramStreamType.DISPLAY,
            "sensor": HologramStreamType.SENSOR,
            "sensors": HologramStreamType.SENSOR,
            "location": HologramStreamType.LOCATION,
            "gps": HologramStreamType.LOCATION,
            "notification": HologramStreamType.NOTIFICATION,
            "notifications": HologramStreamType.NOTIFICATION,
            "control": HologramStreamType.CONTROL,
            "biometric": HologramStreamType.BIOMETRIC,
            "biometrics": HologramStreamType.BIOMETRIC,
            "gesture": HologramStreamType.GESTURE,
            "gestures": HologramStreamType.GESTURE,
            "spatial": HologramStreamType.SPATIAL,
            "spatial_map": HologramStreamType.SPATIAL,
        }
        if raw not in aliases:
            raise ValueError(f"Unsupported stream type: {value}")
        return aliases[raw]

    @staticmethod
    def _normalize_stream_status(value: Any) -> HologramStreamStatus:
        raw = _normalize_text(value).lower()
        allowed = {item.value: item for item in HologramStreamStatus}
        if raw not in allowed:
            raise ValueError(f"Unsupported stream status: {value}")
        return allowed[raw]

    @staticmethod
    def _normalize_control_command(value: Any) -> HologramControlCommand:
        raw = _normalize_text(value).lower()
        aliases = {item.value: item for item in HologramControlCommand}
        if raw not in aliases:
            raise ValueError(f"Unsupported control command: {value}")
        return aliases[raw]

    @staticmethod
    def _default_capabilities_for_device(device_type: HologramDeviceType) -> List[str]:
        """Return safe default capabilities for simulated device types."""
        if device_type == HologramDeviceType.GLASSES:
            return [
                HologramStreamType.CAMERA.value,
                HologramStreamType.MICROPHONE.value,
                HologramStreamType.DISPLAY.value,
                HologramStreamType.SENSOR.value,
                HologramStreamType.GESTURE.value,
                HologramStreamType.SPATIAL.value,
                HologramStreamType.NOTIFICATION.value,
                HologramStreamType.CONTROL.value,
            ]

        if device_type == HologramDeviceType.WATCH:
            return [
                HologramStreamType.SENSOR.value,
                HologramStreamType.BIOMETRIC.value,
                HologramStreamType.NOTIFICATION.value,
                HologramStreamType.CONTROL.value,
            ]

        if device_type == HologramDeviceType.PHONE:
            return [
                HologramStreamType.CAMERA.value,
                HologramStreamType.MICROPHONE.value,
                HologramStreamType.DISPLAY.value,
                HologramStreamType.SENSOR.value,
                HologramStreamType.LOCATION.value,
                HologramStreamType.NOTIFICATION.value,
                HologramStreamType.CONTROL.value,
            ]

        if device_type == HologramDeviceType.LAPTOP:
            return [
                HologramStreamType.CAMERA.value,
                HologramStreamType.MICROPHONE.value,
                HologramStreamType.DISPLAY.value,
                HologramStreamType.NOTIFICATION.value,
                HologramStreamType.CONTROL.value,
            ]

        if device_type == HologramDeviceType.TABLET:
            return [
                HologramStreamType.CAMERA.value,
                HologramStreamType.MICROPHONE.value,
                HologramStreamType.DISPLAY.value,
                HologramStreamType.SENSOR.value,
                HologramStreamType.NOTIFICATION.value,
                HologramStreamType.CONTROL.value,
            ]

        return [
            HologramStreamType.NOTIFICATION.value,
            HologramStreamType.CONTROL.value,
        ]

    # ------------------------------------------------------------------
    # Security / summary / downstream helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Create safe payload summary for logs/security.

        Raw camera/mic frames, tokens, credentials, or large payloads are never
        included in summary.
        """
        secret_keywords = {
            "secret",
            "token",
            "password",
            "api_key",
            "apikey",
            "authorization",
            "access_token",
            "refresh_token",
            "frame",
            "image",
            "audio",
            "video",
            "raw",
            "blob",
            "binary",
        }

        summary: Dict[str, Any] = {}
        for key, value in dict(payload).items():
            key_str = str(key)
            key_lower = key_str.lower()

            if any(secret in key_lower for secret in secret_keywords):
                summary[key_str] = "***redacted***"
            elif isinstance(value, Mapping):
                summary[key_str] = HologramDeviceBridge._summarize_payload(value)
            elif isinstance(value, list):
                summary[key_str] = [
                    HologramDeviceBridge._truncate_for_summary(item)
                    for item in value[:10]
                ]
            else:
                summary[key_str] = HologramDeviceBridge._truncate_for_summary(value)

        return summary

    @staticmethod
    def _truncate_for_summary(value: Any, max_length: int = 160) -> Any:
        """Truncate long values for audit/security summaries."""
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        text = str(value)
        if len(text) > max_length:
            return text[:max_length] + "...[truncated]"
        return text

    def _send_optional_verification(self, verification_payload: Mapping[str, Any]) -> None:
        """Send payload to Verification Agent/client if configured."""
        if not self.verification_client:
            return

        try:
            if hasattr(self.verification_client, "submit"):
                self.verification_client.submit(dict(verification_payload))
            elif hasattr(self.verification_client, "verify"):
                self.verification_client.verify(dict(verification_payload))
        except Exception as exc:
            self.logger.warning("Verification payload send failed: %s", exc)

    def _send_optional_memory(self, memory_payload: Mapping[str, Any]) -> None:
        """Send useful safe memory payload to Memory Agent/client if configured."""
        if not self.memory_client:
            return

        try:
            if hasattr(self.memory_client, "store"):
                self.memory_client.store(dict(memory_payload))
            elif hasattr(self.memory_client, "remember"):
                self.memory_client.remember(dict(memory_payload))
        except Exception as exc:
            self.logger.warning("Memory payload send failed: %s", exc)


# ---------------------------------------------------------------------------
# Module-level factory / registry helpers
# ---------------------------------------------------------------------------

def create_device_bridge(
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> HologramDeviceBridge:
    """
    Factory for Agent Loader / Registry / tests.

    Example:
        bridge = create_device_bridge(
            config={"allow_simulated_sensitive_without_security": True}
        )
    """
    return HologramDeviceBridge(config=config, **kwargs)


def get_module_metadata() -> Dict[str, Any]:
    """
    Lightweight metadata for import-time discovery.

    This function does not instantiate device SDKs or execute hardware actions.
    """
    return {
        "agent": HologramDeviceBridge.agent_name,
        "agent_type": HologramDeviceBridge.agent_type,
        "module": HologramDeviceBridge.module_name,
        "class_name": "HologramDeviceBridge",
        "version": HologramDeviceBridge.version,
        "file_path": "agents/super_agents/hologram_agent/device_bridge.py",
        "safe_import": True,
        "purpose": "Connects glasses/watch/phone/laptop streams and controls.",
        "requires_context": ["user_id", "workspace_id"],
        "device_types": [item.value for item in HologramDeviceType],
        "stream_types": [item.value for item in HologramStreamType],
        "control_commands": [item.value for item in HologramControlCommand],
        "actions": [item.value for item in HologramBridgeAction],
        "master_agent_routes": [
            "hologram.device.register",
            "hologram.device.update",
            "hologram.device.remove",
            "hologram.device.connect",
            "hologram.device.disconnect",
            "hologram.device.start_stream",
            "hologram.device.stop_stream",
            "hologram.device.pause_stream",
            "hologram.device.resume_stream",
            "hologram.device.send_control",
            "hologram.device.ingest_telemetry",
            "hologram.device.status",
        ],
    }


__all__ = [
    "HologramDeviceBridge",
    "HologramTaskContext",
    "HologramDevice",
    "HologramStream",
    "HologramTelemetry",
    "HologramControlReceipt",
    "HologramDeviceType",
    "HologramDeviceStatus",
    "HologramStreamType",
    "HologramStreamStatus",
    "HologramControlCommand",
    "HologramBridgeAction",
    "InMemoryDeviceBridgeStore",
    "SimulatedDeviceAdapter",
    "create_device_bridge",
    "get_module_metadata",
]