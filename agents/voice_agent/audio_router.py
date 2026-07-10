"""
agents/voice_agent/audio_router.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Routes audio input/output across phone, laptop, earbuds, watch, glasses,
    and car Bluetooth.

This file provides:
    - AudioRouter class
    - SaaS-safe user_id / workspace_id validation
    - Audio device registration and routing
    - Input/output device selection
    - Bluetooth/car/earbuds/watch/glasses routing profiles
    - Fallback routing when preferred device is unavailable
    - Security Agent compatibility for sensitive routing changes
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard/API event emission
    - Audit logging hooks
    - Structured William-style result format

Important:
    This module does not directly control OS audio devices by default.
    It provides production-safe routing state, adapter hooks, and clear interfaces.
    Real platform routing can be connected later using injected callbacks/adapters.

Public Class:
    AudioRouter
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import platform
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the real William BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.voice_agent.audio_router")
logger.addHandler(logging.NullHandler())


# =============================================================================
# Type aliases
# =============================================================================

StructuredResult = Dict[str, Any]
EventCallback = Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
AuditCallback = Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
DeviceDiscoveryCallback = Callable[[Dict[str, Any]], Union[List[Dict[str, Any]], Awaitable[List[Dict[str, Any]]]]]
RouteApplyCallback = Callable[[Dict[str, Any]], Union[bool, Dict[str, Any], Awaitable[Union[bool, Dict[str, Any]]]]]


# =============================================================================
# Enums
# =============================================================================

class AudioDeviceType(str, Enum):
    """
    Supported audio device categories.
    """

    PHONE = "phone"
    LAPTOP = "laptop"
    DESKTOP = "desktop"
    EARBUDS = "earbuds"
    HEADPHONES = "headphones"
    WATCH = "watch"
    GLASSES = "glasses"
    CAR_BLUETOOTH = "car_bluetooth"
    BLUETOOTH_SPEAKER = "bluetooth_speaker"
    MICROPHONE = "microphone"
    SPEAKER = "speaker"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


class AudioDirection(str, Enum):
    """
    Direction of audio routing.
    """

    INPUT = "input"
    OUTPUT = "output"
    DUPLEX = "duplex"


class AudioRouteStatus(str, Enum):
    """
    Current route status.
    """

    IDLE = "idle"
    DISCOVERING = "discovering"
    ROUTING = "routing"
    ACTIVE = "active"
    FALLBACK_ACTIVE = "fallback_active"
    FAILED = "failed"
    DISABLED = "disabled"


class AudioConnectionType(str, Enum):
    """
    Device connection type.
    """

    BUILT_IN = "built_in"
    BLUETOOTH = "bluetooth"
    USB = "usb"
    WIFI = "wifi"
    WEBRTC = "webrtc"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


class AudioPriority(str, Enum):
    """
    Routing priority level.
    """

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class AudioRouterConfig:
    """
    Runtime config for AudioRouter.
    """

    enabled: bool = True

    # Automatically choose fallback device if preferred device is unavailable.
    allow_fallback: bool = True

    # Emit dashboard/API events.
    emit_events: bool = True

    # Enable audit logs.
    audit_enabled: bool = True

    # Prepare Verification Agent payloads.
    verification_payload_enabled: bool = True

    # Prepare Memory Agent payloads.
    memory_payload_enabled: bool = True

    # Thread-safe state management.
    thread_safe: bool = True

    # Require security before dashboard/API-triggered device route changes.
    require_security_for_dashboard_route: bool = False
    require_security_for_api_route: bool = False

    # Max route history kept in memory.
    max_route_history: int = 300

    # Device discovery timeout.
    discovery_timeout_seconds: float = 8.0

    # Route apply timeout.
    route_apply_timeout_seconds: float = 8.0

    # Default input preference order.
    default_input_preference: Tuple[AudioDeviceType, ...] = (
        AudioDeviceType.EARBUDS,
        AudioDeviceType.HEADPHONES,
        AudioDeviceType.PHONE,
        AudioDeviceType.LAPTOP,
        AudioDeviceType.DESKTOP,
        AudioDeviceType.WATCH,
        AudioDeviceType.GLASSES,
        AudioDeviceType.MICROPHONE,
    )

    # Default output preference order.
    default_output_preference: Tuple[AudioDeviceType, ...] = (
        AudioDeviceType.EARBUDS,
        AudioDeviceType.HEADPHONES,
        AudioDeviceType.CAR_BLUETOOTH,
        AudioDeviceType.PHONE,
        AudioDeviceType.LAPTOP,
        AudioDeviceType.DESKTOP,
        AudioDeviceType.WATCH,
        AudioDeviceType.GLASSES,
        AudioDeviceType.SPEAKER,
    )

    # When user is in car mode, prefer car Bluetooth output.
    car_mode_output_preference: Tuple[AudioDeviceType, ...] = (
        AudioDeviceType.CAR_BLUETOOTH,
        AudioDeviceType.EARBUDS,
        AudioDeviceType.PHONE,
        AudioDeviceType.LAPTOP,
        AudioDeviceType.SPEAKER,
    )

    # When discreet mode is active, prefer earbuds/watch/glasses.
    discreet_mode_output_preference: Tuple[AudioDeviceType, ...] = (
        AudioDeviceType.EARBUDS,
        AudioDeviceType.HEADPHONES,
        AudioDeviceType.WATCH,
        AudioDeviceType.GLASSES,
        AudioDeviceType.PHONE,
    )

    # Useful for dashboard analytics.
    analytics_enabled: bool = True


@dataclass
class AudioDevice:
    """
    Represents one available audio device.
    """

    device_id: str
    name: str
    device_type: AudioDeviceType = AudioDeviceType.UNKNOWN
    direction: AudioDirection = AudioDirection.DUPLEX
    connection_type: AudioConnectionType = AudioConnectionType.UNKNOWN
    is_available: bool = True
    is_default: bool = False
    input_supported: bool = True
    output_supported: bool = True
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    platform_name: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["device_type"] = self.device_type.value
        data["direction"] = self.direction.value
        data["connection_type"] = self.connection_type.value
        return data


@dataclass
class AudioRoute:
    """
    Represents active or requested audio route.
    """

    route_id: str
    user_id: str
    workspace_id: str
    input_device_id: Optional[str] = None
    output_device_id: Optional[str] = None
    preferred_device_type: Optional[AudioDeviceType] = None
    direction: AudioDirection = AudioDirection.DUPLEX
    status: AudioRouteStatus = AudioRouteStatus.IDLE
    priority: AudioPriority = AudioPriority.NORMAL
    reason: str = "manual"
    fallback_used: bool = False
    source: str = "system"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["direction"] = self.direction.value
        data["status"] = self.status.value
        data["priority"] = self.priority.value
        data["preferred_device_type"] = (
            self.preferred_device_type.value if self.preferred_device_type else None
        )
        return data


# =============================================================================
# Helper functions
# =============================================================================

def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_str(value: Any, max_length: int = 5000) -> str:
    try:
        text = "" if value is None else str(value)
    except Exception:
        text = "<unprintable>"
    if len(text) > max_length:
        return text[:max_length] + "...[truncated]"
    return text


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


# =============================================================================
# Main class
# =============================================================================

class AudioRouter(BaseAgent):
    """
    Routes William Voice Agent audio input/output across devices.

    Main responsibilities:
        1. Register audio devices.
        2. Discover devices using optional adapter callback.
        3. Select best input/output device.
        4. Route audio to phone/laptop/earbuds/watch/glasses/car Bluetooth.
        5. Maintain SaaS-safe user/workspace isolation.
        6. Prepare Security, Verification, Memory, Audit, Dashboard events.
        7. Return all results in William structured dict format.

    Important:
        This class is platform-adapter ready. It does not directly modify OS
        audio routing unless route_apply_callback is injected.

    Example:
        router = AudioRouter()
        router.register_device(
            user_id="u1",
            workspace_id="w1",
            name="AirPods Pro",
            device_type="earbuds",
            connection_type="bluetooth",
            input_supported=True,
            output_supported=True,
        )

        result = await router.route_audio(
            user_id="u1",
            workspace_id="w1",
            preferred_device_type="earbuds",
            direction="duplex",
        )
    """

    def __init__(
        self,
        config: Optional[AudioRouterConfig] = None,
        discovery_callback: Optional[DeviceDiscoveryCallback] = None,
        route_apply_callback: Optional[RouteApplyCallback] = None,
        event_callback: Optional[EventCallback] = None,
        audit_logger: Optional[AuditCallback] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        agent_name: str = "voice_audio_router",
        agent_id: str = "voice_agent.audio_router",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)

        self.config = config or AudioRouterConfig()
        self.discovery_callback = discovery_callback
        self.route_apply_callback = route_apply_callback
        self.event_callback = event_callback
        self.audit_logger = audit_logger

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent

        self.status: AudioRouteStatus = AudioRouteStatus.IDLE

        self._lock = threading.RLock()
        self._devices: Dict[str, AudioDevice] = {}
        self._active_routes: Dict[Tuple[str, str], AudioRoute] = {}
        self._route_history: List[AudioRoute] = []

        self._stats: Dict[str, Any] = {
            "total_devices_registered": 0,
            "total_routes_requested": 0,
            "successful_routes": 0,
            "failed_routes": 0,
            "fallback_routes": 0,
            "discoveries": 0,
            "created_at": time.time(),
            "updated_at": time.time(),
        }

    # =========================================================================
    # Device registration and discovery
    # =========================================================================

    def register_device(
        self,
        user_id: str,
        workspace_id: str,
        name: str,
        device_type: Union[str, AudioDeviceType] = AudioDeviceType.UNKNOWN,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        connection_type: Union[str, AudioConnectionType] = AudioConnectionType.UNKNOWN,
        device_id: Optional[str] = None,
        input_supported: bool = True,
        output_supported: bool = True,
        is_default: bool = False,
        is_available: bool = True,
        capabilities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Register or update an audio device for a user/workspace.

        Devices are isolated by user_id/workspace_id through metadata and
        filtering. This prevents one workspace from routing to another user's
        registered device.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not name or not str(name).strip():
            return self._error_result(
                message="Device name is required.",
                error="missing_device_name",
                data={"registered": False},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        parsed_type = self._parse_device_type(device_type)
        parsed_direction = self._parse_direction(direction)
        parsed_connection = self._parse_connection_type(connection_type)

        final_device_id = device_id or self._build_device_id(
            user_id=user_id,
            workspace_id=workspace_id,
            name=name,
            device_type=parsed_type,
        )

        device = AudioDevice(
            device_id=final_device_id,
            name=str(name).strip(),
            device_type=parsed_type,
            direction=parsed_direction,
            connection_type=parsed_connection,
            is_available=bool(is_available),
            is_default=bool(is_default),
            input_supported=bool(input_supported),
            output_supported=bool(output_supported),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            platform_name=platform.system(),
            capabilities=capabilities or [],
            metadata=metadata or {},
        )

        with self._guard():
            existing = self._devices.get(final_device_id)
            if existing:
                device.created_at = existing.created_at
            device.updated_at = time.time()
            self._devices[final_device_id] = device
            self._stats["total_devices_registered"] += 1
            self._stats["updated_at"] = time.time()

        self._emit_agent_event_sync({
            "event_type": "audio_device_registered",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "device": device.to_dict(),
            "timestamp_ms": _now_ms(),
        })

        return self._safe_result(
            message="Audio device registered successfully.",
            data={
                "registered": True,
                "device": device.to_dict(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    async def discover_devices(
        self,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Discover available audio devices.

        If discovery_callback is provided, this method uses it.
        Otherwise, it returns registered devices and creates safe built-in
        fallback devices if no device exists.

        Real implementation can later connect:
            - Android AudioManager
            - iOS AVAudioSession
            - Windows Core Audio
            - macOS CoreAudio
            - Linux PulseAudio/PipeWire
            - WebRTC browser devices
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        metadata = metadata or {}

        with self._guard():
            self.status = AudioRouteStatus.DISCOVERING
            self._stats["discoveries"] += 1
            self._stats["updated_at"] = time.time()

        try:
            discovered_raw: List[Dict[str, Any]] = []

            if self.discovery_callback:
                discovered_raw = await asyncio.wait_for(
                    _maybe_await(self.discovery_callback({
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "metadata": metadata,
                        "timeout_seconds": self.config.discovery_timeout_seconds,
                    })),
                    timeout=self.config.discovery_timeout_seconds,
                )

            for raw_device in discovered_raw or []:
                self.register_device(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    name=raw_device.get("name", "Unknown Audio Device"),
                    device_type=raw_device.get("device_type", AudioDeviceType.UNKNOWN.value),
                    direction=raw_device.get("direction", AudioDirection.DUPLEX.value),
                    connection_type=raw_device.get("connection_type", AudioConnectionType.UNKNOWN.value),
                    device_id=raw_device.get("device_id"),
                    input_supported=raw_device.get("input_supported", True),
                    output_supported=raw_device.get("output_supported", True),
                    is_default=raw_device.get("is_default", False),
                    is_available=raw_device.get("is_available", True),
                    capabilities=raw_device.get("capabilities", []),
                    metadata=raw_device.get("metadata", {}),
                )

            self._ensure_builtin_fallback_devices(user_id=user_id, workspace_id=workspace_id)

            devices = self.list_devices(
                user_id=user_id,
                workspace_id=workspace_id,
                available_only=True,
            ).get("data", {}).get("devices", [])

            with self._guard():
                self.status = AudioRouteStatus.IDLE

            await self._emit_agent_event({
                "event_type": "audio_devices_discovered",
                "agent": self.agent_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "device_count": len(devices),
                "timestamp_ms": _now_ms(),
            })

            return self._safe_result(
                message="Audio device discovery completed.",
                data={
                    "devices": devices,
                    "count": len(devices),
                    "used_discovery_callback": bool(self.discovery_callback),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except asyncio.TimeoutError:
            with self._guard():
                self.status = AudioRouteStatus.FAILED

            return self._error_result(
                message="Audio device discovery timed out.",
                error="discovery_timeout",
                data={"devices": []},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            logger.exception("Audio device discovery failed.")
            with self._guard():
                self.status = AudioRouteStatus.FAILED

            return self._error_result(
                message="Audio device discovery failed.",
                error=_safe_str(exc),
                data={"devices": []},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def list_devices(
        self,
        user_id: str,
        workspace_id: str,
        available_only: bool = False,
        direction: Optional[Union[str, AudioDirection]] = None,
        device_type: Optional[Union[str, AudioDeviceType]] = None,
    ) -> StructuredResult:
        """
        List devices for one user/workspace only.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        parsed_direction = self._parse_direction(direction) if direction else None
        parsed_type = self._parse_device_type(device_type) if device_type else None

        with self._guard():
            devices = list(self._devices.values())

        filtered: List[AudioDevice] = []
        for device in devices:
            if str(device.user_id) != str(user_id):
                continue
            if str(device.workspace_id) != str(workspace_id):
                continue
            if available_only and not device.is_available:
                continue
            if parsed_type and device.device_type != parsed_type:
                continue
            if parsed_direction:
                if parsed_direction == AudioDirection.INPUT and not device.input_supported:
                    continue
                if parsed_direction == AudioDirection.OUTPUT and not device.output_supported:
                    continue
                if parsed_direction == AudioDirection.DUPLEX and not (
                    device.input_supported and device.output_supported
                ):
                    continue
            filtered.append(device)

        filtered.sort(key=lambda d: (
            not d.is_default,
            not d.is_available,
            d.device_type.value,
            d.name.lower(),
        ))

        return self._safe_result(
            message="Audio devices retrieved.",
            data={
                "devices": [device.to_dict() for device in filtered],
                "count": len(filtered),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def set_device_availability(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        is_available: bool,
    ) -> StructuredResult:
        """
        Mark device available/unavailable.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._guard():
            device = self._devices.get(device_id)
            if not device:
                return self._error_result(
                    message="Audio device not found.",
                    error="device_not_found",
                    data={"device_id": device_id},
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            if str(device.user_id) != str(user_id) or str(device.workspace_id) != str(workspace_id):
                return self._error_result(
                    message="Device does not belong to this user/workspace.",
                    error="device_context_mismatch",
                    data={"device_id": device_id},
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            device.is_available = bool(is_available)
            device.updated_at = time.time()

        return self._safe_result(
            message="Audio device availability updated.",
            data={
                "device": device.to_dict(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # =========================================================================
    # Routing methods
    # =========================================================================

    async def route_audio(
        self,
        user_id: str,
        workspace_id: str,
        preferred_device_type: Optional[Union[str, AudioDeviceType]] = None,
        input_device_id: Optional[str] = None,
        output_device_id: Optional[str] = None,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        mode: str = "default",
        source: str = "system",
        priority: Union[str, AudioPriority] = AudioPriority.NORMAL,
        reason: str = "manual",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        """
        Main audio routing method.

        Can route:
            - input only
            - output only
            - duplex input + output

        Supports:
            - phone
            - laptop
            - earbuds
            - watch
            - glasses
            - car Bluetooth
            - fallback devices
        """
        started_at = time.time()
        metadata = metadata or {}

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not self.config.enabled:
            return self._error_result(
                message="Audio router is disabled.",
                error="audio_router_disabled",
                data={"routed": False},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        parsed_direction = self._parse_direction(direction)
        parsed_priority = self._parse_priority(priority)
        parsed_preferred = (
            self._parse_device_type(preferred_device_type)
            if preferred_device_type
            else None
        )

        route = AudioRoute(
            route_id=str(uuid.uuid4()),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            input_device_id=input_device_id,
            output_device_id=output_device_id,
            preferred_device_type=parsed_preferred,
            direction=parsed_direction,
            status=AudioRouteStatus.ROUTING,
            priority=parsed_priority,
            reason=reason,
            source=source,
            metadata=metadata,
        )

        with self._guard():
            self.status = AudioRouteStatus.ROUTING
            self._stats["total_routes_requested"] += 1
            self._stats["updated_at"] = time.time()

        security_result = None
        if self._requires_security_check(source=source, priority=parsed_priority, metadata=metadata):
            security_result = await self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="audio_route_change",
                payload=route.to_dict(),
            )
            if not security_result.get("success"):
                route.status = AudioRouteStatus.FAILED
                route.error = security_result.get("error") or "security_denied"
                self._record_route(route)

                return self._error_result(
                    message="Audio routing blocked by Security Agent.",
                    error=route.error,
                    data={
                        "routed": False,
                        "route": route.to_dict(),
                        "security_result": security_result,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        await self.discover_devices(user_id=user_id, workspace_id=workspace_id, metadata=metadata)

        selection = self._select_route_devices(
            user_id=user_id,
            workspace_id=workspace_id,
            direction=parsed_direction,
            preferred_device_type=parsed_preferred,
            input_device_id=input_device_id,
            output_device_id=output_device_id,
            mode=mode,
        )

        if not selection["success"]:
            route.status = AudioRouteStatus.FAILED
            route.error = selection.get("error")
            self._record_route(route)

            with self._guard():
                self.status = AudioRouteStatus.FAILED
                self._stats["failed_routes"] += 1

            return self._error_result(
                message="Unable to select audio route devices.",
                error=selection.get("error") or "route_selection_failed",
                data={
                    "routed": False,
                    "route": route.to_dict(),
                    "selection": selection,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        route.input_device_id = selection["data"].get("input_device_id")
        route.output_device_id = selection["data"].get("output_device_id")
        route.fallback_used = bool(selection["data"].get("fallback_used"))

        apply_result = await self._apply_route(route=route)

        if not apply_result.get("success"):
            route.status = AudioRouteStatus.FAILED
            route.error = apply_result.get("error")
            route.updated_at = time.time()
            self._record_route(route)

            with self._guard():
                self.status = AudioRouteStatus.FAILED
                self._stats["failed_routes"] += 1

            return self._error_result(
                message="Audio route application failed.",
                error=apply_result.get("error") or "route_apply_failed",
                data={
                    "routed": False,
                    "route": route.to_dict(),
                    "apply_result": apply_result,
                    "security_result": security_result,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

        route.status = (
            AudioRouteStatus.FALLBACK_ACTIVE
            if route.fallback_used
            else AudioRouteStatus.ACTIVE
        )
        route.updated_at = time.time()
        self._record_route(route)

        with self._guard():
            self.status = route.status
            self._active_routes[(str(user_id), str(workspace_id))] = route
            self._stats["successful_routes"] += 1
            if route.fallback_used:
                self._stats["fallback_routes"] += 1
            self._stats["updated_at"] = time.time()

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            route=route,
            apply_result=apply_result,
        )

        memory_payload = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            route=route,
            apply_result=apply_result,
        )

        await self._log_audit_event({
            "event_type": "audio_route_changed",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "route": route.to_dict(),
            "duration_ms": int((time.time() - started_at) * 1000),
            "timestamp_ms": _now_ms(),
        })

        await self._emit_agent_event({
            "event_type": "audio_route_active",
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "route": route.to_dict(),
            "timestamp_ms": _now_ms(),
        })

        return self._safe_result(
            message="Audio routed successfully.",
            data={
                "routed": True,
                "route": route.to_dict(),
                "input_device": self._get_device_dict(route.input_device_id),
                "output_device": self._get_device_dict(route.output_device_id),
                "fallback_used": route.fallback_used,
                "apply_result": apply_result,
                "security_result": security_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "duration_ms": int((time.time() - started_at) * 1000),
            },
        )

    async def route_to_phone(
        self,
        user_id: str,
        workspace_id: str,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        return await self.route_audio(
            user_id=user_id,
            workspace_id=workspace_id,
            preferred_device_type=AudioDeviceType.PHONE,
            direction=direction,
            reason="route_to_phone",
            metadata=metadata,
        )

    async def route_to_laptop(
        self,
        user_id: str,
        workspace_id: str,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        return await self.route_audio(
            user_id=user_id,
            workspace_id=workspace_id,
            preferred_device_type=AudioDeviceType.LAPTOP,
            direction=direction,
            reason="route_to_laptop",
            metadata=metadata,
        )

    async def route_to_earbuds(
        self,
        user_id: str,
        workspace_id: str,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        return await self.route_audio(
            user_id=user_id,
            workspace_id=workspace_id,
            preferred_device_type=AudioDeviceType.EARBUDS,
            direction=direction,
            reason="route_to_earbuds",
            metadata=metadata,
        )

    async def route_to_watch(
        self,
        user_id: str,
        workspace_id: str,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        return await self.route_audio(
            user_id=user_id,
            workspace_id=workspace_id,
            preferred_device_type=AudioDeviceType.WATCH,
            direction=direction,
            reason="route_to_watch",
            metadata=metadata,
        )

    async def route_to_glasses(
        self,
        user_id: str,
        workspace_id: str,
        direction: Union[str, AudioDirection] = AudioDirection.DUPLEX,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        return await self.route_audio(
            user_id=user_id,
            workspace_id=workspace_id,
            preferred_device_type=AudioDeviceType.GLASSES,
            direction=direction,
            reason="route_to_glasses",
            metadata=metadata,
        )

    async def route_to_car_bluetooth(
        self,
        user_id: str,
        workspace_id: str,
        direction: Union[str, AudioDirection] = AudioDirection.OUTPUT,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StructuredResult:
        return await self.route_audio(
            user_id=user_id,
            workspace_id=workspace_id,
            preferred_device_type=AudioDeviceType.CAR_BLUETOOTH,
            direction=direction,
            mode="car",
            reason="route_to_car_bluetooth",
            metadata=metadata,
        )

    # =========================================================================
    # Active route/status methods
    # =========================================================================

    def get_active_route(
        self,
        user_id: str,
        workspace_id: str,
    ) -> StructuredResult:
        """
        Get active route for a user/workspace.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._guard():
            route = self._active_routes.get((str(user_id), str(workspace_id)))

        return self._safe_result(
            message="Active audio route retrieved.",
            data={
                "active_route": route.to_dict() if route else None,
                "input_device": self._get_device_dict(route.input_device_id) if route else None,
                "output_device": self._get_device_dict(route.output_device_id) if route else None,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def get_status(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> StructuredResult:
        """
        Get router status for dashboard/API.
        """
        with self._guard():
            data = {
                "agent": self.agent_id,
                "enabled": self.config.enabled,
                "status": self.status.value,
                "stats": dict(self._stats),
                "registered_device_count": len(self._devices),
                "active_route_count": len(self._active_routes),
            }

            if user_id and workspace_id:
                route = self._active_routes.get((str(user_id), str(workspace_id)))
                user_devices = [
                    d.to_dict()
                    for d in self._devices.values()
                    if str(d.user_id) == str(user_id)
                    and str(d.workspace_id) == str(workspace_id)
                ]
                data["active_route"] = route.to_dict() if route else None
                data["devices"] = user_devices

        return self._safe_result(
            message="Audio router status retrieved.",
            data=data,
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def get_route_history(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        limit: int = 50,
    ) -> StructuredResult:
        """
        Get route history with SaaS-safe optional filtering.
        """
        limit = max(1, min(int(limit), self.config.max_route_history))

        with self._guard():
            routes = list(self._route_history)

        if user_id:
            routes = [r for r in routes if str(r.user_id) == str(user_id)]

        if workspace_id:
            routes = [r for r in routes if str(r.workspace_id) == str(workspace_id)]

        routes = routes[-limit:]

        return self._safe_result(
            message="Audio route history retrieved.",
            data={
                "routes": [route.to_dict() for route in routes],
                "count": len(routes),
                "limit": limit,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def clear_route_history(
        self,
        user_id: str,
        workspace_id: str,
    ) -> StructuredResult:
        """
        Clear route history for one user/workspace only.
        """
        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._guard():
            before = len(self._route_history)
            self._route_history = [
                route for route in self._route_history
                if not (
                    str(route.user_id) == str(user_id)
                    and str(route.workspace_id) == str(workspace_id)
                )
            ]
            after = len(self._route_history)

        return self._safe_result(
            message="Audio route history cleared for user/workspace.",
            data={
                "removed": before - after,
                "remaining": after,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def enable(self) -> StructuredResult:
        self.config.enabled = True
        self.status = AudioRouteStatus.IDLE
        return self._safe_result(
            message="Audio router enabled.",
            data={"enabled": True},
        )

    def disable(self) -> StructuredResult:
        self.config.enabled = False
        self.status = AudioRouteStatus.DISABLED
        return self._safe_result(
            message="Audio router disabled.",
            data={"enabled": False},
        )

    def update_config(self, **kwargs: Any) -> StructuredResult:
        """
        Update allowed config fields only.
        """
        allowed = set(AudioRouterConfig.__dataclass_fields__.keys())
        changed: Dict[str, Any] = {}
        rejected: Dict[str, Any] = {}

        for key, value in kwargs.items():
            if key in allowed:
                setattr(self.config, key, value)
                changed[key] = value
            else:
                rejected[key] = value

        return self._safe_result(
            message="Audio router config updated.",
            data={
                "changed": changed,
                "rejected": rejected,
                "config": self._config_to_dict(),
            },
        )

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Validate SaaS user/workspace context.
        """
        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing required user_id.",
                error="missing_user_id",
                data={"valid": False},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing required workspace_id.",
                error="missing_workspace_id",
                data={"valid": False},
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "valid": True,
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        source: str = "system",
        priority: Union[str, AudioPriority] = AudioPriority.NORMAL,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Audio routing is usually safe, but remote dashboard/API control may be
        protected depending on config.
        """
        metadata = metadata or {}
        parsed_priority = self._parse_priority(priority)
        source_normalized = str(source).lower().strip()

        if metadata.get("requires_security") is True:
            return True

        if parsed_priority == AudioPriority.CRITICAL:
            return True

        if source_normalized == "dashboard" and self.config.require_security_for_dashboard_route:
            return True

        if source_normalized == "api" and self.config.require_security_for_api_route:
            return True

        return False

    async def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Dict[str, Any],
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Request approval from Security Agent.

        If unavailable, safe fallback approval is granted for non-destructive
        routing state updates.
        """
        try:
            security_agent = self.security_agent

            if security_agent is None and SecurityAgent is not None:
                try:
                    security_agent = SecurityAgent()
                except Exception:
                    security_agent = None

            if security_agent is None:
                return self._safe_result(
                    message="Security Agent unavailable. Safe fallback approval granted.",
                    data={
                        "approved": True,
                        "fallback": True,
                        "action": action,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            approval_method = None
            for method_name in (
                "approve_action",
                "request_approval",
                "check_permission",
                "validate_action",
            ):
                if hasattr(security_agent, method_name):
                    approval_method = getattr(security_agent, method_name)
                    break

            if approval_method is None:
                return self._safe_result(
                    message="Security Agent has no compatible approval method. Safe fallback approval granted.",
                    data={
                        "approved": True,
                        "fallback": True,
                        "action": action,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            result = await _maybe_await(approval_method(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                payload=payload,
            ))

            if isinstance(result, dict):
                approved = bool(
                    result.get("approved")
                    or result.get("allowed")
                    or result.get("success")
                    or result.get("data", {}).get("approved")
                )

                if approved:
                    return self._safe_result(
                        message="Security approval granted.",
                        data={
                            "approved": True,
                            "security_result": result,
                        },
                        metadata={
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                        },
                    )

                return self._error_result(
                    message="Security approval denied.",
                    error=result.get("error") or "security_denied",
                    data={
                        "approved": False,
                        "security_result": result,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            if bool(result):
                return self._safe_result(
                    message="Security approval granted.",
                    data={
                        "approved": True,
                        "security_result": result,
                    },
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            return self._error_result(
                message="Security approval denied.",
                error="security_denied",
                data={"approved": False},
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            logger.exception("Security approval failed.")
            return self._error_result(
                message="Security approval failed.",
                error=_safe_str(exc),
                data={"approved": False},
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "action": action,
                },
            )

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        route: AudioRoute,
        apply_result: Optional[StructuredResult] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.
        """
        if not self.config.verification_payload_enabled:
            return {
                "enabled": False,
                "reason": "verification_payload_disabled",
            }

        return {
            "verification_type": "audio_route",
            "agent": self.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "route_id": route.route_id,
            "expected_outcome": {
                "route_status": route.status.value,
                "input_device_id": route.input_device_id,
                "output_device_id": route.output_device_id,
            },
            "observed": {
                "apply_success": bool(apply_result and apply_result.get("success")),
                "fallback_used": route.fallback_used,
                "active_status": route.status.value,
            },
            "evidence": {
                "route": route.to_dict(),
                "input_device": self._get_device_dict(route.input_device_id),
                "output_device": self._get_device_dict(route.output_device_id),
            },
            "metadata": {
                "timestamp_ms": _now_ms(),
                "created_by": self.agent_id,
            },
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        route: AudioRoute,
        apply_result: Optional[StructuredResult] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Memory Agent may store user preferences such as:
            - prefers earbuds
            - uses car Bluetooth mode
            - routes calls through watch/glasses
        """
        if not self.config.memory_payload_enabled:
            return {
                "enabled": False,
                "reason": "memory_payload_disabled",
            }

        input_device = self._get_device_dict(route.input_device_id)
        output_device = self._get_device_dict(route.output_device_id)

        should_store = route.reason in {
            "route_to_earbuds",
            "route_to_car_bluetooth",
            "route_to_watch",
            "route_to_glasses",
            "manual",
        }

        return {
            "memory_type": "audio_route_preference",
            "agent": self.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "should_store": should_store,
            "summary": self._build_memory_summary(route, input_device, output_device),
            "data": {
                "route_id": route.route_id,
                "direction": route.direction.value,
                "preferred_device_type": (
                    route.preferred_device_type.value if route.preferred_device_type else None
                ),
                "input_device": input_device,
                "output_device": output_device,
                "fallback_used": route.fallback_used,
                "reason": route.reason,
            },
            "metadata": {
                "timestamp_ms": _now_ms(),
                "created_by": self.agent_id,
            },
        }

    async def _emit_agent_event(
        self,
        payload: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """
        Emit dashboard/API event.
        """
        if not self.config.emit_events:
            return

        try:
            if self.event_callback:
                await _maybe_await(self.event_callback(payload))
            else:
                logger.debug("AudioRouter event: %s", payload)
        except Exception:
            logger.exception("Failed to emit AudioRouter event.")

    def _emit_agent_event_sync(self, payload: Dict[str, Any]) -> None:
        """
        Sync-safe event emission.
        """
        if not self.config.emit_events:
            return

        try:
            if self.event_callback:
                result = self.event_callback(payload)
                if inspect.isawaitable(result):
                    try:
                        loop = asyncio.get_running_loop()
                        if loop.is_running():
                            loop.create_task(result)  # type: ignore[arg-type]
                        else:
                            asyncio.run(result)  # type: ignore[arg-type]
                    except RuntimeError:
                        asyncio.run(result)  # type: ignore[arg-type]
            else:
                logger.debug("AudioRouter event: %s", payload)
        except Exception:
            logger.exception("Failed to emit sync AudioRouter event.")

    async def _log_audit_event(
        self,
        payload: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """
        Log audit event.
        """
        if not self.config.audit_enabled:
            return

        try:
            payload = {
                **payload,
                "audit_agent": self.agent_id,
                "audit_timestamp_ms": _now_ms(),
            }

            if self.audit_logger:
                await _maybe_await(self.audit_logger(payload))
            else:
                logger.info("AudioRouter audit event: %s", payload)
        except Exception:
            logger.exception("Failed to log AudioRouter audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Standard William structured success/result format.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.agent_id,
                "timestamp_ms": _now_ms(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> StructuredResult:
        """
        Standard William structured error format.
        """
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=_safe_str(error),
            metadata=metadata or {},
        )

    # =========================================================================
    # Internal route selection/application
    # =========================================================================

    def _select_route_devices(
        self,
        user_id: str,
        workspace_id: str,
        direction: AudioDirection,
        preferred_device_type: Optional[AudioDeviceType] = None,
        input_device_id: Optional[str] = None,
        output_device_id: Optional[str] = None,
        mode: str = "default",
    ) -> StructuredResult:
        """
        Select best input/output devices based on preference, mode, and fallback.
        """
        with self._guard():
            devices = [
                device for device in self._devices.values()
                if str(device.user_id) == str(user_id)
                and str(device.workspace_id) == str(workspace_id)
                and device.is_available
            ]

        if not devices:
            return self._error_result(
                message="No available audio devices found.",
                error="no_available_devices",
                data={},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        selected_input: Optional[AudioDevice] = None
        selected_output: Optional[AudioDevice] = None
        fallback_used = False

        if direction in {AudioDirection.INPUT, AudioDirection.DUPLEX}:
            selected_input = self._select_specific_or_best_device(
                devices=devices,
                explicit_device_id=input_device_id,
                preferred_device_type=preferred_device_type,
                direction=AudioDirection.INPUT,
                mode=mode,
            )

            if selected_input is None and self.config.allow_fallback:
                selected_input = self._select_fallback_device(
                    devices=devices,
                    direction=AudioDirection.INPUT,
                    mode=mode,
                )
                fallback_used = selected_input is not None

        if direction in {AudioDirection.OUTPUT, AudioDirection.DUPLEX}:
            selected_output = self._select_specific_or_best_device(
                devices=devices,
                explicit_device_id=output_device_id,
                preferred_device_type=preferred_device_type,
                direction=AudioDirection.OUTPUT,
                mode=mode,
            )

            if selected_output is None and self.config.allow_fallback:
                selected_output = self._select_fallback_device(
                    devices=devices,
                    direction=AudioDirection.OUTPUT,
                    mode=mode,
                )
                fallback_used = selected_output is not None

        if direction == AudioDirection.INPUT and selected_input is None:
            return self._error_result(
                message="No suitable input device found.",
                error="no_input_device",
                data={},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        if direction == AudioDirection.OUTPUT and selected_output is None:
            return self._error_result(
                message="No suitable output device found.",
                error="no_output_device",
                data={},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        if direction == AudioDirection.DUPLEX and (selected_input is None or selected_output is None):
            return self._error_result(
                message="No suitable duplex audio route found.",
                error="no_duplex_route",
                data={
                    "input_found": selected_input is not None,
                    "output_found": selected_output is not None,
                },
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        return self._safe_result(
            message="Audio route devices selected.",
            data={
                "input_device_id": selected_input.device_id if selected_input else None,
                "output_device_id": selected_output.device_id if selected_output else None,
                "input_device": selected_input.to_dict() if selected_input else None,
                "output_device": selected_output.to_dict() if selected_output else None,
                "fallback_used": fallback_used,
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id},
        )

    def _select_specific_or_best_device(
        self,
        devices: List[AudioDevice],
        explicit_device_id: Optional[str],
        preferred_device_type: Optional[AudioDeviceType],
        direction: AudioDirection,
        mode: str,
    ) -> Optional[AudioDevice]:
        """
        Select explicit device first, then preferred type, then preference order.
        """
        capable_devices = [
            device for device in devices
            if self._device_supports_direction(device, direction)
        ]

        if explicit_device_id:
            for device in capable_devices:
                if device.device_id == explicit_device_id:
                    return device

        if preferred_device_type:
            preferred_matches = [
                device for device in capable_devices
                if device.device_type == preferred_device_type
            ]
            if preferred_matches:
                preferred_matches.sort(key=lambda d: (not d.is_default, d.name.lower()))
                return preferred_matches[0]

        preference_order = self._get_preference_order(direction=direction, mode=mode)

        for preferred_type in preference_order:
            matches = [
                device for device in capable_devices
                if device.device_type == preferred_type
            ]
            if matches:
                matches.sort(key=lambda d: (not d.is_default, d.name.lower()))
                return matches[0]

        capable_devices.sort(key=lambda d: (not d.is_default, d.device_type.value, d.name.lower()))
        return capable_devices[0] if capable_devices else None

    def _select_fallback_device(
        self,
        devices: List[AudioDevice],
        direction: AudioDirection,
        mode: str,
    ) -> Optional[AudioDevice]:
        """
        Select fallback device by mode-specific preference.
        """
        capable_devices = [
            device for device in devices
            if self._device_supports_direction(device, direction)
        ]

        if not capable_devices:
            return None

        preference_order = self._get_preference_order(direction=direction, mode=mode)

        for preferred_type in preference_order:
            matches = [
                device for device in capable_devices
                if device.device_type == preferred_type
            ]
            if matches:
                matches.sort(key=lambda d: (not d.is_default, d.name.lower()))
                return matches[0]

        capable_devices.sort(key=lambda d: (not d.is_default, d.name.lower()))
        return capable_devices[0]

    async def _apply_route(self, route: AudioRoute) -> StructuredResult:
        """
        Apply selected route.

        If route_apply_callback is not configured, this method safely records
        route state only. Production OS-level routing can be added by callback.
        """
        payload = {
            "route": route.to_dict(),
            "input_device": self._get_device_dict(route.input_device_id),
            "output_device": self._get_device_dict(route.output_device_id),
            "timeout_seconds": self.config.route_apply_timeout_seconds,
        }

        try:
            if self.route_apply_callback:
                raw_result = await asyncio.wait_for(
                    _maybe_await(self.route_apply_callback(payload)),
                    timeout=self.config.route_apply_timeout_seconds,
                )

                if isinstance(raw_result, dict):
                    success = bool(
                        raw_result.get("success")
                        or raw_result.get("applied")
                        or raw_result.get("routed")
                    )
                    if success:
                        return self._safe_result(
                            message="Audio route applied by platform adapter.",
                            data={
                                "applied": True,
                                "adapter_result": raw_result,
                            },
                        )

                    return self._error_result(
                        message="Platform adapter failed to apply audio route.",
                        error=raw_result.get("error") or "adapter_route_failed",
                        data={
                            "applied": False,
                            "adapter_result": raw_result,
                        },
                    )

                if bool(raw_result):
                    return self._safe_result(
                        message="Audio route applied by platform adapter.",
                        data={
                            "applied": True,
                            "adapter_result": raw_result,
                        },
                    )

                return self._error_result(
                    message="Platform adapter returned false.",
                    error="adapter_returned_false",
                    data={"applied": False},
                )

            return self._safe_result(
                message="Audio route stored in router state. No platform adapter configured.",
                data={
                    "applied": True,
                    "state_only": True,
                    "route": route.to_dict(),
                },
            )

        except asyncio.TimeoutError:
            return self._error_result(
                message="Audio route application timed out.",
                error="route_apply_timeout",
                data={"applied": False},
            )

        except Exception as exc:
            logger.exception("Failed to apply audio route.")
            return self._error_result(
                message="Failed to apply audio route.",
                error=_safe_str(exc),
                data={"applied": False},
            )

    # =========================================================================
    # Internal utilities
    # =========================================================================

    def _ensure_builtin_fallback_devices(self, user_id: str, workspace_id: str) -> None:
        """
        Create safe built-in fallback devices if user/workspace has no devices.

        This makes the router testable even without real OS discovery.
        """
        existing = self.list_devices(
            user_id=user_id,
            workspace_id=workspace_id,
            available_only=False,
        ).get("data", {}).get("devices", [])

        if existing:
            return

        system_name = platform.system().lower()
        fallback_type = AudioDeviceType.LAPTOP

        if "android" in system_name or "ios" in system_name:
            fallback_type = AudioDeviceType.PHONE
        elif "windows" in system_name or "darwin" in system_name or "linux" in system_name:
            fallback_type = AudioDeviceType.LAPTOP

        self.register_device(
            user_id=user_id,
            workspace_id=workspace_id,
            name="Built-in Microphone",
            device_type=AudioDeviceType.MICROPHONE,
            direction=AudioDirection.INPUT,
            connection_type=AudioConnectionType.BUILT_IN,
            input_supported=True,
            output_supported=False,
            is_default=True,
            is_available=True,
            metadata={"fallback": True, "created_by": self.agent_id},
        )

        self.register_device(
            user_id=user_id,
            workspace_id=workspace_id,
            name="Built-in Speaker",
            device_type=AudioDeviceType.SPEAKER,
            direction=AudioDirection.OUTPUT,
            connection_type=AudioConnectionType.BUILT_IN,
            input_supported=False,
            output_supported=True,
            is_default=True,
            is_available=True,
            metadata={"fallback": True, "created_by": self.agent_id},
        )

        self.register_device(
            user_id=user_id,
            workspace_id=workspace_id,
            name=f"Default {fallback_type.value.title()} Audio",
            device_type=fallback_type,
            direction=AudioDirection.DUPLEX,
            connection_type=AudioConnectionType.BUILT_IN,
            input_supported=True,
            output_supported=True,
            is_default=True,
            is_available=True,
            metadata={"fallback": True, "created_by": self.agent_id},
        )

    def _device_supports_direction(
        self,
        device: AudioDevice,
        direction: AudioDirection,
    ) -> bool:
        if not device.is_available:
            return False

        if direction == AudioDirection.INPUT:
            return bool(device.input_supported)

        if direction == AudioDirection.OUTPUT:
            return bool(device.output_supported)

        if direction == AudioDirection.DUPLEX:
            return bool(device.input_supported and device.output_supported)

        return False

    def _get_preference_order(
        self,
        direction: AudioDirection,
        mode: str = "default",
    ) -> Tuple[AudioDeviceType, ...]:
        mode_normalized = str(mode).lower().strip()

        if direction == AudioDirection.OUTPUT:
            if mode_normalized in {"car", "driving", "car_mode"}:
                return self.config.car_mode_output_preference
            if mode_normalized in {"discreet", "private", "quiet"}:
                return self.config.discreet_mode_output_preference
            return self.config.default_output_preference

        if direction == AudioDirection.INPUT:
            return self.config.default_input_preference

        if mode_normalized in {"car", "driving", "car_mode"}:
            return self.config.car_mode_output_preference

        if mode_normalized in {"discreet", "private", "quiet"}:
            return self.config.discreet_mode_output_preference

        return self.config.default_output_preference

    def _record_route(self, route: AudioRoute) -> None:
        """
        Store route in history with max-size cap.
        """
        with self._guard():
            self._route_history.append(route)
            max_history = max(1, int(self.config.max_route_history))
            if len(self._route_history) > max_history:
                self._route_history = self._route_history[-max_history:]

    def _get_device_dict(self, device_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not device_id:
            return None

        with self._guard():
            device = self._devices.get(device_id)

        return device.to_dict() if device else None

    def _build_device_id(
        self,
        user_id: str,
        workspace_id: str,
        name: str,
        device_type: AudioDeviceType,
    ) -> str:
        raw = f"{user_id}:{workspace_id}:{device_type.value}:{name}".lower()
        safe = "".join(ch if ch.isalnum() else "_" for ch in raw)
        return f"audio_{safe[:100]}_{uuid.uuid5(uuid.NAMESPACE_DNS, raw).hex[:10]}"

    def _parse_device_type(
        self,
        value: Union[str, AudioDeviceType, None],
    ) -> AudioDeviceType:
        if isinstance(value, AudioDeviceType):
            return value

        if value is None:
            return AudioDeviceType.UNKNOWN

        normalized = str(value).lower().strip().replace("-", "_").replace(" ", "_")

        aliases = {
            "airpods": AudioDeviceType.EARBUDS,
            "earpod": AudioDeviceType.EARBUDS,
            "earpods": AudioDeviceType.EARBUDS,
            "buds": AudioDeviceType.EARBUDS,
            "bluetooth_car": AudioDeviceType.CAR_BLUETOOTH,
            "car": AudioDeviceType.CAR_BLUETOOTH,
            "car_audio": AudioDeviceType.CAR_BLUETOOTH,
            "car_bt": AudioDeviceType.CAR_BLUETOOTH,
            "pc": AudioDeviceType.DESKTOP,
            "computer": AudioDeviceType.DESKTOP,
            "notebook": AudioDeviceType.LAPTOP,
            "smartwatch": AudioDeviceType.WATCH,
            "smart_glasses": AudioDeviceType.GLASSES,
            "ar_glasses": AudioDeviceType.GLASSES,
        }

        if normalized in aliases:
            return aliases[normalized]

        try:
            return AudioDeviceType(normalized)
        except Exception:
            return AudioDeviceType.UNKNOWN

    def _parse_direction(
        self,
        value: Union[str, AudioDirection, None],
    ) -> AudioDirection:
        if isinstance(value, AudioDirection):
            return value

        if value is None:
            return AudioDirection.DUPLEX

        normalized = str(value).lower().strip().replace("-", "_").replace(" ", "_")

        aliases = {
            "in": AudioDirection.INPUT,
            "mic": AudioDirection.INPUT,
            "microphone": AudioDirection.INPUT,
            "out": AudioDirection.OUTPUT,
            "speaker": AudioDirection.OUTPUT,
            "speakers": AudioDirection.OUTPUT,
            "both": AudioDirection.DUPLEX,
            "input_output": AudioDirection.DUPLEX,
            "two_way": AudioDirection.DUPLEX,
        }

        if normalized in aliases:
            return aliases[normalized]

        try:
            return AudioDirection(normalized)
        except Exception:
            return AudioDirection.DUPLEX

    def _parse_connection_type(
        self,
        value: Union[str, AudioConnectionType, None],
    ) -> AudioConnectionType:
        if isinstance(value, AudioConnectionType):
            return value

        if value is None:
            return AudioConnectionType.UNKNOWN

        normalized = str(value).lower().strip().replace("-", "_").replace(" ", "_")

        aliases = {
            "bt": AudioConnectionType.BLUETOOTH,
            "ble": AudioConnectionType.BLUETOOTH,
            "builtin": AudioConnectionType.BUILT_IN,
            "internal": AudioConnectionType.BUILT_IN,
            "wifi_direct": AudioConnectionType.WIFI,
            "network": AudioConnectionType.WIFI,
        }

        if normalized in aliases:
            return aliases[normalized]

        try:
            return AudioConnectionType(normalized)
        except Exception:
            return AudioConnectionType.UNKNOWN

    def _parse_priority(
        self,
        value: Union[str, AudioPriority, None],
    ) -> AudioPriority:
        if isinstance(value, AudioPriority):
            return value

        if value is None:
            return AudioPriority.NORMAL

        normalized = str(value).lower().strip()

        try:
            return AudioPriority(normalized)
        except Exception:
            return AudioPriority.NORMAL

    def _build_memory_summary(
        self,
        route: AudioRoute,
        input_device: Optional[Dict[str, Any]],
        output_device: Optional[Dict[str, Any]],
    ) -> str:
        input_name = input_device.get("name") if input_device else "none"
        output_name = output_device.get("name") if output_device else "none"

        if route.preferred_device_type:
            return (
                f"User routed William audio to preferred device type "
                f"{route.preferred_device_type.value}. Input: {input_name}. "
                f"Output: {output_name}."
            )

        return (
            f"User changed William audio route. Input: {input_name}. "
            f"Output: {output_name}."
        )

    def _guard(self) -> Any:
        """
        Return lock context manager or no-op context manager.
        """
        if self.config.thread_safe:
            return self._lock

        class _NoopLock:
            def __enter__(self) -> None:
                return None

            def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
                return False

        return _NoopLock()

    def _config_to_dict(self) -> Dict[str, Any]:
        """
        Convert config to JSON-safe dict.
        """
        data = asdict(self.config)

        for key, value in list(data.items()):
            if isinstance(value, tuple):
                data[key] = [
                    item.value if isinstance(item, Enum) else item
                    for item in value
                ]

        return data


# =============================================================================
# Convenience factory
# =============================================================================

def create_audio_router(
    config: Optional[AudioRouterConfig] = None,
    discovery_callback: Optional[DeviceDiscoveryCallback] = None,
    route_apply_callback: Optional[RouteApplyCallback] = None,
    event_callback: Optional[EventCallback] = None,
    audit_logger: Optional[AuditCallback] = None,
    **kwargs: Any,
) -> AudioRouter:
    """
    Factory helper for Agent Loader / Registry.
    """
    return AudioRouter(
        config=config,
        discovery_callback=discovery_callback,
        route_apply_callback=route_apply_callback,
        event_callback=event_callback,
        audit_logger=audit_logger,
        **kwargs,
    )


# =============================================================================
# Module metadata for Agent Registry / Agent Loader
# =============================================================================

AGENT_MODULE = "voice_agent"
AGENT_FILE = "audio_router.py"
AGENT_CLASS = "AudioRouter"
AGENT_VERSION = "1.0.0"
AGENT_DESCRIPTION = "Routes audio input/output across phone, laptop, earbuds, watch, glasses, and car Bluetooth."
AGENT_CAPABILITIES = [
    "register_audio_device",
    "discover_audio_devices",
    "route_audio_input",
    "route_audio_output",
    "route_audio_duplex",
    "route_to_phone",
    "route_to_laptop",
    "route_to_earbuds",
    "route_to_watch",
    "route_to_glasses",
    "route_to_car_bluetooth",
    "fallback_audio_routing",
    "audio_route_audit_logging",
    "audio_route_verification_payload",
    "audio_route_memory_payload",
]
AGENT_REQUIRES_USER_CONTEXT = True
AGENT_REQUIRES_WORKSPACE_CONTEXT = True


__all__ = [
    "AudioRouter",
    "AudioRouterConfig",
    "AudioDevice",
    "AudioRoute",
    "AudioDeviceType",
    "AudioDirection",
    "AudioRouteStatus",
    "AudioConnectionType",
    "AudioPriority",
    "create_audio_router",
    "AGENT_MODULE",
    "AGENT_FILE",
    "AGENT_CLASS",
    "AGENT_VERSION",
    "AGENT_DESCRIPTION",
    "AGENT_CAPABILITIES",
    "AGENT_REQUIRES_USER_CONTEXT",
    "AGENT_REQUIRES_WORKSPACE_CONTEXT",
]


# =============================================================================
# Lightweight self-test
# =============================================================================

if __name__ == "__main__":
    async def _demo() -> None:
        router = AudioRouter()

        print(router.register_device(
            user_id="demo-user",
            workspace_id="demo-workspace",
            name="Demo AirPods",
            device_type="earbuds",
            direction="duplex",
            connection_type="bluetooth",
            input_supported=True,
            output_supported=True,
            is_default=True,
        ))

        print(router.register_device(
            user_id="demo-user",
            workspace_id="demo-workspace",
            name="Demo Car Bluetooth",
            device_type="car_bluetooth",
            direction="output",
            connection_type="bluetooth",
            input_supported=False,
            output_supported=True,
        ))

        print(await router.route_to_earbuds(
            user_id="demo-user",
            workspace_id="demo-workspace",
        ))

        print(await router.route_to_car_bluetooth(
            user_id="demo-user",
            workspace_id="demo-workspace",
        ))

        print(router.get_status(
            user_id="demo-user",
            workspace_id="demo-workspace",
        ))

    asyncio.run(_demo())