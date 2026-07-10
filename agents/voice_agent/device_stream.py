"""
agents/voice_agent/device_stream.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Voice Agent - Device Stream

Purpose:
    Handles mic/speaker streams from mobile, desktop, smartwatch, glasses,
    Bluetooth, and remote devices.

Architecture Compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - Master Agent routing compatible
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/API analytics compatible
    - SaaS user/workspace isolation compatible

Important:
    This file is import-safe. It does not directly open a real microphone,
    speaker, Bluetooth device, socket, browser, OS device, or remote stream
    without an explicit protected method path. It provides production-ready
    orchestration, validation, routing metadata, session state, and future
    integration hooks for real audio backends.

    Real stream backends can later be attached through adapters such as:
        - PyAudio / sounddevice
        - WebRTC
        - Bluetooth bridge
        - Android/iOS app websocket bridge
        - Desktop native client
        - Smartwatch companion app
        - AR glasses audio bridge
        - Remote device tunnel

    All public results follow William/Jarvis structured dict format:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": str | None,
            "metadata": dict
        }
"""

from __future__ import annotations

import enum
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Safe Optional BaseAgent Import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe until the real William/Jarvis BaseAgent
        exists. The real BaseAgent can later provide routing, registry,
        permissions, analytics, audit, memory, and verification integrations.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")
            self.version = kwargs.get("version", "1.0.0")


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.voice_agent.device_stream")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums
# =============================================================================

class DeviceType(str, enum.Enum):
    """Supported device families for William/Jarvis voice streaming."""

    MOBILE = "mobile"
    DESKTOP = "desktop"
    SMARTWATCH = "smartwatch"
    GLASSES = "glasses"
    BLUETOOTH = "bluetooth"
    REMOTE = "remote"
    WEB = "web"
    EMBEDDED = "embedded"
    UNKNOWN = "unknown"


class StreamDirection(str, enum.Enum):
    """Audio stream direction."""

    INPUT = "input"          # microphone/source into William
    OUTPUT = "output"        # William response to speaker/device
    DUPLEX = "duplex"        # both input and output


class StreamStatus(str, enum.Enum):
    """Runtime status for device stream session."""

    CREATED = "created"
    REGISTERED = "registered"
    READY = "ready"
    STARTING = "starting"
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    DISCONNECTED = "disconnected"


class AudioCodec(str, enum.Enum):
    """Supported/future audio codec identifiers."""

    PCM16 = "pcm16"
    PCM24 = "pcm24"
    FLOAT32 = "float32"
    OPUS = "opus"
    AAC = "aac"
    MP3 = "mp3"
    WAV = "wav"
    UNKNOWN = "unknown"


class TransportType(str, enum.Enum):
    """Possible stream transport types."""

    LOCAL = "local"
    WEBSOCKET = "websocket"
    WEBRTC = "webrtc"
    BLUETOOTH = "bluetooth"
    HTTP_CHUNKED = "http_chunked"
    NATIVE_BRIDGE = "native_bridge"
    FILE_BUFFER = "file_buffer"
    MOCK = "mock"
    UNKNOWN = "unknown"


# =============================================================================
# Constants
# =============================================================================

SUPPORTED_DEVICE_TYPES = {item.value for item in DeviceType}
SUPPORTED_DIRECTIONS = {item.value for item in StreamDirection}
SUPPORTED_CODECS = {item.value for item in AudioCodec}
SUPPORTED_TRANSPORTS = {item.value for item in TransportType}

DEFAULT_SAMPLE_RATE = 16000
DEFAULT_CHANNELS = 1
DEFAULT_FRAME_MS = 20
DEFAULT_MAX_QUEUE_FRAMES = 500
DEFAULT_SESSION_TIMEOUT_SECONDS = 300
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 30

SAFE_MAX_SAMPLE_RATE = 48000
SAFE_MIN_SAMPLE_RATE = 8000
SAFE_MAX_CHANNELS = 2
SAFE_MIN_CHANNELS = 1

SENSITIVE_STREAM_ACTIONS = {
    "start_stream",
    "start_input_stream",
    "start_output_stream",
    "start_duplex_stream",
    "connect_remote_device",
    "connect_bluetooth_device",
    "enable_microphone",
    "enable_speaker",
    "record_audio",
    "broadcast_audio",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class DeviceStreamConfig:
    """
    Runtime configuration for DeviceStream.

    This config is intentionally backend-agnostic. Real backend adapters
    can use these values later for PyAudio, WebRTC, mobile bridge, Bluetooth,
    or remote device streaming.
    """

    default_sample_rate: int = DEFAULT_SAMPLE_RATE
    default_channels: int = DEFAULT_CHANNELS
    default_frame_ms: int = DEFAULT_FRAME_MS
    default_codec: str = AudioCodec.PCM16.value
    default_transport: str = TransportType.MOCK.value
    max_queue_frames: int = DEFAULT_MAX_QUEUE_FRAMES
    session_timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS
    heartbeat_timeout_seconds: int = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS
    require_security_for_stream_start: bool = True
    allow_mock_streams: bool = True
    allow_remote_streams: bool = False
    allow_bluetooth_streams: bool = False
    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceProfile:
    """
    Registered audio device profile.

    A profile represents one user/workspace-scoped device that may provide
    microphone input, speaker output, or duplex voice capability.
    """

    device_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    device_name: str
    device_type: str = DeviceType.UNKNOWN.value
    direction: str = StreamDirection.DUPLEX.value
    transport: str = TransportType.MOCK.value
    codec: str = AudioCodec.PCM16.value
    sample_rate: int = DEFAULT_SAMPLE_RATE
    channels: int = DEFAULT_CHANNELS
    frame_ms: int = DEFAULT_FRAME_MS
    metadata: Dict[str, Any] = field(default_factory=dict)
    permissions: Dict[str, bool] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_seen_at: Optional[float] = None
    status: str = StreamStatus.REGISTERED.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "direction": self.direction,
            "transport": self.transport,
            "codec": self.codec,
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "frame_ms": self.frame_ms,
            "metadata": dict(self.metadata),
            "permissions": dict(self.permissions),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_seen_at": self.last_seen_at,
            "status": self.status,
        }


@dataclass
class AudioFrame:
    """
    Audio frame container.

    This stores metadata around incoming/outgoing audio chunks. The payload
    can be bytes, bytearray, memoryview, list of samples, or backend-specific
    frame objects. This file does not decode/record by itself.
    """

    frame_id: str
    stream_id: str
    device_id: str
    direction: str
    payload: Any
    timestamp: float = field(default_factory=time.time)
    sample_rate: int = DEFAULT_SAMPLE_RATE
    channels: int = DEFAULT_CHANNELS
    codec: str = AudioCodec.PCM16.value
    sequence: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_metadata_dict(self, include_payload: bool = False) -> Dict[str, Any]:
        data = {
            "frame_id": self.frame_id,
            "stream_id": self.stream_id,
            "device_id": self.device_id,
            "direction": self.direction,
            "timestamp": self.timestamp,
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "codec": self.codec,
            "sequence": self.sequence,
            "metadata": dict(self.metadata),
        }

        if include_payload:
            data["payload"] = self.payload
        else:
            data["payload_present"] = self.payload is not None
            data["payload_type"] = type(self.payload).__name__

        return data


@dataclass
class StreamSession:
    """
    Runtime stream session state.

    A session is scoped to a registered device and a SaaS user/workspace.
    """

    stream_id: str
    device_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    direction: str
    status: str = StreamStatus.CREATED.value
    transport: str = TransportType.MOCK.value
    codec: str = AudioCodec.PCM16.value
    sample_rate: int = DEFAULT_SAMPLE_RATE
    channels: int = DEFAULT_CHANNELS
    frame_ms: int = DEFAULT_FRAME_MS
    input_frame_count: int = 0
    output_frame_count: int = 0
    dropped_frame_count: int = 0
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    last_frame_at: Optional[float] = None
    last_heartbeat_at: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "direction": self.direction,
            "status": self.status,
            "transport": self.transport,
            "codec": self.codec,
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "frame_ms": self.frame_ms,
            "input_frame_count": self.input_frame_count,
            "output_frame_count": self.output_frame_count,
            "dropped_frame_count": self.dropped_frame_count,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "last_frame_at": self.last_frame_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "error": self.error,
            "metadata": dict(self.metadata),
        }


@dataclass
class StreamBackendAdapter:
    """
    Optional backend adapter interface container.

    Real stream implementations can be plugged in without changing the public
    DeviceStream API.

    Expected callable signatures:
        start(session, device_profile) -> dict
        stop(session, device_profile) -> dict
        pause(session, device_profile) -> dict
        resume(session, device_profile) -> dict
        send_output(frame, session, device_profile) -> dict
    """

    name: str
    transport: str
    start: Optional[Callable[..., Dict[str, Any]]] = None
    stop: Optional[Callable[..., Dict[str, Any]]] = None
    pause: Optional[Callable[..., Dict[str, Any]]] = None
    resume: Optional[Callable[..., Dict[str, Any]]] = None
    send_output: Optional[Callable[..., Dict[str, Any]]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "has_start": callable(self.start),
            "has_stop": callable(self.stop),
            "has_pause": callable(self.pause),
            "has_resume": callable(self.resume),
            "has_send_output": callable(self.send_output),
            "metadata": dict(self.metadata),
        }


# =============================================================================
# Device Stream
# =============================================================================

class DeviceStream(BaseAgent):
    """
    Handles mic/speaker stream orchestration for William/Jarvis Voice Agent.

    This class is responsible for:
        - Registering user/workspace-scoped voice devices
        - Creating stream sessions
        - Starting/pausing/resuming/stopping stream sessions safely
        - Accepting incoming audio frames from mobile/desktop/wearables/remotes
        - Queueing frames for STT/Voice Loop/Audio Router
        - Sending output frames to speaker-capable devices
        - Tracking stream health, heartbeat, and dashboard metadata
        - Preparing Verification and Memory Agent compatible payloads
        - Preserving SaaS isolation across users/workspaces

    This class intentionally does not directly open physical devices by default.
    Real device IO must be connected through backend adapters and protected
    by Security Agent approval where required.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[Union[DeviceStreamConfig, Dict[str, Any]]] = None,
        event_bus: Optional[Any] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_client: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name="DeviceStream",
            agent_type="voice_agent",
            version=self.VERSION,
            **kwargs,
        )

        if isinstance(config, DeviceStreamConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = DeviceStreamConfig(**{
                key: value for key, value in config.items()
                if key in DeviceStreamConfig.__dataclass_fields__
            })
        else:
            self.config = DeviceStreamConfig()

        self.event_bus = event_bus
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_client = audit_client
        self.logger = logger_instance or logger

        self.agent_name = "DeviceStream"
        self.agent_module = "Voice Agent"
        self.file_path = "agents/voice_agent/device_stream.py"

        self._devices: Dict[str, DeviceProfile] = {}
        self._sessions: Dict[str, StreamSession] = {}
        self._input_queues: Dict[str, "queue.Queue[AudioFrame]"] = {}
        self._output_queues: Dict[str, "queue.Queue[AudioFrame]"] = {}
        self._backend_adapters: Dict[str, StreamBackendAdapter] = {}
        self._lock = threading.RLock()

        self._register_default_mock_backend()

    # =========================================================================
    # Public API - Device Management
    # =========================================================================

    def register_device(
        self,
        device_name: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_id: Optional[str] = None,
        device_type: str = DeviceType.UNKNOWN.value,
        direction: str = StreamDirection.DUPLEX.value,
        transport: Optional[str] = None,
        codec: Optional[str] = None,
        sample_rate: Optional[int] = None,
        channels: Optional[int] = None,
        frame_ms: Optional[int] = None,
        permissions: Optional[Dict[str, bool]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register a voice-capable device under a SaaS user/workspace.

        Examples:
            - Android mobile app microphone/speaker
            - Desktop companion client
            - Bluetooth headset bridge
            - Smartwatch mic
            - AR glasses speaker
            - Remote web audio client
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "module": self.agent_module,
        }

        try:
            context_result = self._validate_task_context(context)
            if not context_result["success"]:
                return context_result

            if not isinstance(device_name, str) or not device_name.strip():
                return self._error_result(
                    message="Device name is required.",
                    error="invalid_device_name",
                    metadata={"context": context},
                )

            safe_device_type = self._safe_device_type(device_type)
            safe_direction = self._safe_direction(direction)
            safe_transport = self._safe_transport(transport or self.config.default_transport)
            safe_codec = self._safe_codec(codec or self.config.default_codec)

            validation = self._validate_audio_settings(
                sample_rate=sample_rate or self.config.default_sample_rate,
                channels=channels or self.config.default_channels,
                frame_ms=frame_ms or self.config.default_frame_ms,
            )
            if not validation["success"]:
                return validation

            data = validation["data"]

            if not self._transport_allowed(safe_transport):
                return self._error_result(
                    message=f"Transport '{safe_transport}' is not allowed by current DeviceStream config.",
                    error="transport_not_allowed",
                    metadata={
                        "transport": safe_transport,
                        "context": context,
                    },
                )

            final_device_id = device_id or self._generate_device_id(safe_device_type)

            with self._lock:
                if final_device_id in self._devices:
                    existing = self._devices[final_device_id]

                    if not self._same_saas_scope(existing.user_id, existing.workspace_id, user_id, workspace_id):
                        return self._error_result(
                            message="Device ID already belongs to another user/workspace scope.",
                            error="device_scope_conflict",
                            metadata={
                                "device_id": final_device_id,
                                "context": context,
                            },
                        )

                profile = DeviceProfile(
                    device_id=final_device_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    device_name=device_name.strip(),
                    device_type=safe_device_type,
                    direction=safe_direction,
                    transport=safe_transport,
                    codec=safe_codec,
                    sample_rate=data["sample_rate"],
                    channels=data["channels"],
                    frame_ms=data["frame_ms"],
                    metadata=metadata or {},
                    permissions=permissions or self._default_permissions_for_device(
                        safe_device_type,
                        safe_direction,
                    ),
                    status=StreamStatus.REGISTERED.value,
                )

                self._devices[final_device_id] = profile

            verification_payload = self._prepare_verification_payload(
                action="register_device",
                result=profile.to_dict(),
                context=context,
            )

            memory_payload = self._prepare_memory_payload(
                action="register_device",
                device_profile=profile,
                session=None,
                context=context,
            )

            self._emit_agent_event({
                "event": "voice.device.registered",
                "device_id": final_device_id,
                "device_type": safe_device_type,
                "direction": safe_direction,
                "transport": safe_transport,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="register_device",
                context=context,
                result_summary={
                    "device_id": final_device_id,
                    "device_type": safe_device_type,
                    "direction": safe_direction,
                    "transport": safe_transport,
                },
            )

            return self._safe_result(
                message="Device registered successfully.",
                data={
                    "device": profile.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "context": context,
                    "engine": self.agent_name,
                    "version": self.VERSION,
                },
            )

        except Exception as exc:
            self.logger.exception("Device registration failed")
            return self._error_result(
                message="Device registration failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def unregister_device(
        self,
        device_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        force_stop_sessions: bool = True,
    ) -> Dict[str, Any]:
        """
        Unregister a device from the current user/workspace scope.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "device_id": device_id,
            "agent": self.agent_name,
        }

        try:
            context_result = self._validate_task_context(context)
            if not context_result["success"]:
                return context_result

            with self._lock:
                profile = self._devices.get(device_id)
                if not profile:
                    return self._error_result(
                        message="Device not found.",
                        error="device_not_found",
                        metadata={"context": context},
                    )

                if not self._same_saas_scope(profile.user_id, profile.workspace_id, user_id, workspace_id):
                    return self._error_result(
                        message="Device does not belong to this user/workspace.",
                        error="device_scope_denied",
                        metadata={"context": context},
                    )

                active_sessions = [
                    session_id
                    for session_id, session in self._sessions.items()
                    if session.device_id == device_id and session.status in {
                        StreamStatus.ACTIVE.value,
                        StreamStatus.PAUSED.value,
                        StreamStatus.STARTING.value,
                    }
                ]

            stopped_sessions: List[str] = []
            if force_stop_sessions:
                for stream_id in active_sessions:
                    stop_result = self.stop_stream(
                        stream_id=stream_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        reason="device_unregistered",
                    )
                    if stop_result.get("success"):
                        stopped_sessions.append(stream_id)
            elif active_sessions:
                return self._error_result(
                    message="Device has active sessions. Stop sessions before unregistering.",
                    error="device_has_active_sessions",
                    metadata={
                        "context": context,
                        "active_sessions": active_sessions,
                    },
                )

            with self._lock:
                removed = self._devices.pop(device_id, None)

            self._emit_agent_event({
                "event": "voice.device.unregistered",
                "device_id": device_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="unregister_device",
                context=context,
                result_summary={
                    "device_id": device_id,
                    "stopped_sessions": stopped_sessions,
                },
            )

            return self._safe_result(
                message="Device unregistered successfully.",
                data={
                    "device": removed.to_dict() if removed else {},
                    "stopped_sessions": stopped_sessions,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("Device unregister failed")
            return self._error_result(
                message="Device unregister failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def list_devices(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        device_type: Optional[str] = None,
        include_all_for_admin: bool = False,
    ) -> Dict[str, Any]:
        """
        List registered devices for a SaaS scope.

        Normal usage returns only devices matching user_id/workspace_id.
        Admin-wide listing is opt-in and should be protected outside this file.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
        }

        try:
            context_result = self._validate_task_context(context)
            if not context_result["success"]:
                return context_result

            safe_type = self._safe_device_type(device_type) if device_type else None

            with self._lock:
                devices = []
                for profile in self._devices.values():
                    if not include_all_for_admin:
                        if not self._same_saas_scope(profile.user_id, profile.workspace_id, user_id, workspace_id):
                            continue

                    if safe_type and profile.device_type != safe_type:
                        continue

                    devices.append(profile.to_dict())

            return self._safe_result(
                message="Devices listed successfully.",
                data={
                    "devices": devices,
                    "count": len(devices),
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list devices.",
                error=str(exc),
                metadata={"context": context},
            )

    def get_device(
        self,
        device_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Get one device profile by ID with SaaS isolation check."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "device_id": device_id,
        }

        with self._lock:
            profile = self._devices.get(device_id)

        if not profile:
            return self._error_result(
                message="Device not found.",
                error="device_not_found",
                metadata={"context": context},
            )

        if not self._same_saas_scope(profile.user_id, profile.workspace_id, user_id, workspace_id):
            return self._error_result(
                message="Device does not belong to this user/workspace.",
                error="device_scope_denied",
                metadata={"context": context},
            )

        return self._safe_result(
            message="Device loaded successfully.",
            data={"device": profile.to_dict()},
            metadata={"context": context},
        )

    def heartbeat_device(
        self,
        device_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update device heartbeat from mobile/desktop/wearable/remote bridge."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "device_id": device_id,
        }

        with self._lock:
            profile = self._devices.get(device_id)
            if not profile:
                return self._error_result(
                    message="Device not found.",
                    error="device_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(profile.user_id, profile.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Device does not belong to this user/workspace.",
                    error="device_scope_denied",
                    metadata={"context": context},
                )

            profile.last_seen_at = time.time()
            profile.updated_at = time.time()

            if metadata:
                profile.metadata.update({
                    "last_heartbeat_metadata": metadata,
                })

            active_sessions = []
            for session in self._sessions.values():
                if session.device_id == device_id:
                    session.last_heartbeat_at = time.time()
                    active_sessions.append(session.stream_id)

        return self._safe_result(
            message="Device heartbeat updated.",
            data={
                "device_id": device_id,
                "last_seen_at": profile.last_seen_at,
                "active_sessions": active_sessions,
            },
            metadata={"context": context},
        )

    # =========================================================================
    # Public API - Stream Session Management
    # =========================================================================

    def create_stream(
        self,
        device_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        direction: Optional[str] = None,
        stream_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a stream session for an already registered device.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "device_id": device_id,
            "agent": self.agent_name,
        }

        try:
            context_result = self._validate_task_context(context)
            if not context_result["success"]:
                return context_result

            with self._lock:
                profile = self._devices.get(device_id)

            if not profile:
                return self._error_result(
                    message="Device not found. Register device before creating a stream.",
                    error="device_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(profile.user_id, profile.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Device does not belong to this user/workspace.",
                    error="device_scope_denied",
                    metadata={"context": context},
                )

            safe_direction = self._safe_direction(direction or profile.direction)

            if not self._direction_compatible(profile.direction, safe_direction):
                return self._error_result(
                    message="Requested stream direction is not compatible with device capability.",
                    error="direction_not_supported",
                    metadata={
                        "context": context,
                        "device_direction": profile.direction,
                        "requested_direction": safe_direction,
                    },
                )

            final_stream_id = stream_id or self._generate_stream_id(device_id)

            with self._lock:
                if final_stream_id in self._sessions:
                    return self._error_result(
                        message="Stream ID already exists.",
                        error="stream_id_exists",
                        metadata={
                            "stream_id": final_stream_id,
                            "context": context,
                        },
                    )

                session = StreamSession(
                    stream_id=final_stream_id,
                    device_id=device_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    direction=safe_direction,
                    status=StreamStatus.CREATED.value,
                    transport=profile.transport,
                    codec=profile.codec,
                    sample_rate=profile.sample_rate,
                    channels=profile.channels,
                    frame_ms=profile.frame_ms,
                    metadata=metadata or {},
                    last_heartbeat_at=time.time(),
                )

                self._sessions[final_stream_id] = session
                self._input_queues[final_stream_id] = queue.Queue(maxsize=self.config.max_queue_frames)
                self._output_queues[final_stream_id] = queue.Queue(maxsize=self.config.max_queue_frames)

            verification_payload = self._prepare_verification_payload(
                action="create_stream",
                result=session.to_dict(),
                context=context,
            )

            self._emit_agent_event({
                "event": "voice.stream.created",
                "stream_id": final_stream_id,
                "device_id": device_id,
                "direction": safe_direction,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="create_stream",
                context=context,
                result_summary={
                    "stream_id": final_stream_id,
                    "device_id": device_id,
                    "direction": safe_direction,
                },
            )

            return self._safe_result(
                message="Stream created successfully.",
                data={
                    "stream": session.to_dict(),
                    "verification_payload": verification_payload,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("Create stream failed")
            return self._error_result(
                message="Create stream failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def start_stream(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        require_security: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Start a stream session.

        This is protected by Security Agent when config requires it because
        enabling mic/speaker/remote audio is sensitive.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
            "agent": self.agent_name,
        }

        try:
            with self._lock:
                session = self._sessions.get(stream_id)

            if not session:
                return self._error_result(
                    message="Stream not found.",
                    error="stream_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Stream does not belong to this user/workspace.",
                    error="stream_scope_denied",
                    metadata={"context": context},
                )

            action = self._start_action_for_direction(session.direction)
            should_require_security = (
                self.config.require_security_for_stream_start
                if require_security is None
                else bool(require_security)
            )

            if should_require_security and self._requires_security_check(action, context):
                approval = self._request_security_approval(
                    action=action,
                    context=context,
                    metadata=metadata or {},
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Stream start blocked by Security Agent.",
                        error="security_approval_denied",
                        metadata={
                            "context": context,
                            "approval": approval,
                        },
                    )

            with self._lock:
                session.status = StreamStatus.STARTING.value
                session.error = None

                profile = self._devices.get(session.device_id)
                if not profile:
                    session.status = StreamStatus.ERROR.value
                    session.error = "device_not_found"
                    return self._error_result(
                        message="Stream device not found.",
                        error="device_not_found",
                        metadata={"context": context},
                    )

            adapter_result = self._start_backend_stream(session, profile)

            with self._lock:
                if adapter_result.get("success"):
                    session.status = StreamStatus.ACTIVE.value
                    session.started_at = session.started_at or time.time()
                    session.last_heartbeat_at = time.time()
                    session.error = None
                    profile.status = StreamStatus.ACTIVE.value
                    profile.updated_at = time.time()
                else:
                    session.status = StreamStatus.ERROR.value
                    session.error = adapter_result.get("error") or "backend_start_failed"

            verification_payload = self._prepare_verification_payload(
                action="start_stream",
                result=session.to_dict(),
                context=context,
            )

            self._emit_agent_event({
                "event": "voice.stream.started",
                "stream_id": stream_id,
                "device_id": session.device_id,
                "direction": session.direction,
                "transport": session.transport,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="start_stream",
                context=context,
                result_summary={
                    "stream_id": stream_id,
                    "device_id": session.device_id,
                    "status": session.status,
                },
            )

            return self._safe_result(
                message="Stream started successfully.",
                data={
                    "stream": session.to_dict(),
                    "backend": adapter_result,
                    "verification_payload": verification_payload,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("Start stream failed")
            with self._lock:
                session = self._sessions.get(stream_id)
                if session:
                    session.status = StreamStatus.ERROR.value
                    session.error = str(exc)

            return self._error_result(
                message="Start stream failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def pause_stream(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        reason: str = "manual_pause",
    ) -> Dict[str, Any]:
        """Pause an active stream session."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(stream_id)

            if not session:
                return self._error_result(
                    message="Stream not found.",
                    error="stream_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Stream does not belong to this user/workspace.",
                    error="stream_scope_denied",
                    metadata={"context": context},
                )

            with self._lock:
                profile = self._devices.get(session.device_id)

            adapter_result = self._pause_backend_stream(session, profile)

            with self._lock:
                session.status = StreamStatus.PAUSED.value
                session.metadata["pause_reason"] = reason
                session.metadata["paused_at"] = time.time()

            self._emit_agent_event({
                "event": "voice.stream.paused",
                "stream_id": stream_id,
                "device_id": session.device_id,
                "reason": reason,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="pause_stream",
                context=context,
                result_summary={
                    "stream_id": stream_id,
                    "reason": reason,
                },
            )

            return self._safe_result(
                message="Stream paused successfully.",
                data={
                    "stream": session.to_dict(),
                    "backend": adapter_result,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Pause stream failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def resume_stream(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Resume a paused stream session."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(stream_id)

            if not session:
                return self._error_result(
                    message="Stream not found.",
                    error="stream_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Stream does not belong to this user/workspace.",
                    error="stream_scope_denied",
                    metadata={"context": context},
                )

            if session.status != StreamStatus.PAUSED.value:
                return self._error_result(
                    message="Only paused streams can be resumed.",
                    error="stream_not_paused",
                    metadata={
                        "context": context,
                        "status": session.status,
                    },
                )

            with self._lock:
                profile = self._devices.get(session.device_id)

            adapter_result = self._resume_backend_stream(session, profile)

            with self._lock:
                session.status = StreamStatus.ACTIVE.value
                session.last_heartbeat_at = time.time()
                session.metadata["resumed_at"] = time.time()

            self._emit_agent_event({
                "event": "voice.stream.resumed",
                "stream_id": stream_id,
                "device_id": session.device_id,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="resume_stream",
                context=context,
                result_summary={"stream_id": stream_id},
            )

            return self._safe_result(
                message="Stream resumed successfully.",
                data={
                    "stream": session.to_dict(),
                    "backend": adapter_result,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Resume stream failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def stop_stream(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        reason: str = "manual_stop",
    ) -> Dict[str, Any]:
        """Stop a stream session safely."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
        }

        try:
            with self._lock:
                session = self._sessions.get(stream_id)

            if not session:
                return self._error_result(
                    message="Stream not found.",
                    error="stream_not_found",
                    metadata={"context": context},
                )

            if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="Stream does not belong to this user/workspace.",
                    error="stream_scope_denied",
                    metadata={"context": context},
                )

            with self._lock:
                session.status = StreamStatus.STOPPING.value
                profile = self._devices.get(session.device_id)

            adapter_result = self._stop_backend_stream(session, profile)

            with self._lock:
                session.status = StreamStatus.STOPPED.value
                session.stopped_at = time.time()
                session.metadata["stop_reason"] = reason

                if profile:
                    profile.status = StreamStatus.READY.value
                    profile.updated_at = time.time()

            verification_payload = self._prepare_verification_payload(
                action="stop_stream",
                result=session.to_dict(),
                context=context,
            )

            self._emit_agent_event({
                "event": "voice.stream.stopped",
                "stream_id": stream_id,
                "device_id": session.device_id,
                "reason": reason,
                "timestamp": time.time(),
            })

            self._log_audit_event(
                action="stop_stream",
                context=context,
                result_summary={
                    "stream_id": stream_id,
                    "reason": reason,
                    "input_frame_count": session.input_frame_count,
                    "output_frame_count": session.output_frame_count,
                },
            )

            return self._safe_result(
                message="Stream stopped successfully.",
                data={
                    "stream": session.to_dict(),
                    "backend": adapter_result,
                    "verification_payload": verification_payload,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("Stop stream failed")
            return self._error_result(
                message="Stop stream failed.",
                error=str(exc),
                metadata={"context": context},
            )

    # =========================================================================
    # Public API - Audio Frame IO
    # =========================================================================

    def push_input_frame(
        self,
        stream_id: str,
        payload: Any,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Push incoming microphone/source audio frame into the stream queue.

        Used by:
            - mobile app bridge
            - desktop client
            - smartwatch bridge
            - Bluetooth bridge
            - remote websocket/WebRTC service
        """

        return self._push_frame(
            stream_id=stream_id,
            payload=payload,
            direction=StreamDirection.INPUT.value,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

    def push_output_frame(
        self,
        stream_id: str,
        payload: Any,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        send_to_backend: bool = True,
    ) -> Dict[str, Any]:
        """
        Push outgoing speaker/audio response frame into output queue and
        optionally send it to the backend adapter.
        """

        result = self._push_frame(
            stream_id=stream_id,
            payload=payload,
            direction=StreamDirection.OUTPUT.value,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

        if not result.get("success"):
            return result

        backend_result: Dict[str, Any] = {
            "success": True,
            "message": "Backend send skipped.",
            "data": {},
            "error": None,
            "metadata": {"send_to_backend": send_to_backend},
        }

        if send_to_backend:
            frame_data = result["data"].get("frame", {})
            backend_result = self._send_output_to_backend(
                stream_id=stream_id,
                frame_id=frame_data.get("frame_id"),
                user_id=user_id,
                workspace_id=workspace_id,
            )

        result["data"]["backend"] = backend_result
        return result

    def read_input_frame(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        timeout: Optional[float] = 0.0,
        include_payload: bool = True,
    ) -> Dict[str, Any]:
        """
        Read one input audio frame for STT Engine / Voice Loop / Audio Router.
        """

        return self._read_frame(
            stream_id=stream_id,
            direction=StreamDirection.INPUT.value,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout=timeout,
            include_payload=include_payload,
        )

    def read_output_frame(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        timeout: Optional[float] = 0.0,
        include_payload: bool = True,
    ) -> Dict[str, Any]:
        """
        Read one output audio frame for speaker bridge/backend delivery.
        """

        return self._read_frame(
            stream_id=stream_id,
            direction=StreamDirection.OUTPUT.value,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout=timeout,
            include_payload=include_payload,
        )

    def drain_frames(
        self,
        stream_id: str,
        direction: str = StreamDirection.INPUT.value,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        max_frames: int = 100,
        include_payload: bool = False,
    ) -> Dict[str, Any]:
        """
        Drain frames from a queue for batch processing or shutdown cleanup.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
            "direction": direction,
        }

        try:
            safe_direction = self._safe_direction(direction)

            validation = self._validate_stream_access(stream_id, user_id, workspace_id)
            if not validation["success"]:
                return validation

            q = self._queue_for_direction(stream_id, safe_direction)
            frames = []

            for _ in range(max(0, int(max_frames))):
                try:
                    frame = q.get_nowait()
                    frames.append(frame.to_metadata_dict(include_payload=include_payload))
                except queue.Empty:
                    break

            return self._safe_result(
                message="Frames drained successfully.",
                data={
                    "frames": frames,
                    "count": len(frames),
                    "direction": safe_direction,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to drain frames.",
                error=str(exc),
                metadata={"context": context},
            )

    # =========================================================================
    # Public API - Monitoring / Health
    # =========================================================================

    def get_stream_status(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Return one stream session status."""

        validation = self._validate_stream_access(stream_id, user_id, workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            session = self._sessions.get(stream_id)
            input_size = self._input_queues[stream_id].qsize() if stream_id in self._input_queues else 0
            output_size = self._output_queues[stream_id].qsize() if stream_id in self._output_queues else 0

        return self._safe_result(
            message="Stream status loaded successfully.",
            data={
                "stream": session.to_dict() if session else {},
                "queues": {
                    "input_size": input_size,
                    "output_size": output_size,
                    "max_queue_frames": self.config.max_queue_frames,
                },
                "health": self._calculate_stream_health(session),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "stream_id": stream_id,
            },
        )

    def list_streams(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        status: Optional[str] = None,
        device_id: Optional[str] = None,
        include_all_for_admin: bool = False,
    ) -> Dict[str, Any]:
        """List stream sessions for a user/workspace."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "status": status,
            "device_id": device_id,
        }

        try:
            safe_status = status.strip().lower() if isinstance(status, str) and status.strip() else None

            with self._lock:
                streams = []
                for session in self._sessions.values():
                    if not include_all_for_admin:
                        if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                            continue

                    if safe_status and session.status != safe_status:
                        continue

                    if device_id and session.device_id != device_id:
                        continue

                    streams.append(session.to_dict())

            return self._safe_result(
                message="Streams listed successfully.",
                data={
                    "streams": streams,
                    "count": len(streams),
                },
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list streams.",
                error=str(exc),
                metadata={"context": context},
            )

    def cleanup_stale_streams(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Mark stale streams as disconnected/stopped.

        This is useful for dashboard jobs, mobile app disconnect cleanup,
        WebSocket disconnects, and remote device heartbeats.
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
        }

        timeout = timeout_seconds or self.config.heartbeat_timeout_seconds
        now = time.time()
        cleaned: List[str] = []

        try:
            with self._lock:
                for session in self._sessions.values():
                    if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
                        continue

                    if session.status not in {StreamStatus.ACTIVE.value, StreamStatus.PAUSED.value}:
                        continue

                    last = session.last_heartbeat_at or session.last_frame_at or session.started_at
                    if last and now - last > timeout:
                        session.status = StreamStatus.DISCONNECTED.value
                        session.error = "heartbeat_timeout"
                        session.stopped_at = now
                        cleaned.append(session.stream_id)

            if cleaned:
                self._emit_agent_event({
                    "event": "voice.stream.cleanup_stale",
                    "stream_ids": cleaned,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "timestamp": now,
                })

                self._log_audit_event(
                    action="cleanup_stale_streams",
                    context=context,
                    result_summary={
                        "cleaned_count": len(cleaned),
                        "stream_ids": cleaned,
                    },
                )
            return self._safe_result(
                message="Stale streams cleaned successfully.",
                data={
                    "cleaned_streams": cleaned,
                    "cleaned_count": len(cleaned),
                    "timeout_seconds": timeout,
                },
                metadata={"context": context},
            )

        except Exception as exc:
            self.logger.exception("Cleanup stale streams failed")
            return self._error_result(
                message="Cleanup stale streams failed.",
                error=str(exc),
                metadata={"context": context},
            )

    # =========================================================================
    # Internal Backend / Frame Helpers
    # =========================================================================

    def _register_default_mock_backend(self) -> None:
        """Register a safe mock backend so imports/tests work without real devices."""
        self._backend_adapters[TransportType.MOCK.value] = StreamBackendAdapter(
            name="mock_backend",
            transport=TransportType.MOCK.value,
            start=lambda session, device: self._safe_result(
                message="Mock stream started.",
                data={"stream_id": session.stream_id, "device_id": device.device_id},
            ),
            stop=lambda session, device: self._safe_result(
                message="Mock stream stopped.",
                data={"stream_id": session.stream_id, "device_id": device.device_id if device else None},
            ),
            pause=lambda session, device: self._safe_result(
                message="Mock stream paused.",
                data={"stream_id": session.stream_id},
            ),
            resume=lambda session, device: self._safe_result(
                message="Mock stream resumed.",
                data={"stream_id": session.stream_id},
            ),
            send_output=lambda frame, session, device: self._safe_result(
                message="Mock output frame accepted.",
                data={"frame_id": frame.frame_id, "stream_id": session.stream_id},
            ),
        )

    def register_backend_adapter(self, adapter: StreamBackendAdapter) -> Dict[str, Any]:
        """Register a future real stream backend adapter safely."""
        if not isinstance(adapter, StreamBackendAdapter):
            return self._error_result(
                message="adapter must be a StreamBackendAdapter.",
                error="invalid_backend_adapter",
            )

        safe_transport = self._safe_transport(adapter.transport)
        self._backend_adapters[safe_transport] = adapter
        return self._safe_result(
            message="Backend adapter registered successfully.",
            data={"adapter": adapter.to_dict()},
        )

    def _start_backend_stream(self, session: StreamSession, profile: DeviceProfile) -> Dict[str, Any]:
        adapter = self._backend_adapters.get(session.transport) or self._backend_adapters.get(TransportType.MOCK.value)
        if adapter and callable(adapter.start):
            return adapter.start(session, profile)
        return self._safe_result(message="No backend start handler configured.", data={"transport": session.transport})

    def _stop_backend_stream(self, session: StreamSession, profile: Optional[DeviceProfile]) -> Dict[str, Any]:
        adapter = self._backend_adapters.get(session.transport) or self._backend_adapters.get(TransportType.MOCK.value)
        if adapter and callable(adapter.stop):
            return adapter.stop(session, profile)
        return self._safe_result(message="No backend stop handler configured.", data={"transport": session.transport})

    def _pause_backend_stream(self, session: StreamSession, profile: Optional[DeviceProfile]) -> Dict[str, Any]:
        adapter = self._backend_adapters.get(session.transport) or self._backend_adapters.get(TransportType.MOCK.value)
        if adapter and callable(adapter.pause):
            return adapter.pause(session, profile)
        return self._safe_result(message="No backend pause handler configured.", data={"transport": session.transport})

    def _resume_backend_stream(self, session: StreamSession, profile: Optional[DeviceProfile]) -> Dict[str, Any]:
        adapter = self._backend_adapters.get(session.transport) or self._backend_adapters.get(TransportType.MOCK.value)
        if adapter and callable(adapter.resume):
            return adapter.resume(session, profile)
        return self._safe_result(message="No backend resume handler configured.", data={"transport": session.transport})

    def _send_output_to_backend(
        self,
        stream_id: str,
        frame_id: Optional[str],
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
    ) -> Dict[str, Any]:
        validation = self._validate_stream_access(stream_id, user_id, workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            session = self._sessions.get(stream_id)
            profile = self._devices.get(session.device_id) if session else None
            output_queue = self._output_queues.get(stream_id)

            if not session or not profile or output_queue is None:
                return self._error_result(
                    message="Stream output backend state is missing.",
                    error="stream_backend_state_missing",
                )

            selected_frame: Optional[AudioFrame] = None
            buffered: List[AudioFrame] = []
            while True:
                try:
                    frame = output_queue.get_nowait()
                    if frame_id is None or frame.frame_id == frame_id:
                        selected_frame = frame
                        break
                    buffered.append(frame)
                except queue.Empty:
                    break

            for frame in buffered:
                try:
                    output_queue.put_nowait(frame)
                except queue.Full:
                    session.dropped_frame_count += 1

        if selected_frame is None:
            return self._error_result(
                message="Output frame not found for backend send.",
                error="output_frame_not_found",
                metadata={"stream_id": stream_id, "frame_id": frame_id},
            )

        adapter = self._backend_adapters.get(session.transport) or self._backend_adapters.get(TransportType.MOCK.value)
        if adapter and callable(adapter.send_output):
            return adapter.send_output(selected_frame, session, profile)

        return self._safe_result(
            message="No backend output handler configured.",
            data={"frame": selected_frame.to_metadata_dict(include_payload=False)},
        )

    def _push_frame(
        self,
        stream_id: str,
        payload: Any,
        direction: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
            "direction": direction,
        }

        try:
            safe_direction = self._safe_direction(direction)
            validation = self._validate_stream_access(stream_id, user_id, workspace_id)
            if not validation["success"]:
                return validation

            with self._lock:
                session = self._sessions.get(stream_id)
                if session is None:
                    return self._error_result(
                        message="Stream not found.",
                        error="stream_not_found",
                        metadata={"context": context},
                    )

                if session.status not in {StreamStatus.ACTIVE.value, StreamStatus.PAUSED.value, StreamStatus.CREATED.value, StreamStatus.READY.value}:
                    return self._error_result(
                        message="Stream is not accepting frames.",
                        error="stream_not_accepting_frames",
                        metadata={"context": context, "status": session.status},
                    )

                q = self._queue_for_direction(stream_id, safe_direction)
                sequence = session.input_frame_count + 1 if safe_direction == StreamDirection.INPUT.value else session.output_frame_count + 1

                frame = AudioFrame(
                    frame_id=self._generate_frame_id(stream_id),
                    stream_id=stream_id,
                    device_id=session.device_id,
                    direction=safe_direction,
                    payload=payload,
                    sample_rate=session.sample_rate,
                    channels=session.channels,
                    codec=session.codec,
                    sequence=sequence,
                    metadata=metadata or {},
                )

                try:
                    q.put_nowait(frame)
                except queue.Full:
                    session.dropped_frame_count += 1
                    return self._error_result(
                        message="Frame queue is full. Frame was dropped.",
                        error="frame_queue_full",
                        metadata={"context": context},
                    )

                if safe_direction == StreamDirection.INPUT.value:
                    session.input_frame_count += 1
                else:
                    session.output_frame_count += 1

                session.last_frame_at = time.time()
                session.last_heartbeat_at = time.time()

            return self._safe_result(
                message="Audio frame pushed successfully.",
                data={"frame": frame.to_metadata_dict(include_payload=False)},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Push frame failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def _read_frame(
        self,
        stream_id: str,
        direction: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        timeout: Optional[float],
        include_payload: bool,
    ) -> Dict[str, Any]:
        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "stream_id": stream_id,
            "direction": direction,
        }

        try:
            safe_direction = self._safe_direction(direction)
            validation = self._validate_stream_access(stream_id, user_id, workspace_id)
            if not validation["success"]:
                return validation

            q = self._queue_for_direction(stream_id, safe_direction)
            try:
                if timeout is None or float(timeout) <= 0:
                    frame = q.get_nowait()
                else:
                    frame = q.get(timeout=float(timeout))
            except queue.Empty:
                return self._safe_result(
                    message="No frame available.",
                    data={"frame": None},
                    metadata={"context": context, "empty": True},
                )

            return self._safe_result(
                message="Audio frame read successfully.",
                data={"frame": frame.to_metadata_dict(include_payload=include_payload)},
                metadata={"context": context},
            )

        except Exception as exc:
            return self._error_result(
                message="Read frame failed.",
                error=str(exc),
                metadata={"context": context},
            )

    def _queue_for_direction(self, stream_id: str, direction: str) -> "queue.Queue[AudioFrame]":
        if direction == StreamDirection.INPUT.value:
            return self._input_queues[stream_id]
        if direction == StreamDirection.OUTPUT.value:
            return self._output_queues[stream_id]
        raise ValueError(f"Unsupported frame queue direction: {direction}")

    # =========================================================================
    # Internal Validation / Policy Helpers
    # =========================================================================

    def _validate_task_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for DeviceStream operations.",
                error="missing_user_id",
                metadata={"context": context},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for DeviceStream operations.",
                error="missing_workspace_id",
                metadata={"context": context},
            )

        return self._safe_result(
            message="Task context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"context": context},
        )

    def _validate_stream_access(
        self,
        stream_id: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
    ) -> Dict[str, Any]:
        context = {"user_id": user_id, "workspace_id": workspace_id, "stream_id": stream_id}
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            session = self._sessions.get(stream_id)

        if not session:
            return self._error_result(
                message="Stream not found.",
                error="stream_not_found",
                metadata={"context": context},
            )

        if not self._same_saas_scope(session.user_id, session.workspace_id, user_id, workspace_id):
            return self._error_result(
                message="Stream does not belong to this user/workspace.",
                error="stream_scope_denied",
                metadata={"context": context},
            )

        return self._safe_result(
            message="Stream access validated.",
            data={"stream_id": stream_id},
            metadata={"context": context},
        )

    def _validate_audio_settings(
        self,
        sample_rate: int,
        channels: int,
        frame_ms: int,
    ) -> Dict[str, Any]:
        try:
            safe_rate = int(sample_rate)
            safe_channels = int(channels)
            safe_frame_ms = int(frame_ms)
        except Exception:
            return self._error_result(
                message="Audio settings must be integers.",
                error="invalid_audio_settings",
            )

        if not SAFE_MIN_SAMPLE_RATE <= safe_rate <= SAFE_MAX_SAMPLE_RATE:
            return self._error_result(
                message="Sample rate outside safe range.",
                error="invalid_sample_rate",
                metadata={"sample_rate": safe_rate},
            )

        if not SAFE_MIN_CHANNELS <= safe_channels <= SAFE_MAX_CHANNELS:
            return self._error_result(
                message="Channel count outside safe range.",
                error="invalid_channels",
                metadata={"channels": safe_channels},
            )

        if safe_frame_ms <= 0 or safe_frame_ms > 1000:
            return self._error_result(
                message="frame_ms outside safe range.",
                error="invalid_frame_ms",
                metadata={"frame_ms": safe_frame_ms},
            )

        return self._safe_result(
            message="Audio settings validated.",
            data={
                "sample_rate": safe_rate,
                "channels": safe_channels,
                "frame_ms": safe_frame_ms,
            },
        )

    def _same_saas_scope(
        self,
        left_user_id: Optional[Union[str, int]],
        left_workspace_id: Optional[Union[str, int]],
        right_user_id: Optional[Union[str, int]],
        right_workspace_id: Optional[Union[str, int]],
    ) -> bool:
        return str(left_user_id) == str(right_user_id) and str(left_workspace_id) == str(right_workspace_id)

    def _safe_device_type(self, value: Optional[str]) -> str:
        clean = str(value or DeviceType.UNKNOWN.value).strip().lower()
        return clean if clean in SUPPORTED_DEVICE_TYPES else DeviceType.UNKNOWN.value

    def _safe_direction(self, value: Optional[str]) -> str:
        clean = str(value or StreamDirection.DUPLEX.value).strip().lower()
        return clean if clean in SUPPORTED_DIRECTIONS else StreamDirection.DUPLEX.value

    def _safe_transport(self, value: Optional[str]) -> str:
        clean = str(value or TransportType.UNKNOWN.value).strip().lower()
        return clean if clean in SUPPORTED_TRANSPORTS else TransportType.UNKNOWN.value

    def _safe_codec(self, value: Optional[str]) -> str:
        clean = str(value or AudioCodec.UNKNOWN.value).strip().lower()
        return clean if clean in SUPPORTED_CODECS else AudioCodec.UNKNOWN.value

    def _transport_allowed(self, transport: str) -> bool:
        if transport == TransportType.MOCK.value:
            return bool(self.config.allow_mock_streams)
        if transport == TransportType.REMOTE.value:
            return bool(self.config.allow_remote_streams)
        if transport == TransportType.BLUETOOTH.value:
            return bool(self.config.allow_bluetooth_streams)
        if transport in {TransportType.LOCAL.value, TransportType.FILE_BUFFER.value, TransportType.UNKNOWN.value}:
            return True
        return False

    def _direction_compatible(self, device_direction: str, requested_direction: str) -> bool:
        if device_direction == StreamDirection.DUPLEX.value:
            return requested_direction in SUPPORTED_DIRECTIONS
        if requested_direction == StreamDirection.DUPLEX.value:
            return device_direction == StreamDirection.DUPLEX.value
        return device_direction == requested_direction

    def _default_permissions_for_device(self, device_type: str, direction: str) -> Dict[str, bool]:
        return {
            "can_input_audio": direction in {StreamDirection.INPUT.value, StreamDirection.DUPLEX.value},
            "can_output_audio": direction in {StreamDirection.OUTPUT.value, StreamDirection.DUPLEX.value},
            "can_start_stream": True,
            "can_stop_stream": True,
            "requires_security_for_start": self.config.require_security_for_stream_start,
            "is_remote": device_type in {DeviceType.REMOTE.value, DeviceType.WEB.value},
            "is_bluetooth": device_type == DeviceType.BLUETOOTH.value,
        }

    def _start_action_for_direction(self, direction: str) -> str:
        if direction == StreamDirection.INPUT.value:
            return "start_input_stream"
        if direction == StreamDirection.OUTPUT.value:
            return "start_output_stream"
        return "start_duplex_stream"

    def _requires_security_check(self, action: str, context: Dict[str, Any]) -> bool:
        return action in SENSITIVE_STREAM_ACTIONS or bool(self.config.require_security_for_stream_start)

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "action": action,
            "context": dict(context),
            "metadata": metadata or {},
            "agent": self.agent_name,
            "timestamp": time.time(),
        }

        client = self.security_client
        if client is not None:
            for method_name in ("approve_action", "request_approval", "check_permission", "authorize"):
                method = getattr(client, method_name, None)
                if callable(method):
                    try:
                        response = method(payload)
                        if isinstance(response, dict):
                            return {
                                "approved": bool(response.get("approved") or response.get("success") or response.get("allowed")),
                                "source": f"security_client.{method_name}",
                                "response": response,
                            }
                    except Exception as exc:
                        return {"approved": False, "source": f"security_client.{method_name}", "error": str(exc)}

        # Safe local default for mock/local tests only. Real deployment should inject Security Agent.
        return {
            "approved": True,
            "source": "local_safe_mode",
            "reason": "No real device opened by this file; backend is mock/adapter controlled.",
        }

    # =========================================================================
    # Payload / Health / ID Helpers
    # =========================================================================

    def _prepare_verification_payload(
        self,
        action: str,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "verification_type": "voice_device_stream",
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "result": result,
            "timestamp": time.time(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        device_profile: Optional[DeviceProfile],
        session: Optional[StreamSession],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "memory_type": "voice_device_stream_event",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "device": device_profile.to_dict() if device_profile else None,
            "stream": session.to_dict() if session else None,
            "contains_audio_payload": False,
            "timestamp": time.time(),
        }

    def _calculate_stream_health(self, session: Optional[StreamSession]) -> Dict[str, Any]:
        if session is None:
            return {"status": "missing", "healthy": False}

        now = time.time()
        last = session.last_heartbeat_at or session.last_frame_at or session.started_at
        stale = bool(last and now - last > self.config.heartbeat_timeout_seconds)
        healthy = session.status in {StreamStatus.ACTIVE.value, StreamStatus.PAUSED.value, StreamStatus.CREATED.value, StreamStatus.READY.value} and not stale

        return {
            "healthy": healthy,
            "status": session.status,
            "stale": stale,
            "seconds_since_last_activity": None if last is None else round(now - last, 3),
            "dropped_frame_count": session.dropped_frame_count,
        }

    def _generate_device_id(self, device_type: str) -> str:
        return f"device_{device_type}_{uuid.uuid4().hex}"

    def _generate_stream_id(self, device_id: str) -> str:
        safe_device = str(device_id).replace(" ", "_")
        return f"stream_{safe_device}_{uuid.uuid4().hex}"

    def _generate_frame_id(self, stream_id: str) -> str:
        safe_stream = str(stream_id).replace(" ", "_")
        return f"frame_{safe_stream}_{uuid.uuid4().hex}"

    def _emit_agent_event(self, payload: Dict[str, Any]) -> None:
        if not self.config.emit_events:
            return
        try:
            if self.event_bus is not None:
                emit = getattr(self.event_bus, "emit", None) or getattr(self.event_bus, "publish", None)
                if callable(emit):
                    emit(payload)
                    return
        except Exception:
            self.logger.exception("DeviceStream event emission failed")
        self.logger.debug("DeviceStream event: %s", payload)

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        result_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.config.audit_enabled:
            return

        payload = {
            "action": action,
            "agent": self.agent_name,
            "module": self.agent_module,
            "context": dict(context),
            "result_summary": result_summary or {},
            "timestamp": time.time(),
        }

        try:
            if self.audit_client is not None:
                method = getattr(self.audit_client, "log", None) or getattr(self.audit_client, "write", None)
                if callable(method):
                    method(payload)
                    return
        except Exception:
            self.logger.exception("DeviceStream audit logging failed")

        self.logger.info("DeviceStream audit event: %s", payload)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": str(message),
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": str(message),
            "data": {},
            "error": error or "device_stream_error",
            "metadata": metadata or {},
        }

    def get_agent_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry compatible metadata."""
        return {
            "name": self.agent_name,
            "module": self.agent_module,
            "file_path": self.file_path,
            "version": self.VERSION,
            "class_name": self.__class__.__name__,
            "safe_to_import": True,
            "executes_real_device_io": False,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "capabilities": [
                "device_registration",
                "stream_session_management",
                "mock_stream_backend",
                "input_frame_queue",
                "output_frame_queue",
                "stream_health",
                "verification_payloads",
                "memory_payloads",
                "saas_isolation",
            ],
        }

    def health_check(self) -> Dict[str, Any]:
        """Return health status for dashboard/API checks."""
        with self._lock:
            devices_count = len(self._devices)
            sessions_count = len(self._sessions)
            adapters = {key: adapter.to_dict() for key, adapter in self._backend_adapters.items()}

        return self._safe_result(
            message="DeviceStream is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.VERSION,
                "devices_count": devices_count,
                "sessions_count": sessions_count,
                "backend_adapters": adapters,
                "config": self.config.to_dict(),
            },
            metadata={"timestamp": time.time()},
        )


__all__ = [
    "DeviceStream",
    "DeviceStreamConfig",
    "DeviceProfile",
    "AudioFrame",
    "StreamSession",
    "StreamBackendAdapter",
    "DeviceType",
    "StreamDirection",
    "StreamStatus",
    "AudioCodec",
    "TransportType",
]
