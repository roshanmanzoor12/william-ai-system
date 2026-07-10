"""
agents/super_agents/hologram_agent/gesture_bridge.py

Purpose:
    Maps hand/glasses gestures to safe William commands for the William / Jarvis
    Multi-Agent AI SaaS System by Digital Promotix.

Architecture Role:
    GestureBridge is a Hologram Agent helper that receives normalized AR glasses,
    hand-tracking, controller, gaze, tap, pinch, swipe, or voice-assisted gesture
    events and converts them into safe command payloads for Master Agent routing.

Important Safety Rule:
    This file does NOT directly execute system, browser, message, call, finance,
    destructive, or real-world actions. It only prepares safe structured command
    payloads and optionally forwards them to a configured command router after
    context validation and Security Agent approval where required.

Compatibility:
    - Safe to import even if future William/Jarvis files are missing.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and audit/event streams.
    - Every user-specific task requires user_id and workspace_id.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import math
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe while the full William/Jarvis BaseAgent
        may not exist yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from agents.super_agents.hologram_agent.hologram_agent import HologramAgent  # type: ignore
except Exception:  # pragma: no cover
    HologramAgent = None  # type: ignore


try:
    from agents.super_agents.hologram_agent.ar_overlay import AROverlay  # type: ignore
except Exception:  # pragma: no cover
    AROverlay = None  # type: ignore


try:
    from agents.super_agents.hologram_agent.spatial_mapper import SpatialMapper  # type: ignore
except Exception:  # pragma: no cover
    SpatialMapper = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

StructuredDict = Dict[str, Any]
CommandRouterCallable = Callable[[StructuredDict], Union[StructuredDict, Awaitable[StructuredDict]]]
HookCallable = Callable[..., Union[StructuredDict, Awaitable[StructuredDict], None]]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_GESTURE_BRIDGE_VERSION = "1.0.0"

SAFE_GESTURE_TYPES = {
    "pinch",
    "open_palm",
    "closed_fist",
    "swipe_left",
    "swipe_right",
    "swipe_up",
    "swipe_down",
    "tap",
    "double_tap",
    "long_press",
    "thumbs_up",
    "thumbs_down",
    "peace",
    "point",
    "gaze_hold",
    "head_nod",
    "head_shake",
    "air_draw",
    "two_hand_zoom_in",
    "two_hand_zoom_out",
    "rotate_clockwise",
    "rotate_counterclockwise",
    "custom",
}

SAFE_COMMAND_TYPES = {
    "overlay.show",
    "overlay.hide",
    "overlay.toggle",
    "overlay.next",
    "overlay.previous",
    "overlay.select",
    "overlay.cancel",
    "overlay.confirm",
    "overlay.scroll_up",
    "overlay.scroll_down",
    "overlay.zoom_in",
    "overlay.zoom_out",
    "overlay.rotate",
    "overlay.pin",
    "overlay.unpin",
    "notification.dismiss",
    "notification.expand",
    "navigation.back",
    "navigation.forward",
    "navigation.home",
    "assistant.listen",
    "assistant.stop_listening",
    "assistant.command_palette",
    "context.capture_view",
    "context.mark_object",
    "workflow.prepare",
    "workflow.confirm_start",
    "manual.safe_command",
}

SENSITIVE_COMMAND_PREFIXES = {
    "workflow.",
    "browser.",
    "system.",
    "file.",
    "email.",
    "message.",
    "sms.",
    "whatsapp.",
    "call.",
    "finance.",
    "payment.",
    "publish.",
    "ads.",
    "crm.",
}

SENSITIVE_COMMAND_KEYWORDS = {
    "send",
    "delete",
    "remove",
    "archive",
    "call",
    "message",
    "email",
    "whatsapp",
    "sms",
    "payment",
    "charge",
    "refund",
    "transfer",
    "publish",
    "post",
    "ad",
    "campaign",
    "browser",
    "system",
    "file",
    "credential",
    "secret",
    "api_key",
    "financial",
    "bank",
    "execute",
    "start workflow",
    "run workflow",
}

DEFAULT_GESTURE_MAP: Dict[str, str] = {
    "pinch": "overlay.select",
    "open_palm": "overlay.show",
    "closed_fist": "overlay.cancel",
    "swipe_left": "overlay.next",
    "swipe_right": "overlay.previous",
    "swipe_up": "overlay.scroll_down",
    "swipe_down": "overlay.scroll_up",
    "tap": "overlay.select",
    "double_tap": "overlay.confirm",
    "long_press": "assistant.command_palette",
    "thumbs_up": "overlay.confirm",
    "thumbs_down": "overlay.cancel",
    "peace": "assistant.listen",
    "point": "context.mark_object",
    "gaze_hold": "overlay.select",
    "head_nod": "overlay.confirm",
    "head_shake": "overlay.cancel",
    "two_hand_zoom_in": "overlay.zoom_in",
    "two_hand_zoom_out": "overlay.zoom_out",
    "rotate_clockwise": "overlay.rotate",
    "rotate_counterclockwise": "overlay.rotate",
}

MAX_PAYLOAD_BYTES_DEFAULT = 256_000
MAX_METADATA_BYTES_DEFAULT = 64_000


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class GestureType(str, Enum):
    """Supported normalized gesture types."""

    PINCH = "pinch"
    OPEN_PALM = "open_palm"
    CLOSED_FIST = "closed_fist"
    SWIPE_LEFT = "swipe_left"
    SWIPE_RIGHT = "swipe_right"
    SWIPE_UP = "swipe_up"
    SWIPE_DOWN = "swipe_down"
    TAP = "tap"
    DOUBLE_TAP = "double_tap"
    LONG_PRESS = "long_press"
    THUMBS_UP = "thumbs_up"
    THUMBS_DOWN = "thumbs_down"
    PEACE = "peace"
    POINT = "point"
    GAZE_HOLD = "gaze_hold"
    HEAD_NOD = "head_nod"
    HEAD_SHAKE = "head_shake"
    AIR_DRAW = "air_draw"
    TWO_HAND_ZOOM_IN = "two_hand_zoom_in"
    TWO_HAND_ZOOM_OUT = "two_hand_zoom_out"
    ROTATE_CLOCKWISE = "rotate_clockwise"
    ROTATE_COUNTERCLOCKWISE = "rotate_counterclockwise"
    CUSTOM = "custom"


class GestureSource(str, Enum):
    """Where a gesture came from."""

    HAND_TRACKING = "hand_tracking"
    AR_GLASSES = "ar_glasses"
    CONTROLLER = "controller"
    GAZE = "gaze"
    HEAD_TRACKING = "head_tracking"
    CAMERA = "camera"
    SIMULATOR = "simulator"
    API = "api"
    UNKNOWN = "unknown"


class GestureStatus(str, Enum):
    """Gesture processing statuses."""

    RECEIVED = "received"
    VALIDATED = "validated"
    MAPPED = "mapped"
    SECURITY_PENDING = "security_pending"
    SECURITY_APPROVED = "security_approved"
    SECURITY_DENIED = "security_denied"
    ROUTED = "outed"
    FAILED = "failed"
    SKIPPED = "skipped"


class GestureConfidenceLevel(str, Enum):
    """Confidence classification for gesture recognition."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class GesturePriority(str, Enum):
    """Command priority for Master Agent / Router integration."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GestureContext:
    """
    SaaS isolation context.

    Every gesture mapped to a user-specific command must carry user_id and
    workspace_id. This protects memory, logs, analytics, task history, and
    command routing from crossing tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=tuple)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> StructuredDict:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role": self.role,
            "subscription_plan": self.subscription_plan,
            "permissions": list(self.permissions or []),
            "request_id": self.request_id,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "device_type": self.device_type,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "correlation_id": self.correlation_id,
        }


@dataclass
class GestureEvent:
    """
    Normalized gesture event.

    Device bridges, AR glasses SDKs, spatial mappers, dashboards, and simulator
    tools can normalize raw events into this shape before command mapping.
    """

    gesture_type: GestureType
    context: GestureContext
    source: GestureSource = GestureSource.UNKNOWN
    confidence: float = 1.0
    payload: StructuredDict = field(default_factory=dict)
    target: Optional[str] = None
    coordinates: Optional[StructuredDict] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    gesture_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    priority: GesturePriority = GesturePriority.NORMAL
    metadata: StructuredDict = field(default_factory=dict)

    def to_dict(self) -> StructuredDict:
        return {
            "gesture_id": self.gesture_id,
            "gesture_type": self.gesture_type.value,
            "context": self.context.to_dict(),
            "source": self.source.value,
            "confidence": self.confidence,
            "payload": self.payload,
            "target": self.target,
            "coordinates": self.coordinates,
            "timestamp": self.timestamp,
            "priority": self.priority.value,
            "metadata": self.metadata,
        }


@dataclass
class WilliamCommand:
    """
    Safe William command payload prepared from a gesture.

    This structure is compatible with Master Agent routing and future Agent Router
    integrations. It is only a command request, not direct execution.
    """

    command_type: str
    command_name: str
    context: GestureContext
    source_gesture: GestureEvent
    params: StructuredDict = field(default_factory=dict)
    route_to: str = "master_agent"
    target_agent: Optional[str] = None
    requires_confirmation: bool = False
    requires_security: bool = False
    command_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: StructuredDict = field(default_factory=dict)

    def to_dict(self) -> StructuredDict:
        return {
            "command_id": self.command_id,
            "command_type": self.command_type,
            "command_name": self.command_name,
            "route_to": self.route_to,
            "target_agent": self.target_agent,
            "params": self.params,
            "requires_confirmation": self.requires_confirmation,
            "requires_security": self.requires_security,
            "context": self.context.to_dict(),
            "source_gesture": self.source_gesture.to_dict(),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass
class GestureBridgeConfig:
    """
    GestureBridge configuration.

    Future config.py can pass these values into GestureBridge without changing
    public methods.
    """

    enabled: bool = True
    min_confidence: float = 0.65
    allow_custom_gestures: bool = True
    require_security_for_sensitive_commands: bool = True
    require_confirmation_for_low_confidence: bool = True
    low_confidence_threshold: float = 0.75
    safe_mode: bool = True
    max_payload_bytes: int = MAX_PAYLOAD_BYTES_DEFAULT
    max_metadata_bytes: int = MAX_METADATA_BYTES_DEFAULT
    dedupe_ttl_seconds: int = 1
    default_priority: GesturePriority = GesturePriority.NORMAL
    gesture_map: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_GESTURE_MAP))
    allowed_command_types: Sequence[str] = field(default_factory=lambda: tuple(SAFE_COMMAND_TYPES))
    emit_audit_events: bool = True
    emit_memory_payloads: bool = True
    emit_verification_payloads: bool = True
    dashboard_event_enabled: bool = True

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "GestureBridgeConfig":
        if not data:
            return cls()

        valid_fields = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        kwargs: Dict[str, Any] = {}

        for key, value in data.items():
            if key not in valid_fields:
                continue
            if key == "default_priority" and isinstance(value, str):
                try:
                    kwargs[key] = GesturePriority(value)
                except ValueError:
                    kwargs[key] = GesturePriority.NORMAL
            elif key == "gesture_map" and isinstance(value, Mapping):
                merged = dict(DEFAULT_GESTURE_MAP)
                merged.update({str(k): str(v) for k, v in value.items()})
                kwargs[key] = merged
            else:
                kwargs[key] = value

        return cls(**kwargs)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, max_len: int = 5000) -> str:
    text = "" if value is None else str(value)
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def _safe_json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, default=str).encode("utf-8"))
    except Exception:
        return len(str(value).encode("utf-8"))


def _stable_hash(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, default=str)
    except Exception:
        raw = str(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalize_permissions(permissions: Optional[Iterable[Any]]) -> Tuple[str, ...]:
    if not permissions:
        return tuple()
    return tuple(str(item).strip() for item in permissions if str(item).strip())


def _clamp_float(value: Any, minimum: float, maximum: float, default: float) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default

    if math.isnan(parsed) or math.isinf(parsed):
        return default

    return max(minimum, min(maximum, parsed))


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _command_is_sensitive(command_type: str, params: Optional[Mapping[str, Any]] = None) -> bool:
    command = command_type.lower().strip()

    if any(command.startswith(prefix) for prefix in SENSITIVE_COMMAND_PREFIXES):
        if command in SAFE_COMMAND_TYPES:
            return False
        return True

    try:
        text = json.dumps({"command_type": command_type, "params": params or {}}, default=str).lower()
    except Exception:
        text = f"{command_type} {params}".lower()

    return any(keyword in text for keyword in SENSITIVE_COMMAND_KEYWORDS)


def _confidence_level(confidence: float) -> GestureConfidenceLevel:
    if confidence >= 0.85:
        return GestureConfidenceLevel.HIGH
    if confidence >= 0.65:
        return GestureConfidenceLevel.MEDIUM
    return GestureConfidenceLevel.LOW


def _slugify_command_name(command_type: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", command_type.strip())
    return text.strip("_") or "manual.safe_command"


# ---------------------------------------------------------------------------
# GestureBridge
# ---------------------------------------------------------------------------

class GestureBridge(BaseAgent):
    """
    Maps hand/glasses gestures to safe William commands.

    Public methods:
        - map_gesture_to_command()
        - route_gesture()
        - register_command_router()
        - register_gesture_mapping()
        - remove_gesture_mapping()
        - list_gesture_mappings()
        - register_event_hook()
        - clear_dedupe_cache()
        - health_check()
        - export_registry_manifest()

    Integration points:
        Master Agent:
            Receives prepared WilliamCommand payloads through command_router or
            via returned structured result.

        Security Agent:
            Sensitive or high-risk gesture commands go through
            _requires_security_check() and _request_security_approval().

        Memory Agent:
            _prepare_memory_payload() creates gesture/command context memory.

        Verification Agent:
            _prepare_verification_payload() prepares evidence that a gesture was
            mapped and routed safely.

        Dashboard/API:
            _emit_agent_event() and _log_audit_event() provide visibility.

        Registry/Loader:
            Stable required class name: GestureBridge.
    """

    agent_type = "hologram_agent"
    component_name = "gesture_bridge"
    version = DEFAULT_GESTURE_BRIDGE_VERSION

    def __init__(
        self,
        config: Optional[Union[GestureBridgeConfig, Mapping[str, Any]]] = None,
        command_router: Optional[CommandRouterCallable] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="GestureBridge", **kwargs)

        if isinstance(config, GestureBridgeConfig):
            self.config = config
        else:
            self.config = GestureBridgeConfig.from_dict(config)

        self.command_router = command_router
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.logger = logger_instance or logger

        self._gesture_map: Dict[str, str] = {
            str(k): str(v) for k, v in dict(self.config.gesture_map).items()
        }
        self._event_hooks: Dict[str, List[HookCallable]] = {}
        self._dedupe_cache: Dict[str, float] = {}
        self._local_audit_events: List[StructuredDict] = []
        self._local_agent_events: List[StructuredDict] = []

    # ------------------------------------------------------------------
    # Public registration methods
    # ------------------------------------------------------------------

    def register_command_router(self, router: CommandRouterCallable) -> StructuredDict:
        """
        Register a callable that receives prepared William command payloads.

        The router may be:
            - Master Agent route function
            - Agent Router
            - Dashboard queue
            - API command dispatcher
            - Test fake router
        """
        if not callable(router):
            return self._error_result(
                message="Command router must be callable.",
                error_code="invalid_command_router",
            )

        self.command_router = router
        return self._safe_result(
            message="Command router registered successfully.",
            data={"registered": True},
        )

    def register_gesture_mapping(
        self,
        gesture_type: str,
        command_type: str,
        *,
        overwrite: bool = True,
    ) -> StructuredDict:
        """
        Register or update a gesture-to-command mapping.

        This does not execute commands. It only controls how future gesture
        events are translated.
        """
        gesture = _safe_str(gesture_type, 100).strip().lower()
        command = _safe_str(command_type, 200).strip()

        if not gesture:
            return self._error_result("Gesture type is required.", "missing_gesture_type")

        if not command:
            return self._error_result("Command type is required.", "missing_command_type")

        if gesture not in SAFE_GESTURE_TYPES and not self.config.allow_custom_gestures:
            return self._error_result(
                message="Custom gestures are disabled.",
                error_code="custom_gestures_disabled",
                data={"gesture_type": gesture},
            )

        if gesture in self._gesture_map and not overwrite:
            return self._error_result(
                message="Gesture mapping already exists.",
                error_code="gesture_mapping_exists",
                data={"gesture_type": gesture, "existing_command": self._gesture_map[gesture]},
            )

        if not self._is_command_allowed(command):
            return self._error_result(
                message="Command type is not allowed by GestureBridge configuration.",
                error_code="command_not_allowed",
                data={"command_type": command},
            )

        self._gesture_map[gesture] = command
        return self._safe_result(
            message="Gesture mapping registered successfully.",
            data={"gesture_type": gesture, "command_type": command},
        )

    def remove_gesture_mapping(self, gesture_type: str) -> StructuredDict:
        """Remove a gesture mapping."""
        gesture = _safe_str(gesture_type, 100).strip().lower()
        if not gesture:
            return self._error_result("Gesture type is required.", "missing_gesture_type")

        removed = self._gesture_map.pop(gesture, None)
        if removed is None:
            return self._error_result(
                message="Gesture mapping not found.",
                error_code="gesture_mapping_not_found",
                data={"gesture_type": gesture},
            )

        return self._safe_result(
            message="Gesture mapping removed successfully.",
            data={"gesture_type": gesture, "removed_command": removed},
        )

    def list_gesture_mappings(self) -> StructuredDict:
        """Return active gesture-to-command mappings."""
        return self._safe_result(
            message="Gesture mappings retrieved.",
            data={
                "mappings": dict(sorted(self._gesture_map.items())),
                "count": len(self._gesture_map),
            },
        )

    def register_event_hook(self, event_name: str, hook: HookCallable) -> StructuredDict:
        """
        Register a hook for lifecycle events.

        Examples:
            - gesture.received
            - gesture.validated
            - gesture.mapped
            - gesture.security_pending
            - gesture.routed
            - gesture.failed
            - *
        """
        normalized_event = _safe_str(event_name, 100).strip()
        if not normalized_event:
            return self._error_result("Event name is required.", "missing_event_name")

        if not callable(hook):
            return self._error_result("Event hook must be callable.", "invalid_event_hook")

        self._event_hooks.setdefault(normalized_event, []).append(hook)

        return self._safe_result(
            message="Event hook registered successfully.",
            data={
                "event_name": normalized_event,
                "hook_count": len(self._event_hooks[normalized_event]),
            },
        )

    # ------------------------------------------------------------------
    # Main public gesture methods
    # ------------------------------------------------------------------

    async def map_gesture_to_command(
        self,
        *,
        user_id: str,
        workspace_id: str,
        gesture_type: Union[str, GestureType],
        confidence: float = 1.0,
        source: Union[str, GestureSource] = GestureSource.UNKNOWN,
        payload: Optional[Mapping[str, Any]] = None,
        target: Optional[str] = None,
        coordinates: Optional[Mapping[str, Any]] = None,
        command_override: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Map a gesture event into a safe William command payload.

        This method validates and maps the gesture but does not route it unless
        route_gesture() is used.
        """
        try:
            event = self._build_gesture_event(
                user_id=user_id,
                workspace_id=workspace_id,
                gesture_type=gesture_type,
                confidence=confidence,
                source=source,
                payload=payload,
                target=target,
                coordinates=coordinates,
                role=role,
                permissions=permissions,
                metadata=metadata,
                request_info=request_info,
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build gesture event.",
                error_code="gesture_event_build_failed",
                error=str(exc),
            )

        return await self._map_event_to_command(
            event,
            command_override=command_override,
            route=False,
        )

    async def route_gesture(
        self,
        *,
        user_id: str,
        workspace_id: str,
        gesture_type: Union[str, GestureType],
        confidence: float = 1.0,
        source: Union[str, GestureSource] = GestureSource.UNKNOWN,
        payload: Optional[Mapping[str, Any]] = None,
        target: Optional[str] = None,
        coordinates: Optional[Mapping[str, Any]] = None,
        command_override: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Map and safely route a gesture command to the configured command router.

        If no command_router is registered, this returns a prepared command
        payload for Master Agent / Dashboard / API routing.
        """
        try:
            event = self._build_gesture_event(
                user_id=user_id,
                workspace_id=workspace_id,
                gesture_type=gesture_type,
                confidence=confidence,
                source=source,
                payload=payload,
                target=target,
                coordinates=coordinates,
                role=role,
                permissions=permissions,
                metadata=metadata,
                request_info=request_info,
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build gesture event.",
                error_code="gesture_event_build_failed",
                error=str(exc),
            )

        return await self._map_event_to_command(
            event,
            command_override=command_override,
            route=True,
        )

    async def process_gesture_event(
        self,
        event: Union[GestureEvent, Mapping[str, Any]],
        *,
        command_override: Optional[str] = None,
        route: bool = True,
    ) -> StructuredDict:
        """
        Process an already-normalized GestureEvent or dict.

        DeviceBridge, SpatialMapper, HologramAgent, API routes, and simulators
        can use this method directly.
        """
        try:
            normalized_event = self._coerce_gesture_event(event)
        except Exception as exc:
            return self._error_result(
                message="Invalid gesture event.",
                error_code="invalid_gesture_event",
                error=str(exc),
            )

        return await self._map_event_to_command(
            normalized_event,
            command_override=command_override,
            route=route,
        )

    # ------------------------------------------------------------------
    # Core mapping pipeline
    # ------------------------------------------------------------------

    async def _map_event_to_command(
        self,
        event: GestureEvent,
        *,
        command_override: Optional[str],
        route: bool,
    ) -> StructuredDict:
        started_at = time.time()

        if not self.config.enabled:
            return self._error_result("GestureBridge is disabled.", "gesture_bridge_disabled")

        await self._emit_agent_event("gesture.received", event.to_dict())
        self._log_audit_event(
            action="gesture_received",
            event=event,
            status=GestureStatus.RECEIVED,
        )

        validation = self._validate_gesture_event(event)
        if not validation["success"]:
            self._log_audit_event(
                action="gesture_validation_failed",
                event=event,
                status=GestureStatus.FAILED,
                details=validation,
            )
            await self._emit_agent_event("gesture.failed", validation)
            return validation

        dedupe = self._check_and_store_dedupe(event)
        if not dedupe["success"]:
            self._log_audit_event(
                action="gesture_deduped",
                event=event,
                status=GestureStatus.SKIPPED,
                details=dedupe,
            )
            await self._emit_agent_event("gesture.skipped", dedupe)
            return dedupe

        await self._emit_agent_event("gesture.validated", event.to_dict())

        command_result = self._build_command_from_gesture(event, command_override=command_override)
        if not command_result["success"]:
            self._log_audit_event(
                action="gesture_mapping_failed",
                event=event,
                status=GestureStatus.FAILED,
                details=command_result,
            )
            await self._emit_agent_event("gesture.failed", command_result)
            return command_result

        command = command_result["data"]["command_object"]
        if not isinstance(command, WilliamCommand):
            return self._error_result(
                message="Internal command mapping failed.",
                error_code="invalid_internal_command_object",
            )

        await self._emit_agent_event("gesture.mapped", command.to_dict())
        self._log_audit_event(
            action="gesture_mapped_to_command",
            event=event,
            status=GestureStatus.MAPPED,
            details={"command": command.to_dict()},
        )

        security_required = self._requires_security_check(command)
        security_result: Optional[StructuredDict] = None

        if security_required:
            await self._emit_agent_event("gesture.security_pending", command.to_dict())
            self._log_audit_event(
                action="gesture_command_security_required",
                event=event,
                status=GestureStatus.SECURITY_PENDING,
                details={"command": command.to_dict()},
            )

            security_result = await self._request_security_approval(command)
            if not security_result.get("success"):
                denied = self._error_result(
                    message="Gesture command blocked by Security Agent.",
                    error_code="security_denied",
                    data={
                        "gesture_id": event.gesture_id,
                        "command": command.to_dict(),
                    },
                    metadata={
                        "security_result": security_result,
                        "duration_ms": int((time.time() - started_at) * 1000),
                    },
                )
                self._log_audit_event(
                    action="gesture_command_security_denied",
                    event=event,
                    status=GestureStatus.SECURITY_DENIED,
                    details=denied,
                )
                await self._emit_agent_event("gesture.security_denied", denied)
                return denied

            await self._emit_agent_event("gesture.security_approved", security_result)
            self._log_audit_event(
                action="gesture_command_security_approved",
                event=event,
                status=GestureStatus.SECURITY_APPROVED,
                details=security_result,
            )

        verification_payload = self._prepare_verification_payload(
            command,
            security_result=security_result,
            routed=route,
        )
        memory_payload = self._prepare_memory_payload(command)

        if self.config.emit_memory_payloads:
            await self._send_memory_payload(memory_payload)

        route_result: Optional[StructuredDict] = None
        if route:
            route_result = await self._route_command(command, verification_payload, memory_payload, security_result)
        else:
            route_result = self._safe_result(
                message="Gesture mapped to command. Routing was not requested.",
                data={
                    "mode": "mapped_only",
                    "command": command.to_dict(),
                },
            )

        duration_ms = int((time.time() - started_at) * 1000)

        if route_result.get("success"):
            result = self._safe_result(
                message="Gesture processed successfully.",
                data={
                    "gesture": event.to_dict(),
                    "command": command.to_dict(),
                    "route_result": route_result,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "duration_ms": duration_ms,
                    "routed": route,
                    "security_required": security_required,
                    "security_result": security_result,
                    "confidence_level": _confidence_level(event.confidence).value,
                },
            )
            self._log_audit_event(
                action="gesture_command_completed",
                event=event,
                status=GestureStatus.ROUTED if route else GestureStatus.MAPPED,
                details=result,
            )
            await self._emit_agent_event("gesture.routed" if route else "gesture.mapped_only", result)
            return result

        result = self._error_result(
            message="Gesture mapped, but command routing failed.",
            error_code="command_routing_failed",
            data={
                "gesture": event.to_dict(),
                "command": command.to_dict(),
                "route_result": route_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "duration_ms": duration_ms,
                "routed": route,
                "security_required": security_required,
                "security_result": security_result,
            },
        )
        self._log_audit_event(
            action="gesture_command_failed",
            event=event,
            status=GestureStatus.FAILED,
            details=result,
        )
        await self._emit_agent_event("gesture.failed", result)
        return result

    # ------------------------------------------------------------------
    # Validation hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Union[GestureContext, Mapping[str, Any]]) -> StructuredDict:
        """
        Required compatibility hook.

        Validates SaaS user/workspace isolation.
        """
        try:
            ctx = context if isinstance(context, GestureContext) else self._context_from_mapping(context)
        except Exception as exc:
            return self._error_result(
                message="Invalid task context.",
                error_code="invalid_task_context",
                error=str(exc),
            )

        missing: List[str] = []
        if not _safe_str(ctx.user_id, 200).strip():
            missing.append("user_id")
        if not _safe_str(ctx.workspace_id, 200).strip():
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Missing required SaaS isolation context fields.",
                error_code="missing_context_fields",
                data={"missing": missing},
            )

        if ctx.user_id == ctx.workspace_id:
            return self._error_result(
                message="user_id and workspace_id must be separate identifiers.",
                error_code="invalid_context_isolation",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={"context": ctx.to_dict()},
        )

    def _validate_gesture_event(self, event: GestureEvent) -> StructuredDict:
        context_result = self._validate_task_context(event.context)
        if not context_result["success"]:
            return context_result

        if event.gesture_type.value not in SAFE_GESTURE_TYPES and not self.config.allow_custom_gestures:
            return self._error_result(
                message="Gesture type is not supported.",
                error_code="unsupported_gesture_type",
                data={"gesture_type": event.gesture_type.value},
            )

        if event.confidence < self.config.min_confidence:
            return self._error_result(
                message="Gesture confidence is below minimum threshold.",
                error_code="low_gesture_confidence",
                data={
                    "gesture_id": event.gesture_id,
                    "confidence": event.confidence,
                    "min_confidence": self.config.min_confidence,
                },
            )

        payload_size = _safe_json_size(event.payload)
        metadata_size = _safe_json_size(event.metadata)

        if payload_size > self.config.max_payload_bytes:
            return self._error_result(
                message="Gesture payload is too large.",
                error_code="gesture_payload_too_large",
                data={
                    "payload_size_bytes": payload_size,
                    "max_payload_bytes": self.config.max_payload_bytes,
                },
            )

        if metadata_size > self.config.max_metadata_bytes:
            return self._error_result(
                message="Gesture metadata is too large.",
                error_code="gesture_metadata_too_large",
                data={
                    "metadata_size_bytes": metadata_size,
                    "max_metadata_bytes": self.config.max_metadata_bytes,
                },
            )

        return self._safe_result(
            message="Gesture event is valid.",
            data={
                "gesture_id": event.gesture_id,
                "gesture_type": event.gesture_type.value,
                "confidence": event.confidence,
                "confidence_level": _confidence_level(event.confidence).value,
            },
        )

    # ------------------------------------------------------------------
    # Security hook
    # ------------------------------------------------------------------

    def _requires_security_check(self, command: WilliamCommand) -> bool:
        """
        Required compatibility hook.

        Sensitive commands require Security Agent approval. GestureBridge is
        conservative because gestures can be accidental.
        """
        if not self.config.require_security_for_sensitive_commands:
            return False

        if command.requires_security:
            return True

        if _command_is_sensitive(command.command_type, command.params):
            return True

        permissions = set(command.context.permissions or [])
        if "hologram:gesture:execute_sensitive" in permissions:
            return True

        if command.requires_confirmation and self.config.safe_mode:
            return True

        return False

    async def _request_security_approval(self, command: WilliamCommand) -> StructuredDict:
        """
        Required compatibility hook.

        Uses Security Agent/client if available. In fallback safe mode, sensitive
        commands are blocked unless they are in the explicitly safe command set.
        """
        approval_payload = {
            "action": "hologram_gesture_command",
            "agent": self.agent_type,
            "component": self.component_name,
            "command": command.to_dict(),
            "risk": {
                "command_sensitive": _command_is_sensitive(command.command_type, command.params),
                "requires_confirmation": command.requires_confirmation,
                "safe_mode": self.config.safe_mode,
                "confidence": command.source_gesture.confidence,
            },
            "requested_at": _utc_now(),
        }

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve"):
                    result = self.security_client.approve(approval_payload)
                    result = await _maybe_await(result)
                    return self._normalize_external_result(result, default_message="Security approval completed.")

                if hasattr(self.security_client, "request_approval"):
                    result = self.security_client.request_approval(approval_payload)
                    result = await _maybe_await(result)
                    return self._normalize_external_result(result, default_message="Security approval completed.")

                if callable(self.security_client):
                    result = self.security_client(approval_payload)
                    result = await _maybe_await(result)
                    return self._normalize_external_result(result, default_message="Security approval completed.")

            except Exception as exc:
                self.logger.exception("Security approval request failed.")
                return self._error_result(
                    message="Security approval request failed.",
                    error_code="security_client_error",
                    error=str(exc),
                    metadata={"approval_payload_hash": _stable_hash(approval_payload)},
                )

        is_sensitive = _command_is_sensitive(command.command_type, command.params)

        if self.config.safe_mode and is_sensitive and command.command_type not in SAFE_COMMAND_TYPES:
            return self._error_result(
                message="Fallback Security Agent blocked sensitive gesture command in safe mode.",
                error_code="fallback_security_blocked",
                data={
                    "command_id": command.command_id,
                    "command_type": command.command_type,
                    "reason": "sensitive_command_without_security_client",
                },
            )

        return self._safe_result(
            message="Fallback security approval granted.",
            data={
                "approved": True,
                "mode": "fallback",
                "command_id": command.command_id,
                "command_type": command.command_type,
            },
            metadata={"security_client_available": False},
        )

    # ------------------------------------------------------------------
    # Payload hooks
    # ------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        command: WilliamCommand,
        *,
        security_result: Optional[Mapping[str, Any]] = None,
        routed: bool = False,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Prepares Verification Agent evidence that a gesture was safely mapped
        into a command request.
        """
        event = command.source_gesture

        return {
            "verification_type": "hologram_gesture_command_mapping",
            "agent": self.agent_type,
            "component": self.component_name,
            "gesture_id": event.gesture_id,
            "command_id": command.command_id,
            "command_type": command.command_type,
            "command_name": command.command_name,
            "route_to": command.route_to,
            "target_agent": command.target_agent,
            "routed": routed,
            "context": command.context.to_dict(),
            "evidence": {
                "gesture_type": event.gesture_type.value,
                "gesture_source": event.source.value,
                "gesture_confidence": event.confidence,
                "confidence_level": _confidence_level(event.confidence).value,
                "payload_hash": _stable_hash(event.payload),
                "params_hash": _stable_hash(command.params),
                "mapped_at": command.created_at,
                "prepared_at": _utc_now(),
            },
            "security": {
                "required": self._requires_security_check(command),
                "result": dict(security_result) if security_result else None,
            },
            "next_expected_step": "master_agent_or_agent_router_handles_command_request",
        }

    def _prepare_memory_payload(self, command: WilliamCommand) -> StructuredDict:
        """
        Required compatibility hook.

        Prepares Memory Agent-compatible context for gesture usage patterns,
        without storing raw secrets or cross-tenant data.
        """
        event = command.source_gesture

        return {
            "memory_type": "hologram_gesture_command_context",
            "agent": self.agent_type,
            "component": self.component_name,
            "user_id": command.context.user_id,
            "workspace_id": command.context.workspace_id,
            "gesture_id": event.gesture_id,
            "command_id": command.command_id,
            "gesture_type": event.gesture_type.value,
            "gesture_source": event.source.value,
            "command_type": command.command_type,
            "command_name": command.command_name,
            "target": event.target,
            "confidence": event.confidence,
            "confidence_level": _confidence_level(event.confidence).value,
            "summary": self._summarize_command(command),
            "payload": self._redact_sensitive_data(event.payload),
            "params": self._redact_sensitive_data(command.params),
            "metadata": self._redact_sensitive_data(command.metadata),
            "created_at": _utc_now(),
            "isolation": {
                "user_id": command.context.user_id,
                "workspace_id": command.context.workspace_id,
            },
        }

    async def _send_memory_payload(self, memory_payload: Mapping[str, Any]) -> None:
        """
        Best-effort Memory Agent integration.

        Failure to store gesture memory must not fail gesture routing.
        """
        if self.memory_client is None:
            return

        try:
            if hasattr(self.memory_client, "store"):
                await _maybe_await(self.memory_client.store(dict(memory_payload)))
            elif hasattr(self.memory_client, "remember"):
                await _maybe_await(self.memory_client.remember(dict(memory_payload)))
            elif callable(self.memory_client):
                await _maybe_await(self.memory_client(dict(memory_payload)))
        except Exception:
            self.logger.exception("Failed to send memory payload.")

    # ------------------------------------------------------------------
    # Event and audit hooks
    # ------------------------------------------------------------------

    async def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> StructuredDict:
        """
        Required compatibility hook.

        Emits lifecycle events for dashboard, analytics, agent registry,
        Master Agent visibility, and debugging.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_type,
            "component": self.component_name,
            "timestamp": _utc_now(),
            "payload": self._redact_sensitive_data(dict(payload)),
        }

        self._local_agent_events.append(event)

        if self.config.dashboard_event_enabled and self.event_bus is not None:
            try:
                if hasattr(self.event_bus, "emit"):
                    await _maybe_await(self.event_bus.emit(event_name, event))
                elif hasattr(self.event_bus, "publish"):
                    await _maybe_await(self.event_bus.publish(event_name, event))
                elif callable(self.event_bus):
                    await _maybe_await(self.event_bus(event_name, event))
            except Exception:
                self.logger.exception("Failed to emit GestureBridge event to event_bus.")

        hooks = self._event_hooks.get(event_name, []) + self._event_hooks.get("*", [])
        for hook in hooks:
            try:
                await _maybe_await(hook(event))
            except Exception:
                self.logger.exception("GestureBridge event hook failed for %s.", event_name)

        return self._safe_result(
            message="Agent event emitted.",
            data={"event_name": event_name},
        )

    def _log_audit_event(
        self,
        *,
        action: str,
        event: GestureEvent,
        status: GestureStatus,
        details: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Logs audit-safe gesture activity. Raw camera data or secrets are never
        required here; hashes and redacted payloads are enough for traceability.
        """
        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "status": status.value,
            "agent": self.agent_type,
            "component": self.component_name,
            "gesture_id": event.gesture_id,
            "gesture_type": event.gesture_type.value,
            "gesture_source": event.source.value,
            "confidence": event.confidence,
            "user_id": event.context.user_id,
            "workspace_id": event.context.workspace_id,
            "device_id": event.context.device_id,
            "target": event.target,
            "payload_hash": _stable_hash(event.payload),
            "metadata_hash": _stable_hash(event.metadata),
            "details": self._redact_sensitive_data(dict(details or {})),
            "timestamp": _utc_now(),
        }

        self._local_audit_events.append(audit_event)

        if self.config.emit_audit_events and self.audit_logger is not None:
            try:
                if hasattr(self.audit_logger, "log"):
                    result = self.audit_logger.log(audit_event)
                    if inspect.isawaitable(result):
                        asyncio.create_task(result)
                elif callable(self.audit_logger):
                    result = self.audit_logger(audit_event)
                    if inspect.isawaitable(result):
                        asyncio.create_task(result)
            except Exception:
                self.logger.exception("Failed to log GestureBridge audit event.")

        return self._safe_result(
            message="Audit event logged.",
            data={"audit_id": audit_event["audit_id"]},
        )

    # ------------------------------------------------------------------
    # Result hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Standard success response shape.
        """
        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent": self.agent_type,
                "component": self.component_name,
                "version": self.version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error.",
        error_code: str = "error",
        error: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Standard error response shape.
        """
        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": {
                "agent": self.agent_type,
                "component": self.component_name,
                "version": self.version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Command building and routing
    # ------------------------------------------------------------------

    def _build_command_from_gesture(
        self,
        event: GestureEvent,
        *,
        command_override: Optional[str] = None,
    ) -> StructuredDict:
        gesture_key = event.gesture_type.value

        command_type = _safe_str(command_override, 200).strip() if command_override else ""
        if not command_type:
            command_type = self._gesture_map.get(gesture_key, "")

        if not command_type:
            if event.gesture_type == GestureType.CUSTOM and self.config.allow_custom_gestures:
                command_type = _safe_str(event.payload.get("command_type"), 200).strip()
            if not command_type:
                return self._error_result(
                    message="No command mapping found for gesture.",
                    error_code="gesture_mapping_not_found",
                    data={"gesture_type": gesture_key},
                )

        if not self._is_command_allowed(command_type):
            return self._error_result(
                message="Mapped command type is not allowed.",
                error_code="command_not_allowed",
                data={"command_type": command_type, "gesture_type": gesture_key},
            )

        params = self._build_command_params(event, command_type)

        requires_confirmation = self._requires_confirmation(event, command_type, params)
        requires_security = _command_is_sensitive(command_type, params)

        target_agent = self._infer_target_agent(command_type)
        route_to = "master_agent"

        command = WilliamCommand(
            command_type=command_type,
            command_name=_slugify_command_name(command_type),
            context=event.context,
            source_gesture=event,
            params=params,
            route_to=route_to,
            target_agent=target_agent,
            requires_confirmation=requires_confirmation,
            requires_security=requires_security,
            metadata={
                "mapped_by": self.component_name,
                "gesture_bridge_version": self.version,
                "confidence_level": _confidence_level(event.confidence).value,
                "safe_mode": self.config.safe_mode,
            },
        )

        return self._safe_result(
            message="Gesture mapped to William command.",
            data={
                "command": command.to_dict(),
                "command_object": command,
            },
        )

    async def _route_command(
        self,
        command: WilliamCommand,
        verification_payload: Mapping[str, Any],
        memory_payload: Mapping[str, Any],
        security_result: Optional[Mapping[str, Any]],
    ) -> StructuredDict:
        command_payload = {
            "task_type": "hologram_gesture_command",
            "agent": self.agent_type,
            "component": self.component_name,
            "command": command.to_dict(),
            "context": command.context.to_dict(),
            "verification_payload": dict(verification_payload),
            "memory_payload": dict(memory_payload),
            "security_result": dict(security_result) if security_result else None,
            "routing": {
                "preferred_route": command.route_to,
                "target_agent": command.target_agent,
                "master_agent_compatible": True,
                "agent_router_compatible": True,
                "dashboard_compatible": True,
                "execute_directly": False,
            },
            "created_at": _utc_now(),
        }

        if self.command_router is None:
            return self._safe_result(
                message="Gesture command prepared. No command router registered, so no execution was performed.",
                data={
                    "mode": "prepared_only",
                    "command_payload": command_payload,
                },
                metadata={"router_registered": False},
            )

        try:
            result = self.command_router(command_payload)
            result = await _maybe_await(result)
            return self._normalize_external_result(
                result,
                default_message="Command router completed.",
            )
        except Exception as exc:
            self.logger.exception("Gesture command router failed.")
            return self._error_result(
                message="Gesture command router failed.",
                error_code="command_router_exception",
                error=str(exc),
            )

    def _build_command_params(self, event: GestureEvent, command_type: str) -> StructuredDict:
        payload = dict(event.payload or {})

        params: StructuredDict = {
            "gesture_id": event.gesture_id,
            "gesture_type": event.gesture_type.value,
            "source": event.source.value,
            "confidence": event.confidence,
            "confidence_level": _confidence_level(event.confidence).value,
            "target": event.target,
            "coordinates": event.coordinates,
            "safe_origin": "hologram_gesture_bridge",
            "raw_payload": self._redact_sensitive_data(payload),
        }

        if command_type == "overlay.rotate":
            direction = "clockwise" if event.gesture_type == GestureType.ROTATE_CLOCKWISE else "counterclockwise"
            params["direction"] = payload.get("direction") or direction
            params["degrees"] = _clamp_float(payload.get("degrees", 15), -360, 360, 15)

        elif command_type in {"overlay.zoom_in", "overlay.zoom_out"}:
            params["scale_delta"] = _clamp_float(payload.get("scale_delta", 0.1), 0.01, 2.0, 0.1)

        elif command_type in {"overlay.scroll_up", "overlay.scroll_down"}:
            params["distance"] = _clamp_float(payload.get("distance", 1.0), 0.1, 20.0, 1.0)

        elif command_type in {"overlay.next", "overlay.previous"}:
            params["step"] = int(_clamp_float(payload.get("step", 1), 1, 20, 1))

        elif command_type == "context.mark_object":
            params["object_id"] = _safe_str(payload.get("object_id") or event.target, 300) or None
            params["label"] = _safe_str(payload.get("label"), 300) or None

        elif command_type == "context.capture_view":
            params["capture_mode"] = _safe_str(payload.get("capture_mode") or "metadata_only", 100)
            params["include_image"] = bool(payload.get("include_image", False))

        elif command_type in {"workflow.prepare", "workflow.confirm_start"}:
            params["workflow_id"] = _safe_str(payload.get("workflow_id"), 300) or None
            params["workflow_name"] = _safe_str(payload.get("workflow_name"), 300) or None
            params["workflow_input"] = self._redact_sensitive_data(
                payload.get("workflow_input") if isinstance(payload.get("workflow_input"), Mapping) else {}
            )

        elif command_type == "manual.safe_command":
            params["text"] = _safe_str(payload.get("text") or payload.get("command") or "", 2000)

        return params

    def _requires_confirmation(
        self,
        event: GestureEvent,
        command_type: str,
        params: Mapping[str, Any],
    ) -> bool:
        if self.config.require_confirmation_for_low_confidence and event.confidence < self.config.low_confidence_threshold:
            return True

        if command_type == "workflow.confirm_start":
            return True

        if _command_is_sensitive(command_type, params):
            return True

        if event.gesture_type in {GestureType.DOUBLE_TAP, GestureType.THUMBS_UP, GestureType.HEAD_NOD}:
            return False

        return False

    def _is_command_allowed(self, command_type: str) -> bool:
        command = _safe_str(command_type, 200).strip()
        if not command:
            return False

        allowed = set(str(item) for item in self.config.allowed_command_types)

        if command in allowed:
            return True

        if command.startswith("workflow.") and command in {"workflow.prepare", "workflow.confirm_start"}:
            return True

        if self.config.safe_mode:
            return False

        return True

    def _infer_target_agent(self, command_type: str) -> Optional[str]:
        command = command_type.lower().strip()

        if command.startswith("overlay.") or command.startswith("notification.") or command.startswith("navigation."):
            return "hologram_agent"

        if command.startswith("context."):
            return "visual_agent"

        if command.startswith("workflow."):
            return "workflow_agent"

        if command.startswith("assistant."):
            return "master_agent"

        if command.startswith("browser."):
            return "browser_agent"

        if command.startswith("system."):
            return "system_agent"

        if command.startswith("call."):
            return "call_agent"

        if command.startswith("finance.") or command.startswith("payment."):
            return "finance_agent"

        if command.startswith("email.") or command.startswith("message.") or command.startswith("whatsapp."):
            return "workflow_agent"

        return "master_agent"

    # ------------------------------------------------------------------
    # Event/context coercion
    # ------------------------------------------------------------------

    def _build_gesture_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        gesture_type: Union[str, GestureType],
        confidence: float,
        source: Union[str, GestureSource],
        payload: Optional[Mapping[str, Any]],
        target: Optional[str],
        coordinates: Optional[Mapping[str, Any]],
        role: Optional[str],
        permissions: Optional[Iterable[Any]],
        metadata: Optional[Mapping[str, Any]],
        request_info: Optional[Mapping[str, Any]],
    ) -> GestureEvent:
        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        gtype = self._coerce_gesture_type(gesture_type)
        gsource = self._coerce_gesture_source(source)

        return GestureEvent(
            gesture_type=gtype,
            context=context,
            source=gsource,
            confidence=_clamp_float(confidence, 0.0, 1.0, 0.0),
            payload=self._redact_sensitive_data(dict(payload or {})),
            target=_safe_str(target, 300) if target else None,
            coordinates=self._normalize_coordinates(coordinates),
            priority=self.config.default_priority,
            metadata=self._redact_sensitive_data(dict(metadata or {})),
        )

    def _build_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str],
        permissions: Optional[Iterable[Any]],
        request_info: Optional[Mapping[str, Any]],
    ) -> GestureContext:
        info = dict(request_info or {})

        return GestureContext(
            user_id=_safe_str(user_id, 200).strip(),
            workspace_id=_safe_str(workspace_id, 200).strip(),
            role=role,
            subscription_plan=info.get("subscription_plan"),
            permissions=_normalize_permissions(permissions),
            request_id=_safe_str(info.get("request_id") or str(uuid.uuid4()), 200),
            session_id=info.get("session_id"),
            device_id=info.get("device_id"),
            device_type=info.get("device_type"),
            source_ip=info.get("source_ip") or info.get("ip"),
            user_agent=info.get("user_agent"),
            correlation_id=info.get("correlation_id"),
        )

    def _context_from_mapping(self, data: Mapping[str, Any]) -> GestureContext:
        return GestureContext(
            user_id=_safe_str(data.get("user_id"), 200).strip(),
            workspace_id=_safe_str(data.get("workspace_id"), 200).strip(),
            role=data.get("role"),
            subscription_plan=data.get("subscription_plan"),
            permissions=_normalize_permissions(data.get("permissions")),
            request_id=_safe_str(data.get("request_id") or str(uuid.uuid4()), 200),
            session_id=data.get("session_id"),
            device_id=data.get("device_id"),
            device_type=data.get("device_type"),
            source_ip=data.get("source_ip"),
            user_agent=data.get("user_agent"),
            correlation_id=data.get("correlation_id"),
        )

    def _coerce_gesture_event(self, event: Union[GestureEvent, Mapping[str, Any]]) -> GestureEvent:
        if isinstance(event, GestureEvent):
            return event

        data = dict(event or {})

        context_raw = data.get("context") or {}
        context = context_raw if isinstance(context_raw, GestureContext) else self._context_from_mapping(context_raw)

        priority_raw = data.get("priority") or self.config.default_priority.value
        if isinstance(priority_raw, GesturePriority):
            priority = priority_raw
        else:
            try:
                priority = GesturePriority(str(priority_raw))
            except ValueError:
                priority = GesturePriority.NORMAL

        return GestureEvent(
            gesture_type=self._coerce_gesture_type(data.get("gesture_type") or data.get("type")),
            context=context,
            source=self._coerce_gesture_source(data.get("source") or GestureSource.UNKNOWN.value),
            confidence=_clamp_float(data.get("confidence", 1.0), 0.0, 1.0, 0.0),
            payload=self._redact_sensitive_data(dict(data.get("payload") or {})),
            target=data.get("target"),
            coordinates=self._normalize_coordinates(data.get("coordinates")),
            timestamp=_safe_str(data.get("timestamp") or _utc_now(), 100),
            gesture_id=_safe_str(data.get("gesture_id") or str(uuid.uuid4()), 200),
            priority=priority,
            metadata=self._redact_sensitive_data(dict(data.get("metadata") or {})),
        )

    def _coerce_gesture_type(self, value: Any) -> GestureType:
        if isinstance(value, GestureType):
            return value

        normalized = _safe_str(value, 100).strip().lower().replace("-", "_").replace(" ", "_")
        try:
            return GestureType(normalized)
        except ValueError:
            if self.config.allow_custom_gestures:
                return GestureType.CUSTOM
            raise ValueError(f"Unsupported gesture type: {value}")

    def _coerce_gesture_source(self, value: Any) -> GestureSource:
        if isinstance(value, GestureSource):
            return value

        normalized = _safe_str(value, 100).strip().lower().replace("-", "_").replace(" ", "_")
        try:
            return GestureSource(normalized)
        except ValueError:
            return GestureSource.UNKNOWN

    def _normalize_coordinates(self, coordinates: Optional[Mapping[str, Any]]) -> Optional[StructuredDict]:
        if not coordinates:
            return None

        result: StructuredDict = {}
        for key in ("x", "y", "z", "screen_x", "screen_y", "depth", "confidence"):
            if key in coordinates:
                result[key] = _clamp_float(coordinates.get(key), -1000000.0, 1000000.0, 0.0)

        for key in ("space_id", "object_id", "anchor_id", "frame"):
            if key in coordinates:
                result[key] = _safe_str(coordinates.get(key), 300)

        return result

    # ------------------------------------------------------------------
    # Dedupe
    # ------------------------------------------------------------------

    def _check_and_store_dedupe(self, event: GestureEvent) -> StructuredDict:
        """
        Prevents accidental duplicate gesture firing within a short window.
        """
        self._purge_dedupe_cache()

        dedupe_key = self._dedupe_key(event)
        now = time.time()
        existing = self._dedupe_cache.get(dedupe_key)

        if existing and now - existing < self.config.dedupe_ttl_seconds:
            return self._error_result(
                message="Duplicate gesture skipped within dedupe window.",
                error_code="duplicate_gesture",
                data={
                    "gesture_id": event.gesture_id,
                    "gesture_type": event.gesture_type.value,
                    "dedupe_ttl_seconds": self.config.dedupe_ttl_seconds,
                },
            )

        self._dedupe_cache[dedupe_key] = now
        return self._safe_result(
            message="Gesture dedupe check passed.",
            data={"dedupe_key": dedupe_key},
        )

    def _dedupe_key(self, event: GestureEvent) -> str:
        key_data = {
            "user_id": event.context.user_id,
            "workspace_id": event.context.workspace_id,
            "device_id": event.context.device_id,
            "gesture_type": event.gesture_type.value,
            "source": event.source.value,
            "target": event.target,
            "payload_hash": _stable_hash(event.payload),
        }
        return _stable_hash(key_data)

    def _purge_dedupe_cache(self) -> None:
        now = time.time()
        expired = [
            key for key, created_at in self._dedupe_cache.items()
            if now - created_at >= self.config.dedupe_ttl_seconds
        ]
        for key in expired:
            self._dedupe_cache.pop(key, None)

    def clear_dedupe_cache(self) -> StructuredDict:
        """Clear duplicate gesture cache."""
        count = len(self._dedupe_cache)
        self._dedupe_cache.clear()
        return self._safe_result(
            message="Gesture dedupe cache cleared.",
            data={"cleared_count": count},
        )

    # ------------------------------------------------------------------
    # Sanitization and summaries
    # ------------------------------------------------------------------

    def _redact_sensitive_data(self, data: Any) -> Any:
        """
        Recursively redact secrets and unsafe raw values.
        """
        sensitive_key_parts = {
            "password",
            "pass",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "authorization",
            "cookie",
            "credential",
            "card",
            "cvv",
            "ssn",
            "bank",
            "iban",
            "routing",
            "face_embedding",
            "biometric",
            "raw_image",
            "raw_video",
            "camera_frame",
        }

        if isinstance(data, Mapping):
            redacted: StructuredDict = {}
            for key, value in data.items():
                key_str = _safe_str(key, 200)
                lowered = key_str.lower()
                if any(part in lowered for part in sensitive_key_parts):
                    redacted[key_str] = "[REDACTED]"
                else:
                    redacted[key_str] = self._redact_sensitive_data(value)
            return redacted

        if isinstance(data, list):
            return [self._redact_sensitive_data(item) for item in data[:500]]

        if isinstance(data, tuple):
            return tuple(self._redact_sensitive_data(item) for item in data[:500])

        if isinstance(data, str):
            if len(data) > 15000:
                return data[:15000] + "...[truncated]"
            return data

        return data

    def _summarize_command(self, command: WilliamCommand) -> str:
        event = command.source_gesture
        return (
            f"{event.gesture_type.value} gesture from {event.source.value} "
            f"mapped to {command.command_type} with "
            f"{_confidence_level(event.confidence).value} confidence."
        )

    # ------------------------------------------------------------------
    # External result normalization
    # ------------------------------------------------------------------

    def _normalize_external_result(self, result: Any, *, default_message: str) -> StructuredDict:
        if isinstance(result, Mapping):
            result_dict = dict(result)
            if "success" in result_dict:
                return {
                    "success": bool(result_dict.get("success")),
                    "message": _safe_str(result_dict.get("message") or default_message, 2000),
                    "data": dict(result_dict.get("data") or {}),
                    "error": result_dict.get("error"),
                    "metadata": dict(result_dict.get("metadata") or {}),
                }

            return self._safe_result(
                message=default_message,
                data={"external_result": result_dict},
            )

        if result is None:
            return self._safe_result(
                message=default_message,
                data={"external_result": None},
            )

        return self._safe_result(
            message=default_message,
            data={"external_result": result},
        )

    # ------------------------------------------------------------------
    # Health, diagnostics, registry
    # ------------------------------------------------------------------

    def health_check(self) -> StructuredDict:
        """Dashboard/API health check."""
        return self._safe_result(
            message="GestureBridge is healthy.",
            data={
                "enabled": self.config.enabled,
                "agent_type": self.agent_type,
                "component": self.component_name,
                "version": self.version,
                "router_registered": self.command_router is not None,
                "security_client_available": self.security_client is not None,
                "memory_client_available": self.memory_client is not None,
                "verification_client_available": self.verification_client is not None,
                "audit_logger_available": self.audit_logger is not None,
                "event_bus_available": self.event_bus is not None,
                "gesture_mappings_count": len(self._gesture_map),
                "dedupe_cache_size": len(self._dedupe_cache),
                "local_audit_events": len(self._local_audit_events),
                "local_agent_events": len(self._local_agent_events),
                "supported_gesture_types": sorted(SAFE_GESTURE_TYPES),
                "safe_command_types": sorted(SAFE_COMMAND_TYPES),
            },
        )

    def get_local_audit_events(self, limit: int = 100) -> StructuredDict:
        """Return recent local audit events for development/testing dashboard."""
        safe_limit = max(1, min(int(limit), 1000))
        return self._safe_result(
            message="Local audit events retrieved.",
            data={"events": self._local_audit_events[-safe_limit:]},
        )

    def get_local_agent_events(self, limit: int = 100) -> StructuredDict:
        """Return recent local agent events for development/testing dashboard."""
        safe_limit = max(1, min(int(limit), 1000))
        return self._safe_result(
            message="Local agent events retrieved.",
            data={"events": self._local_agent_events[-safe_limit:]},
        )

    def export_registry_manifest(self) -> StructuredDict:
        """
        Agent Registry / Agent Loader compatible manifest.
        """
        return self._safe_result(
            message="GestureBridge registry manifest exported.",
            data={
                "class_name": "GestureBridge",
                "module": "agents.super_agents.hologram_agent.gesture_bridge",
                "agent_type": self.agent_type,
                "component_name": self.component_name,
                "version": self.version,
                "public_methods": [
                    "map_gesture_to_command",
                    "route_gesture",
                    "process_gesture_event",
                    "register_command_router",
                    "register_gesture_mapping",
                    "remove_gesture_mapping",
                    "list_gesture_mappings",
                    "register_event_hook",
                    "clear_dedupe_cache",
                    "health_check",
                    "export_registry_manifest",
                ],
                "required_context": ["user_id", "workspace_id"],
                "supported_gestures": sorted(SAFE_GESTURE_TYPES),
                "default_mappings": dict(DEFAULT_GESTURE_MAP),
                "security_hook": "_requires_security_check",
                "verification_hook": "_prepare_verification_payload",
                "memory_hook": "_prepare_memory_payload",
                "audit_hook": "_log_audit_event",
                "event_hook": "_emit_agent_event",
                "result_hooks": ["_safe_result", "_error_result"],
                "direct_execution": False,
                "master_agent_compatible": True,
                "agent_router_compatible": True,
                "dashboard_api_ready": True,
            },
        )


# ---------------------------------------------------------------------------
# Convenience helpers for tests/scripts
# ---------------------------------------------------------------------------

def run_async(coro: Awaitable[StructuredDict]) -> StructuredDict:
    """
    Convenience helper for local scripts/tests.

    In FastAPI or async services, call GestureBridge methods with await directly.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None  # type: ignore[assignment]

    if loop and loop.is_running():
        raise RuntimeError("run_async() cannot be used inside a running event loop. Use await instead.")

    return asyncio.run(coro)


async def _smoke_test() -> StructuredDict:
    """
    Import-safe smoke test helper.

    This function is not executed on import.
    """
    bridge = GestureBridge(config={"safe_mode": True})

    return await bridge.route_gesture(
        user_id="test_user",
        workspace_id="test_workspace",
        gesture_type="pinch",
        confidence=0.94,
        source="hand_tracking",
        target="card_001",
        coordinates={"x": 120, "y": 250, "z": 0.8},
        request_info={
            "device_id": "simulator_device",
            "device_type": "ar_glasses_simulator",
        },
    )


__all__ = [
    "GestureBridge",
    "GestureBridgeConfig",
    "GestureContext",
    "GestureEvent",
    "WilliamCommand",
    "GestureType",
    "GestureSource",
    "GestureStatus",
    "GestureConfidenceLevel",
    "GesturePriority",
    "run_async",
]


"""
Where to place it:
    agents/super_agents/hologram_agent/gesture_bridge.py

Required dependencies:
    - Python 3.10+
    - Standard library only for this file.
    - Optional future integrations:
        agents.base_agent.BaseAgent
        agents.super_agents.hologram_agent.hologram_agent.HologramAgent
        agents.super_agents.hologram_agent.ar_overlay.AROverlay
        agents.super_agents.hologram_agent.spatial_mapper.SpatialMapper

How to test it:
    1. Save this file at:
        agents/super_agents/hologram_agent/gesture_bridge.py

    2. From project root, run:
        python -m py_compile agents/super_agents/hologram_agent/gesture_bridge.py

    3. Optional async smoke test:
        python - <<'PY'
        import asyncio
        from agents.super_agents.hologram_agent.gesture_bridge import GestureBridge

        async def main():
            bridge = GestureBridge(config={"safe_mode": True})
            result = await bridge.route_gesture(
                user_id="user_123",
                workspace_id="workspace_456",
                gesture_type="pinch",
                confidence=0.95,
                source="hand_tracking",
                target="lead_card",
                coordinates={"x": 100, "y": 240, "z": 0.5},
                request_info={
                    "device_id": "glasses_demo_001",
                    "device_type": "ar_glasses"
                }
            )
            print(result)

        asyncio.run(main())
        PY

Agent/Module: Hologram Agent
File Completed: gesture_bridge.py
Completion: 36.4%
Completed Files: ['hologram_agent.py', 'ar_overlay.py', 'spatial_mapper.py', 'gesture_bridge.py']
Remaining Files: ['real_world_context.py', 'object_recognizer.py', 'navigation_overlay.py', 'notification_overlay.py', 'device_bridge.py', 'hologram_memory.py', 'config.py']
Next Recommended File: agents/super_agents/hologram_agent/real_world_context.py
FILE COMPLETE
"""