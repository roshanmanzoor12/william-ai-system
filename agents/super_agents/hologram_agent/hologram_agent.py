"""
William / Jarvis All-File Prompt Bible - Digital Promotix
Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.

File: agents/super_agents/hologram_agent/hologram_agent.py
Agent/Module: Hologram Agent
Purpose:
    Main AR/hologram controller for glasses, overlays, gestures, spatial context,
    device bridge planning, privacy-safe real-world context, navigation overlays,
    notification overlays, and future AR/holographic interfaces.

What this file does:
    - Provides the main HologramAgent class for William/Jarvis.
    - Accepts AR/hologram tasks from Master Agent, dashboard, API, or router.
    - Validates user_id and workspace_id for SaaS isolation.
    - Manages safe AR session planning for glasses/headsets/mobile AR.
    - Creates overlay plans for dashboards, navigation, notifications, object labels, and assistant panels.
    - Handles gesture events safely and maps them to internal UI intents.
    - Handles spatial context updates without exposing private camera data.
    - Detects sensitive actions such as camera capture, microphone use, location, recording, external device actions, navigation, and notifications.
    - Routes sensitive actions through Security Agent approval hooks.
    - Prepares Verification Agent payloads after every completed action.
    - Prepares Memory Agent payloads for reusable AR preferences and safe spatial context summaries.
    - Emits events and audit logs for dashboard/API/registry integration.
    - Is import-safe even if future William/Jarvis modules are not created yet.

Where to place it:
    agents/super_agents/hologram_agent/hologram_agent.py

Required dependencies:
    Python 3.10+
    Standard library only for this file.

Optional future dependencies:
    pydantic for strict schemas.
    FastAPI/WebSockets for live AR dashboard/control streams.
    OpenXR/WebXR/device SDKs for real glasses/headset integration.
    OpenCV/MediaPipe for gestures/object recognition.
    numpy/scipy for spatial transforms.
    redis/postgres for persistent session state.

How to test it:
    python -m py_compile agents/super_agents/hologram_agent/hologram_agent.py

    Example quick test:
        from agents.super_agents.hologram_agent.hologram_agent import HologramAgent

        agent = HologramAgent()
        result = agent.run({
            "user_id": "user_123",
            "workspace_id": "workspace_123",
            "task_type": "create_overlay",
            "payload": {
                "session_id": "ar_session_1",
                "overlay_type": "assistant_panel",
                "title": "William",
                "content": "How can I help?",
                "anchor": {"mode": "head_locked"},
                "dry_run": True
            }
        })
        print(result)

Agent/module completion percentage after this file:
    9.1%

Next file to generate:
    agents/super_agents/hologram_agent/ar_overlay.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple


# =============================================================================
# Safe optional imports / fallback stubs
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe while the wider William/Jarvis architecture
        is still being generated. Production BaseAgent should provide shared
        run hooks, registry identity, permissions, logging, event bus, memory,
        router compatibility, and agent lifecycle methods.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def run(self, task: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.run is not implemented.")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    class SecurityAgent:  # type: ignore
        """
        Fallback SecurityAgent stub.

        Production Security Agent should perform permission checks, sensitive
        action approval, privacy rules, device/camera/microphone/location policy,
        destructive action checks, and SaaS workspace isolation validation.
        """

        def check_permission(self, request: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "approved": True,
                "message": "Fallback security approval granted for dry-run/import-safe mode.",
                "data": {"fallback": True},
                "error": None,
                "metadata": {},
            }


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    class VerificationAgent:  # type: ignore
        """
        Fallback VerificationAgent stub.

        Production Verification Agent should verify AR overlay state, gesture
        routing, device bridge results, privacy constraints, and real-world
        context actions.
        """

        def prepare_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return dict(payload)


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    class MemoryAgent:  # type: ignore
        """
        Fallback MemoryAgent stub.

        Production Memory Agent should save safe per-user/per-workspace AR
        preferences, overlay layouts, gesture preferences, and summarized
        non-sensitive spatial context.
        """

        def prepare_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return dict(payload)


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("William.HologramAgent")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums and constants
# =============================================================================

class HologramTaskType(str, Enum):
    """Supported public task types for HologramAgent."""

    START_SESSION = "start_session"
    END_SESSION = "end_session"
    GET_SESSION = "get_session"
    LIST_SESSIONS = "list_sessions"

    CREATE_OVERLAY = "create_overlay"
    UPDATE_OVERLAY = "update_overlay"
    REMOVE_OVERLAY = "remove_overlay"
    LIST_OVERLAYS = "list_overlays"
    CLEAR_OVERLAYS = "clear_overlays"

    HANDLE_GESTURE = "handle_gesture"
    REGISTER_GESTURE = "register_gesture"
    MAP_GESTURE = "map_gesture"

    UPDATE_SPATIAL_CONTEXT = "update_spatial_context"
    GET_SPATIAL_CONTEXT = "get_spatial_context"
    CREATE_SPATIAL_ANCHOR = "create_spatial_anchor"
    REMOVE_SPATIAL_ANCHOR = "remove_spatial_anchor"

    PLAN_DEVICE_COMMAND = "plan_device_command"
    DEVICE_STATUS = "device_status"

    CREATE_NAVIGATION_OVERLAY = "create_navigation_overlay"
    CREATE_NOTIFICATION_OVERLAY = "create_notification_overlay"
    CREATE_OBJECT_LABEL_OVERLAY = "create_object_label_overlay"

    VALIDATE_AR_PLAN = "validate_ar_plan"
    MONITOR_SESSION = "monitor_session"
    CALIBRATE = "calibrate"


class HologramSessionStatus(str, Enum):
    """AR/hologram session lifecycle states."""

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ENDED = "ended"
    FAILED = "failed"
    WAITING_APPROVAL = "waiting_approval"


class DeviceType(str, Enum):
    """Supported device categories."""

    AR_GLASSES = "ar_glasses"
    VR_HEADSET = "vr_headset"
    MIXED_REALITY_HEADSET = "mixed_reality_headset"
    MOBILE_AR = "mobile_ar"
    DESKTOP_PREVIEW = "desktop_preview"
    UNKNOWN = "unknown"


class OverlayType(str, Enum):
    """Supported overlay categories."""

    ASSISTANT_PANEL = "assistant_panel"
    DASHBOARD_CARD = "dashboard_card"
    NAVIGATION_ARROW = "navigation_arrow"
    NOTIFICATION = "notification"
    OBJECT_LABEL = "object_label"
    CONTEXT_TOOLTIP = "context_tooltip"
    FLOATING_MENU = "floating_menu"
    STATUS_BADGE = "status_badge"
    WARNING = "warning"
    CUSTOM = "custom"


class AnchorMode(str, Enum):
    """Overlay anchoring modes."""

    HEAD_LOCKED = "head_locked"
    WORLD_LOCKED = "world_locked"
    OBJECT_LOCKED = "object_locked"
    SCREEN_LOCKED = "screen_locked"
    HAND_LOCKED = "hand_locked"


class GestureType(str, Enum):
    """Supported gesture event types."""

    TAP = "tap"
    DOUBLE_TAP = "double_tap"
    PINCH = "pinch"
    GRAB = "grab"
    RELEASE = "release"
    SWIPE_LEFT = "swipe_left"
    SWIPE_RIGHT = "swipe_right"
    SWIPE_UP = "swipe_up"
    SWIPE_DOWN = "swipe_down"
    AIR_CLICK = "air_click"
    OPEN_PALM = "open_palm"
    FIST = "fist"
    POINT = "point"
    DWELL = "dwell"
    UNKNOWN = "unknown"


class GestureIntent(str, Enum):
    """Normalized internal gesture intents."""

    SELECT = "select"
    BACK = "back"
    OPEN_MENU = "open_menu"
    CLOSE_MENU = "close_menu"
    SCROLL_UP = "scroll_up"
    SCROLL_DOWN = "scroll_down"
    NEXT = "next"
    PREVIOUS = "previous"
    DRAG_START = "drag_start"
    DRAG_END = "drag_end"
    DISMISS = "dismiss"
    NONE = "none"


class RiskLevel(str, Enum):
    """Risk score categories."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SENSITIVE_ACTION_KEYWORDS = {
    "camera",
    "microphone",
    "record",
    "recording",
    "capture",
    "photo",
    "video",
    "location",
    "gps",
    "navigation",
    "route",
    "device_command",
    "send_notification",
    "external_device",
    "spatial_scan",
    "object_recognition",
    "face",
    "biometric",
    "share",
    "stream",
    "upload",
    "delete",
    "destructive",
}

DEFAULT_ALLOWED_TASK_TYPES = {item.value for item in HologramTaskType}

DEFAULT_SESSION_TIMEOUT_SECONDS = 3600
DEFAULT_OVERLAY_TTL_SECONDS = 900
DEFAULT_MAX_OVERLAYS_PER_SESSION = 50
DEFAULT_MAX_ANCHORS_PER_SESSION = 200
DEFAULT_GESTURE_CONFIDENCE_THRESHOLD = 0.55


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class HologramContext:
    """
    SaaS isolation context.

    Every user-specific AR/hologram operation must include user_id and
    workspace_id. Never mix sessions, overlays, spatial maps, device state,
    logs, memory, or analytics across users/workspaces.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    actor_id: Optional[str] = None
    role: Optional[str] = None
    source: str = "hologram_agent"
    session_ref: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Vector3:
    """Simple 3D vector used for safe spatial planning."""

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


@dataclass
class Quaternion:
    """Simple rotation quaternion used for spatial anchors."""

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    w: float = 1.0

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


@dataclass
class SpatialAnchor:
    """A safe spatial anchor definition."""

    anchor_id: str
    name: str
    mode: str
    position: Vector3 = field(default_factory=Vector3)
    rotation: Quaternion = field(default_factory=Quaternion)
    object_ref: Optional[str] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["position"] = self.position.to_dict()
        data["rotation"] = self.rotation.to_dict()
        return data


@dataclass
class HologramOverlay:
    """AR/hologram overlay plan."""

    overlay_id: str
    session_id: str
    overlay_type: str
    title: str
    content: Dict[str, Any] = field(default_factory=dict)
    anchor: Dict[str, Any] = field(default_factory=dict)
    style: Dict[str, Any] = field(default_factory=dict)
    interaction: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    visible: bool = True
    ttl_seconds: int = DEFAULT_OVERLAY_TTL_SECONDS
    risk_level: str = RiskLevel.LOW.value
    requires_approval: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HologramSession:
    """AR/hologram session state."""

    session_id: str
    device_type: str
    status: str
    started_at: str
    ended_at: Optional[str] = None
    overlays: List[str] = field(default_factory=list)
    anchors: List[str] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    privacy_mode: bool = True
    spatial_context_enabled: bool = False
    gesture_enabled: bool = True
    device_bridge_enabled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GestureEvent:
    """Gesture event normalized by the HologramAgent."""

    gesture_id: str
    session_id: str
    gesture_type: str
    intent: str
    confidence: float
    target_overlay_id: Optional[str] = None
    position: Optional[Vector3] = None
    raw_event_hash: Optional[str] = None
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.position:
            data["position"] = self.position.to_dict()
        return data


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_json_dumps(value: Any) -> str:
    """Safely JSON serialize values for hashing/logging."""
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def _hash_payload(value: Any) -> str:
    """Create a stable SHA-256 hash for payloads."""
    raw = _safe_json_dumps(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _coerce_dict(value: Any) -> Dict[str, Any]:
    """Convert mapping-like values to dict safely."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, Mapping):
        return dict(value)
    return {"value": value}


def _as_list(value: Any) -> List[Any]:
    """Safely convert value to list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _normalize_string(value: Any, default: str = "") -> str:
    """Normalize value to stripped string."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _make_id(prefix: str) -> str:
    """Create readable unique IDs."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert value to safe finite float."""
    try:
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return default
        return number
    except Exception:
        return default


def _clamp(value: float, minimum: float, maximum: float) -> float:
    """Clamp number between minimum and maximum."""
    return max(minimum, min(maximum, value))


# =============================================================================
# HologramAgent
# =============================================================================

class HologramAgent(BaseAgent):
    """
    Main AR/hologram controller for William/Jarvis.

    Responsibilities:
        - Create and manage AR/hologram sessions.
        - Create/update/remove overlays for glasses/headsets/mobile AR.
        - Handle gesture events and map them to safe internal intents.
        - Track privacy-safe spatial context and spatial anchors.
        - Plan device bridge commands without directly executing unsafe hardware actions.
        - Create navigation, notification, object-label, assistant-panel overlays.
        - Route sensitive operations through Security Agent.
        - Prepare Verification Agent and Memory Agent payloads.
        - Emit events/audit logs for dashboard/API/registry integration.

    This file does not directly control real glasses, cameras, microphones,
    navigation apps, sensors, or external devices. Future files should implement
    real integrations behind permission gates:
        - ar_overlay.py
        - spatial_mapper.py
        - gesture_bridge.py
        - real_world_context.py
        - object_recognizer.py
        - navigation_overlay.py
        - notification_overlay.py
        - device_bridge.py
        - hologram_memory.py
        - config.py
    """

    agent_name = "hologram_agent"
    agent_type = "super_agent"
    public_methods = [
        "run",
        "start_session",
        "end_session",
        "get_session",
        "list_sessions",
        "create_overlay",
        "update_overlay",
        "remove_overlay",
        "list_overlays",
        "clear_overlays",
        "handle_gesture",
        "register_gesture",
        "map_gesture",
        "update_spatial_context",
        "get_spatial_context",
        "create_spatial_anchor",
        "remove_spatial_anchor",
        "plan_device_command",
        "device_status",
        "create_navigation_overlay",
        "create_notification_overlay",
        "create_object_label_overlay",
        "validate_ar_plan",
        "monitor_session",
        "calibrate",
    ]

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize HologramAgent.

        Args:
            security_agent:
                Optional Security Agent instance.
            verification_agent:
                Optional Verification Agent instance.
            memory_agent:
                Optional Memory Agent instance.
            event_emitter:
                Optional callable for dashboard/API/event bus integration.
            audit_logger:
                Optional callable for central audit logs.
            config:
                Optional configuration mapping.
            **kwargs:
                Additional BaseAgent-compatible arguments.
        """
        try:
            super().__init__(**kwargs)
        except TypeError:
            super().__init__()

        self.logger = getattr(self, "logger", LOGGER)
        self.security_agent = security_agent or SecurityAgent()
        self.verification_agent = verification_agent or VerificationAgent()
        self.memory_agent = memory_agent or MemoryAgent()
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.config = self._load_default_config(config)

        self._session_store: Dict[str, Dict[str, Any]] = {}
        self._overlay_store: Dict[str, Dict[str, Any]] = {}
        self._anchor_store: Dict[str, Dict[str, Any]] = {}
        self._spatial_context_store: Dict[str, Dict[str, Any]] = {}
        self._gesture_map_store: Dict[str, Dict[str, Any]] = {}
        self._device_status_store: Dict[str, Dict[str, Any]] = {}

    # -------------------------------------------------------------------------
    # Main router
    # -------------------------------------------------------------------------

    def run(self, task: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """
        Master Agent / Router entrypoint.

        Expected task format:
            {
                "user_id": "user_123",
                "workspace_id": "workspace_123",
                "task_type": "create_overlay",
                "payload": {...},
                "metadata": {...}
            }

        Returns:
            Structured dict:
            {
                "success": bool,
                "message": str,
                "data": dict,
                "error": dict | None,
                "metadata": dict
            }
        """
        started_at = _utc_now()
        task_dict = _coerce_dict(task)

        context_result = self._validate_task_context(task_dict)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        task_type = _normalize_string(task_dict.get("task_type") or task_dict.get("type"))
        payload = _coerce_dict(task_dict.get("payload"))

        if not task_type:
            return self._error_result(
                message="Missing task_type for HologramAgent.",
                code="missing_task_type",
                context=context,
                metadata={"started_at": started_at},
            )

        if task_type not in DEFAULT_ALLOWED_TASK_TYPES:
            return self._error_result(
                message=f"Unsupported HologramAgent task_type: {task_type}",
                code="unsupported_task_type",
                context=context,
                metadata={
                    "supported_task_types": sorted(DEFAULT_ALLOWED_TASK_TYPES),
                    "started_at": started_at,
                },
            )

        self._emit_agent_event(
            event_type="hologram.task.received",
            context=context,
            data={
                "task_type": task_type,
                "payload_hash": _hash_payload(payload),
            },
        )

        self._log_audit_event(
            action="hologram_task_received",
            context=context,
            data={
                "task_type": task_type,
                "payload_hash": _hash_payload(payload),
            },
        )

        try:
            if task_type == HologramTaskType.START_SESSION.value:
                result = self.start_session(context=context, payload=payload)
            elif task_type == HologramTaskType.END_SESSION.value:
                result = self.end_session(context=context, payload=payload)
            elif task_type == HologramTaskType.GET_SESSION.value:
                result = self.get_session(context=context, payload=payload)
            elif task_type == HologramTaskType.LIST_SESSIONS.value:
                result = self.list_sessions(context=context, payload=payload)
            elif task_type == HologramTaskType.CREATE_OVERLAY.value:
                result = self.create_overlay(context=context, payload=payload)
            elif task_type == HologramTaskType.UPDATE_OVERLAY.value:
                result = self.update_overlay(context=context, payload=payload)
            elif task_type == HologramTaskType.REMOVE_OVERLAY.value:
                result = self.remove_overlay(context=context, payload=payload)
            elif task_type == HologramTaskType.LIST_OVERLAYS.value:
                result = self.list_overlays(context=context, payload=payload)
            elif task_type == HologramTaskType.CLEAR_OVERLAYS.value:
                result = self.clear_overlays(context=context, payload=payload)
            elif task_type == HologramTaskType.HANDLE_GESTURE.value:
                result = self.handle_gesture(context=context, payload=payload)
            elif task_type == HologramTaskType.REGISTER_GESTURE.value:
                result = self.register_gesture(context=context, payload=payload)
            elif task_type == HologramTaskType.MAP_GESTURE.value:
                result = self.map_gesture(context=context, payload=payload)
            elif task_type == HologramTaskType.UPDATE_SPATIAL_CONTEXT.value:
                result = self.update_spatial_context(context=context, payload=payload)
            elif task_type == HologramTaskType.GET_SPATIAL_CONTEXT.value:
                result = self.get_spatial_context(context=context, payload=payload)
            elif task_type == HologramTaskType.CREATE_SPATIAL_ANCHOR.value:
                result = self.create_spatial_anchor(context=context, payload=payload)
            elif task_type == HologramTaskType.REMOVE_SPATIAL_ANCHOR.value:
                result = self.remove_spatial_anchor(context=context, payload=payload)
            elif task_type == HologramTaskType.PLAN_DEVICE_COMMAND.value:
                result = self.plan_device_command(context=context, payload=payload)
            elif task_type == HologramTaskType.DEVICE_STATUS.value:
                result = self.device_status(context=context, payload=payload)
            elif task_type == HologramTaskType.CREATE_NAVIGATION_OVERLAY.value:
                result = self.create_navigation_overlay(context=context, payload=payload)
            elif task_type == HologramTaskType.CREATE_NOTIFICATION_OVERLAY.value:
                result = self.create_notification_overlay(context=context, payload=payload)
            elif task_type == HologramTaskType.CREATE_OBJECT_LABEL_OVERLAY.value:
                result = self.create_object_label_overlay(context=context, payload=payload)
            elif task_type == HologramTaskType.VALIDATE_AR_PLAN.value:
                result = self.validate_ar_plan(context=context, payload=payload)
            elif task_type == HologramTaskType.MONITOR_SESSION.value:
                result = self.monitor_session(context=context, payload=payload)
            elif task_type == HologramTaskType.CALIBRATE.value:
                result = self.calibrate(context=context, payload=payload)
            else:
                result = self._error_result(
                    message=f"Task type routed but not implemented: {task_type}",
                    code="task_not_implemented",
                    context=context,
                )

            result.setdefault("metadata", {})
            result["metadata"].update(
                {
                    "agent": self.agent_name,
                    "task_type": task_type,
                    "request_id": context.request_id,
                    "started_at": started_at,
                    "finished_at": _utc_now(),
                }
            )

            self._emit_agent_event(
                event_type="hologram.task.completed" if result.get("success") else "hologram.task.failed",
                context=context,
                data={
                    "task_type": task_type,
                    "success": result.get("success"),
                    "message": result.get("message"),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("HologramAgent task failed unexpectedly.")
            return self._error_result(
                message="HologramAgent encountered an unexpected error.",
                code="hologram_agent_exception",
                context=context,
                error_details={"exception": str(exc), "type": exc.__class__.__name__},
                metadata={"started_at": started_at, "finished_at": _utc_now()},
            )

    # -------------------------------------------------------------------------
    # Public session methods
    # -------------------------------------------------------------------------

    def start_session(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Start a safe AR/hologram session.

        Real hardware activation must be performed later by device_bridge.py
        after permission checks.
        """
        payload_dict = _coerce_dict(payload)
        device_type = self._normalize_device_type(payload_dict.get("device_type"))
        dry_run = bool(payload_dict.get("dry_run", True))
        privacy_mode = bool(payload_dict.get("privacy_mode", True))
        spatial_context_enabled = bool(payload_dict.get("spatial_context_enabled", False))
        gesture_enabled = bool(payload_dict.get("gesture_enabled", True))
        device_bridge_enabled = bool(payload_dict.get("device_bridge_enabled", False))

        risk_level = self._calculate_risk(
            action="start_session",
            payload=payload_dict,
            base_risk=RiskLevel.MEDIUM.value if device_bridge_enabled else RiskLevel.LOW.value,
        )

        requires_approval = self._requires_security_check(
            action="start_session",
            payload=payload_dict,
            risk_level=risk_level,
        )

        if requires_approval and not dry_run:
            approval = self._request_security_approval(
                context=context,
                action="start_session",
                payload=payload_dict,
                risk_level=risk_level,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                return self._safe_result(
                    success=False,
                    message="AR session start is waiting for security approval.",
                    data={"approval": approval},
                    context=context,
                    error={"code": "security_approval_required"},
                )

        session = HologramSession(
            session_id=_normalize_string(payload_dict.get("session_id"), default=_make_id("ar_session")),
            device_type=device_type,
            status=HologramSessionStatus.ACTIVE.value if not dry_run else HologramSessionStatus.DRAFT.value,
            started_at=_utc_now(),
            capabilities=self._build_capabilities(device_type=device_type, payload=payload_dict),
            privacy_mode=privacy_mode,
            spatial_context_enabled=spatial_context_enabled,
            gesture_enabled=gesture_enabled,
            device_bridge_enabled=device_bridge_enabled,
            metadata={
                "dry_run": dry_run,
                "created_by": context.user_id,
                "workspace_id": context.workspace_id,
                "risk_level": risk_level,
                "requires_approval": requires_approval,
                "session_timeout_seconds": int(payload_dict.get("session_timeout_seconds", DEFAULT_SESSION_TIMEOUT_SECONDS)),
                "payload_hash": _hash_payload(payload_dict),
            },
        )

        self._session_store[self._store_key(context, session.session_id)] = session.to_dict()
        self._device_status_store[self._store_key(context, session.session_id)] = {
            "session_id": session.session_id,
            "device_type": device_type,
            "connected": False if dry_run else bool(device_bridge_enabled),
            "bridge_mode": "planned" if dry_run else "enabled",
            "last_seen_at": _utc_now(),
            "capabilities": session.capabilities,
            "privacy_mode": privacy_mode,
        }

        self._emit_agent_event(
            event_type="hologram.session.started",
            context=context,
            data=session.to_dict(),
        )

        self._log_audit_event(
            action="hologram_session_started",
            context=context,
            data={
                "session_id": session.session_id,
                "device_type": device_type,
                "dry_run": dry_run,
                "privacy_mode": privacy_mode,
                "risk_level": risk_level,
            },
        )

        return self._safe_result(
            success=True,
            message="AR/hologram session plan created successfully." if dry_run else "AR/hologram session started safely.",
            data={
                "session": session.to_dict(),
                "device_status": self._device_status_store[self._store_key(context, session.session_id)],
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="start_session",
                    result_data=session.to_dict(),
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="start_session",
                    result_data=session.to_dict(),
                ),
            },
            context=context,
        )

    def end_session(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """End a session and hide its overlays safely."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        session["status"] = HologramSessionStatus.ENDED.value
        session["ended_at"] = _utc_now()
        session.setdefault("metadata", {})["ended_by"] = context.user_id
        session["metadata"]["end_reason"] = payload_dict.get("reason", "requested")

        for overlay_id in list(session.get("overlays", [])):
            overlay = self._get_overlay(context, overlay_id)
            if overlay:
                overlay["visible"] = False
                overlay["updated_at"] = _utc_now()
                self._overlay_store[self._store_key(context, overlay_id)] = overlay

        self._session_store[self._store_key(context, session_id)] = session

        device_status = self._device_status_store.get(self._store_key(context, session_id), {})
        device_status.update(
            {
                "connected": False,
                "bridge_mode": "ended",
                "last_seen_at": _utc_now(),
            }
        )
        self._device_status_store[self._store_key(context, session_id)] = device_status

        self._emit_agent_event(
            event_type="hologram.session.ended",
            context=context,
            data={"session_id": session_id, "ended_at": session["ended_at"]},
        )

        self._log_audit_event(
            action="hologram_session_ended",
            context=context,
            data={"session_id": session_id, "reason": session["metadata"]["end_reason"]},
        )

        return self._safe_result(
            success=True,
            message="AR/hologram session ended safely.",
            data={
                "session": session,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="end_session",
                    result_data=session,
                ),
            },
            context=context,
        )

    def get_session(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Get one AR/hologram session."""
        session_id = _normalize_string(_coerce_dict(payload).get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        return self._safe_result(
            success=True,
            message="AR/hologram session loaded.",
            data={"session": session},
            context=context,
        )

    def list_sessions(self, context: HologramContext, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """List isolated AR/hologram sessions for the user/workspace."""
        payload_dict = _coerce_dict(payload)
        status_filter = _normalize_string(payload_dict.get("status"))

        sessions = []
        for key, session in self._session_store.items():
            if not key.startswith(self._store_prefix(context)):
                continue
            if status_filter and session.get("status") != status_filter:
                continue
            sessions.append(copy.deepcopy(session))

        sessions.sort(key=lambda item: item.get("started_at", ""), reverse=True)

        return self._safe_result(
            success=True,
            message="AR/hologram sessions loaded.",
            data={
                "sessions": sessions,
                "count": len(sessions),
            },
            context=context,
        )

    # -------------------------------------------------------------------------
    # Public overlay methods
    # -------------------------------------------------------------------------

    def create_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Create a safe overlay plan.

        The overlay can later be rendered by ar_overlay.py or device_bridge.py.
        """
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))

        session_result = self._ensure_session_for_overlay(context=context, payload=payload_dict)
        if not session_result["success"]:
            return session_result

        session = session_result["data"]["session"]
        session_id = session["session_id"]

        overlay_type = self._normalize_overlay_type(payload_dict.get("overlay_type") or payload_dict.get("type"))
        title = _normalize_string(payload_dict.get("title"), default=self._default_overlay_title(overlay_type))
        content = self._sanitize_overlay_content(_coerce_dict(payload_dict.get("content")))
        anchor = self._normalize_anchor(_coerce_dict(payload_dict.get("anchor")))
        style = self._normalize_style(_coerce_dict(payload_dict.get("style")))
        interaction = self._normalize_interaction(_coerce_dict(payload_dict.get("interaction")))

        current_overlay_count = len(session.get("overlays", []))
        if current_overlay_count >= int(self.config["max_overlays_per_session"]):
            return self._error_result(
                message="Maximum overlays per session exceeded.",
                code="overlay_limit_exceeded",
                context=context,
                metadata={
                    "session_id": session_id,
                    "max_overlays": self.config["max_overlays_per_session"],
                },
            )

        risk_level = self._calculate_risk(
            action="create_overlay",
            payload=payload_dict,
            base_risk=RiskLevel.MEDIUM.value if overlay_type in {OverlayType.NAVIGATION_ARROW.value, OverlayType.NOTIFICATION.value} else RiskLevel.LOW.value,
        )
        requires_approval = self._requires_security_check(
            action="create_overlay",
            payload=payload_dict,
            risk_level=risk_level,
        )
        dry_run = bool(payload_dict.get("dry_run", True))

        if requires_approval and not dry_run:
            approval = self._request_security_approval(
                context=context,
                action="create_overlay",
                payload=payload_dict,
                risk_level=risk_level,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                return self._safe_result(
                    success=False,
                    message="Overlay creation is waiting for security approval.",
                    data={"approval": approval},
                    context=context,
                    error={"code": "security_approval_required"},
                )

        overlay = HologramOverlay(
            overlay_id=_normalize_string(payload_dict.get("overlay_id"), default=_make_id("overlay")),
            session_id=session_id,
            overlay_type=overlay_type,
            title=title,
            content=content,
            anchor=anchor,
            style=style,
            interaction=interaction,
            priority=int(payload_dict.get("priority", 5)),
            visible=bool(payload_dict.get("visible", True)),
            ttl_seconds=int(payload_dict.get("ttl_seconds", DEFAULT_OVERLAY_TTL_SECONDS)),
            risk_level=risk_level,
            requires_approval=requires_approval,
            metadata={
                "created_by": context.user_id,
                "workspace_id": context.workspace_id,
                "dry_run": dry_run,
                "payload_hash": _hash_payload(payload_dict),
                "render_status": "planned" if dry_run else "queued",
            },
        )

        validation = self._validate_overlay(overlay)
        if not validation["success"]:
            return validation

        self._overlay_store[self._store_key(context, overlay.overlay_id)] = overlay.to_dict()
        session.setdefault("overlays", [])
        if overlay.overlay_id not in session["overlays"]:
            session["overlays"].append(overlay.overlay_id)
        session.setdefault("metadata", {})["updated_at"] = _utc_now()
        self._session_store[self._store_key(context, session_id)] = session

        self._emit_agent_event(
            event_type="hologram.overlay.created",
            context=context,
            data=overlay.to_dict(),
        )

        self._log_audit_event(
            action="hologram_overlay_created",
            context=context,
            data={
                "session_id": session_id,
                "overlay_id": overlay.overlay_id,
                "overlay_type": overlay.overlay_type,
                "risk_level": risk_level,
            },
        )

        return self._safe_result(
            success=True,
            message="AR overlay created successfully.",
            data={
                "overlay": overlay.to_dict(),
                "session": session,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="create_overlay",
                    result_data=overlay.to_dict(),
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="create_overlay",
                    result_data=overlay.to_dict(),
                ),
            },
            context=context,
        )

    def update_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Update an existing overlay safely."""
        payload_dict = _coerce_dict(payload)
        overlay_id = _normalize_string(payload_dict.get("overlay_id"))

        if not overlay_id:
            return self._error_result(
                message="overlay_id is required.",
                code="missing_overlay_id",
                context=context,
            )

        overlay = self._get_overlay(context, overlay_id)
        if not overlay:
            return self._error_result(
                message="Overlay not found.",
                code="overlay_not_found",
                context=context,
                metadata={"overlay_id": overlay_id},
            )

        update_fields = {
            "title",
            "content",
            "anchor",
            "style",
            "interaction",
            "priority",
            "visible",
            "ttl_seconds",
            "metadata",
        }

        for field_name in update_fields:
            if field_name not in payload_dict:
                continue
            if field_name == "content":
                overlay[field_name] = self._sanitize_overlay_content(_coerce_dict(payload_dict[field_name]))
            elif field_name == "anchor":
                overlay[field_name] = self._normalize_anchor(_coerce_dict(payload_dict[field_name]))
            elif field_name == "style":
                overlay[field_name] = self._normalize_style(_coerce_dict(payload_dict[field_name]))
            elif field_name == "interaction":
                overlay[field_name] = self._normalize_interaction(_coerce_dict(payload_dict[field_name]))
            elif field_name == "metadata":
                overlay.setdefault("metadata", {}).update(_coerce_dict(payload_dict[field_name]))
            else:
                overlay[field_name] = payload_dict[field_name]

        overlay["updated_at"] = _utc_now()
        overlay.setdefault("metadata", {})["updated_by"] = context.user_id
        overlay["metadata"]["last_update_hash"] = _hash_payload(payload_dict)

        self._overlay_store[self._store_key(context, overlay_id)] = overlay

        self._emit_agent_event(
            event_type="hologram.overlay.updated",
            context=context,
            data={"overlay_id": overlay_id, "updated_at": overlay["updated_at"]},
        )

        self._log_audit_event(
            action="hologram_overlay_updated",
            context=context,
            data={"overlay_id": overlay_id},
        )

        return self._safe_result(
            success=True,
            message="AR overlay updated successfully.",
            data={
                "overlay": overlay,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="update_overlay",
                    result_data=overlay,
                ),
            },
            context=context,
        )

    def remove_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Remove an overlay from the isolated store and session references."""
        payload_dict = _coerce_dict(payload)
        overlay_id = _normalize_string(payload_dict.get("overlay_id"))

        if not overlay_id:
            return self._error_result(
                message="overlay_id is required.",
                code="missing_overlay_id",
                context=context,
            )

        overlay = self._get_overlay(context, overlay_id)
        if not overlay:
            return self._error_result(
                message="Overlay not found.",
                code="overlay_not_found",
                context=context,
                metadata={"overlay_id": overlay_id},
            )

        session_id = overlay.get("session_id")
        session = self._get_session(context, session_id)
        if session:
            session["overlays"] = [item for item in session.get("overlays", []) if item != overlay_id]
            session.setdefault("metadata", {})["updated_at"] = _utc_now()
            self._session_store[self._store_key(context, session_id)] = session

        del self._overlay_store[self._store_key(context, overlay_id)]

        self._emit_agent_event(
            event_type="hologram.overlay.removed",
            context=context,
            data={"overlay_id": overlay_id, "session_id": session_id},
        )

        self._log_audit_event(
            action="hologram_overlay_removed",
            context=context,
            data={"overlay_id": overlay_id, "session_id": session_id},
        )

        return self._safe_result(
            success=True,
            message="AR overlay removed successfully.",
            data={
                "overlay_id": overlay_id,
                "session_id": session_id,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="remove_overlay",
                    result_data={"overlay_id": overlay_id, "session_id": session_id},
                ),
            },
            context=context,
        )

    def list_overlays(self, context: HologramContext, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """List overlays for a session or user/workspace."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        overlay_type = _normalize_string(payload_dict.get("overlay_type"))

        overlays = []
        for key, overlay in self._overlay_store.items():
            if not key.startswith(self._store_prefix(context)):
                continue
            if session_id and overlay.get("session_id") != session_id:
                continue
            if overlay_type and overlay.get("overlay_type") != overlay_type:
                continue
            overlays.append(copy.deepcopy(overlay))

        overlays.sort(key=lambda item: (item.get("priority", 5), item.get("created_at", "")))

        return self._safe_result(
            success=True,
            message="AR overlays loaded.",
            data={
                "overlays": overlays,
                "count": len(overlays),
            },
            context=context,
        )

    def clear_overlays(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Clear overlays for a session."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))

        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        removed = []
        for overlay_id in list(session.get("overlays", [])):
            key = self._store_key(context, overlay_id)
            if key in self._overlay_store:
                del self._overlay_store[key]
                removed.append(overlay_id)

        session["overlays"] = []
        session.setdefault("metadata", {})["updated_at"] = _utc_now()
        self._session_store[self._store_key(context, session_id)] = session

        self._emit_agent_event(
            event_type="hologram.overlays.cleared",
            context=context,
            data={"session_id": session_id, "removed_count": len(removed)},
        )

        self._log_audit_event(
            action="hologram_overlays_cleared",
            context=context,
            data={"session_id": session_id, "removed_count": len(removed)},
        )

        return self._safe_result(
            success=True,
            message="AR overlays cleared successfully.",
            data={
                "session_id": session_id,
                "removed_overlay_ids": removed,
                "removed_count": len(removed),
            },
            context=context,
        )

    # -------------------------------------------------------------------------
    # Gesture methods
    # -------------------------------------------------------------------------

    def handle_gesture(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Handle a gesture event.

        This maps raw gesture data to a safe internal intent without executing
        real device/system actions directly.
        """
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        if not bool(session.get("gesture_enabled", True)):
            return self._safe_result(
                success=False,
                message="Gesture handling is disabled for this session.",
                data={"session_id": session_id},
                context=context,
                error={"code": "gesture_disabled"},
            )

        gesture_type = self._normalize_gesture_type(payload_dict.get("gesture_type") or payload_dict.get("type"))
        confidence = _clamp(_safe_float(payload_dict.get("confidence"), 1.0), 0.0, 1.0)

        if confidence < float(self.config["gesture_confidence_threshold"]):
            intent = GestureIntent.NONE.value
            status_message = "Gesture ignored because confidence is below threshold."
        else:
            intent = self._gesture_to_intent(context=context, session_id=session_id, gesture_type=gesture_type, payload=payload_dict)
            status_message = "Gesture handled safely."

        gesture_event = GestureEvent(
            gesture_id=_make_id("gesture"),
            session_id=session_id,
            gesture_type=gesture_type,
            intent=intent,
            confidence=confidence,
            target_overlay_id=_normalize_string(payload_dict.get("target_overlay_id")) or None,
            position=self._vector_from_payload(payload_dict.get("position")) if payload_dict.get("position") else None,
            raw_event_hash=_hash_payload(payload_dict),
            metadata={
                "source": payload_dict.get("source", "gesture_bridge"),
                "threshold": self.config["gesture_confidence_threshold"],
                "dry_run": bool(payload_dict.get("dry_run", True)),
            },
        )

        routed_action = self._route_gesture_intent(context=context, gesture_event=gesture_event)

        self._emit_agent_event(
            event_type="hologram.gesture.handled",
            context=context,
            data=gesture_event.to_dict(),
        )

        self._log_audit_event(
            action="hologram_gesture_handled",
            context=context,
            data={
                "session_id": session_id,
                "gesture_type": gesture_type,
                "intent": intent,
                "confidence": confidence,
            },
        )

        return self._safe_result(
            success=True,
            message=status_message,
            data={
                "gesture": gesture_event.to_dict(),
                "routed_action": routed_action,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="handle_gesture",
                    result_data=gesture_event.to_dict(),
                ),
            },
            context=context,
        )

    def register_gesture(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Register a gesture-to-intent mapping for a session/workspace."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"), default="global")
        gesture_type = self._normalize_gesture_type(payload_dict.get("gesture_type"))
        intent = self._normalize_gesture_intent(payload_dict.get("intent"))

        key = self._gesture_map_key(context=context, session_id=session_id, gesture_type=gesture_type)
        mapping = {
            "session_id": session_id,
            "gesture_type": gesture_type,
            "intent": intent,
            "target_overlay_id": _normalize_string(payload_dict.get("target_overlay_id")) or None,
            "created_at": _utc_now(),
            "created_by": context.user_id,
            "metadata": _coerce_dict(payload_dict.get("metadata")),
        }
        self._gesture_map_store[key] = mapping

        return self._safe_result(
            success=True,
            message="Gesture mapping registered successfully.",
            data={
                "mapping": mapping,
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="register_gesture",
                    result_data=mapping,
                ),
            },
            context=context,
        )

    def map_gesture(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Map a gesture type to its current safe intent."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"), default="global")
        gesture_type = self._normalize_gesture_type(payload_dict.get("gesture_type"))

        intent = self._gesture_to_intent(
            context=context,
            session_id=session_id,
            gesture_type=gesture_type,
            payload=payload_dict,
        )

        return self._safe_result(
            success=True,
            message="Gesture mapped successfully.",
            data={
                "session_id": session_id,
                "gesture_type": gesture_type,
                "intent": intent,
            },
            context=context,
        )

    # -------------------------------------------------------------------------
    # Spatial context methods
    # -------------------------------------------------------------------------

    def update_spatial_context(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Update privacy-safe spatial context.

        This method stores only sanitized summaries and hashes. It should not
        store raw camera frames, faces, biometric signals, or precise private
        location unless future Security Agent policy explicitly allows it.
        """
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        risk_level = self._calculate_risk(
            action="update_spatial_context",
            payload=payload_dict,
            base_risk=RiskLevel.HIGH.value if payload_dict.get("raw_frame") or payload_dict.get("camera") else RiskLevel.MEDIUM.value,
        )

        dry_run = bool(payload_dict.get("dry_run", True))
        if self._requires_security_check("update_spatial_context", payload_dict, risk_level) and not dry_run:
            approval = self._request_security_approval(
                context=context,
                action="update_spatial_context",
                payload=payload_dict,
                risk_level=risk_level,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                return self._safe_result(
                    success=False,
                    message="Spatial context update is waiting for security approval.",
                    data={"approval": approval},
                    context=context,
                    error={"code": "security_approval_required"},
                )

        sanitized_context = self._sanitize_spatial_context(payload_dict)
        sanitized_context.update(
            {
                "session_id": session_id,
                "updated_at": _utc_now(),
                "risk_level": risk_level,
                "privacy_mode": bool(session.get("privacy_mode", True)),
                "raw_payload_hash": _hash_payload(payload_dict),
            }
        )

        self._spatial_context_store[self._store_key(context, session_id)] = sanitized_context
        session["spatial_context_enabled"] = True
        session.setdefault("metadata", {})["spatial_context_updated_at"] = sanitized_context["updated_at"]
        self._session_store[self._store_key(context, session_id)] = session

        self._emit_agent_event(
            event_type="hologram.spatial_context.updated",
            context=context,
            data={
                "session_id": session_id,
                "updated_at": sanitized_context["updated_at"],
                "risk_level": risk_level,
            },
        )

        self._log_audit_event(
            action="hologram_spatial_context_updated",
            context=context,
            data={
                "session_id": session_id,
                "risk_level": risk_level,
                "stored_raw_camera_data": False,
            },
        )

        return self._safe_result(
            success=True,
            message="Privacy-safe spatial context updated successfully.",
            data={
                "spatial_context": sanitized_context,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="update_spatial_context",
                    result_data=sanitized_context,
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="update_spatial_context",
                    result_data=sanitized_context,
                ),
            },
            context=context,
        )

    def get_spatial_context(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Get sanitized spatial context for a session."""
        session_id = _normalize_string(_coerce_dict(payload).get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        spatial_context = self._spatial_context_store.get(self._store_key(context, session_id), {})
        return self._safe_result(
            success=True,
            message="Privacy-safe spatial context loaded.",
            data={
                "session_id": session_id,
                "spatial_context": copy.deepcopy(spatial_context),
                "has_context": bool(spatial_context),
            },
            context=context,
        )

    def create_spatial_anchor(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Create a spatial anchor for world/object/head locked overlays."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        if len(session.get("anchors", [])) >= int(self.config["max_anchors_per_session"]):
            return self._error_result(
                message="Maximum spatial anchors per session exceeded.",
                code="anchor_limit_exceeded",
                context=context,
                metadata={"session_id": session_id, "max_anchors": self.config["max_anchors_per_session"]},
            )

        anchor_mode = self._normalize_anchor_mode(payload_dict.get("mode") or payload_dict.get("anchor_mode"))
        anchor = SpatialAnchor(
            anchor_id=_normalize_string(payload_dict.get("anchor_id"), default=_make_id("anchor")),
            name=_normalize_string(payload_dict.get("name"), default="Spatial Anchor"),
            mode=anchor_mode,
            position=self._vector_from_payload(payload_dict.get("position")),
            rotation=self._quaternion_from_payload(payload_dict.get("rotation")),
            object_ref=_normalize_string(payload_dict.get("object_ref")) or None,
            confidence=_clamp(_safe_float(payload_dict.get("confidence"), 1.0), 0.0, 1.0),
            metadata={
                "session_id": session_id,
                "created_by": context.user_id,
                "workspace_id": context.workspace_id,
                "payload_hash": _hash_payload(payload_dict),
            },
        )

        self._anchor_store[self._store_key(context, anchor.anchor_id)] = anchor.to_dict()
        session.setdefault("anchors", [])
        if anchor.anchor_id not in session["anchors"]:
            session["anchors"].append(anchor.anchor_id)
        session.setdefault("metadata", {})["updated_at"] = _utc_now()
        self._session_store[self._store_key(context, session_id)] = session

        return self._safe_result(
            success=True,
            message="Spatial anchor created successfully.",
            data={
                "anchor": anchor.to_dict(),
                "session": session,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="create_spatial_anchor",
                    result_data=anchor.to_dict(),
                ),
            },
            context=context,
        )

    def remove_spatial_anchor(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Remove a spatial anchor."""
        payload_dict = _coerce_dict(payload)
        anchor_id = _normalize_string(payload_dict.get("anchor_id"))
        session_id = _normalize_string(payload_dict.get("session_id"))

        if not anchor_id:
            return self._error_result(
                message="anchor_id is required.",
                code="missing_anchor_id",
                context=context,
            )

        anchor = self._anchor_store.get(self._store_key(context, anchor_id))
        if not anchor:
            return self._error_result(
                message="Spatial anchor not found.",
                code="anchor_not_found",
                context=context,
                metadata={"anchor_id": anchor_id},
            )

        if not session_id:
            session_id = _normalize_string(_coerce_dict(anchor.get("metadata")).get("session_id"))

        session = self._get_session(context, session_id)
        if session:
            session["anchors"] = [item for item in session.get("anchors", []) if item != anchor_id]
            session.setdefault("metadata", {})["updated_at"] = _utc_now()
            self._session_store[self._store_key(context, session_id)] = session

        del self._anchor_store[self._store_key(context, anchor_id)]

        return self._safe_result(
            success=True,
            message="Spatial anchor removed successfully.",
            data={
                "anchor_id": anchor_id,
                "session_id": session_id,
            },
            context=context,
        )

    # -------------------------------------------------------------------------
    # Device / special overlay methods
    # -------------------------------------------------------------------------

    def plan_device_command(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Plan a device bridge command.

        This does not execute real hardware commands. Future device_bridge.py
        must perform real execution after Security Agent approval.
        """
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        command = _normalize_string(payload_dict.get("command"))
        dry_run = bool(payload_dict.get("dry_run", True))

        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )
        if not command:
            return self._error_result(
                message="command is required.",
                code="missing_device_command",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        command_plan = {
            "command_id": _make_id("device_cmd"),
            "session_id": session_id,
            "command": command,
            "parameters": self._redact_sensitive_values(_coerce_dict(payload_dict.get("parameters"))),
            "dry_run": dry_run,
            "created_at": _utc_now(),
            "execution_status": "planned",
            "side_effect_executed": False,
            "device_type": session.get("device_type", DeviceType.UNKNOWN.value),
        }

        risk_level = self._calculate_risk(
            action="device_command",
            payload=command_plan,
            base_risk=RiskLevel.HIGH.value,
        )

        if self._requires_security_check("device_command", command_plan, risk_level) and not dry_run:
            approval = self._request_security_approval(
                context=context,
                action="device_command",
                payload=command_plan,
                risk_level=risk_level,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                command_plan["execution_status"] = "waiting_approval"
                return self._safe_result(
                    success=False,
                    message="Device command is waiting for security approval.",
                    data={
                        "command_plan": command_plan,
                        "approval": approval,
                    },
                    context=context,
                    error={"code": "security_approval_required"},
                )

        self._log_audit_event(
            action="hologram_device_command_planned",
            context=context,
            data={
                "session_id": session_id,
                "command": command,
                "risk_level": risk_level,
                "dry_run": dry_run,
            },
        )

        return self._safe_result(
            success=True,
            message="Device command plan created safely.",
            data={
                "command_plan": command_plan,
                "risk_level": risk_level,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="plan_device_command",
                    result_data=command_plan,
                ),
            },
            context=context,
        )

    def device_status(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Get current safe device bridge status."""
        session_id = _normalize_string(_coerce_dict(payload).get("session_id"))
        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        status = self._device_status_store.get(self._store_key(context, session_id), {})
        return self._safe_result(
            success=True,
            message="Device status loaded.",
            data={
                "session_id": session_id,
                "device_status": copy.deepcopy(status),
                "has_status": bool(status),
            },
            context=context,
        )

    def create_navigation_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Create a navigation overlay plan."""
        payload_dict = _coerce_dict(payload)
        destination = self._sanitize_location_payload(_coerce_dict(payload_dict.get("destination")))
        route_summary = self._sanitize_route_payload(_coerce_dict(payload_dict.get("route_summary")))

        overlay_payload = dict(payload_dict)
        overlay_payload.update(
            {
                "overlay_type": OverlayType.NAVIGATION_ARROW.value,
                "title": payload_dict.get("title", "Navigation"),
                "content": {
                    "destination": destination,
                    "route_summary": route_summary,
                    "instructions": _as_list(payload_dict.get("instructions")),
                    "privacy_note": "Exact location data is sanitized by HologramAgent.",
                },
                "anchor": payload_dict.get("anchor", {"mode": AnchorMode.HEAD_LOCKED.value}),
                "priority": payload_dict.get("priority", 2),
            }
        )
        return self.create_overlay(context=context, payload=overlay_payload)

    def create_notification_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Create a notification overlay plan."""
        payload_dict = _coerce_dict(payload)
        severity = _normalize_string(payload_dict.get("severity"), "info").lower()
        if severity not in {"info", "success", "warning", "error", "critical"}:
            severity = "info"

        overlay_payload = dict(payload_dict)
        overlay_payload.update(
            {
                "overlay_type": OverlayType.NOTIFICATION.value,
                "title": payload_dict.get("title", "Notification"),
                "content": {
                    "message": _normalize_string(payload_dict.get("message"), "New notification"),
                    "severity": severity,
                    "actions": self._sanitize_overlay_actions(_as_list(payload_dict.get("actions"))),
                },
                "anchor": payload_dict.get("anchor", {"mode": AnchorMode.HEAD_LOCKED.value}),
                "priority": payload_dict.get("priority", 1 if severity in {"critical", "error"} else 4),
            }
        )
        return self.create_overlay(context=context, payload=overlay_payload)

    def create_object_label_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Create object label overlay.

        This does not run object recognition. Future object_recognizer.py should
        produce safe object_ref and label metadata.
        """
        payload_dict = _coerce_dict(payload)
        object_ref = _normalize_string(payload_dict.get("object_ref"), default=_make_id("object"))
        label = _normalize_string(payload_dict.get("label"), default="Object")

        overlay_payload = dict(payload_dict)
        overlay_payload.update(
            {
                "overlay_type": OverlayType.OBJECT_LABEL.value,
                "title": label,
                "content": {
                    "object_ref": object_ref,
                    "label": label,
                    "confidence": _clamp(_safe_float(payload_dict.get("confidence"), 1.0), 0.0, 1.0),
                    "attributes": self._redact_sensitive_values(_coerce_dict(payload_dict.get("attributes"))),
                },
                "anchor": payload_dict.get(
                    "anchor",
                    {
                        "mode": AnchorMode.OBJECT_LOCKED.value,
                        "object_ref": object_ref,
                    },
                ),
                "priority": payload_dict.get("priority", 5),
            }
        )
        return self.create_overlay(context=context, payload=overlay_payload)

    def validate_ar_plan(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate AR session/overlay plan."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        overlay_id = _normalize_string(payload_dict.get("overlay_id"))
        issues: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        session = self._get_session(context, session_id) if session_id else None
        overlay = self._get_overlay(context, overlay_id) if overlay_id else None

        if session_id and not session:
            issues.append({"code": "session_not_found", "message": "Session does not exist.", "session_id": session_id})

        if overlay_id and not overlay:
            issues.append({"code": "overlay_not_found", "message": "Overlay does not exist.", "overlay_id": overlay_id})

        if session:
            if len(session.get("overlays", [])) > int(self.config["max_overlays_per_session"]):
                issues.append({"code": "too_many_overlays", "message": "Session exceeds overlay limit."})
            if not session.get("privacy_mode", True):
                warnings.append({"code": "privacy_mode_disabled", "message": "Privacy mode is disabled for this session."})
            if session.get("status") == HologramSessionStatus.ENDED.value:
                warnings.append({"code": "session_ended", "message": "Session already ended."})

        if overlay:
            overlay_obj = self._overlay_from_dict(overlay)
            validation = self._validate_overlay(overlay_obj)
            if not validation.get("success"):
                issues.append({"code": "invalid_overlay", "message": validation.get("message"), "error": validation.get("error")})

        valid = len(issues) == 0

        return self._safe_result(
            success=valid,
            message="AR plan validation passed." if valid else "AR plan validation failed.",
            data={
                "valid": valid,
                "issues": issues,
                "warnings": warnings,
                "session_id": session_id,
                "overlay_id": overlay_id,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="validate_ar_plan",
                    result_data={"valid": valid, "issues": issues, "warnings": warnings},
                ),
            },
            context=context,
            error=None if valid else {"code": "ar_plan_validation_failed", "issues": issues},
        )

    def monitor_session(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare monitoring summary for AR/hologram session."""
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))

        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        overlays = [
            self._get_overlay(context, overlay_id)
            for overlay_id in session.get("overlays", [])
            if self._get_overlay(context, overlay_id)
        ]

        active_overlays = [item for item in overlays if item and item.get("visible", True)]
        expired_overlays = [item for item in overlays if item and self._overlay_expired(item)]
        device_status = self._device_status_store.get(self._store_key(context, session_id), {})
        spatial_context = self._spatial_context_store.get(self._store_key(context, session_id), {})

        health = "healthy"
        warnings = []
        if session.get("status") in {HologramSessionStatus.FAILED.value, HologramSessionStatus.ENDED.value}:
            health = session.get("status")
        if len(active_overlays) > int(self.config["max_overlays_per_session"]) * 0.8:
            health = "degraded"
            warnings.append("Overlay count is close to the session limit.")
        if not session.get("privacy_mode", True):
            warnings.append("Privacy mode is disabled.")

        summary = {
            "session_id": session_id,
            "status": session.get("status"),
            "health": health,
            "device_type": session.get("device_type"),
            "device_connected": bool(device_status.get("connected", False)),
            "overlay_count": len(overlays),
            "active_overlay_count": len(active_overlays),
            "expired_overlay_count": len(expired_overlays),
            "anchor_count": len(session.get("anchors", [])),
            "has_spatial_context": bool(spatial_context),
            "privacy_mode": bool(session.get("privacy_mode", True)),
            "warnings": warnings,
            "checked_at": _utc_now(),
        }

        return self._safe_result(
            success=True,
            message="AR/hologram session monitoring summary prepared.",
            data={
                "monitoring": summary,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="monitor_session",
                    result_data=summary,
                ),
            },
            context=context,
        )

    def calibrate(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare calibration plan.

        This does not control real camera/sensors. Future device_bridge.py and
        spatial_mapper.py should perform real calibration after approval.
        """
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))
        dry_run = bool(payload_dict.get("dry_run", True))

        if not session_id:
            return self._error_result(
                message="session_id is required.",
                code="missing_session_id",
                context=context,
            )

        session = self._get_session(context, session_id)
        if not session:
            return self._error_result(
                message="AR/hologram session not found.",
                code="session_not_found",
                context=context,
                metadata={"session_id": session_id},
            )

        calibration_plan = {
            "calibration_id": _make_id("calibration"),
            "session_id": session_id,
            "device_type": session.get("device_type"),
            "steps": [
                "verify_device_capabilities",
                "confirm_privacy_mode",
                "estimate_display_bounds",
                "test_anchor_alignment",
                "test_gesture_confidence",
                "prepare_verification_snapshot",
            ],
            "dry_run": dry_run,
            "side_effect_executed": False,
            "created_at": _utc_now(),
        }

        if not dry_run:
            approval = self._request_security_approval(
                context=context,
                action="calibrate",
                payload=calibration_plan,
                risk_level=RiskLevel.MEDIUM.value,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                return self._safe_result(
                    success=False,
                    message="Calibration is waiting for security approval.",
                    data={"calibration_plan": calibration_plan, "approval": approval},
                    context=context,
                    error={"code": "security_approval_required"},
                )

        return self._safe_result(
            success=True,
            message="Calibration plan prepared successfully.",
            data={
                "calibration_plan": calibration_plan,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="calibrate",
                    result_data=calibration_plan,
                ),
            },
            context=context,
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required by William/Jarvis architecture.
        """
        task_dict = _coerce_dict(task)
        user_id = _normalize_string(task_dict.get("user_id"))
        workspace_id = _normalize_string(task_dict.get("workspace_id"))

        payload = _coerce_dict(task_dict.get("payload"))
        if not user_id:
            user_id = _normalize_string(payload.get("user_id"))
        if not workspace_id:
            workspace_id = _normalize_string(payload.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="user_id is required for HologramAgent task isolation.",
                code="missing_user_id",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for HologramAgent task isolation.",
                code="missing_workspace_id",
            )

        context = HologramContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=_normalize_string(task_dict.get("request_id"), default=str(uuid.uuid4())),
            actor_id=_normalize_string(task_dict.get("actor_id")) or None,
            role=_normalize_string(task_dict.get("role")) or None,
            source=_normalize_string(task_dict.get("source"), default="hologram_agent"),
            session_ref=_normalize_string(task_dict.get("session_ref")) or _normalize_string(payload.get("session_id")) or None,
            permissions=[_normalize_string(item) for item in _as_list(task_dict.get("permissions"))],
            metadata=_coerce_dict(task_dict.get("metadata")),
        )

        return self._safe_result(
            success=True,
            message="Hologram task context validated.",
            data={"context": context},
            context=context,
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
        risk_level: str = RiskLevel.LOW.value,
    ) -> bool:
        """
        Decide whether action needs Security Agent approval.

        Required by William/Jarvis architecture.
        """
        action_norm = _normalize_string(action).lower()
        payload_dict = _coerce_dict(payload)
        payload_text = _safe_json_dumps(payload_dict).lower()

        if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
            return True

        if action_norm in SENSITIVE_ACTION_KEYWORDS:
            return True

        for keyword in SENSITIVE_ACTION_KEYWORDS:
            if keyword in action_norm or keyword in payload_text:
                return True

        return False

    def _request_security_approval(
        self,
        context: HologramContext,
        action: str,
        payload: Mapping[str, Any],
        risk_level: str = RiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Required by William/Jarvis architecture.
        """
        request = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "agent": self.agent_name,
            "action": action,
            "risk_level": risk_level,
            "payload_hash": _hash_payload(payload),
            "payload_preview": self._safe_preview(payload),
            "privacy_domain": "ar_hologram_spatial_device_context",
            "timestamp": _utc_now(),
        }

        try:
            if hasattr(self.security_agent, "check_permission"):
                raw = self.security_agent.check_permission(request)
            elif hasattr(self.security_agent, "run"):
                raw = self.security_agent.run(
                    {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "task_type": "check_permission",
                        "payload": request,
                    }
                )
            else:
                raw = {
                    "success": False,
                    "approved": False,
                    "message": "Security agent has no compatible approval method.",
                }

            raw_dict = _coerce_dict(raw)
            approved = bool(raw_dict.get("approved", raw_dict.get("success", False)))

            result = self._safe_result(
                success=bool(raw_dict.get("success", approved)),
                message=_normalize_string(raw_dict.get("message"), "Security approval processed."),
                data={
                    "approved": approved,
                    "security_result": raw_dict,
                    "request": request,
                },
                context=context,
                error=raw_dict.get("error"),
            )

            self._log_audit_event(
                action="security_approval_requested",
                context=context,
                data={
                    "hologram_action": action,
                    "risk_level": risk_level,
                    "approved": approved,
                    "payload_hash": request["payload_hash"],
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                code="security_approval_error",
                context=context,
                error_details={"exception": str(exc), "type": exc.__class__.__name__},
            )

    def _prepare_verification_payload(
        self,
        context: HologramContext,
        action: str,
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by William/Jarvis architecture.
        """
        payload = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "agent": self.agent_name,
            "action": action,
            "result_hash": _hash_payload(result_data),
            "result_preview": self._safe_preview(result_data),
            "verification_type": "hologram_ar_action",
            "timestamp": _utc_now(),
            "checks": [
                "context_isolation",
                "structured_result",
                "privacy_sanitization",
                "security_gate_checked_when_required",
                "overlay_state_consistency",
                "spatial_context_safety",
            ],
        }

        try:
            if hasattr(self.verification_agent, "prepare_payload"):
                prepared = self.verification_agent.prepare_payload(payload)
                return _coerce_dict(prepared)
        except Exception:
            self.logger.debug("VerificationAgent fallback payload used.", exc_info=True)

        return payload

    def _prepare_memory_payload(
        self,
        context: HologramContext,
        action: str,
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Required by William/Jarvis architecture.
        """
        payload = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "agent": self.agent_name,
            "action": action,
            "memory_type": "hologram_context",
            "timestamp": _utc_now(),
            "content": {
                "summary": f"HologramAgent completed action: {action}",
                "result_hash": _hash_payload(result_data),
                "safe_preview": self._safe_preview(result_data),
            },
            "isolation": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "privacy": {
                "stores_raw_camera_frames": False,
                "stores_biometrics": False,
                "stores_precise_location_by_default": False,
            },
        }

        try:
            if hasattr(self.memory_agent, "prepare_payload"):
                prepared = self.memory_agent.prepare_payload(payload)
                return _coerce_dict(prepared)
        except Exception:
            self.logger.debug("MemoryAgent fallback payload used.", exc_info=True)

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        context: Optional[HologramContext] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit agent event.

        Required by William/Jarvis architecture.
        """
        event = {
            "event_id": _make_id("evt"),
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": _utc_now(),
            "context": context.to_dict() if context else {},
            "data": _coerce_dict(data),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", _safe_json_dumps(event))
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[HologramContext] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Required by William/Jarvis architecture.
        """
        event = {
            "audit_id": _make_id("audit"),
            "action": action,
            "agent": self.agent_name,
            "timestamp": _utc_now(),
            "context": context.to_dict() if context else {},
            "data": _coerce_dict(data),
        }

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                self.logger.debug("Audit event: %s", _safe_json_dumps(event))
        except Exception:
            self.logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        context: Optional[HologramContext] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build standard structured result.

        Required by William/Jarvis architecture.
        """
        final_metadata = _coerce_dict(metadata)
        final_metadata.setdefault("agent", self.agent_name)
        final_metadata.setdefault("timestamp", _utc_now())

        if context:
            final_metadata.setdefault("user_id", context.user_id)
            final_metadata.setdefault("workspace_id", context.workspace_id)
            final_metadata.setdefault("request_id", context.request_id)

        return {
            "success": bool(success),
            "message": message,
            "data": _coerce_dict(data),
            "error": _coerce_dict(error) if error else None,
            "metadata": final_metadata,
        }

    def _error_result(
        self,
        message: str,
        code: str,
        context: Optional[HologramContext] = None,
        error_details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build standard structured error result.

        Required by William/Jarvis architecture.
        """
        error = {
            "code": code,
            "message": message,
            "details": _coerce_dict(error_details),
        }
        return self._safe_result(
            success=False,
            message=message,
            data={},
            context=context,
            error=error,
            metadata=metadata,
        )

    # -------------------------------------------------------------------------
    # Internal config/store helpers
    # -------------------------------------------------------------------------

    def _load_default_config(self, config: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Load safe default configuration."""
        defaults = {
            "default_dry_run": True,
            "session_timeout_seconds": DEFAULT_SESSION_TIMEOUT_SECONDS,
            "overlay_ttl_seconds": DEFAULT_OVERLAY_TTL_SECONDS,
            "max_overlays_per_session": DEFAULT_MAX_OVERLAYS_PER_SESSION,
            "max_anchors_per_session": DEFAULT_MAX_ANCHORS_PER_SESSION,
            "gesture_confidence_threshold": DEFAULT_GESTURE_CONFIDENCE_THRESHOLD,
            "allow_real_device_commands": False,
            "allow_raw_camera_storage": False,
            "allow_biometric_storage": False,
            "allow_precise_location_storage": False,
            "allowed_device_types": [item.value for item in DeviceType],
            "allowed_overlay_types": [item.value for item in OverlayType],
            "allowed_anchor_modes": [item.value for item in AnchorMode],
            "allowed_gesture_types": [item.value for item in GestureType],
            "sensitive_actions": sorted(SENSITIVE_ACTION_KEYWORDS),
        }
        if config:
            defaults.update(_coerce_dict(config))
        return defaults

    def _store_prefix(self, context: HologramContext) -> str:
        """Build isolated store key prefix."""
        return f"{context.user_id}:{context.workspace_id}:"

    def _store_key(self, context: HologramContext, object_id: str) -> str:
        """Build isolated store key."""
        return f"{context.user_id}:{context.workspace_id}:{object_id}"

    def _get_session(self, context: HologramContext, session_id: str) -> Optional[Dict[str, Any]]:
        """Load session from isolated store."""
        if not session_id:
            return None
        session = self._session_store.get(self._store_key(context, session_id))
        return copy.deepcopy(session) if session else None

    def _get_overlay(self, context: HologramContext, overlay_id: str) -> Optional[Dict[str, Any]]:
        """Load overlay from isolated store."""
        if not overlay_id:
            return None
        overlay = self._overlay_store.get(self._store_key(context, overlay_id))
        return copy.deepcopy(overlay) if overlay else None

    def _ensure_session_for_overlay(self, context: HologramContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Ensure a session exists for overlay creation.

        If no session_id is supplied, create a desktop_preview draft session for
        dashboard/API preview use.
        """
        payload_dict = _coerce_dict(payload)
        session_id = _normalize_string(payload_dict.get("session_id"))

        if session_id:
            session = self._get_session(context, session_id)
            if not session:
                return self._error_result(
                    message="AR/hologram session not found.",
                    code="session_not_found",
                    context=context,
                    metadata={"session_id": session_id},
                )
            if session.get("status") == HologramSessionStatus.ENDED.value:
                return self._error_result(
                    message="Cannot create overlay in an ended session.",
                    code="session_ended",
                    context=context,
                    metadata={"session_id": session_id},
                )
            return self._safe_result(
                success=True,
                message="Session ready.",
                data={"session": session},
                context=context,
            )

        session_result = self.start_session(
            context=context,
            payload={
                "device_type": DeviceType.DESKTOP_PREVIEW.value,
                "dry_run": True,
                "privacy_mode": True,
                "gesture_enabled": True,
                "spatial_context_enabled": False,
                "device_bridge_enabled": False,
            },
        )
        if not session_result.get("success"):
            return session_result

        return self._safe_result(
            success=True,
            message="Preview session created for overlay.",
            data={"session": session_result["data"]["session"]},
            context=context,
        )

    # -------------------------------------------------------------------------
    # Normalization / validation helpers
    # -------------------------------------------------------------------------

    def _normalize_device_type(self, value: Any) -> str:
        """Normalize device type."""
        text = _normalize_string(value, DeviceType.UNKNOWN.value).lower()
        if text in {item.value for item in DeviceType}:
            return text
        return DeviceType.UNKNOWN.value

    def _normalize_overlay_type(self, value: Any) -> str:
        """Normalize overlay type."""
        text = _normalize_string(value, OverlayType.CUSTOM.value).lower()
        if text in {item.value for item in OverlayType}:
            return text
        return OverlayType.CUSTOM.value

    def _normalize_anchor_mode(self, value: Any) -> str:
        """Normalize anchor mode."""
        text = _normalize_string(value, AnchorMode.HEAD_LOCKED.value).lower()
        if text in {item.value for item in AnchorMode}:
            return text
        return AnchorMode.HEAD_LOCKED.value

    def _normalize_gesture_type(self, value: Any) -> str:
        """Normalize gesture type."""
        text = _normalize_string(value, GestureType.UNKNOWN.value).lower()
        if text in {item.value for item in GestureType}:
            return text
        return GestureType.UNKNOWN.value

    def _normalize_gesture_intent(self, value: Any) -> str:
        """Normalize gesture intent."""
        text = _normalize_string(value, GestureIntent.NONE.value).lower()
        if text in {item.value for item in GestureIntent}:
            return text
        return GestureIntent.NONE.value

    def _default_overlay_title(self, overlay_type: str) -> str:
        """Return default title by overlay type."""
        titles = {
            OverlayType.ASSISTANT_PANEL.value: "William Assistant",
            OverlayType.DASHBOARD_CARD.value: "Dashboard",
            OverlayType.NAVIGATION_ARROW.value: "Navigation",
            OverlayType.NOTIFICATION.value: "Notification",
            OverlayType.OBJECT_LABEL.value: "Object",
            OverlayType.CONTEXT_TOOLTIP.value: "Context",
            OverlayType.FLOATING_MENU.value: "Menu",
            OverlayType.STATUS_BADGE.value: "Status",
            OverlayType.WARNING.value: "Warning",
            OverlayType.CUSTOM.value: "Overlay",
        }
        return titles.get(overlay_type, "Overlay")

    def _build_capabilities(self, device_type: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Build safe capabilities profile."""
        requested = _coerce_dict(payload.get("capabilities"))
        defaults = {
            "supports_overlays": True,
            "supports_world_anchors": device_type in {
                DeviceType.AR_GLASSES.value,
                DeviceType.MIXED_REALITY_HEADSET.value,
                DeviceType.MOBILE_AR.value,
            },
            "supports_hand_gestures": device_type in {
                DeviceType.AR_GLASSES.value,
                DeviceType.VR_HEADSET.value,
                DeviceType.MIXED_REALITY_HEADSET.value,
            },
            "supports_voice": False,
            "supports_camera": False,
            "supports_microphone": False,
            "supports_navigation": False,
            "supports_object_labels": True,
            "supports_notifications": True,
            "safe_preview_only": device_type == DeviceType.DESKTOP_PREVIEW.value,
        }
        defaults.update(requested)
        return defaults

    def _normalize_anchor(self, anchor: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize overlay anchor payload."""
        anchor_dict = _coerce_dict(anchor)
        mode = self._normalize_anchor_mode(anchor_dict.get("mode"))
        normalized = {
            "mode": mode,
            "anchor_id": _normalize_string(anchor_dict.get("anchor_id")) or None,
            "object_ref": _normalize_string(anchor_dict.get("object_ref")) or None,
            "position": self._vector_from_payload(anchor_dict.get("position")).to_dict(),
            "rotation": self._quaternion_from_payload(anchor_dict.get("rotation")).to_dict(),
            "offset": self._vector_from_payload(anchor_dict.get("offset")).to_dict(),
        }
        return normalized

    def _normalize_style(self, style: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize overlay style with safe defaults."""
        style_dict = _coerce_dict(style)
        return {
            "theme": _normalize_string(style_dict.get("theme"), "william_default"),
            "opacity": _clamp(_safe_float(style_dict.get("opacity"), 0.92), 0.0, 1.0),
            "scale": _clamp(_safe_float(style_dict.get("scale"), 1.0), 0.1, 10.0),
            "width": _clamp(_safe_float(style_dict.get("width"), 0.35), 0.05, 5.0),
            "height": _clamp(_safe_float(style_dict.get("height"), 0.2), 0.05, 5.0),
            "depth": _clamp(_safe_float(style_dict.get("depth"), 0.01), 0.0, 1.0),
            "color": _normalize_string(style_dict.get("color"), "#6400B3"),
            "background": _normalize_string(style_dict.get("background"), "rgba(16,16,16,0.82)"),
            "text_color": _normalize_string(style_dict.get("text_color"), "#FFFFFF"),
            "animation": _normalize_string(style_dict.get("animation"), "fade_in"),
            "safe_area": bool(style_dict.get("safe_area", True)),
        }

    def _normalize_interaction(self, interaction: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize overlay interaction rules."""
        interaction_dict = _coerce_dict(interaction)
        return {
            "selectable": bool(interaction_dict.get("selectable", True)),
            "draggable": bool(interaction_dict.get("draggable", False)),
            "dismissible": bool(interaction_dict.get("dismissible", True)),
            "gesture_intents": [
                self._normalize_gesture_intent(item)
                for item in _as_list(interaction_dict.get("gesture_intents", [GestureIntent.SELECT.value]))
            ],
            "voice_enabled": bool(interaction_dict.get("voice_enabled", False)),
            "actions": self._sanitize_overlay_actions(_as_list(interaction_dict.get("actions"))),
        }

    def _validate_overlay(self, overlay: HologramOverlay) -> Dict[str, Any]:
        """Validate overlay before storing/rendering."""
        if not overlay.overlay_id:
            return self._error_result(message="Overlay is missing overlay_id.", code="invalid_overlay")
        if not overlay.session_id:
            return self._error_result(message="Overlay is missing session_id.", code="invalid_overlay")
        if overlay.overlay_type not in {item.value for item in OverlayType}:
            return self._error_result(message="Unsupported overlay_type.", code="invalid_overlay")
        if not overlay.title:
            return self._error_result(message="Overlay title is required.", code="invalid_overlay")
        if overlay.ttl_seconds < 1:
            return self._error_result(message="Overlay ttl_seconds must be positive.", code="invalid_overlay")
        return self._safe_result(success=True, message="Overlay is valid.", data={"overlay_id": overlay.overlay_id})

    def _overlay_from_dict(self, data: Mapping[str, Any]) -> HologramOverlay:
        """Rebuild HologramOverlay dataclass from dict."""
        data_dict = _coerce_dict(data)
        return HologramOverlay(
            overlay_id=_normalize_string(data_dict.get("overlay_id")),
            session_id=_normalize_string(data_dict.get("session_id")),
            overlay_type=self._normalize_overlay_type(data_dict.get("overlay_type")),
            title=_normalize_string(data_dict.get("title")),
            content=_coerce_dict(data_dict.get("content")),
            anchor=_coerce_dict(data_dict.get("anchor")),
            style=_coerce_dict(data_dict.get("style")),
            interaction=_coerce_dict(data_dict.get("interaction")),
            priority=int(data_dict.get("priority", 5)),
            visible=bool(data_dict.get("visible", True)),
            ttl_seconds=int(data_dict.get("ttl_seconds", DEFAULT_OVERLAY_TTL_SECONDS)),
            risk_level=_normalize_string(data_dict.get("risk_level"), RiskLevel.LOW.value),
            requires_approval=bool(data_dict.get("requires_approval", False)),
            created_at=_normalize_string(data_dict.get("created_at"), _utc_now()),
            updated_at=_normalize_string(data_dict.get("updated_at"), _utc_now()),
            metadata=_coerce_dict(data_dict.get("metadata")),
        )

    def _overlay_expired(self, overlay: Mapping[str, Any]) -> bool:
        """Check whether an overlay TTL has expired."""
        try:
            created = datetime.fromisoformat(str(overlay.get("created_at")))
            ttl = int(overlay.get("ttl_seconds", DEFAULT_OVERLAY_TTL_SECONDS))
            return (datetime.now(timezone.utc) - created).total_seconds() > ttl
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Gesture helpers
    # -------------------------------------------------------------------------

    def _gesture_map_key(self, context: HologramContext, session_id: str, gesture_type: str) -> str:
        """Build gesture mapping key."""
        return f"{context.user_id}:{context.workspace_id}:{session_id}:{gesture_type}"

    def _gesture_to_intent(
        self,
        context: HologramContext,
        session_id: str,
        gesture_type: str,
        payload: Mapping[str, Any],
    ) -> str:
        """Map gesture to safe internal intent."""
        session_key = self._gesture_map_key(context, session_id, gesture_type)
        global_key = self._gesture_map_key(context, "global", gesture_type)

        if session_key in self._gesture_map_store:
            return self._gesture_map_store[session_key].get("intent", GestureIntent.NONE.value)
        if global_key in self._gesture_map_store:
            return self._gesture_map_store[global_key].get("intent", GestureIntent.NONE.value)

        default_map = {
            GestureType.TAP.value: GestureIntent.SELECT.value,
            GestureType.AIR_CLICK.value: GestureIntent.SELECT.value,
            GestureType.DOUBLE_TAP.value: GestureIntent.OPEN_MENU.value,
            GestureType.PINCH.value: GestureIntent.SELECT.value,
            GestureType.GRAB.value: GestureIntent.DRAG_START.value,
            GestureType.RELEASE.value: GestureIntent.DRAG_END.value,
            GestureType.SWIPE_LEFT.value: GestureIntent.PREVIOUS.value,
            GestureType.SWIPE_RIGHT.value: GestureIntent.NEXT.value,
            GestureType.SWIPE_UP.value: GestureIntent.SCROLL_UP.value,
            GestureType.SWIPE_DOWN.value: GestureIntent.SCROLL_DOWN.value,
            GestureType.OPEN_PALM.value: GestureIntent.OPEN_MENU.value,
            GestureType.FIST.value: GestureIntent.CLOSE_MENU.value,
            GestureType.DWELL.value: GestureIntent.SELECT.value,
            GestureType.POINT.value: GestureIntent.NONE.value,
            GestureType.UNKNOWN.value: GestureIntent.NONE.value,
        }
        return default_map.get(gesture_type, GestureIntent.NONE.value)

    def _route_gesture_intent(self, context: HologramContext, gesture_event: GestureEvent) -> Dict[str, Any]:
        """Route gesture intent to safe UI action plan."""
        intent = gesture_event.intent
        target_overlay_id = gesture_event.target_overlay_id

        action = {
            "intent": intent,
            "target_overlay_id": target_overlay_id,
            "side_effect_executed": False,
            "route_status": "planned",
            "created_at": _utc_now(),
        }

        if intent == GestureIntent.DISMISS.value and target_overlay_id:
            overlay = self._get_overlay(context, target_overlay_id)
            if overlay:
                overlay["visible"] = False
                overlay["updated_at"] = _utc_now()
                self._overlay_store[self._store_key(context, target_overlay_id)] = overlay
                action["route_status"] = "overlay_hidden"

        elif intent in {GestureIntent.SELECT.value, GestureIntent.OPEN_MENU.value, GestureIntent.CLOSE_MENU.value}:
            action["route_status"] = "ui_intent_ready"

        elif intent in {GestureIntent.SCROLL_UP.value, GestureIntent.SCROLL_DOWN.value, GestureIntent.NEXT.value, GestureIntent.PREVIOUS.value}:
            action["route_status"] = "navigation_intent_ready"

        elif intent == GestureIntent.NONE.value:
            action["route_status"] = "ignored"

        return action

    # -------------------------------------------------------------------------
    # Spatial/data safety helpers
    # -------------------------------------------------------------------------

    def _sanitize_spatial_context(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Sanitize spatial context before storing."""
        payload_dict = _coerce_dict(payload)

        objects = []
        for item in _as_list(payload_dict.get("objects")):
            obj = _coerce_dict(item)
            objects.append(
                {
                    "object_ref": _normalize_string(obj.get("object_ref"), default=_make_id("object")),
                    "label": _normalize_string(obj.get("label"), "object"),
                    "confidence": _clamp(_safe_float(obj.get("confidence"), 0.0), 0.0, 1.0),
                    "position": self._vector_from_payload(obj.get("position")).to_dict(),
                    "attributes": self._redact_sensitive_values(_coerce_dict(obj.get("attributes"))),
                }
            )

        surfaces = []
        for item in _as_list(payload_dict.get("surfaces")):
            surface = _coerce_dict(item)
            surfaces.append(
                {
                    "surface_ref": _normalize_string(surface.get("surface_ref"), default=_make_id("surface")),
                    "kind": _normalize_string(surface.get("kind"), "unknown"),
                    "position": self._vector_from_payload(surface.get("position")).to_dict(),
                    "normal": self._vector_from_payload(surface.get("normal")).to_dict(),
                    "confidence": _clamp(_safe_float(surface.get("confidence"), 0.0), 0.0, 1.0),
                }
            )

        return {
            "summary": _normalize_string(payload_dict.get("summary"), "Spatial context updated."),
            "room_type": _normalize_string(payload_dict.get("room_type"), "unknown"),
            "lighting": _normalize_string(payload_dict.get("lighting"), "unknown"),
            "objects": objects[:100],
            "surfaces": surfaces[:50],
            "safe_bounds": self._redact_sensitive_values(_coerce_dict(payload_dict.get("safe_bounds"))),
            "contains_raw_frame": False,
            "contains_face_data": False,
            "contains_biometric_data": False,
            "raw_frame_hash": _hash_payload(payload_dict.get("raw_frame")) if payload_dict.get("raw_frame") else None,
        }

    def _sanitize_overlay_content(self, content: Mapping[str, Any]) -> Dict[str, Any]:
        """Sanitize overlay content."""
        content_dict = self._redact_sensitive_values(_coerce_dict(content))
        blocked_keys = {"raw_frame", "camera_frame", "biometric", "face_embedding", "password", "secret", "token"}

        clean = {}
        for key, value in content_dict.items():
            if str(key).lower() in blocked_keys:
                clean[key] = "***REDACTED***"
            else:
                clean[key] = value
        return clean

    def _sanitize_overlay_actions(self, actions: Iterable[Any]) -> List[Dict[str, Any]]:
        """Sanitize overlay action buttons/intents."""
        safe_actions = []
        for action in actions:
            action_dict = _coerce_dict(action)
            safe_actions.append(
                {
                    "label": _normalize_string(action_dict.get("label"), "Action"),
                    "intent": _normalize_string(action_dict.get("intent"), "none"),
                    "requires_approval": bool(action_dict.get("requires_approval", False)),
                    "risk_level": _normalize_string(action_dict.get("risk_level"), RiskLevel.LOW.value),
                    "metadata": self._redact_sensitive_values(_coerce_dict(action_dict.get("metadata"))),
                }
            )
        return safe_actions[:10]

    def _sanitize_location_payload(self, location: Mapping[str, Any]) -> Dict[str, Any]:
        """Sanitize location payload by default."""
        location_dict = _coerce_dict(location)
        if not bool(self.config.get("allow_precise_location_storage", False)):
            return {
                "label": _normalize_string(location_dict.get("label"), "Destination"),
                "area": _normalize_string(location_dict.get("area"), "unknown"),
                "city": _normalize_string(location_dict.get("city"), "unknown"),
                "precise_coordinates_stored": False,
                "coordinate_hash": _hash_payload(
                    {
                        "lat": location_dict.get("lat"),
                        "lng": location_dict.get("lng"),
                        "latitude": location_dict.get("latitude"),
                        "longitude": location_dict.get("longitude"),
                    }
                ),
            }

        return self._redact_sensitive_values(location_dict)

    def _sanitize_route_payload(self, route: Mapping[str, Any]) -> Dict[str, Any]:
        """Sanitize route summary payload."""
        route_dict = _coerce_dict(route)
        return {
            "distance": _normalize_string(route_dict.get("distance"), "unknown"),
            "duration": _normalize_string(route_dict.get("duration"), "unknown"),
            "mode": _normalize_string(route_dict.get("mode"), "unknown"),
            "next_instruction": _normalize_string(route_dict.get("next_instruction"), ""),
            "step_count": len(_as_list(route_dict.get("steps"))),
            "precise_route_points_stored": False,
            "route_hash": _hash_payload(route_dict),
        }

    def _vector_from_payload(self, value: Any) -> Vector3:
        """Build Vector3 from payload."""
        data = _coerce_dict(value)
        return Vector3(
            x=_safe_float(data.get("x"), 0.0),
            y=_safe_float(data.get("y"), 0.0),
            z=_safe_float(data.get("z"), 0.0),
        )

    def _quaternion_from_payload(self, value: Any) -> Quaternion:
        """Build Quaternion from payload."""
        data = _coerce_dict(value)
        return Quaternion(
            x=_safe_float(data.get("x"), 0.0),
            y=_safe_float(data.get("y"), 0.0),
            z=_safe_float(data.get("z"), 0.0),
            w=_safe_float(data.get("w"), 1.0),
        )

    def _calculate_risk(self, action: str, payload: Mapping[str, Any], base_risk: str = RiskLevel.LOW.value) -> str:
        """Calculate AR/hologram risk level."""
        payload_text = _safe_json_dumps(payload).lower()
        action_text = _normalize_string(action).lower()

        priority = {
            RiskLevel.LOW.value: 1,
            RiskLevel.MEDIUM.value: 2,
            RiskLevel.HIGH.value: 3,
            RiskLevel.CRITICAL.value: 4,
        }

        risk = base_risk if base_risk in priority else RiskLevel.LOW.value

        critical_terms = {"biometric", "face_embedding", "payment", "delete", "destructive", "stream_public"}
        high_terms = {"camera", "microphone", "record", "location", "gps", "navigation", "device_command", "spatial_scan"}

        if any(term in payload_text or term in action_text for term in critical_terms):
            risk = RiskLevel.CRITICAL.value
        elif any(term in payload_text or term in action_text for term in high_terms):
            if priority[risk] < priority[RiskLevel.HIGH.value]:
                risk = RiskLevel.HIGH.value

        return risk

    def _safe_preview(self, data: Any, max_chars: int = 1200) -> Dict[str, Any]:
        """Create safe preview of data without exposing obvious secrets."""
        redacted = self._redact_sensitive_values(data)
        text = _safe_json_dumps(redacted)
        truncated = len(text) > max_chars
        if truncated:
            text = text[:max_chars] + "...[truncated]"
        return {
            "preview": text,
            "hash": _hash_payload(data),
            "truncated": truncated,
        }

    def _redact_sensitive_values(self, data: Any) -> Any:
        """Recursively redact secret/private fields."""
        sensitive_fragments = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "credential",
            "private_key",
            "access_key",
            "refresh_token",
            "raw_frame",
            "camera_frame",
            "face_embedding",
            "biometric",
            "precise_location",
        }

        if isinstance(data, Mapping):
            clean = {}
            for key, value in data.items():
                key_str = str(key).lower()
                if any(fragment in key_str for fragment in sensitive_fragments):
                    clean[key] = "***REDACTED***"
                else:
                    clean[key] = self._redact_sensitive_values(value)
            return clean

        if isinstance(data, list):
            return [self._redact_sensitive_values(item) for item in data]

        if isinstance(data, tuple):
            return tuple(self._redact_sensitive_values(item) for item in data)

        return data


# =============================================================================
# Module metadata for Agent Registry / Agent Loader
# =============================================================================

AGENT_CLASS = HologramAgent
AGENT_NAME = HologramAgent.agent_name
AGENT_TYPE = HologramAgent.agent_type
AGENT_MODULE = "agents.super_agents.hologram_agent.hologram_agent"
AGENT_DESCRIPTION = (
    "Main AR/hologram controller for glasses, overlays, gestures, spatial context, "
    "navigation overlays, notification overlays, and device bridge planning."
)

MODULE_COMPLETION = {
    "Agent/Module": "Hologram Agent",
    "File Completed": "hologram_agent.py",
    "Completion": "9.1%",
    "Completed Files": ["hologram_agent.py"],
    "Remaining Files": [
        "ar_overlay.py",
        "spatial_mapper.py",
        "gesture_bridge.py",
        "real_world_context.py",
        "object_recognizer.py",
        "navigation_overlay.py",
        "notification_overlay.py",
        "device_bridge.py",
        "hologram_memory.py",
        "config.py",
    ],
    "Next Recommended File": "agents/super_agents/hologram_agent/ar_overlay.py",
}


__all__ = [
    "HologramAgent",
    "HologramContext",
    "Vector3",
    "Quaternion",
    "SpatialAnchor",
    "HologramOverlay",
    "HologramSession",
    "GestureEvent",
    "HologramTaskType",
    "HologramSessionStatus",
    "DeviceType",
    "OverlayType",
    "AnchorMode",
    "GestureType",
    "GestureIntent",
    "RiskLevel",
    "AGENT_CLASS",
    "AGENT_NAME",
    "AGENT_TYPE",
    "AGENT_MODULE",
    "AGENT_DESCRIPTION",
    "MODULE_COMPLETION",
]


# =============================================================================
# Completion tracking
# =============================================================================

# Agent/Module: Hologram Agent
# File Completed: hologram_agent.py
# Completion: 9.1%
# Completed Files: ['hologram_agent.py']
# Remaining Files: ['ar_overlay.py', 'spatial_mapper.py', 'gesture_bridge.py', 'real_world_context.py', 'object_recognizer.py', 'navigation_overlay.py', 'notification_overlay.py', 'device_bridge.py', 'hologram_memory.py', 'config.py']
# Next Recommended File: agents/super_agents/hologram_agent/ar_overlay.py
# FILE COMPLETE