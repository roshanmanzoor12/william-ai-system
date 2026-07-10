"""
agents/super_agents/hologram_agent/navigation_overlay.py

Purpose:
    Shows path, direction, waypoint, distance, warning, and instruction overlays
    for the William / Jarvis Hologram Agent.

Architecture Fit:
    - Master Agent can route hologram/navigation tasks to NavigationOverlay.
    - Hologram Agent can use this helper to prepare AR-safe overlay payloads.
    - Spatial Mapper can provide coordinates, heading, anchors, and mapped spaces.
    - Real World Context and Object Recognizer can enrich hazard/obstacle warnings.
    - Security Agent approval is requested for sensitive navigation contexts.
    - Verification Agent payloads are prepared after completed overlay operations.
    - Memory Agent compatible payloads are prepared for useful route/context recall.
    - Dashboard/API/FastAPI can use the public methods directly.
    - Agent Registry / Agent Loader compatibility is preserved through safe imports.

Safety / SaaS Isolation:
    - Every user-specific operation requires user_id and workspace_id.
    - Overlay sessions, route instructions, logs, memory payloads, and verification
      payloads are scoped by user_id and workspace_id.
    - The file does not control real devices directly. It prepares structured
      overlay payloads that a device bridge/rendering layer can display.
    - Outdoor/indoor navigation instructions are treated as assistive overlays only.
      The user/device layer must still follow real-world safety, traffic, and
      accessibility constraints.

Public Class:
    NavigationOverlay
"""

from __future__ import annotations

import dataclasses
import json
import logging
import math
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
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
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. When the real BaseAgent is available, it will be used.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_OVERLAY_TTL_SECONDS = 45.0
DEFAULT_SESSION_TTL_SECONDS = 60 * 60
DEFAULT_MAX_ACTIVE_SESSIONS = 5000
DEFAULT_MAX_ROUTE_STEPS = 250
DEFAULT_MAX_INSTRUCTION_LENGTH = 280
DEFAULT_NAVIGATION_VERSION = "v1"

SENSITIVE_NAVIGATION_KEYWORDS = {
    "restricted",
    "private_property",
    "danger",
    "hazard",
    "evacuation",
    "emergency",
    "construction",
    "road",
    "vehicle",
    "driving",
    "traffic",
    "financial",
    "payment",
    "security_zone",
    "access_control",
    "lock",
    "door_unlock",
    "system_control",
    "device_control",
}

SENSITIVE_FIELD_PATTERNS = (
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"authorization", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
)


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(value: Any) -> str:
    """Stable JSON dump for logging/debugging."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def clamp(value: float, minimum: float, maximum: float) -> float:
    """Clamp a number into a safe range."""
    return max(minimum, min(maximum, value))


def redact_sensitive(value: Any) -> Any:
    """Recursively redact sensitive values for logs, memory, and dashboard data."""
    if isinstance(value, Mapping):
        clean: Dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if any(pattern.search(key_str) for pattern in SENSITIVE_FIELD_PATTERNS):
                clean[key_str] = "***REDACTED***"
            else:
                clean[key_str] = redact_sensitive(item)
        return clean

    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)

    return value


def make_id(prefix: str) -> str:
    """Create a William/Jarvis-friendly unique ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_instruction(text: Any, max_length: int = DEFAULT_MAX_INSTRUCTION_LENGTH) -> str:
    """Normalize navigation instruction text for safe overlay display."""
    clean = str(text or "").strip()
    clean = re.sub(r"\s+", " ", clean)
    if len(clean) > max_length:
        clean = clean[: max_length - 3].rstrip() + "..."
    return clean


def distance_3d(a: Mapping[str, Any], b: Mapping[str, Any]) -> float:
    """Calculate Euclidean distance between two AR coordinates."""
    ax, ay, az = float(a.get("x", 0.0)), float(a.get("y", 0.0)), float(a.get("z", 0.0))
    bx, by, bz = float(b.get("x", 0.0)), float(b.get("y", 0.0)), float(b.get("z", 0.0))
    return math.sqrt((bx - ax) ** 2 + (by - ay) ** 2 + (bz - az) ** 2)


def bearing_degrees(from_point: Mapping[str, Any], to_point: Mapping[str, Any]) -> float:
    """
    Calculate a simple horizontal AR bearing in degrees.

    This uses x/z plane for AR scenes:
        - 0 degrees points toward +z
        - 90 degrees points toward +x
    """
    dx = float(to_point.get("x", 0.0)) - float(from_point.get("x", 0.0))
    dz = float(to_point.get("z", 0.0)) - float(from_point.get("z", 0.0))
    angle = math.degrees(math.atan2(dx, dz))
    return (angle + 360.0) % 360.0


def angle_delta_degrees(current: float, target: float) -> float:
    """Return shortest signed delta from current heading to target heading."""
    return (target - current + 540.0) % 360.0 - 180.0


def heading_to_direction(delta: float) -> str:
    """Convert relative heading delta into human-friendly direction text."""
    abs_delta = abs(delta)
    if abs_delta <= 12:
        return "straight"
    if abs_delta <= 45:
        return "slight right" if delta > 0 else "slight left"
    if abs_delta <= 120:
        return "right" if delta > 0 else "left"
    return "turn around"


def validate_coordinate(point: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate an AR coordinate dict."""
    try:
        x = float(point.get("x"))
        y = float(point.get("y", 0.0))
        z = float(point.get("z"))

        if not all(math.isfinite(v) for v in (x, y, z)):
            return {
                "success": False,
                "message": "Coordinate values must be finite numbers.",
                "data": {},
                "error": "invalid_coordinate_values",
                "metadata": {"timestamp": utc_now_iso()},
            }

        return {
            "success": True,
            "message": "Coordinate validated.",
            "data": {"coordinate": {"x": x, "y": y, "z": z}},
            "error": None,
            "metadata": {"timestamp": utc_now_iso()},
        }

    except Exception as exc:
        return {
            "success": False,
            "message": "Invalid coordinate.",
            "data": {},
            "error": str(exc),
            "metadata": {"timestamp": utc_now_iso()},
        }


# ---------------------------------------------------------------------------
# Enums / Data Structures
# ---------------------------------------------------------------------------

class NavigationMode(str, Enum):
    INDOOR = "indoor"
    OUTDOOR = "outdoor"
    MIXED = "mixed"
    AR_ASSIST = "ar_assist"


class OverlayStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class OverlayElementType(str, Enum):
    PATH_LINE = "path_line"
    ARROW = "arrow"
    WAYPOINT_MARKER = "waypoint_marker"
    DESTINATION_MARKER = "destination_marker"
    INSTRUCTION_CARD = "instruction_card"
    DISTANCE_LABEL = "distance_label"
    WARNING_CARD = "warning_card"
    PROGRESS_BAR = "progress_bar"
    COMPASS_RING = "compass_ring"
    MINI_MAP = "mini_map"


class InstructionSeverity(str, Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    CRITICAL = "critical"


class RouteStepAction(str, Enum):
    START = "start"
    GO_STRAIGHT = "go_straight"
    TURN_LEFT = "turn_left"
    TURN_RIGHT = "turn_right"
    SLIGHT_LEFT = "slight_left"
    SLIGHT_RIGHT = "slight_right"
    TURN_AROUND = "turn_around"
    GO_UP = "go_up"
    GO_DOWN = "go_down"
    ENTER = "enter"
    EXIT = "exit"
    ARRIVE = "arrive"
    WAIT = "wait"
    CAUTION = "caution"


@dataclass
class NavigationCoordinate:
    """AR navigation coordinate relative to a mapped scene or device origin."""

    x: float
    y: float = 0.0
    z: float = 0.0
    floor: Optional[str] = None
    anchor_id: Optional[str] = None
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "NavigationCoordinate":
        validation = validate_coordinate(value)
        if not validation["success"]:
            raise ValueError(validation["error"])

        coordinate = validation["data"]["coordinate"]
        return cls(
            x=coordinate["x"],
            y=coordinate["y"],
            z=coordinate["z"],
            floor=value.get("floor"),
            anchor_id=value.get("anchor_id"),
            label=value.get("label"),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass
class NavigationStep:
    """One route instruction/waypoint used for overlay rendering."""

    step_id: str
    sequence: int
    action: RouteStepAction
    instruction: str
    start: NavigationCoordinate
    end: NavigationCoordinate
    distance_meters: float
    bearing_degrees: float
    estimated_seconds: Optional[float] = None
    severity: InstructionSeverity = InstructionSeverity.INFO
    icon: Optional[str] = None
    spoken_instruction: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["action"] = self.action.value
        data["severity"] = self.severity.value
        if redact:
            data = redact_sensitive(data)
        return data


@dataclass
class NavigationOverlayElement:
    """Renderable overlay element for glasses/AR UI/device bridge."""

    element_id: str
    element_type: OverlayElementType
    session_id: str
    user_id: str
    workspace_id: str
    position: Optional[NavigationCoordinate] = None
    rotation_degrees: Optional[float] = None
    scale: float = 1.0
    text: Optional[str] = None
    visible: bool = True
    opacity: float = 1.0
    priority: int = 100
    ttl_seconds: float = DEFAULT_OVERLAY_TTL_SECONDS
    style: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["element_type"] = self.element_type.value
        if redact:
            data = redact_sensitive(data)
        return data


@dataclass
class NavigationOverlaySession:
    """User/workspace-scoped active navigation overlay session."""

    session_id: str
    user_id: str
    workspace_id: str
    mode: NavigationMode
    status: OverlayStatus
    route_id: str
    title: str
    origin: NavigationCoordinate
    destination: NavigationCoordinate
    steps: List[NavigationStep] = field(default_factory=list)
    current_step_index: int = 0
    elements: List[NavigationOverlayElement] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    expires_at_epoch: float = field(default_factory=lambda: time.time() + DEFAULT_SESSION_TTL_SECONDS)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["mode"] = self.mode.value
        data["status"] = self.status.value
        data["steps"] = [step.to_dict(redact=redact) for step in self.steps]
        data["elements"] = [element.to_dict(redact=redact) for element in self.elements]
        if redact:
            data = redact_sensitive(data)
        return data


@dataclass
class DevicePose:
    """Current user/device pose used to update AR guidance."""

    position: NavigationCoordinate
    heading_degrees: float = 0.0
    pitch_degrees: float = 0.0
    roll_degrees: float = 0.0
    confidence: float = 1.0
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["heading_degrees"] = self.heading_degrees % 360.0
        data["confidence"] = clamp(self.confidence, 0.0, 1.0)
        return data

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DevicePose":
        position_data = value.get("position") or value
        return cls(
            position=NavigationCoordinate.from_mapping(position_data),
            heading_degrees=float(value.get("heading_degrees", value.get("heading", 0.0))) % 360.0,
            pitch_degrees=float(value.get("pitch_degrees", value.get("pitch", 0.0))),
            roll_degrees=float(value.get("roll_degrees", value.get("roll", 0.0))),
            confidence=float(value.get("confidence", 1.0)),
            timestamp=str(value.get("timestamp") or utc_now_iso()),
        )


class SessionStore:
    """
    Small in-memory TTL session store.

    Production can replace this with Redis/Postgres while keeping the
    NavigationOverlay public interface unchanged.
    """

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._sessions: "OrderedDict[str, NavigationOverlaySession]" = OrderedDict()

    def set(self, session: NavigationOverlaySession) -> None:
        self.prune()
        self._sessions[session.session_id] = session
        self._sessions.move_to_end(session.session_id)
        while len(self._sessions) > self.max_sessions:
            self._sessions.popitem(last=False)

    def get(self, session_id: str) -> Optional[NavigationOverlaySession]:
        self.prune()
        session = self._sessions.get(session_id)
        if session:
            self._sessions.move_to_end(session_id)
        return session

    def delete(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    def list_for_context(self, user_id: str, workspace_id: str) -> List[NavigationOverlaySession]:
        self.prune()
        return [
            session
            for session in self._sessions.values()
            if session.user_id == user_id and session.workspace_id == workspace_id
        ]

    def prune(self) -> None:
        now = time.time()
        expired_ids = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at_epoch <= now
        ]
        for session_id in expired_ids:
            session = self._sessions.get(session_id)
            if session:
                session.status = OverlayStatus.EXPIRED
            self._sessions.pop(session_id, None)


# ---------------------------------------------------------------------------
# Navigation Overlay
# ---------------------------------------------------------------------------

class NavigationOverlay(BaseAgent):
    """
    Production-ready Navigation Overlay helper for the William / Jarvis
    Hologram Agent.

    Responsibilities:
        1. Create path, waypoint, instruction, warning, compass, and distance overlays.
        2. Start, update, pause, resume, complete, and cancel navigation sessions.
        3. Convert route coordinates into AR render payloads.
        4. Use user_id/workspace_id isolation for all navigation context.
        5. Request Security Agent approval for sensitive navigation contexts.
        6. Prepare Verification Agent and Memory Agent compatible payloads.
        7. Emit dashboard/API/registry friendly events.

    This class prepares overlay instructions only. It does not directly control
    AR glasses, sensors, vehicles, locks, doors, financial tools, calls, messages,
    browsers, or destructive systems.
    """

    def __init__(
        self,
        *,
        agent_name: str = "HologramNavigationOverlay",
        agent_id: str = "hologram.navigation_overlay",
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        session_store: Optional[SessionStore] = None,
        default_overlay_ttl_seconds: float = DEFAULT_OVERLAY_TTL_SECONDS,
        max_route_steps: int = DEFAULT_MAX_ROUTE_STEPS,
        strict_workspace_isolation: bool = True,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = getattr(self, "logger", logging.getLogger(agent_name))

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self.session_store = session_store or SessionStore()
        self.default_overlay_ttl_seconds = default_overlay_ttl_seconds
        self.max_route_steps = max_route_steps
        self.strict_workspace_isolation = strict_workspace_isolation

    # ------------------------------------------------------------------
    # Public Session Methods
    # ------------------------------------------------------------------

    def start_navigation_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        origin: Mapping[str, Any],
        destination: Mapping[str, Any],
        waypoints: Optional[Sequence[Mapping[str, Any]]] = None,
        mode: Union[NavigationMode, str] = NavigationMode.AR_ASSIST,
        title: str = "Navigation",
        route_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Start a new navigation overlay session.

        The method builds route steps, creates initial overlay elements, stores
        the session, and returns a structured payload ready for Device Bridge,
        Dashboard/API, or Hologram Agent rendering.
        """
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="start_navigation_overlay",
        )
        if not context["success"]:
            return context

        try:
            mode_enum = NavigationMode(str(mode).lower())
            metadata = metadata or {}

            origin_coord = NavigationCoordinate.from_mapping(origin)
            destination_coord = NavigationCoordinate.from_mapping(destination)
            waypoint_coords = [
                NavigationCoordinate.from_mapping(item)
                for item in (waypoints or [])
            ]

            security_result = self._request_security_approval(
                action="hologram.navigation.start",
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "mode": mode_enum.value,
                    "title": title,
                    "origin": origin_coord.to_dict(),
                    "destination": destination_coord.to_dict(),
                    "waypoints_count": len(waypoint_coords),
                    "metadata": metadata,
                },
            )
            if not security_result["success"]:
                return security_result

            session_id = make_id("nav_session")
            final_route_id = route_id or make_id("route")

            steps_result = self.build_route_steps(
                user_id=user_id,
                workspace_id=workspace_id,
                origin=origin_coord.to_dict(),
                destination=destination_coord.to_dict(),
                waypoints=[point.to_dict() for point in waypoint_coords],
                metadata=metadata,
            )
            if not steps_result["success"]:
                return steps_result

            steps = [
                self._step_from_dict(item)
                for item in steps_result["data"]["steps"]
            ]

            session = NavigationOverlaySession(
                session_id=session_id,
                user_id=user_id,
                workspace_id=workspace_id,
                mode=mode_enum,
                status=OverlayStatus.ACTIVE,
                route_id=final_route_id,
                title=normalize_instruction(title, 120),
                origin=origin_coord,
                destination=destination_coord,
                steps=steps,
                current_step_index=0,
                metadata=metadata,
            )

            elements_result = self.create_navigation_elements(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                steps=[step.to_dict() for step in steps],
                current_step_index=0,
                mode=mode_enum,
                metadata=metadata,
            )
            if not elements_result["success"]:
                return elements_result

            session.elements = [
                self._element_from_dict(item)
                for item in elements_result["data"]["elements"]
            ]

            self.session_store.set(session)

            verification_payload = self._prepare_verification_payload(
                action="hologram.navigation.start",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "route_id": final_route_id,
                    "mode": mode_enum.value,
                    "step_count": len(steps),
                },
            )

            memory_payload = self._prepare_memory_payload(
                action="hologram.navigation.start",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "route_id": final_route_id,
                    "title": session.title,
                    "origin_label": origin_coord.label,
                    "destination_label": destination_coord.label,
                    "mode": mode_enum.value,
                    "step_count": len(steps),
                },
            )

            self._emit_agent_event(
                event_type="hologram.navigation.started",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "route_id": final_route_id,
                    "mode": mode_enum.value,
                    "step_count": len(steps),
                },
            )

            self._log_audit_event(
                event_type="navigation_overlay.started",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "route_id": final_route_id,
                    "title": session.title,
                    "mode": mode_enum.value,
                },
            )

            return self._safe_result(
                message="Navigation overlay session started.",
                data={
                    "session": session.to_dict(redact=True),
                    "render_payload": self._build_render_payload(session),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "session_id": session_id,
                    "route_id": final_route_id,
                    "version": DEFAULT_NAVIGATION_VERSION,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to start navigation overlay.")
            return self._error_result(
                message="Failed to start navigation overlay.",
                error=str(exc),
                metadata={"operation": "start_navigation_overlay"},
            )

    def update_navigation_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        device_pose: Mapping[str, Any],
        hazards: Optional[Sequence[Mapping[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update an active navigation session from current device pose.

        Returns refreshed AR overlay elements with:
            - next-step arrow orientation
            - distance label
            - instruction card
            - hazard/warning card when needed
            - progress data
        """
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="update_navigation_overlay",
        )
        if not context["success"]:
            return context

        try:
            session = self._get_session_checked(
                session_id=session_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not session["success"]:
                return session

            nav_session: NavigationOverlaySession = session["data"]["session_object"]

            if nav_session.status != OverlayStatus.ACTIVE:
                return self._error_result(
                    message="Navigation session is not active.",
                    error="session_not_active",
                    metadata={"session_id": session_id, "status": nav_session.status.value},
                )

            pose = DevicePose.from_mapping(device_pose)
            metadata = metadata or {}
            hazards = list(hazards or [])

            progress = self._calculate_progress(
                session=nav_session,
                pose=pose,
            )

            nav_session.current_step_index = progress["current_step_index"]
            nav_session.updated_at = utc_now_iso()

            elements = self._build_live_elements(
                session=nav_session,
                pose=pose,
                progress=progress,
                hazards=hazards,
                metadata=metadata,
            )

            nav_session.elements = elements

            if progress["arrived"]:
                nav_session.status = OverlayStatus.COMPLETED
                nav_session.updated_at = utc_now_iso()

            self.session_store.set(nav_session)

            event_type = (
                "hologram.navigation.completed"
                if nav_session.status == OverlayStatus.COMPLETED
                else "hologram.navigation.updated"
            )

            self._emit_agent_event(
                event_type=event_type,
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "status": nav_session.status.value,
                    "current_step_index": nav_session.current_step_index,
                    "remaining_distance_meters": progress["remaining_distance_meters"],
                    "arrived": progress["arrived"],
                },
            )

            self._log_audit_event(
                event_type="navigation_overlay.updated",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "status": nav_session.status.value,
                    "current_step_index": nav_session.current_step_index,
                    "hazard_count": len(hazards),
                },
            )

            verification_payload = self._prepare_verification_payload(
                action="hologram.navigation.update",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "status": nav_session.status.value,
                    "arrived": progress["arrived"],
                    "remaining_distance_meters": progress["remaining_distance_meters"],
                },
            )

            return self._safe_result(
                message="Navigation overlay updated.",
                data={
                    "session": nav_session.to_dict(redact=True),
                    "progress": progress,
                    "render_payload": self._build_render_payload(nav_session),
                    "verification_payload": verification_payload,
                },
                metadata={
                    "session_id": session_id,
                    "status": nav_session.status.value,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to update navigation overlay.")
            return self._error_result(
                message="Failed to update navigation overlay.",
                error=str(exc),
                metadata={"operation": "update_navigation_overlay"},
            )

    def pause_navigation_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pause an active navigation overlay session."""
        return self._set_session_status(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            status=OverlayStatus.PAUSED,
            action="hologram.navigation.pause",
            message="Navigation overlay paused.",
            reason=reason,
        )

    def resume_navigation_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resume a paused navigation overlay session."""
        return self._set_session_status(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            status=OverlayStatus.ACTIVE,
            action="hologram.navigation.resume",
            message="Navigation overlay resumed.",
            reason=reason,
        )

    def complete_navigation_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark a navigation overlay session as completed."""
        return self._set_session_status(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            status=OverlayStatus.COMPLETED,
            action="hologram.navigation.complete",
            message="Navigation overlay completed.",
            reason=reason,
        )

    def cancel_navigation_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a navigation overlay session."""
        return self._set_session_status(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            status=OverlayStatus.CANCELLED,
            action="hologram.navigation.cancel",
            message="Navigation overlay cancelled.",
            reason=reason,
        )

    def get_navigation_session(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
    ) -> Dict[str, Any]:
        """Return one navigation overlay session."""
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="get_navigation_session",
        )
        if not context["success"]:
            return context

        session_result = self._get_session_checked(
            session_id=session_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not session_result["success"]:
            return session_result

        session: NavigationOverlaySession = session_result["data"]["session_object"]
        return self._safe_result(
            message="Navigation overlay session found.",
            data={
                "session": session.to_dict(redact=True),
                "render_payload": self._build_render_payload(session),
            },
            metadata={"session_id": session_id},
        )

    def list_navigation_sessions(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[Union[OverlayStatus, str]] = None,
    ) -> Dict[str, Any]:
        """List navigation overlay sessions for one user/workspace."""
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="list_navigation_sessions",
        )
        if not context["success"]:
            return context

        try:
            status_value = str(status.value if isinstance(status, OverlayStatus) else status).lower() if status else None
            sessions = self.session_store.list_for_context(user_id=user_id, workspace_id=workspace_id)

            filtered = []
            for session in sessions:
                if status_value and session.status.value != status_value:
                    continue
                filtered.append(session.to_dict(redact=True))

            return self._safe_result(
                message="Navigation overlay sessions listed.",
                data={
                    "sessions": filtered,
                    "count": len(filtered),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list navigation overlay sessions.",
                error=str(exc),
                metadata={"operation": "list_navigation_sessions"},
            )

    # ------------------------------------------------------------------
    # Public Route / Overlay Building Methods
    # ------------------------------------------------------------------

    def build_route_steps(
        self,
        *,
        user_id: str,
        workspace_id: str,
        origin: Mapping[str, Any],
        destination: Mapping[str, Any],
        waypoints: Optional[Sequence[Mapping[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build route steps from origin, optional waypoints, and destination.

        This method does not do external map routing. It converts provided route
        coordinates into AR overlay-ready step instructions. Future Spatial Mapper
        or external route service output can pass waypoints here.
        """
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="build_route_steps",
        )
        if not context["success"]:
            return context

        try:
            metadata = metadata or {}
            points = [NavigationCoordinate.from_mapping(origin)]
            points.extend(NavigationCoordinate.from_mapping(item) for item in (waypoints or []))
            points.append(NavigationCoordinate.from_mapping(destination))

            if len(points) < 2:
                return self._error_result(
                    message="At least origin and destination coordinates are required.",
                    error="insufficient_route_points",
                )

            if len(points) - 1 > self.max_route_steps:
                return self._error_result(
                    message="Route has too many steps.",
                    error="too_many_route_steps",
                    metadata={
                        "max_route_steps": self.max_route_steps,
                        "received_steps": len(points) - 1,
                    },
                )

            steps: List[NavigationStep] = []
            for index in range(len(points) - 1):
                start = points[index]
                end = points[index + 1]

                start_dict = start.to_dict()
                end_dict = end.to_dict()

                dist = distance_3d(start_dict, end_dict)
                bearing = bearing_degrees(start_dict, end_dict)
                action = self._infer_action_for_segment(
                    previous=points[index - 1] if index > 0 else None,
                    start=start,
                    end=end,
                    is_first=index == 0,
                    is_last=index == len(points) - 2,
                )

                instruction = self._build_instruction_text(
                    action=action,
                    distance_meters=dist,
                    end=end,
                    is_first=index == 0,
                    is_last=index == len(points) - 2,
                )

                severity = InstructionSeverity.INFO
                if action in {RouteStepAction.CAUTION, RouteStepAction.WAIT}:
                    severity = InstructionSeverity.WARNING
                if action == RouteStepAction.ARRIVE:
                    severity = InstructionSeverity.SUCCESS

                steps.append(
                    NavigationStep(
                        step_id=make_id("nav_step"),
                        sequence=index,
                        action=action,
                        instruction=instruction,
                        start=start,
                        end=end,
                        distance_meters=round(dist, 3),
                        bearing_degrees=round(bearing, 2),
                        estimated_seconds=self._estimate_seconds(dist),
                        severity=severity,
                        icon=self._icon_for_action(action),
                        spoken_instruction=instruction,
                        metadata={
                            "route_metadata": redact_sensitive(metadata),
                            "start_label": start.label,
                            "end_label": end.label,
                        },
                    )
                )

            return self._safe_result(
                message="Route steps built.",
                data={
                    "steps": [step.to_dict(redact=True) for step in steps],
                    "step_count": len(steps),
                    "total_distance_meters": round(sum(step.distance_meters for step in steps), 3),
                    "estimated_seconds": round(sum(step.estimated_seconds or 0 for step in steps), 1),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to build route steps.",
                error=str(exc),
                metadata={"operation": "build_route_steps"},
            )

    def create_navigation_elements(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        steps: Sequence[Mapping[str, Any]],
        current_step_index: int = 0,
        mode: Union[NavigationMode, str] = NavigationMode.AR_ASSIST,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create AR overlay elements from route steps.

        The returned elements can be rendered by a Hologram device bridge, web
        dashboard simulator, or glasses client.
        """
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="create_navigation_elements",
        )
        if not context["success"]:
            return context

        try:
            mode_enum = NavigationMode(str(mode).lower())
            metadata = metadata or {}

            parsed_steps = [self._step_from_dict(item) for item in steps]
            if not parsed_steps:
                return self._error_result(
                    message="At least one navigation step is required.",
                    error="missing_navigation_steps",
                )

            current_index = int(clamp(float(current_step_index), 0.0, float(len(parsed_steps) - 1)))
            current_step = parsed_steps[current_index]

            elements: List[NavigationOverlayElement] = []

            elements.append(
                NavigationOverlayElement(
                    element_id=make_id("overlay_path"),
                    element_type=OverlayElementType.PATH_LINE,
                    session_id=session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    priority=40,
                    ttl_seconds=self.default_overlay_ttl_seconds,
                    style=self._default_style("path_line", mode_enum),
                    payload={
                        "points": [step.start.to_dict() for step in parsed_steps] + [parsed_steps[-1].end.to_dict()],
                        "current_step_index": current_index,
                        "mode": mode_enum.value,
                    },
                )
            )

            elements.append(
                NavigationOverlayElement(
                    element_id=make_id("overlay_arrow"),
                    element_type=OverlayElementType.ARROW,
                    session_id=session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    position=current_step.end,
                    rotation_degrees=current_step.bearing_degrees,
                    priority=10,
                    ttl_seconds=self.default_overlay_ttl_seconds,
                    style=self._default_style("arrow", mode_enum),
                    payload={
                        "step_id": current_step.step_id,
                        "action": current_step.action.value,
                        "bearing_degrees": current_step.bearing_degrees,
                    },
                )
            )

            elements.append(
                NavigationOverlayElement(
                    element_id=make_id("overlay_instruction"),
                    element_type=OverlayElementType.INSTRUCTION_CARD,
                    session_id=session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    text=current_step.instruction,
                    priority=5,
                    ttl_seconds=self.default_overlay_ttl_seconds,
                    style=self._default_style("instruction_card", mode_enum),
                    payload={
                        "step_id": current_step.step_id,
                        "icon": current_step.icon,
                        "severity": current_step.severity.value,
                        "spoken_instruction": current_step.spoken_instruction,
                    },
                )
            )

            elements.append(
                NavigationOverlayElement(
                    element_id=make_id("overlay_distance"),
                    element_type=OverlayElementType.DISTANCE_LABEL,
                    session_id=session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    position=current_step.end,
                    text=self._format_distance(current_step.distance_meters),
                    priority=20,
                    ttl_seconds=self.default_overlay_ttl_seconds,
                    style=self._default_style("distance_label", mode_enum),
                    payload={
                        "step_distance_meters": current_step.distance_meters,
                    },
                )
            )

            for step in parsed_steps:
                marker_type = (
                    OverlayElementType.DESTINATION_MARKER
                    if step.sequence == len(parsed_steps) - 1
                    else OverlayElementType.WAYPOINT_MARKER
                )
                elements.append(
                    NavigationOverlayElement(
                        element_id=make_id("overlay_marker"),
                        element_type=marker_type,
                        session_id=session_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        position=step.end,
                        priority=60,
                        ttl_seconds=self.default_overlay_ttl_seconds,
                        style=self._default_style(marker_type.value, mode_enum),
                        payload={
                            "step_id": step.step_id,
                            "sequence": step.sequence,
                            "label": step.end.label,
                            "action": step.action.value,
                        },
                    )
                )

            elements.append(
                NavigationOverlayElement(
                    element_id=make_id("overlay_progress"),
                    element_type=OverlayElementType.PROGRESS_BAR,
                    session_id=session_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    priority=30,
                    ttl_seconds=self.default_overlay_ttl_seconds,
                    style=self._default_style("progress_bar", mode_enum),
                    payload={
                        "current_step_index": current_index,
                        "total_steps": len(parsed_steps),
                        "progress_ratio": round((current_index + 1) / max(len(parsed_steps), 1), 4),
                    },
                )
            )

            return self._safe_result(
                message="Navigation overlay elements created.",
                data={
                    "elements": [element.to_dict(redact=True) for element in elements],
                    "element_count": len(elements),
                    "current_step_index": current_index,
                    "mode": mode_enum.value,
                    "metadata": redact_sensitive(metadata),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create navigation overlay elements.",
                error=str(exc),
                metadata={"operation": "create_navigation_elements"},
            )

    def create_instruction_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        instruction: str,
        severity: Union[InstructionSeverity, str] = InstructionSeverity.INFO,
        position: Optional[Mapping[str, Any]] = None,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a standalone instruction card overlay."""
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="create_instruction_overlay",
        )
        if not context["success"]:
            return context

        try:
            severity_enum = InstructionSeverity(str(severity).lower())
            coordinate = NavigationCoordinate.from_mapping(position) if position else None

            element = NavigationOverlayElement(
                element_id=make_id("overlay_instruction"),
                element_type=OverlayElementType.INSTRUCTION_CARD,
                session_id=session_id,
                user_id=user_id,
                workspace_id=workspace_id,
                position=coordinate,
                text=normalize_instruction(instruction),
                priority=5 if severity_enum in {InstructionSeverity.WARNING, InstructionSeverity.CRITICAL} else 25,
                ttl_seconds=ttl_seconds or self.default_overlay_ttl_seconds,
                style=self._default_style("instruction_card", NavigationMode.AR_ASSIST),
                payload={
                    "severity": severity_enum.value,
                    "metadata": redact_sensitive(metadata or {}),
                },
            )

            return self._safe_result(
                message="Instruction overlay created.",
                data={"element": element.to_dict(redact=True)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create instruction overlay.",
                error=str(exc),
                metadata={"operation": "create_instruction_overlay"},
            )

    def create_warning_overlay(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        warning: str,
        position: Optional[Mapping[str, Any]] = None,
        severity: Union[InstructionSeverity, str] = InstructionSeverity.WARNING,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a warning overlay card for hazards, obstacles, or route notices."""
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="create_warning_overlay",
        )
        if not context["success"]:
            return context

        try:
            severity_enum = InstructionSeverity(str(severity).lower())
            coordinate = NavigationCoordinate.from_mapping(position) if position else None

            security_result = self._request_security_approval(
                action="hologram.navigation.warning",
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "warning": warning,
                    "severity": severity_enum.value,
                    "position": coordinate.to_dict() if coordinate else None,
                    "metadata": metadata or {},
                },
            )
            if not security_result["success"]:
                return security_result

            element = NavigationOverlayElement(
                element_id=make_id("overlay_warning"),
                element_type=OverlayElementType.WARNING_CARD,
                session_id=session_id,
                user_id=user_id,
                workspace_id=workspace_id,
                position=coordinate,
                text=normalize_instruction(warning),
                priority=1,
                ttl_seconds=ttl_seconds or self.default_overlay_ttl_seconds,
                style=self._default_style("warning_card", NavigationMode.AR_ASSIST),
                payload={
                    "severity": severity_enum.value,
                    "metadata": redact_sensitive(metadata or {}),
                },
            )

            self._log_audit_event(
                event_type="navigation_overlay.warning_created",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "warning": warning,
                    "severity": severity_enum.value,
                },
            )

            return self._safe_result(
                message="Warning overlay created.",
                data={"element": element.to_dict(redact=True)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create warning overlay.",
                error=str(exc),
                metadata={"operation": "create_warning_overlay"},
            )

    # ------------------------------------------------------------------
    # Required William/Jarvis Compatibility Hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        operation: str = "unknown",
        allow_system: bool = False,
    ) -> Dict[str, Any]:
        """Validate required SaaS user/workspace context."""
        if allow_system and user_id == "system" and workspace_id == "system":
            return self._safe_result(
                message="System context validated.",
                data={"operation": operation},
            )

        if not user_id or not str(user_id).strip():
            return self._error_result(
                message="Missing user_id for navigation overlay operation.",
                error="missing_user_id",
                metadata={"operation": operation},
            )

        if not workspace_id or not str(workspace_id).strip():
            return self._error_result(
                message="Missing workspace_id for navigation overlay operation.",
                error="missing_workspace_id",
                metadata={"operation": operation},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "operation": operation,
            },
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is needed.

        Navigation overlays that mention restricted areas, emergency routes,
        traffic, locks, physical system controls, or hazards are treated as
        sensitive and require approval.
        """
        action_l = str(action or "").lower()
        if any(keyword in action_l for keyword in SENSITIVE_NAVIGATION_KEYWORDS):
            return True

        if payload:
            combined = safe_json_dumps(redact_sensitive(payload)).lower()
            if any(keyword in combined for keyword in SENSITIVE_NAVIGATION_KEYWORDS):
                return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is attached, sensitive operations are blocked by
        safe default. Non-sensitive overlay rendering is allowed.
        """
        requires = self._requires_security_check(action=action, payload=payload)
        if not requires:
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True, "required": False},
            )

        approval_request = {
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": redact_sensitive(payload),
            "requested_by": self.agent_id,
            "requested_at": utc_now_iso(),
        }

        if not self.security_agent:
            return self._error_result(
                message="Sensitive navigation overlay action blocked because Security Agent is unavailable.",
                error="security_agent_unavailable",
                data={"approved": False, "required": True},
            )

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_request)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_request)
            else:
                return self._error_result(
                    message="Security Agent does not expose an approval method.",
                    error="security_agent_approval_method_missing",
                    data={"approved": False, "required": True},
                )

            if isinstance(response, dict):
                approved = bool(
                    response.get("approved")
                    or response.get("success")
                    or response.get("data", {}).get("approved")
                )
                if approved:
                    return self._safe_result(
                        message="Security Agent approved navigation overlay action.",
                        data={"approved": True, "required": True, "response": response},
                    )

                return self._error_result(
                    message="Security Agent rejected navigation overlay action.",
                    error="security_rejected",
                    data={"approved": False, "required": True, "response": response},
                )

            if bool(response):
                return self._safe_result(
                    message="Security Agent approved navigation overlay action.",
                    data={"approved": True, "required": True},
                )

            return self._error_result(
                message="Security Agent rejected navigation overlay action.",
                error="security_rejected",
                data={"approved": False, "required": True},
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=str(exc),
                data={"approved": False, "required": True},
            )

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""
        return {
            "success": True,
            "message": "Verification payload prepared.",
            "data": {
                "verification_type": "hologram_navigation_overlay_action",
                "action": action,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "source_agent": self.agent_id,
                "payload": redact_sensitive(data),
                "created_at": utc_now_iso(),
            },
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "compatible_with": "VerificationAgent",
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This payload can help remember route preferences, frequently used
        navigation anchors, and AR overlay behavior without mixing workspaces.
        """
        memory_payload = {
            "memory_type": "hologram_navigation_context",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_id,
            "content": redact_sensitive(data),
            "created_at": utc_now_iso(),
            "tags": ["hologram", "navigation", "overlay", "ar"],
        }

        if self.memory_agent:
            try:
                if hasattr(self.memory_agent, "prepare_memory_payload"):
                    prepared = self.memory_agent.prepare_memory_payload(memory_payload)
                    if isinstance(prepared, dict):
                        return prepared
                elif hasattr(self.memory_agent, "store"):
                    self.memory_agent.store(memory_payload)
            except Exception as exc:
                self.logger.warning("Memory Agent integration failed: %s", exc)

        return {
            "success": True,
            "message": "Memory payload prepared.",
            "data": memory_payload,
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "compatible_with": "MemoryAgent",
            },
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Emit event for Master Agent, dashboard/API, or future event bus."""
        event = {
            "event_id": make_id("agent_evt"),
            "event_type": event_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_id,
            "data": redact_sensitive(data),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.info("Agent event: %s", safe_json_dumps(event))

            return self._safe_result(
                message="Agent event emitted.",
                data={"event": event},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to emit agent event.",
                error=str(exc),
                data={"event": event},
            )

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Log audit event for SaaS traceability and dashboard analytics."""
        audit_event = {
            "audit_id": make_id("audit"),
            "event_type": event_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_id,
            "data": redact_sensitive(data),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", safe_json_dumps(audit_event))

            return self._safe_result(
                message="Audit event logged.",
                data={"audit_event": audit_event},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to log audit event.",
                error=str(exc),
                data={"audit_event": audit_event},
            )

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis structured result."""
        return {
            "success": success,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Dict[str, Any], Exception],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=str(error),
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Internal Session / Rendering Helpers
    # ------------------------------------------------------------------

    def _get_session_checked(
        self,
        *,
        session_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        session = self.session_store.get(session_id)
        if not session:
            return self._error_result(
                message="Navigation overlay session not found.",
                error="session_not_found",
                metadata={"session_id": session_id},
            )

        if self.strict_workspace_isolation:
            if session.user_id != user_id:
                return self._error_result(
                    message="Navigation session user context mismatch.",
                    error="user_context_mismatch",
                    metadata={
                        "session_id": session_id,
                        "expected_user_id": session.user_id,
                        "received_user_id": user_id,
                    },
                )

            if session.workspace_id != workspace_id:
                return self._error_result(
                    message="Navigation session workspace context mismatch.",
                    error="workspace_context_mismatch",
                    metadata={
                        "session_id": session_id,
                        "expected_workspace_id": session.workspace_id,
                        "received_workspace_id": workspace_id,
                    },
                )

        return self._safe_result(
            message="Navigation session validated.",
            data={
                "session": session.to_dict(redact=True),
                "session_object": session,
            },
        )

    def _set_session_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        status: OverlayStatus,
        action: str,
        message: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation=action,
        )
        if not context["success"]:
            return context

        try:
            session_result = self._get_session_checked(
                session_id=session_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not session_result["success"]:
                return session_result

            session: NavigationOverlaySession = session_result["data"]["session_object"]

            security_result = self._request_security_approval(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "session_id": session_id,
                    "new_status": status.value,
                    "reason": reason,
                    "route_id": session.route_id,
                },
            )
            if not security_result["success"]:
                return security_result

            session.status = status
            session.updated_at = utc_now_iso()
            session.metadata["last_status_reason"] = reason

            self.session_store.set(session)

            verification_payload = self._prepare_verification_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "status": status.value,
                    "reason": reason,
                },
            )

            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "route_id": session.route_id,
                    "status": status.value,
                    "reason": reason,
                },
            )

            self._emit_agent_event(
                event_type=action,
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "status": status.value,
                    "reason": reason,
                },
            )

            self._log_audit_event(
                event_type=f"navigation_overlay.{status.value}",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "session_id": session_id,
                    "status": status.value,
                    "reason": reason,
                },
            )

            return self._safe_result(
                message=message,
                data={
                    "session": session.to_dict(redact=True),
                    "render_payload": self._build_render_payload(session),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "session_id": session_id,
                    "status": status.value,
                },
            )

        except Exception as exc:
            return self._error_result(
                message=f"Failed to update navigation overlay status to {status.value}.",
                error=str(exc),
                metadata={"operation": action},
            )

    def _calculate_progress(
        self,
        *,
        session: NavigationOverlaySession,
        pose: DevicePose,
    ) -> Dict[str, Any]:
        if not session.steps:
            return {
                "current_step_index": 0,
                "arrived": True,
                "remaining_distance_meters": 0.0,
                "distance_to_next_meters": 0.0,
                "target_bearing_degrees": 0.0,
                "heading_delta_degrees": 0.0,
                "relative_direction": "arrived",
                "progress_ratio": 1.0,
            }

        current_index = int(clamp(float(session.current_step_index), 0, len(session.steps) - 1))
        current_step = session.steps[current_index]
        pose_position = pose.position.to_dict()

        distance_to_next = distance_3d(pose_position, current_step.end.to_dict())

        while distance_to_next <= 0.75 and current_index < len(session.steps) - 1:
            current_index += 1
            current_step = session.steps[current_index]
            distance_to_next = distance_3d(pose_position, current_step.end.to_dict())

        remaining = distance_to_next
        for step in session.steps[current_index + 1:]:
            remaining += step.distance_meters

        destination_distance = distance_3d(pose_position, session.destination.to_dict())
        arrived = destination_distance <= 0.85 or (
            current_index == len(session.steps) - 1 and distance_to_next <= 0.85
        )

        target_bearing = bearing_degrees(pose_position, current_step.end.to_dict())
        heading_delta = angle_delta_degrees(pose.heading_degrees, target_bearing)
        relative_direction = heading_to_direction(heading_delta)

        completed_ratio = current_index / max(len(session.steps), 1)
        step_ratio = 1.0 - clamp(distance_to_next / max(current_step.distance_meters, 0.001), 0.0, 1.0)
        progress_ratio = clamp(completed_ratio + (step_ratio / max(len(session.steps), 1)), 0.0, 1.0)
        if arrived:
            progress_ratio = 1.0
            remaining = 0.0

        return {
            "current_step_index": current_index,
            "arrived": arrived,
            "remaining_distance_meters": round(remaining, 3),
            "distance_to_next_meters": round(distance_to_next, 3),
            "target_bearing_degrees": round(target_bearing, 2),
            "heading_delta_degrees": round(heading_delta, 2),
            "relative_direction": relative_direction,
            "progress_ratio": round(progress_ratio, 4),
            "pose_confidence": clamp(pose.confidence, 0.0, 1.0),
        }

    def _build_live_elements(
        self,
        *,
        session: NavigationOverlaySession,
        pose: DevicePose,
        progress: Dict[str, Any],
        hazards: Sequence[Mapping[str, Any]],
        metadata: Dict[str, Any],
    ) -> List[NavigationOverlayElement]:
        current_index = int(progress["current_step_index"])
        current_step = session.steps[current_index]

        direction_text = progress["relative_direction"]
        distance_text = self._format_distance(progress["distance_to_next_meters"])

        if progress["arrived"]:
            instruction_text = "You have arrived."
            severity = InstructionSeverity.SUCCESS
            action = RouteStepAction.ARRIVE
        else:
            instruction_text = f"{direction_text.title()} • {distance_text}"
            if current_step.instruction:
                instruction_text = f"{current_step.instruction} ({distance_text})"
            severity = current_step.severity
            action = current_step.action

        elements = [
            NavigationOverlayElement(
                element_id=make_id("overlay_live_arrow"),
                element_type=OverlayElementType.ARROW,
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                position=current_step.end,
                rotation_degrees=progress["target_bearing_degrees"],
                priority=5,
                ttl_seconds=self.default_overlay_ttl_seconds,
                style=self._default_style("arrow", session.mode),
                payload={
                    "step_id": current_step.step_id,
                    "action": action.value,
                    "relative_direction": direction_text,
                    "heading_delta_degrees": progress["heading_delta_degrees"],
                    "target_bearing_degrees": progress["target_bearing_degrees"],
                },
            ),
            NavigationOverlayElement(
                element_id=make_id("overlay_live_instruction"),
                element_type=OverlayElementType.INSTRUCTION_CARD,
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                text=normalize_instruction(instruction_text),
                priority=4,
                ttl_seconds=self.default_overlay_ttl_seconds,
                style=self._default_style("instruction_card", session.mode),
                payload={
                    "severity": severity.value,
                    "icon": self._icon_for_action(action),
                    "spoken_instruction": normalize_instruction(instruction_text),
                    "pose_confidence": progress["pose_confidence"],
                },
            ),
            NavigationOverlayElement(
                element_id=make_id("overlay_live_distance"),
                element_type=OverlayElementType.DISTANCE_LABEL,
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                position=current_step.end,
                text=distance_text,
                priority=12,
                ttl_seconds=self.default_overlay_ttl_seconds,
                style=self._default_style("distance_label", session.mode),
                payload={
                    "distance_to_next_meters": progress["distance_to_next_meters"],
                    "remaining_distance_meters": progress["remaining_distance_meters"],
                },
            ),
            NavigationOverlayElement(
                element_id=make_id("overlay_live_progress"),
                element_type=OverlayElementType.PROGRESS_BAR,
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                priority=20,
                ttl_seconds=self.default_overlay_ttl_seconds,
                style=self._default_style("progress_bar", session.mode),
                payload={
                    "progress_ratio": progress["progress_ratio"],
                    "current_step_index": current_index,
                    "total_steps": len(session.steps),
                    "arrived": progress["arrived"],
                },
            ),
            NavigationOverlayElement(
                element_id=make_id("overlay_compass"),
                element_type=OverlayElementType.COMPASS_RING,
                session_id=session.session_id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                rotation_degrees=pose.heading_degrees,
                priority=50,
                ttl_seconds=self.default_overlay_ttl_seconds,
                style=self._default_style("compass_ring", session.mode),
                payload={
                    "heading_degrees": pose.heading_degrees,
                    "target_bearing_degrees": progress["target_bearing_degrees"],
                },
            ),
        ]

        for hazard in hazards:
            warning_text = normalize_instruction(
                hazard.get("warning")
                or hazard.get("label")
                or hazard.get("message")
                or "Caution nearby."
            )
            hazard_position = None
            if hazard.get("position"):
                try:
                    hazard_position = NavigationCoordinate.from_mapping(hazard["position"])
                except Exception:
                    hazard_position = None

            elements.append(
                NavigationOverlayElement(
                    element_id=make_id("overlay_hazard"),
                    element_type=OverlayElementType.WARNING_CARD,
                    session_id=session.session_id,
                    user_id=session.user_id,
                    workspace_id=session.workspace_id,
                    position=hazard_position,
                    text=warning_text,
                    priority=1,
                    ttl_seconds=self.default_overlay_ttl_seconds,
                    style=self._default_style("warning_card", session.mode),
                    payload={
                        "severity": str(hazard.get("severity") or InstructionSeverity.WARNING.value),
                        "hazard": redact_sensitive(dict(hazard)),
                        "metadata": redact_sensitive(metadata),
                    },
                )
            )

        return elements

    def _build_render_payload(self, session: NavigationOverlaySession) -> Dict[str, Any]:
        """Build device-bridge/dashboard friendly render payload."""
        active_elements = [
            element.to_dict(redact=True)
            for element in session.elements
            if element.visible
        ]
        active_elements.sort(key=lambda item: item.get("priority", 100))

        return {
            "render_id": make_id("nav_render"),
            "session_id": session.session_id,
            "route_id": session.route_id,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "mode": session.mode.value,
            "status": session.status.value,
            "title": session.title,
            "current_step_index": session.current_step_index,
            "elements": active_elements,
            "element_count": len(active_elements),
            "safety_note": (
                "Navigation overlay is assistive. User and device layer must follow "
                "real-world safety, traffic, access, and accessibility rules."
            ),
            "created_at": utc_now_iso(),
            "version": DEFAULT_NAVIGATION_VERSION,
        }

    # ------------------------------------------------------------------
    # Internal Conversion / Inference Helpers
    # ------------------------------------------------------------------

    def _step_from_dict(self, data: Mapping[str, Any]) -> NavigationStep:
        start_data = data.get("start") or {}
        end_data = data.get("end") or {}

        return NavigationStep(
            step_id=str(data.get("step_id") or make_id("nav_step")),
            sequence=int(data.get("sequence", 0)),
            action=RouteStepAction(str(data.get("action") or RouteStepAction.GO_STRAIGHT.value)),
            instruction=normalize_instruction(data.get("instruction")),
            start=NavigationCoordinate.from_mapping(start_data),
            end=NavigationCoordinate.from_mapping(end_data),
            distance_meters=float(data.get("distance_meters", distance_3d(start_data, end_data))),
            bearing_degrees=float(data.get("bearing_degrees", bearing_degrees(start_data, end_data))),
            estimated_seconds=(
                float(data["estimated_seconds"])
                if data.get("estimated_seconds") is not None
                else None
            ),
            severity=InstructionSeverity(str(data.get("severity") or InstructionSeverity.INFO.value)),
            icon=data.get("icon"),
            spoken_instruction=data.get("spoken_instruction"),
            metadata=dict(data.get("metadata") or {}),
        )

    def _element_from_dict(self, data: Mapping[str, Any]) -> NavigationOverlayElement:
        position = None
        if data.get("position"):
            position = NavigationCoordinate.from_mapping(data["position"])

        return NavigationOverlayElement(
            element_id=str(data.get("element_id") or make_id("overlay")),
            element_type=OverlayElementType(str(data.get("element_type") or OverlayElementType.INSTRUCTION_CARD.value)),
            session_id=str(data.get("session_id") or ""),
            user_id=str(data.get("user_id") or ""),
            workspace_id=str(data.get("workspace_id") or ""),
            position=position,
            rotation_degrees=(
                float(data["rotation_degrees"])
                if data.get("rotation_degrees") is not None
                else None
            ),
            scale=float(data.get("scale", 1.0)),
            text=data.get("text"),
            visible=bool(data.get("visible", True)),
            opacity=float(data.get("opacity", 1.0)),
            priority=int(data.get("priority", 100)),
            ttl_seconds=float(data.get("ttl_seconds", self.default_overlay_ttl_seconds)),
            style=dict(data.get("style") or {}),
            payload=dict(data.get("payload") or {}),
            created_at=str(data.get("created_at") or utc_now_iso()),
            updated_at=str(data.get("updated_at") or utc_now_iso()),
        )

    def _infer_action_for_segment(
        self,
        *,
        previous: Optional[NavigationCoordinate],
        start: NavigationCoordinate,
        end: NavigationCoordinate,
        is_first: bool,
        is_last: bool,
    ) -> RouteStepAction:
        if is_last:
            return RouteStepAction.ARRIVE

        dy = end.y - start.y
        if dy > 1.5:
            return RouteStepAction.GO_UP
        if dy < -1.5:
            return RouteStepAction.GO_DOWN

        if is_first or previous is None:
            return RouteStepAction.START

        prev_bearing = bearing_degrees(previous.to_dict(), start.to_dict())
        next_bearing = bearing_degrees(start.to_dict(), end.to_dict())
        delta = angle_delta_degrees(prev_bearing, next_bearing)

        direction = heading_to_direction(delta)
        if direction == "straight":
            return RouteStepAction.GO_STRAIGHT
        if direction == "slight right":
            return RouteStepAction.SLIGHT_RIGHT
        if direction == "slight left":
            return RouteStepAction.SLIGHT_LEFT
        if direction == "right":
            return RouteStepAction.TURN_RIGHT
        if direction == "left":
            return RouteStepAction.TURN_LEFT
        return RouteStepAction.TURN_AROUND

    def _build_instruction_text(
        self,
        *,
        action: RouteStepAction,
        distance_meters: float,
        end: NavigationCoordinate,
        is_first: bool,
        is_last: bool,
    ) -> str:
        distance_text = self._format_distance(distance_meters)
        label = f" toward {end.label}" if end.label else ""

        if action == RouteStepAction.START:
            return f"Start navigation and move {distance_text}{label}."
        if action == RouteStepAction.GO_STRAIGHT:
            return f"Go straight for {distance_text}{label}."
        if action == RouteStepAction.TURN_LEFT:
            return f"Turn left and continue {distance_text}{label}."
        if action == RouteStepAction.TURN_RIGHT:
            return f"Turn right and continue {distance_text}{label}."
        if action == RouteStepAction.SLIGHT_LEFT:
            return f"Keep slightly left for {distance_text}{label}."
        if action == RouteStepAction.SLIGHT_RIGHT:
            return f"Keep slightly right for {distance_text}{label}."
        if action == RouteStepAction.TURN_AROUND:
            return f"Turn around and continue {distance_text}{label}."
        if action == RouteStepAction.GO_UP:
            return f"Go up and continue {distance_text}{label}."
        if action == RouteStepAction.GO_DOWN:
            return f"Go down and continue {distance_text}{label}."
        if action == RouteStepAction.ENTER:
            return f"Enter and continue {distance_text}{label}."
        if action == RouteStepAction.EXIT:
            return f"Exit and continue {distance_text}{label}."
        if action == RouteStepAction.WAIT:
            return "Wait before continuing."
        if action == RouteStepAction.CAUTION:
            return f"Proceed with caution for {distance_text}{label}."
        if action == RouteStepAction.ARRIVE:
            return f"Arrive at {end.label or 'your destination'}."

        return f"Continue for {distance_text}{label}."

    def _estimate_seconds(self, distance_meters: float, walking_speed_mps: float = 1.25) -> float:
        return round(max(distance_meters, 0.0) / max(walking_speed_mps, 0.1), 1)

    def _format_distance(self, meters: float) -> str:
        meters = max(float(meters), 0.0)
        if meters < 1:
            return "less than 1 m"
        if meters < 1000:
            return f"{round(meters, 1)} m"
        return f"{round(meters / 1000, 2)} km"

    def _icon_for_action(self, action: RouteStepAction) -> str:
        icons = {
            RouteStepAction.START: "navigation-start",
            RouteStepAction.GO_STRAIGHT: "arrow-up",
            RouteStepAction.TURN_LEFT: "turn-left",
            RouteStepAction.TURN_RIGHT: "turn-right",
            RouteStepAction.SLIGHT_LEFT: "slight-left",
            RouteStepAction.SLIGHT_RIGHT: "slight-right",
            RouteStepAction.TURN_AROUND: "u-turn",
            RouteStepAction.GO_UP: "stairs-up",
            RouteStepAction.GO_DOWN: "stairs-down",
            RouteStepAction.ENTER: "enter",
            RouteStepAction.EXIT: "exit",
            RouteStepAction.ARRIVE: "destination",
            RouteStepAction.WAIT: "pause",
            RouteStepAction.CAUTION: "warning",
        }
        return icons.get(action, "navigation")

    def _default_style(
        self,
        element_type: str,
        mode: NavigationMode,
    ) -> Dict[str, Any]:
        """
        Return renderer-neutral style tokens.

        The Device Bridge / AR client can map these to native colors, meshes,
        materials, fonts, haptics, or accessibility settings.
        """
        base = {
            "theme": "william_hologram",
            "mode": mode.value,
            "depth_test": True,
            "billboard": True,
            "accessibility": {
                "high_contrast_ready": True,
                "voice_prompt_ready": True,
                "large_text_ready": True,
            },
        }

        styles = {
            "path_line": {
                "line_width": 0.035,
                "material": "hologram_path",
                "animation": "flow_forward",
            },
            "arrow": {
                "mesh": "direction_arrow",
                "material": "hologram_primary",
                "animation": "pulse",
            },
            "instruction_card": {
                "panel": "floating_card",
                "placement": "upper_center",
                "text_size": "medium",
                "animation": "fade_slide",
            },
            "distance_label": {
                "panel": "compact_label",
                "placement": "near_target",
                "text_size": "small",
            },
            "warning_card": {
                "panel": "warning_card",
                "placement": "center_safe",
                "text_size": "medium",
                "animation": "attention_pulse",
            },
            "progress_bar": {
                "placement": "bottom_center",
                "height": 0.012,
                "animation": "smooth_progress",
            },
            "compass_ring": {
                "placement": "lower_right",
                "mesh": "compass_ring",
                "text_size": "small",
            },
            "waypoint_marker": {
                "mesh": "waypoint_pin",
                "material": "hologram_secondary",
            },
            "destination_marker": {
                "mesh": "destination_pin",
                "material": "hologram_success",
                "animation": "pulse",
            },
            "mini_map": {
                "placement": "lower_left",
                "panel": "mini_map",
            },
        }

        return {**base, **styles.get(element_type, {})}

    # ------------------------------------------------------------------
    # Export Helpers
    # ------------------------------------------------------------------

    def export_state(self, *, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """Export active navigation overlay sessions for one user/workspace."""
        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="export_navigation_overlay_state",
        )
        if not context["success"]:
            return context

        sessions = self.session_store.list_for_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )

        return self._safe_result(
            message="Navigation overlay state exported.",
            data={
                "sessions": [session.to_dict(redact=True) for session in sessions],
                "count": len(sessions),
                "version": DEFAULT_NAVIGATION_VERSION,
            },
        )


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

__all__ = [
    "NavigationOverlay",
    "NavigationCoordinate",
    "NavigationStep",
    "NavigationOverlayElement",
    "NavigationOverlaySession",
    "DevicePose",
    "SessionStore",
    "NavigationMode",
    "OverlayStatus",
    "OverlayElementType",
    "InstructionSeverity",
    "RouteStepAction",
    "distance_3d",
    "bearing_degrees",
    "angle_delta_degrees",
    "heading_to_direction",
    "redact_sensitive",
]


# ---------------------------------------------------------------------------
# Minimal self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight local test.

    This does not run automatically on import. Developers may call:
        python -c "from agents.super_agents.hologram_agent.navigation_overlay import _self_test; import json; print(json.dumps(_self_test(), indent=2))"
    """
    overlay = NavigationOverlay()

    start_result = overlay.start_navigation_overlay(
        user_id="user_test",
        workspace_id="workspace_test",
        origin={"x": 0, "y": 0, "z": 0, "label": "Desk"},
        waypoints=[
            {"x": 2, "y": 0, "z": 3, "label": "Door"},
            {"x": 5, "y": 0, "z": 6, "label": "Hallway"},
        ],
        destination={"x": 8, "y": 0, "z": 8, "label": "Meeting Room"},
        title="Test Indoor Navigation",
        mode=NavigationMode.INDOOR,
    )

    if not start_result["success"]:
        return start_result

    session_id = start_result["data"]["session"]["session_id"]

    update_result = overlay.update_navigation_overlay(
        user_id="user_test",
        workspace_id="workspace_test",
        session_id=session_id,
        device_pose={
            "position": {"x": 1, "y": 0, "z": 1},
            "heading_degrees": 25,
            "confidence": 0.96,
        },
        hazards=[
            {
                "warning": "Caution: object near path.",
                "severity": "warning",
                "position": {"x": 2.5, "y": 0, "z": 3.2},
            }
        ],
    )

    return update_result


"""
Where to place:
    agents/super_agents/hologram_agent/navigation_overlay.py

Required dependencies:
    - Python 3.10+
    - Standard library only:
        dataclasses, enum, typing, json, logging, math, re, time, uuid,
        datetime, collections

How to test:
    1. Save this file at:
        agents/super_agents/hologram_agent/navigation_overlay.py

    2. Run import/compile test:
        python -m py_compile agents/super_agents/hologram_agent/navigation_overlay.py

    3. Run lightweight self-test:
        python -c "from agents.super_agents.hologram_agent.navigation_overlay import _self_test; import json; print(json.dumps(_self_test(), indent=2))"

    4. Expected:
        - success: true
        - message: Navigation overlay updated.
        - data.render_payload contains AR overlay elements:
            arrow, instruction_card, distance_label, progress_bar, compass_ring, warning_card

Agent/module completion percentage after this file:
    63.6%

Next file to generate:
    agents/super_agents/hologram_agent/notification_overlay.py

Agent/Module: Hologram Agent
File Completed: navigation_overlay.py
Completion: 63.6%
Completed Files: ['hologram_agent.py', 'ar_overlay.py', 'spatial_mapper.py', 'gesture_bridge.py', 'real_world_context.py', 'object_recognizer.py', 'navigation_overlay.py']
Remaining Files: ['notification_overlay.py', 'device_bridge.py', 'hologram_memory.py', 'config.py']
Next Recommended File: agents/super_agents/hologram_agent/notification_overlay.py
FILE COMPLETE
"""