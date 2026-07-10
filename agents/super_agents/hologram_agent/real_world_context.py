"""
agents/super_agents/hologram_agent/real_world_context.py

William / Jarvis Multi-Agent AI SaaS System
Hologram Agent - Real World Context

Purpose:
    Understands environment context and routes real-world tasks.

This module is designed for AR glasses, hologram interfaces, wearable devices,
camera/sensor streams, spatial context, object context, and real-world commands.

It safely normalizes real-world observations such as:
    - detected objects
    - scene labels
    - room/environment state
    - user position
    - device/sensor metadata
    - spatial map hints
    - gesture/voice/user instruction
    - safety-critical surroundings

Then it routes real-world tasks to:
    - Hologram Agent
    - Visual Agent
    - Workflow Agent
    - Browser Agent
    - Memory Agent
    - Navigation overlay
    - Object recognizer
    - Spatial mapper
    - Device bridge
    - Master Agent / Agent Router compatible targets

Core safety goals:
    - Never mix users/workspaces
    - Never perform physical-world, navigation, message, browser, financial,
      destructive, or device-control tasks without permission/security checks
    - Prepare Verification Agent payloads after useful actions
    - Prepare Memory Agent payloads only with safe redacted context
    - Remain import-safe even before the full William/Jarvis system exists
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import math
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


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe while other William/Jarvis modules are still
        being generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def log_audit(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.super_agents.hologram_agent.spatial_mapper import SpatialMapper  # type: ignore
except Exception:  # pragma: no cover
    SpatialMapper = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.ar_overlay import AROverlay  # type: ignore
except Exception:  # pragma: no cover
    AROverlay = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.gesture_bridge import GestureBridge  # type: ignore
except Exception:  # pragma: no cover
    GestureBridge = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.object_recognizer import ObjectRecognizer  # type: ignore
except Exception:  # pragma: no cover
    ObjectRecognizer = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.navigation_overlay import NavigationOverlay  # type: ignore
except Exception:  # pragma: no cover
    NavigationOverlay = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.notification_overlay import NotificationOverlay  # type: ignore
except Exception:  # pragma: no cover
    NotificationOverlay = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.device_bridge import DeviceBridge  # type: ignore
except Exception:  # pragma: no cover
    DeviceBridge = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.hologram_memory import HologramMemory  # type: ignore
except Exception:  # pragma: no cover
    HologramMemory = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums and constants
# =============================================================================

class EnvironmentType(str, Enum):
    """Normalized real-world environment categories."""

    UNKNOWN = "unknown"
    INDOOR = "indoor"
    OUTDOOR = "outdoor"
    VEHICLE = "vehicle"
    OFFICE = "office"
    HOME = "home"
    STORE = "store"
    STREET = "street"
    WAREHOUSE = "warehouse"
    MEDICAL = "medical"
    INDUSTRIAL = "industrial"


class RealWorldIntent(str, Enum):
    """Task intent inferred from a real-world instruction."""

    UNKNOWN = "unknown"
    DESCRIBE_SCENE = "describe_scene"
    IDENTIFY_OBJECT = "identify_object"
    NAVIGATE = "navigate"
    OVERLAY_INFO = "overlay_info"
    REMIND_OR_NOTIFY = "remind_or_notify"
    RECORD_CONTEXT = "record_context"
    SEARCH_OR_BROWSER = "search_or_browser"
    WORKFLOW_ACTION = "workflow_action"
    DEVICE_CONTROL = "device_control"
    SAFETY_ALERT = "safety_alert"
    MEASURE_SPACE = "measure_space"
    TRACK_OBJECT = "track_object"
    CALL_OR_MESSAGE = "call_or_message"
    FINANCIAL_OR_PAYMENT = "financial_or_payment"


class RealWorldRiskLevel(str, Enum):
    """Risk level for real-world context actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RealWorldRouteKind(str, Enum):
    """Route categories used by this context module."""

    LOCAL = "local"
    HOLOGRAM = "hologram"
    VISUAL = "visual"
    WORKFLOW = "workflow"
    BROWSER = "browser"
    MEMORY = "memory"
    MASTER_AGENT = "master_agent"
    SPATIAL_MAPPER = "spatial_mapper"
    OBJECT_RECOGNIZER = "object_recognizer"
    AR_OVERLAY = "ar_overlay"
    NAVIGATION_OVERLAY = "navigation_overlay"
    NOTIFICATION_OVERLAY = "notification_overlay"
    DEVICE_BRIDGE = "device_bridge"
    UNKNOWN = "unknown"


class ContextStatus(str, Enum):
    """Status values for context interpretation and routing."""

    RECEIVED = "received"
    VALIDATED = "validated"
    INTERPRETED = "interpreted"
    ROUTED = "routed"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    SKIPPED = "skipped"


SENSITIVE_INTENT_KEYWORDS: Tuple[str, ...] = (
    "send",
    "message",
    "call",
    "email",
    "sms",
    "whatsapp",
    "pay",
    "payment",
    "charge",
    "refund",
    "purchase",
    "buy",
    "unlock",
    "open door",
    "lock",
    "delete",
    "remove",
    "shutdown",
    "restart",
    "browser",
    "login",
    "submit",
    "post",
    "share",
    "record",
    "stream",
    "upload",
    "camera",
    "microphone",
    "location",
    "navigate",
    "drive",
    "medical",
    "hazard",
    "danger",
    "emergency",
)

CRITICAL_REAL_WORLD_KEYWORDS: Tuple[str, ...] = (
    "emergency",
    "fire",
    "smoke",
    "gas leak",
    "weapon",
    "accident",
    "crash",
    "blood",
    "injury",
    "unconscious",
    "fall",
    "danger",
    "hazard",
    "toxic",
    "electric shock",
    "medical emergency",
)

NAVIGATION_KEYWORDS: Tuple[str, ...] = (
    "navigate",
    "route",
    "directions",
    "take me",
    "guide me",
    "where is",
    "find way",
    "path",
    "turn left",
    "turn right",
)

OBJECT_KEYWORDS: Tuple[str, ...] = (
    "what is this",
    "identify",
    "recognize",
    "object",
    "thing",
    "label",
    "scan",
)

OVERLAY_KEYWORDS: Tuple[str, ...] = (
    "overlay",
    "show",
    "display",
    "pin",
    "float",
    "card",
    "highlight",
    "label this",
)

MEASURE_KEYWORDS: Tuple[str, ...] = (
    "measure",
    "distance",
    "height",
    "width",
    "area",
    "dimension",
    "size",
)

DEVICE_CONTROL_KEYWORDS: Tuple[str, ...] = (
    "turn on",
    "turn off",
    "connect",
    "disconnect",
    "volume",
    "brightness",
    "camera",
    "microphone",
    "record",
    "stream",
    "pair device",
)

DEFAULT_TIMEOUT_SECONDS = 45
DEFAULT_CONFIDENCE_THRESHOLD = 0.55


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class RealWorldTaskContext:
    """
    SaaS-safe task context.

    user_id and workspace_id are mandatory for user-specific real-world context.
    This prevents camera/sensor/memory/task data from leaking across tenants.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    agent_permissions: Dict[str, Any] = field(default_factory=dict)
    locale: Optional[str] = None
    timezone: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RealWorldTaskContext":
        permissions_raw = value.get("permissions", [])
        if isinstance(permissions_raw, str):
            permissions = [permissions_raw]
        elif isinstance(permissions_raw, Iterable):
            permissions = [str(item) for item in permissions_raw if item is not None]
        else:
            permissions = []

        agent_permissions_raw = value.get("agent_permissions", {})
        agent_permissions = dict(agent_permissions_raw) if isinstance(agent_permissions_raw, Mapping) else {}

        metadata_raw = value.get("metadata", {})
        metadata = dict(metadata_raw) if isinstance(metadata_raw, Mapping) else {}

        return cls(
            user_id=str(value.get("user_id") or "").strip(),
            workspace_id=str(value.get("workspace_id") or "").strip(),
            request_id=str(value.get("request_id") or uuid.uuid4()),
            session_id=_optional_str(value.get("session_id")),
            device_id=_optional_str(value.get("device_id")),
            role=_optional_str(value.get("role")),
            subscription_plan=_optional_str(value.get("subscription_plan")),
            permissions=permissions,
            agent_permissions=agent_permissions,
            locale=_optional_str(value.get("locale")),
            timezone=_optional_str(value.get("timezone")),
            metadata=metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "role": self.role,
            "subscription_plan": self.subscription_plan,
            "permissions": list(self.permissions),
            "agent_permissions": dict(self.agent_permissions),
            "locale": self.locale,
            "timezone": self.timezone,
            "metadata": dict(self.metadata),
        }


@dataclass
class DetectedObject:
    """Normalized object observation from visual/object-recognition systems."""

    label: str
    confidence: float = 0.0
    object_id: Optional[str] = None
    category: Optional[str] = None
    bounding_box: Optional[Dict[str, float]] = None
    position_3d: Optional[Dict[str, float]] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DetectedObject":
        bbox = value.get("bounding_box") or value.get("bbox") or value.get("box")
        position = value.get("position_3d") or value.get("position") or value.get("coordinates")

        return cls(
            label=str(value.get("label") or value.get("name") or value.get("class") or "unknown"),
            confidence=_safe_float(value.get("confidence"), default=0.0),
            object_id=_optional_str(value.get("object_id") or value.get("id")),
            category=_optional_str(value.get("category") or value.get("type")),
            bounding_box=dict(bbox) if isinstance(bbox, Mapping) else None,
            position_3d=dict(position) if isinstance(position, Mapping) else None,
            attributes=dict(value.get("attributes", {})) if isinstance(value.get("attributes"), Mapping) else {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "object_id": self.object_id,
            "category": self.category,
            "bounding_box": dict(self.bounding_box or {}),
            "position_3d": dict(self.position_3d or {}),
            "attributes": _redact_sensitive(dict(self.attributes)),
        }


@dataclass
class SpatialObservation:
    """Normalized spatial/environment observation."""

    environment_type: EnvironmentType = EnvironmentType.UNKNOWN
    scene_labels: List[str] = field(default_factory=list)
    objects: List[DetectedObject] = field(default_factory=list)
    location: Dict[str, Any] = field(default_factory=dict)
    user_pose: Dict[str, Any] = field(default_factory=dict)
    device_pose: Dict[str, Any] = field(default_factory=dict)
    room_map: Dict[str, Any] = field(default_factory=dict)
    hazards: List[Dict[str, Any]] = field(default_factory=list)
    raw_sensor_summary: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "environment_type": self.environment_type.value,
            "scene_labels": list(self.scene_labels),
            "objects": [obj.to_dict() for obj in self.objects],
            "location": _redact_sensitive(dict(self.location)),
            "user_pose": _redact_sensitive(dict(self.user_pose)),
            "device_pose": _redact_sensitive(dict(self.device_pose)),
            "room_map": _redact_sensitive(dict(self.room_map)),
            "hazards": _redact_sensitive(list(self.hazards)),
            "raw_sensor_summary": _redact_sensitive(dict(self.raw_sensor_summary)),
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class RealWorldInterpretation:
    """Result of understanding the real-world context and instruction."""

    intent: RealWorldIntent
    risk_level: RealWorldRiskLevel
    route_kind: RealWorldRouteKind
    confidence: float
    summary: str
    recommended_action: str
    reasons: List[str] = field(default_factory=list)
    extracted_entities: Dict[str, Any] = field(default_factory=dict)
    safety_notes: List[str] = field(default_factory=list)
    requires_security: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent.value,
            "risk_level": self.risk_level.value,
            "route_kind": self.route_kind.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "reasons": list(self.reasons),
            "extracted_entities": _redact_sensitive(dict(self.extracted_entities)),
            "safety_notes": list(self.safety_notes),
            "requires_security": self.requires_security,
            "metadata": _redact_sensitive(dict(self.metadata)),
        }


@dataclass
class RouteTarget:
    """Resolved route target for a real-world task."""

    kind: RealWorldRouteKind
    name: str
    target: Any = None
    method_name: Optional[str] = None
    requires_security: bool = False
    risk_level: RealWorldRiskLevel = RealWorldRiskLevel.LOW
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "method_name": self.method_name,
            "requires_security": self.requires_security,
            "risk_level": self.risk_level.value,
            "target_type": type(self.target).__name__ if self.target is not None else None,
            "metadata": _redact_sensitive(dict(self.metadata)),
        }


@dataclass
class RealWorldExecutionRecord:
    """Bounded local execution record for debugging/dashboard/API usage."""

    record_id: str
    request_id: str
    user_id: str
    workspace_id: str
    intent: str
    route_kind: str
    route_name: str
    status: ContextStatus
    started_at: str
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    security_required: bool = False
    security_approved: Optional[bool] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "intent": self.intent,
            "route_kind": self.route_kind,
            "route_name": self.route_name,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "security_required": self.security_required,
            "security_approved": self.security_approved,
            "error": self.error,
            "metadata": _redact_sensitive(dict(self.metadata)),
        }


# =============================================================================
# Utility helpers
# =============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _duration_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _lower_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    try:
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return default
        return number
    except Exception:
        return default


def _safe_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _contains_any(text: str, keywords: Sequence[str]) -> bool:
    clean = _lower_text(text)
    return any(keyword in clean for keyword in keywords)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _redact_sensitive(value: Any) -> Any:
    """
    Recursively redact sensitive data before logs, memory, audit, dashboard, and
    verification payloads.
    """

    sensitive_markers = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "private_key",
        "client_secret",
        "access_token",
        "refresh_token",
        "exact_location",
        "precise_location",
        "lat",
        "latitude",
        "lon",
        "lng",
        "longitude",
        "address",
        "microphone_raw",
        "camera_raw",
        "image_raw",
        "video_raw",
        "audio_raw",
        "biometric",
        "face_id",
        "fingerprint",
    )

    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if any(marker in key_lower for marker in sensitive_markers):
                redacted[key_text] = "***REDACTED***"
            else:
                redacted[key_text] = _redact_sensitive(item)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item) for item in value)

    return value


def _normalize_environment_type(value: Any, scene_labels: Optional[Sequence[str]] = None) -> EnvironmentType:
    text = _lower_text(value)
    labels_text = " ".join(_lower_text(label) for label in (scene_labels or []))
    combined = f"{text} {labels_text}"

    if any(word in combined for word in ("office", "desk", "meeting room", "workspace")):
        return EnvironmentType.OFFICE
    if any(word in combined for word in ("home", "bedroom", "kitchen", "living room")):
        return EnvironmentType.HOME
    if any(word in combined for word in ("vehicle", "car", "bus", "truck", "train")):
        return EnvironmentType.VEHICLE
    if any(word in combined for word in ("store", "shop", "mall", "market")):
        return EnvironmentType.STORE
    if any(word in combined for word in ("street", "road", "sidewalk", "traffic")):
        return EnvironmentType.STREET
    if any(word in combined for word in ("warehouse", "factory", "industrial")):
        return EnvironmentType.WAREHOUSE
    if any(word in combined for word in ("hospital", "clinic", "medical")):
        return EnvironmentType.MEDICAL
    if any(word in combined for word in ("outdoor", "outside", "park")):
        return EnvironmentType.OUTDOOR
    if any(word in combined for word in ("indoor", "inside", "room")):
        return EnvironmentType.INDOOR

    try:
        return EnvironmentType(text)
    except Exception:
        return EnvironmentType.UNKNOWN


# =============================================================================
# Main class
# =============================================================================

class RealWorldContext(BaseAgent):
    """
    Understands environment context and routes real-world tasks.

    Integration notes:
        - Master Agent can call understand_context(), route_real_world_task(),
          process_environment_update(), or handle_real_world_request().
        - Hologram Agent can use this as the context reasoning layer between
          AR overlays, spatial mapping, gesture input, object recognition, and
          device bridge.
        - Security Agent is called before sensitive real-world actions.
        - Verification Agent receives structured payloads for checking results.
        - Memory Agent receives safe, redacted real-world context summaries.
        - Dashboard/API can display interpretation, route, status, risk, and
          bounded execution history.
        - Agent Registry / Agent Loader can inject route targets at runtime.
    """

    agent_name = "real_world_context"
    version = "1.0.0"

    def __init__(
        self,
        *,
        route_registry: Optional[Mapping[str, Any]] = None,
        agent_registry: Optional[Mapping[str, Any]] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        allow_safe_local_fallback: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, **kwargs)

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.confidence_threshold = max(0.0, min(float(confidence_threshold), 1.0))
        self.default_timeout_seconds = max(1, int(default_timeout_seconds or DEFAULT_TIMEOUT_SECONDS))
        self.allow_safe_local_fallback = bool(allow_safe_local_fallback)

        self.route_registry: Dict[str, Any] = {}
        self.agent_registry: Dict[str, Any] = {}
        self.local_handlers: Dict[str, Callable[..., Any]] = {}
        self._execution_history: List[RealWorldExecutionRecord] = []

        self._install_optional_hologram_components()
        self._install_default_local_handlers()

        if route_registry:
            for name, target in route_registry.items():
                self.register_route(str(name), target)

        if agent_registry:
            for name, agent in agent_registry.items():
                self.register_agent(str(name), agent)

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    def register_route(self, name: str, target: Any) -> Dict[str, Any]:
        """Register a route target such as overlay, navigation, device bridge."""

        clean_name = self._normalize_name(name)
        if not clean_name:
            return self._error_result(
                message="Route name is required.",
                error="missing_route_name",
            )

        self.route_registry[clean_name] = target
        return self._safe_result(
            message=f"Real-world route registered: {clean_name}",
            data={"route": clean_name},
        )

    def register_agent(self, name: str, agent: Any) -> Dict[str, Any]:
        """Register an internal William/Jarvis agent target."""

        clean_name = self._normalize_name(name)
        if not clean_name:
            return self._error_result(
                message="Agent name is required.",
                error="missing_agent_name",
            )

        self.agent_registry[clean_name] = agent
        return self._safe_result(
            message=f"Real-world agent registered: {clean_name}",
            data={"agent": clean_name},
        )

    def register_handler(self, intent: Union[str, RealWorldIntent], handler: Callable[..., Any]) -> Dict[str, Any]:
        """Register a local handler for a real-world intent."""

        clean_intent = self._normalize_name(intent.value if isinstance(intent, RealWorldIntent) else intent)
        if not clean_intent:
            return self._error_result(
                message="Intent name is required.",
                error="missing_intent_name",
            )

        if not callable(handler):
            return self._error_result(
                message="Handler must be callable.",
                error="invalid_handler",
                data={"intent": clean_intent},
            )

        self.local_handlers[clean_intent] = handler
        return self._safe_result(
            message=f"Real-world local handler registered: {clean_intent}",
            data={"intent": clean_intent},
        )

    def list_routes(self) -> Dict[str, Any]:
        """Return route/agent/local handler availability for dashboard/API."""

        return self._safe_result(
            message="Available real-world context routes.",
            data={
                "routes": sorted(self.route_registry.keys()),
                "agents": sorted(self.agent_registry.keys()),
                "local_handlers": sorted(self.local_handlers.keys()),
                "agent": self.agent_name,
                "version": self.version,
            },
        )

    def get_execution_history(self, limit: int = 100) -> Dict[str, Any]:
        """Return recent bounded execution history."""

        safe_limit = max(1, min(int(limit or 100), 1000))
        records = self._execution_history[-safe_limit:]
        return self._safe_result(
            message="Real-world context execution history.",
            data={
                "count": len(records),
                "records": [record.to_dict() for record in records],
            },
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def handle_real_world_request(
        self,
        *,
        instruction: Optional[str] = None,
        observation: Optional[Mapping[str, Any]] = None,
        context: Union[RealWorldTaskContext, Mapping[str, Any]],
        dry_run: bool = False,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Main entry point for Master Agent and Hologram Agent.

        It normalizes environment data, interprets user intent, performs security
        checks if required, routes the task, and returns structured output.
        """

        return await self.route_real_world_task(
            instruction=instruction,
            observation=observation,
            context=context,
            dry_run=dry_run,
            timeout_seconds=timeout_seconds,
        )

    async def process_environment_update(
        self,
        observation: Mapping[str, Any],
        context: Union[RealWorldTaskContext, Mapping[str, Any]],
        *,
        instruction: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Process passive environment updates from AR glasses/device bridge.

        If no instruction is provided, this only summarizes and records safe
        context unless a safety-critical hazard is detected.
        """

        normalized_observation = self.normalize_observation(observation)
        instruction_text = instruction or self._derive_passive_instruction(normalized_observation)

        return await self.route_real_world_task(
            instruction=instruction_text,
            observation=normalized_observation.to_dict(),
            context=context,
            dry_run=dry_run,
        )

    def understand_context(
        self,
        *,
        instruction: Optional[str] = None,
        observation: Optional[Mapping[str, Any]] = None,
        context: Optional[Union[RealWorldTaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous context interpretation.

        This does not execute route targets. It is safe for dashboard previews,
        tests, API validation, and Master Agent planning.
        """

        normalized_observation = self.normalize_observation(observation or {})
        interpretation = self.interpret_real_world_task(
            instruction=instruction or "",
            observation=normalized_observation,
            context=context,
        )

        return self._safe_result(
            message="Real-world context interpreted.",
            data={
                "observation": normalized_observation.to_dict(),
                "interpretation": interpretation.to_dict(),
            },
        )

    async def route_real_world_task(
        self,
        *,
        instruction: Optional[str],
        observation: Optional[Mapping[str, Any]],
        context: Union[RealWorldTaskContext, Mapping[str, Any]],
        dry_run: bool = False,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Understand and route one real-world task.

        Args:
            instruction:
                Natural language command from voice, gesture, dashboard, Master
                Agent, or Hologram Agent.

            observation:
                Sensor/camera/spatial/object/scene context dictionary.

            context:
                SaaS-safe user/workspace context.

            dry_run:
                If True, validates and prepares route/security/verification/memory
                data without executing target handlers.

            timeout_seconds:
                Optional route execution timeout.
        """

        started = time.monotonic()
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        task_context: RealWorldTaskContext = context_result["data"]["context"]
        normalized_observation = self.normalize_observation(observation or {})
        interpretation = self.interpret_real_world_task(
            instruction=instruction or "",
            observation=normalized_observation,
            context=task_context,
        )
        route = self._resolve_route(interpretation)

        requires_security = self._requires_security_check(
            instruction=instruction or "",
            observation=normalized_observation,
            interpretation=interpretation,
            route=route,
        )

        record = RealWorldExecutionRecord(
            record_id=str(uuid.uuid4()),
            request_id=task_context.request_id,
            user_id=task_context.user_id,
            workspace_id=task_context.workspace_id,
            intent=interpretation.intent.value,
            route_kind=route.kind.value,
            route_name=route.name,
            status=ContextStatus.RECEIVED,
            started_at=_now_iso(),
            security_required=requires_security,
            metadata={
                "dry_run": dry_run,
                "session_id": task_context.session_id,
                "device_id": task_context.device_id,
            },
        )

        await self._emit_agent_event(
            event_type="hologram.real_world_context.started",
            context=task_context,
            payload={
                "instruction": instruction,
                "interpretation": interpretation.to_dict(),
                "route": route.to_dict(),
                "dry_run": dry_run,
            },
        )

        try:
            record.status = ContextStatus.INTERPRETED

            if requires_security:
                approval = await self._request_security_approval(
                    instruction=instruction or "",
                    observation=normalized_observation,
                    interpretation=interpretation,
                    context=task_context,
                    route=route,
                    dry_run=dry_run,
                )
                record.security_approved = bool(approval.get("success"))

                if not approval.get("success"):
                    record.status = ContextStatus.BLOCKED
                    record.error = str(approval.get("error") or "security_denied")
                    record.finished_at = _now_iso()
                    record.duration_ms = _duration_ms(started)
                    self._remember_record(record)

                    result = self._error_result(
                        message="Real-world task blocked by Security Agent.",
                        error=record.error,
                        data={
                            "instruction": instruction,
                            "observation": normalized_observation.to_dict(),
                            "interpretation": interpretation.to_dict(),
                            "route": route.to_dict(),
                            "security": approval,
                            "executed": False,
                        },
                        metadata=self._result_metadata(task_context, record),
                    )

                    await self._log_audit_event(
                        event_type="hologram.real_world_context.security_blocked",
                        context=task_context,
                        payload=result,
                    )
                    return result

            if dry_run:
                record.status = ContextStatus.SKIPPED
                record.finished_at = _now_iso()
                record.duration_ms = _duration_ms(started)
                self._remember_record(record)

                dry_result = {
                    "success": True,
                    "message": "Dry run completed. Real-world task was not executed.",
                    "data": {"executed": False, "dry_run": True},
                    "error": None,
                }

                verification_payload = self._prepare_verification_payload(
                    instruction=instruction or "",
                    observation=normalized_observation,
                    interpretation=interpretation,
                    context=task_context,
                    route=route,
                    action_result=dry_result,
                )

                memory_payload = self._prepare_memory_payload(
                    instruction=instruction or "",
                    observation=normalized_observation,
                    interpretation=interpretation,
                    context=task_context,
                    route=route,
                    action_result=dry_result,
                )

                result = self._safe_result(
                    message="Dry run completed. Real-world route is valid but was not executed.",
                    data={
                        "instruction": instruction,
                        "observation": normalized_observation.to_dict(),
                        "interpretation": interpretation.to_dict(),
                        "route": route.to_dict(),
                        "executed": False,
                        "dry_run": True,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata=self._result_metadata(task_context, record),
                )

                await self._log_audit_event(
                    event_type="hologram.real_world_context.dry_run",
                    context=task_context,
                    payload=result,
                )
                return result

            record.status = ContextStatus.ROUTED
            effective_timeout = max(1, int(timeout_seconds or self.default_timeout_seconds))

            raw_route_result = await asyncio.wait_for(
                self._execute_route(
                    instruction=instruction or "",
                    observation=normalized_observation,
                    interpretation=interpretation,
                    context=task_context,
                    route=route,
                ),
                timeout=effective_timeout,
            )

            route_result = self._normalize_target_result(raw_route_result)

            record.status = ContextStatus.COMPLETED if route_result.get("success") else ContextStatus.FAILED
            record.error = None if route_result.get("success") else str(route_result.get("error") or "route_failed")
            record.finished_at = _now_iso()
            record.duration_ms = _duration_ms(started)

            verification_payload = self._prepare_verification_payload(
                instruction=instruction or "",
                observation=normalized_observation,
                interpretation=interpretation,
                context=task_context,
                route=route,
                action_result=route_result,
            )

            memory_payload = self._prepare_memory_payload(
                instruction=instruction or "",
                observation=normalized_observation,
                interpretation=interpretation,
                context=task_context,
                route=route,
                action_result=route_result,
            )

            self._remember_record(record)

            result = self._safe_result(
                message=(
                    "Real-world task understood and routed successfully."
                    if route_result.get("success")
                    else "Real-world task was understood but route execution failed."
                ),
                data={
                    "instruction": instruction,
                    "observation": normalized_observation.to_dict(),
                    "interpretation": interpretation.to_dict(),
                    "route": route.to_dict(),
                    "executed": True,
                    "route_result": route_result,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                error=None if route_result.get("success") else route_result.get("error"),
                metadata=self._result_metadata(task_context, record),
            )
            result["success"] = bool(route_result.get("success"))

            await self._emit_agent_event(
                event_type=(
                    "hologram.real_world_context.completed"
                    if result["success"]
                    else "hologram.real_world_context.failed"
                ),
                context=task_context,
                payload={
                    "intent": interpretation.intent.value,
                    "route": route.to_dict(),
                    "success": result["success"],
                    "duration_ms": record.duration_ms,
                },
            )

            await self._log_audit_event(
                event_type=(
                    "hologram.real_world_context.completed"
                    if result["success"]
                    else "hologram.real_world_context.failed"
                ),
                context=task_context,
                payload=result,
            )

            return result

        except asyncio.TimeoutError:
            record.status = ContextStatus.FAILED
            record.error = "real_world_task_timeout"
            record.finished_at = _now_iso()
            record.duration_ms = _duration_ms(started)
            self._remember_record(record)

            result = self._error_result(
                message="Real-world task route timed out.",
                error="real_world_task_timeout",
                data={
                    "instruction": instruction,
                    "interpretation": interpretation.to_dict(),
                    "route": route.to_dict(),
                    "executed": False,
                },
                metadata=self._result_metadata(task_context, record),
            )

            await self._log_audit_event(
                event_type="hologram.real_world_context.timeout",
                context=task_context,
                payload=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("Real-world context routing failed.")
            record.status = ContextStatus.FAILED
            record.error = str(exc)
            record.finished_at = _now_iso()
            record.duration_ms = _duration_ms(started)
            self._remember_record(record)

            result = self._error_result(
                message="Real-world context routing failed.",
                error=str(exc),
                data={
                    "instruction": instruction,
                    "interpretation": interpretation.to_dict(),
                    "route": route.to_dict(),
                    "executed": False,
                },
                metadata=self._result_metadata(task_context, record),
            )

            await self._log_audit_event(
                event_type="hologram.real_world_context.exception",
                context=task_context,
                payload=result,
            )
            return result

    # -------------------------------------------------------------------------
    # Context normalization and interpretation
    # -------------------------------------------------------------------------

    def normalize_observation(self, observation: Mapping[str, Any]) -> SpatialObservation:
        """
        Normalize raw real-world input.

        Supported raw shapes:
            {
                "environment_type": "office",
                "scene_labels": ["desk", "laptop"],
                "objects": [{"label": "laptop", "confidence": 0.94}],
                "location": {...},
                "user_pose": {...},
                "device_pose": {...},
                "room_map": {...},
                "hazards": [...],
                "sensors": {...},
                "confidence": 0.82
            }
        """

        raw = _safe_dict(observation)
        scene_labels_raw = raw.get("scene_labels") or raw.get("labels") or raw.get("scene") or []
        scene_labels = [str(item) for item in _safe_list(scene_labels_raw) if item is not None]

        objects_raw = raw.get("objects") or raw.get("detected_objects") or raw.get("items") or []
        objects: List[DetectedObject] = []
        for item in _safe_list(objects_raw):
            if isinstance(item, Mapping):
                objects.append(DetectedObject.from_mapping(item))
            elif item is not None:
                objects.append(DetectedObject(label=str(item), confidence=0.0))

        hazards_raw = raw.get("hazards") or raw.get("risks") or raw.get("warnings") or []
        hazards: List[Dict[str, Any]] = []
        for hazard in _safe_list(hazards_raw):
            if isinstance(hazard, Mapping):
                hazards.append(dict(hazard))
            elif hazard:
                hazards.append({"label": str(hazard), "confidence": 0.0})

        environment_type = _normalize_environment_type(
            raw.get("environment_type") or raw.get("environment") or raw.get("place_type"),
            scene_labels=scene_labels,
        )

        confidence = _safe_float(raw.get("confidence"), default=0.0)
        if confidence <= 0 and objects:
            confidence = sum(obj.confidence for obj in objects) / max(1, len(objects))

        raw_sensor_summary = {}
        for key in ("sensors", "sensor_summary", "device_state", "ar_state"):
            if isinstance(raw.get(key), Mapping):
                raw_sensor_summary.update(dict(raw[key]))

        return SpatialObservation(
            environment_type=environment_type,
            scene_labels=scene_labels,
            objects=objects,
            location=_safe_dict(raw.get("location")),
            user_pose=_safe_dict(raw.get("user_pose")),
            device_pose=_safe_dict(raw.get("device_pose")),
            room_map=_safe_dict(raw.get("room_map") or raw.get("spatial_map")),
            hazards=hazards,
            raw_sensor_summary=raw_sensor_summary,
            confidence=max(0.0, min(confidence, 1.0)),
            timestamp=str(raw.get("timestamp") or _now_iso()),
        )

    def interpret_real_world_task(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        context: Optional[Union[RealWorldTaskContext, Mapping[str, Any]]] = None,
    ) -> RealWorldInterpretation:
        """
        Infer intent, risk, route, and recommended action from instruction +
        real-world observation.
        """

        text = _lower_text(instruction)
        labels_text = " ".join(observation.scene_labels).lower()
        objects_text = " ".join(obj.label for obj in observation.objects).lower()
        hazards_text = " ".join(str(hazard.get("label") or hazard) for hazard in observation.hazards).lower()
        combined = f"{text} {labels_text} {objects_text} {hazards_text}"

        safety_notes = self._extract_safety_notes(combined, observation)
        intent = self._infer_intent(text, combined, observation)
        risk = self._infer_risk_level(intent, combined, observation)
        route_kind = self._infer_route_kind(intent, text)
        confidence = self._calculate_interpretation_confidence(text, observation, intent)
        entities = self._extract_entities(text, observation)

        requires_security = risk in {RealWorldRiskLevel.HIGH, RealWorldRiskLevel.CRITICAL}
        if _contains_any(combined, SENSITIVE_INTENT_KEYWORDS):
            requires_security = True

        summary = self._build_context_summary(
            instruction=instruction,
            observation=observation,
            intent=intent,
            risk=risk,
        )

        recommended_action = self._recommend_action(intent, route_kind, risk)

        reasons = []
        if text:
            reasons.append("User instruction was provided.")
        if observation.objects:
            reasons.append(f"{len(observation.objects)} object(s) detected.")
        if observation.scene_labels:
            reasons.append("Scene labels are available.")
        if observation.hazards:
            reasons.append("Potential hazard context is available.")
        if confidence < self.confidence_threshold:
            reasons.append("Confidence is below preferred threshold, so route should be cautious.")

        return RealWorldInterpretation(
            intent=intent,
            risk_level=risk,
            route_kind=route_kind,
            confidence=confidence,
            summary=summary,
            recommended_action=recommended_action,
            reasons=reasons,
            extracted_entities=entities,
            safety_notes=safety_notes,
            requires_security=requires_security,
            metadata={
                "environment_type": observation.environment_type.value,
                "confidence_threshold": self.confidence_threshold,
                "object_count": len(observation.objects),
                "hazard_count": len(observation.hazards),
            },
        )

    def _infer_intent(
        self,
        text: str,
        combined: str,
        observation: SpatialObservation,
    ) -> RealWorldIntent:
        """Rule-based intent classifier for import-safe production baseline."""

        if _contains_any(combined, CRITICAL_REAL_WORLD_KEYWORDS) or observation.hazards:
            return RealWorldIntent.SAFETY_ALERT

        if _contains_any(text, NAVIGATION_KEYWORDS):
            return RealWorldIntent.NAVIGATE

        if _contains_any(text, OBJECT_KEYWORDS):
            return RealWorldIntent.IDENTIFY_OBJECT

        if _contains_any(text, MEASURE_KEYWORDS):
            return RealWorldIntent.MEASURE_SPACE

        if _contains_any(text, OVERLAY_KEYWORDS):
            return RealWorldIntent.OVERLAY_INFO

        if _contains_any(text, DEVICE_CONTROL_KEYWORDS):
            return RealWorldIntent.DEVICE_CONTROL

        if any(word in text for word in ("remember", "save this", "record this", "note this")):
            return RealWorldIntent.RECORD_CONTEXT

        if any(word in text for word in ("remind", "notify", "alert me")):
            return RealWorldIntent.REMIND_OR_NOTIFY

        if any(word in text for word in ("search", "google", "browse", "open website", "find online")):
            return RealWorldIntent.SEARCH_OR_BROWSER

        if any(word in text for word in ("workflow", "automation", "trigger", "send to crm", "add to sheet")):
            return RealWorldIntent.WORKFLOW_ACTION

        if any(word in text for word in ("call", "message", "email", "whatsapp", "sms")):
            return RealWorldIntent.CALL_OR_MESSAGE

        if any(word in text for word in ("pay", "charge", "refund", "invoice", "buy", "purchase")):
            return RealWorldIntent.FINANCIAL_OR_PAYMENT

        if any(word in text for word in ("track", "follow", "monitor this object")):
            return RealWorldIntent.TRACK_OBJECT

        if text or observation.objects or observation.scene_labels:
            return RealWorldIntent.DESCRIBE_SCENE

        return RealWorldIntent.UNKNOWN

    def _infer_risk_level(
        self,
        intent: RealWorldIntent,
        combined: str,
        observation: SpatialObservation,
    ) -> RealWorldRiskLevel:
        """Estimate safety and permission risk level."""

        if intent in {
            RealWorldIntent.SAFETY_ALERT,
            RealWorldIntent.FINANCIAL_OR_PAYMENT,
        }:
            return RealWorldRiskLevel.CRITICAL

        if intent in {
            RealWorldIntent.CALL_OR_MESSAGE,
            RealWorldIntent.DEVICE_CONTROL,
            RealWorldIntent.SEARCH_OR_BROWSER,
            RealWorldIntent.NAVIGATE,
        }:
            return RealWorldRiskLevel.HIGH

        if intent in {
            RealWorldIntent.WORKFLOW_ACTION,
            RealWorldIntent.REMIND_OR_NOTIFY,
            RealWorldIntent.RECORD_CONTEXT,
            RealWorldIntent.TRACK_OBJECT,
        }:
            return RealWorldRiskLevel.MEDIUM

        if _contains_any(combined, SENSITIVE_INTENT_KEYWORDS):
            return RealWorldRiskLevel.MEDIUM

        if observation.environment_type in {
            EnvironmentType.MEDICAL,
            EnvironmentType.INDUSTRIAL,
            EnvironmentType.VEHICLE,
            EnvironmentType.STREET,
        }:
            return RealWorldRiskLevel.MEDIUM

        return RealWorldRiskLevel.LOW

    def _infer_route_kind(self, intent: RealWorldIntent, text: str) -> RealWorldRouteKind:
        """Map inferred intent to route category."""

        mapping = {
            RealWorldIntent.DESCRIBE_SCENE: RealWorldRouteKind.LOCAL,
            RealWorldIntent.IDENTIFY_OBJECT: RealWorldRouteKind.OBJECT_RECOGNIZER,
            RealWorldIntent.NAVIGATE: RealWorldRouteKind.NAVIGATION_OVERLAY,
            RealWorldIntent.OVERLAY_INFO: RealWorldRouteKind.AR_OVERLAY,
            RealWorldIntent.REMIND_OR_NOTIFY: RealWorldRouteKind.NOTIFICATION_OVERLAY,
            RealWorldIntent.RECORD_CONTEXT: RealWorldRouteKind.MEMORY,
            RealWorldIntent.SEARCH_OR_BROWSER: RealWorldRouteKind.BROWSER,
            RealWorldIntent.WORKFLOW_ACTION: RealWorldRouteKind.WORKFLOW,
            RealWorldIntent.DEVICE_CONTROL: RealWorldRouteKind.DEVICE_BRIDGE,
            RealWorldIntent.SAFETY_ALERT: RealWorldRouteKind.AR_OVERLAY,
            RealWorldIntent.MEASURE_SPACE: RealWorldRouteKind.SPATIAL_MAPPER,
            RealWorldIntent.TRACK_OBJECT: RealWorldRouteKind.OBJECT_RECOGNIZER,
            RealWorldIntent.CALL_OR_MESSAGE: RealWorldRouteKind.MASTER_AGENT,
            RealWorldIntent.FINANCIAL_OR_PAYMENT: RealWorldRouteKind.MASTER_AGENT,
        }
        return mapping.get(intent, RealWorldRouteKind.LOCAL)

    def _calculate_interpretation_confidence(
        self,
        text: str,
        observation: SpatialObservation,
        intent: RealWorldIntent,
    ) -> float:
        """Calculate simple deterministic confidence score."""

        score = 0.25

        if text:
            score += 0.2
        if observation.scene_labels:
            score += 0.15
        if observation.objects:
            score += 0.15
        if observation.confidence:
            score += min(observation.confidence, 1.0) * 0.2
        if intent != RealWorldIntent.UNKNOWN:
            score += 0.15
        if observation.hazards:
            score += 0.1

        return max(0.0, min(score, 1.0))

    def _extract_entities(self, text: str, observation: SpatialObservation) -> Dict[str, Any]:
        """Extract useful route entities from the instruction and observation."""

        top_objects = sorted(
            observation.objects,
            key=lambda obj: obj.confidence,
            reverse=True,
        )[:10]

        destination = None
        for phrase in ("to ", "toward ", "near "):
            if phrase in text:
                destination = text.split(phrase, 1)[1].strip()
                break

        return {
            "top_objects": [obj.to_dict() for obj in top_objects],
            "environment_type": observation.environment_type.value,
            "scene_labels": list(observation.scene_labels),
            "destination_hint": destination,
            "hazards": _redact_sensitive(list(observation.hazards)),
        }

    def _extract_safety_notes(
        self,
        combined: str,
        observation: SpatialObservation,
    ) -> List[str]:
        """Create safety notes from environment and hazards."""

        notes: List[str] = []

        if _contains_any(combined, CRITICAL_REAL_WORLD_KEYWORDS):
            notes.append("Potential critical hazard detected or mentioned.")

        if observation.hazards:
            notes.append("Hazard observations are present and should be verified before action.")

        if observation.environment_type in {EnvironmentType.STREET, EnvironmentType.VEHICLE}:
            notes.append("Navigation or visual overlays should avoid distracting the user in traffic or vehicle contexts.")

        if observation.environment_type in {EnvironmentType.MEDICAL, EnvironmentType.INDUSTRIAL}:
            notes.append("Environment may require professional or workplace safety rules.")

        return notes

    def _build_context_summary(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        intent: RealWorldIntent,
        risk: RealWorldRiskLevel,
    ) -> str:
        """Build concise context summary."""

        object_labels = [obj.label for obj in observation.objects[:5]]
        scene = ", ".join(observation.scene_labels[:5]) if observation.scene_labels else "no scene labels"
        objects = ", ".join(object_labels) if object_labels else "no detected objects"

        if instruction:
            return (
                f"Instruction understood as {intent.value}. "
                f"Environment: {observation.environment_type.value}. "
                f"Scene: {scene}. Objects: {objects}. Risk: {risk.value}."
            )

        return (
            f"Passive environment update interpreted as {intent.value}. "
            f"Environment: {observation.environment_type.value}. "
            f"Scene: {scene}. Objects: {objects}. Risk: {risk.value}."
        )

    def _recommend_action(
        self,
        intent: RealWorldIntent,
        route_kind: RealWorldRouteKind,
        risk: RealWorldRiskLevel,
    ) -> str:
        """Recommend next action for route target or dashboard."""

        if risk == RealWorldRiskLevel.CRITICAL:
            return "Request immediate safety validation and route only through approved safety-aware path."

        if intent == RealWorldIntent.NAVIGATE:
            return "Prepare navigation overlay after security and distraction checks."

        if intent == RealWorldIntent.IDENTIFY_OBJECT:
            return "Route to object recognizer or visual agent for object-level analysis."

        if intent == RealWorldIntent.OVERLAY_INFO:
            return "Render safe AR overlay with contextual information."

        if intent == RealWorldIntent.RECORD_CONTEXT:
            return "Prepare redacted memory payload for Memory Agent."

        return f"Route to {route_kind.value} with SaaS context and audit tracking."

    def _derive_passive_instruction(self, observation: SpatialObservation) -> str:
        """Create a safe passive instruction for environment updates."""

        if observation.hazards:
            return "Check this environment for possible safety alerts."

        if observation.objects or observation.scene_labels:
            return "Describe the current real-world environment."

        return "Record passive real-world context update."

    # -------------------------------------------------------------------------
    # Route resolution and execution
    # -------------------------------------------------------------------------

    def _resolve_route(self, interpretation: RealWorldInterpretation) -> RouteTarget:
        """Resolve interpretation to a route target."""

        route_name = interpretation.route_kind.value
        target = self.route_registry.get(route_name)

        if target is None:
            target = self.agent_registry.get(route_name)

        alias_map = {
            RealWorldRouteKind.AR_OVERLAY: ("ar_overlay", "overlay", "hologram"),
            RealWorldRouteKind.NAVIGATION_OVERLAY: ("navigation_overlay", "navigation", "hologram"),
            RealWorldRouteKind.NOTIFICATION_OVERLAY: ("notification_overlay", "notification", "hologram"),
            RealWorldRouteKind.SPATIAL_MAPPER: ("spatial_mapper", "spatial", "hologram"),
            RealWorldRouteKind.OBJECT_RECOGNIZER: ("object_recognizer", "visual", "visual_agent"),
            RealWorldRouteKind.DEVICE_BRIDGE: ("device_bridge", "device", "hologram"),
            RealWorldRouteKind.WORKFLOW: ("workflow", "workflow_agent"),
            RealWorldRouteKind.BROWSER: ("browser", "browser_agent"),
            RealWorldRouteKind.MEMORY: ("memory", "memory_agent", "hologram_memory"),
            RealWorldRouteKind.MASTER_AGENT: ("master", "master_agent", "agent_router"),
        }

        if target is None:
            for alias in alias_map.get(interpretation.route_kind, ()):
                target = self.route_registry.get(alias) or self.agent_registry.get(alias)
                if target is not None:
                    route_name = alias
                    break

        method_name = self._method_for_intent(interpretation.intent)

        if target is None and self.allow_safe_local_fallback:
            local_handler = self.local_handlers.get(interpretation.intent.value)
            if local_handler is not None:
                return RouteTarget(
                    kind=RealWorldRouteKind.LOCAL,
                    name=interpretation.intent.value,
                    target=local_handler,
                    method_name=None,
                    requires_security=interpretation.requires_security,
                    risk_level=interpretation.risk_level,
                    metadata={"resolution": "local_fallback"},
                )

        if target is None:
            return RouteTarget(
                kind=RealWorldRouteKind.UNKNOWN,
                name=route_name or "unknown",
                target=None,
                method_name=method_name,
                requires_security=interpretation.requires_security,
                risk_level=interpretation.risk_level,
                metadata={"resolution": "unresolved"},
            )

        return RouteTarget(
            kind=interpretation.route_kind,
            name=route_name,
            target=target,
            method_name=method_name,
            requires_security=interpretation.requires_security,
            risk_level=interpretation.risk_level,
            metadata={"resolution": "registry"},
        )

    async def _execute_route(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Any:
        """Execute resolved route target."""

        if route.kind == RealWorldRouteKind.UNKNOWN:
            if self.allow_safe_local_fallback:
                return self._handle_describe_scene(
                    instruction=instruction,
                    observation=observation,
                    interpretation=interpretation,
                    context=context,
                    route=route,
                )

            return self._error_result(
                message="No route target found for real-world task.",
                error="route_not_found",
                data={"route": route.to_dict()},
            )

        if route.kind == RealWorldRouteKind.LOCAL:
            if callable(route.target):
                return await self._call_callable_route(
                    route.target,
                    instruction=instruction,
                    observation=observation,
                    interpretation=interpretation,
                    context=context,
                    route=route,
                )

        if route.target is None:
            return self._error_result(
                message="Resolved route target is unavailable.",
                error="target_unavailable",
                data={"route": route.to_dict()},
            )

        return await self._call_target_method(
            target=route.target,
            method_name=route.method_name,
            instruction=instruction,
            observation=observation,
            interpretation=interpretation,
            context=context,
            route=route,
        )

    async def _call_callable_route(
        self,
        handler: Callable[..., Any],
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Any:
        """Call a local handler using compatible signature."""

        try:
            signature = inspect.signature(handler)
            names = set(signature.parameters.keys())

            if {"instruction", "observation", "interpretation", "context", "route"}.issubset(names):
                return await _maybe_await(
                    handler(
                        instruction=instruction,
                        observation=observation,
                        interpretation=interpretation,
                        context=context,
                        route=route,
                    )
                )

            if {"observation", "context"}.issubset(names):
                return await _maybe_await(handler(observation=observation, context=context))

            if {"payload", "context"}.issubset(names):
                return await _maybe_await(
                    handler(
                        payload=self._build_route_payload(instruction, observation, interpretation, context, route),
                        context=context,
                    )
                )

            return await _maybe_await(
                handler(self._build_route_payload(instruction, observation, interpretation, context, route))
            )
        except TypeError:
            return await _maybe_await(
                handler(self._build_route_payload(instruction, observation, interpretation, context, route))
            )

    async def _call_target_method(
        self,
        *,
        target: Any,
        method_name: Optional[str],
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Any:
        """Call a target object method with flexible compatibility."""

        candidates = self._candidate_method_names(method_name, interpretation.intent)
        payload = self._build_route_payload(instruction, observation, interpretation, context, route)

        for candidate in candidates:
            method = getattr(target, candidate, None)
            if not callable(method):
                continue

            try:
                signature = inspect.signature(method)
                names = set(signature.parameters.keys())

                if {"instruction", "observation", "interpretation", "context"}.issubset(names):
                    return await _maybe_await(
                        method(
                            instruction=instruction,
                            observation=observation,
                            interpretation=interpretation,
                            context=context,
                        )
                    )

                if {"payload", "context"}.issubset(names):
                    return await _maybe_await(method(payload=payload, context=context))

                if {"task", "context"}.issubset(names):
                    return await _maybe_await(method(task=payload, context=context))

                if {"observation", "context"}.issubset(names):
                    return await _maybe_await(method(observation=observation.to_dict(), context=context.to_dict()))

                if len(signature.parameters) == 0:
                    return await _maybe_await(method())

                return await _maybe_await(method(payload))

            except TypeError:
                continue

        return self._error_result(
            message="No compatible method found on real-world route target.",
            error="target_method_unavailable",
            data={
                "route": route.to_dict(),
                "candidate_methods": candidates,
                "target_type": type(target).__name__,
            },
        )

    def _build_route_payload(
        self,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Dict[str, Any]:
        """Build safe route payload for target agents/components."""

        return {
            "instruction": instruction,
            "observation": observation.to_dict(),
            "interpretation": interpretation.to_dict(),
            "context": context.to_dict(),
            "route": route.to_dict(),
            "source": "RealWorldContext",
            "created_at": _now_iso(),
        }

    def _method_for_intent(self, intent: RealWorldIntent) -> str:
        """Map intent to preferred route method."""

        mapping = {
            RealWorldIntent.DESCRIBE_SCENE: "describe_scene",
            RealWorldIntent.IDENTIFY_OBJECT: "identify_object",
            RealWorldIntent.NAVIGATE: "create_navigation_overlay",
            RealWorldIntent.OVERLAY_INFO: "render_overlay",
            RealWorldIntent.REMIND_OR_NOTIFY: "send_notification",
            RealWorldIntent.RECORD_CONTEXT: "store_context",
            RealWorldIntent.SEARCH_OR_BROWSER: "handle_browser_task",
            RealWorldIntent.WORKFLOW_ACTION: "route_action",
            RealWorldIntent.DEVICE_CONTROL: "handle_device_command",
            RealWorldIntent.SAFETY_ALERT: "render_safety_alert",
            RealWorldIntent.MEASURE_SPACE: "measure_space",
            RealWorldIntent.TRACK_OBJECT: "track_object",
            RealWorldIntent.CALL_OR_MESSAGE: "route_task",
            RealWorldIntent.FINANCIAL_OR_PAYMENT: "route_task",
            RealWorldIntent.UNKNOWN: "handle",
        }
        return mapping.get(intent, "handle")

    def _candidate_method_names(self, preferred: Optional[str], intent: RealWorldIntent) -> List[str]:
        """Create ordered compatible method names."""

        candidates: List[str] = []
        for name in (
            preferred,
            self._method_for_intent(intent),
            "handle_real_world_request",
            "route_real_world_task",
            "process",
            "handle",
            "execute",
            "run",
            "__call__",
        ):
            clean = _optional_str(name)
            if clean and clean not in candidates:
                candidates.append(clean)
        return candidates

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[RealWorldTaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Every real-world observation, AR task, device route, memory payload,
        dashboard event, and audit event must remain scoped to user_id and
        workspace_id.
        """

        try:
            if isinstance(context, RealWorldTaskContext):
                task_context = context
            elif isinstance(context, Mapping):
                task_context = RealWorldTaskContext.from_mapping(context)
            else:
                return self._error_result(
                    message="Invalid real-world task context.",
                    error="invalid_context",
                    metadata={"context_type": type(context).__name__},
                )

            if not task_context.user_id:
                return self._error_result(
                    message="user_id is required for real-world context routing.",
                    error="missing_user_id",
                )

            if not task_context.workspace_id:
                return self._error_result(
                    message="workspace_id is required for real-world context routing.",
                    error="missing_workspace_id",
                )

            return self._safe_result(
                message="Real-world task context is valid.",
                data={"context": task_context},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate real-world task context.",
                error=str(exc),
            )

    def _requires_security_check(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        route: RouteTarget,
    ) -> bool:
        """
        Decide whether a real-world action needs Security Agent approval.

        Sensitive examples:
            - navigation guidance in vehicle/street contexts
            - message/call/email actions
            - device control
            - browser/login/submission tasks
            - memory recording with sensitive context
            - financial/payment actions
            - safety-critical alerts
        """

        if interpretation.requires_security or route.requires_security:
            return True

        if interpretation.risk_level in {RealWorldRiskLevel.HIGH, RealWorldRiskLevel.CRITICAL}:
            return True

        combined = " ".join(
            [
                instruction,
                interpretation.intent.value,
                route.name,
                observation.environment_type.value,
                " ".join(observation.scene_labels),
                " ".join(obj.label for obj in observation.objects),
                " ".join(str(hazard.get("label") or hazard) for hazard in observation.hazards),
            ]
        )

        if _contains_any(combined, SENSITIVE_INTENT_KEYWORDS):
            return True

        if observation.environment_type in {EnvironmentType.VEHICLE, EnvironmentType.STREET}:
            if interpretation.intent in {RealWorldIntent.NAVIGATE, RealWorldIntent.OVERLAY_INFO}:
                return True

        return False

    async def _request_security_approval(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent exists:
            - dry_run is allowed
            - low/medium local descriptive tasks may continue
            - high/critical tasks are blocked
        """

        payload = {
            "request_id": context.request_id,
            "session_id": context.session_id,
            "device_id": context.device_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "instruction": instruction,
            "observation": observation.to_dict(),
            "interpretation": interpretation.to_dict(),
            "route": route.to_dict(),
            "risk_level": interpretation.risk_level.value,
            "dry_run": dry_run,
            "timestamp": _now_iso(),
            "source": "RealWorldContext._request_security_approval",
        }
        payload = _redact_sensitive(payload)

        await self._emit_agent_event(
            event_type="hologram.real_world_context.security_check_requested",
            context=context,
            payload=payload,
        )

        if dry_run:
            return self._safe_result(
                message="Dry run security check passed without executing real-world action.",
                data={"approved": True, "dry_run": True, "security_payload": payload},
            )

        trusted_preapproved = bool(context.metadata.get("trusted_internal_route")) and bool(
            context.metadata.get("security_preapproved")
        )
        if trusted_preapproved:
            return self._safe_result(
                message="Real-world action pre-approved by trusted internal route.",
                data={"approved": True, "preapproved": True, "security_payload": payload},
            )

        if self.security_agent is None:
            if interpretation.risk_level in {RealWorldRiskLevel.LOW, RealWorldRiskLevel.MEDIUM}:
                return self._safe_result(
                    message="No Security Agent attached; only safe non-destructive route permitted.",
                    data={"approved": True, "limited_approval": True, "security_payload": payload},
                )

            return self._error_result(
                message="High-risk real-world task requires Security Agent approval, but no Security Agent is attached.",
                error="security_agent_unavailable",
                data={"approved": False, "security_payload": payload},
            )

        try:
            for method_name in (
                "approve_real_world_action",
                "approve_hologram_action",
                "request_approval",
                "validate_action",
                "check_permission",
                "run",
                "execute",
            ):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    response = await _maybe_await(method(payload))
                    return self._normalize_security_response(response)

            return self._error_result(
                message="Security Agent does not expose a compatible approval method.",
                error="security_method_unavailable",
                data={"approved": False, "security_payload": payload},
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security Agent approval request failed.",
                error=str(exc),
                data={"approved": False, "security_payload": payload},
            )

    def _prepare_verification_payload(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
        action_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm overlay state, route result,
        object detection result, memory write request, workflow delegation, or
        safety route outcome.
        """

        return _redact_sensitive(
            {
                "verification_type": "real_world_context_route",
                "request_id": context.request_id,
                "session_id": context.session_id,
                "device_id": context.device_id,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "instruction": instruction,
                "observation_summary": {
                    "environment_type": observation.environment_type.value,
                    "scene_labels": list(observation.scene_labels),
                    "object_count": len(observation.objects),
                    "hazard_count": len(observation.hazards),
                    "confidence": observation.confidence,
                },
                "interpretation": interpretation.to_dict(),
                "route": route.to_dict(),
                "actual_result": {
                    "success": action_result.get("success"),
                    "message": action_result.get("message"),
                    "error": action_result.get("error"),
                    "data": action_result.get("data"),
                },
                "requires_followup_verification": True,
                "created_at": _now_iso(),
                "metadata": {
                    "source": "RealWorldContext._prepare_verification_payload",
                    "agent": self.agent_name,
                    "version": self.version,
                },
            }
        )

    def _prepare_memory_payload(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
        action_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        This avoids raw camera/audio/video and precise location storage. The
        Memory Agent should still apply user/workspace memory policy before
        persistence.
        """

        safe_objects = [
            {
                "label": obj.label,
                "confidence": obj.confidence,
                "category": obj.category,
            }
            for obj in observation.objects[:10]
        ]

        return _redact_sensitive(
            {
                "memory_type": "hologram_real_world_context",
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "session_id": context.session_id,
                "device_id": context.device_id,
                "summary": interpretation.summary,
                "instruction": instruction,
                "environment_type": observation.environment_type.value,
                "scene_labels": list(observation.scene_labels[:10]),
                "objects": safe_objects,
                "intent": interpretation.intent.value,
                "risk_level": interpretation.risk_level.value,
                "route_kind": route.kind.value,
                "route_name": route.name,
                "success": bool(action_result.get("success")),
                "created_at": _now_iso(),
                "metadata": {
                    "source": "RealWorldContext._prepare_memory_payload",
                    "agent": self.agent_name,
                    "version": self.version,
                    "memory_policy_note": "No raw camera/audio/video or precise location should be stored from this payload.",
                },
            }
        )

    async def _emit_agent_event(
        self,
        *,
        event_type: str,
        context: RealWorldTaskContext,
        payload: Mapping[str, Any],
    ) -> None:
        """Emit best-effort dashboard/API/observability event."""

        event = {
            "event_type": event_type,
            "agent": self.agent_name,
            "version": self.version,
            "context": context.to_dict(),
            "payload": _redact_sensitive(dict(payload)),
            "timestamp": _now_iso(),
        }

        try:
            if self.event_emitter is not None:
                if callable(self.event_emitter):
                    await _maybe_await(self.event_emitter(event))
                    return

                emit = getattr(self.event_emitter, "emit", None)
                if callable(emit):
                    await _maybe_await(emit(event))
                    return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                await _maybe_await(emit_event(event))

        except Exception:
            self.logger.debug("Failed to emit RealWorldContext event.", exc_info=True)

    async def _log_audit_event(
        self,
        *,
        event_type: str,
        context: RealWorldTaskContext,
        payload: Mapping[str, Any],
    ) -> None:
        """Log best-effort audit event scoped by user/workspace."""

        audit_event = {
            "event_type": event_type,
            "agent": self.agent_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "device_id": context.device_id,
            "payload": _redact_sensitive(dict(payload)),
            "timestamp": _now_iso(),
        }

        try:
            if self.audit_logger is not None:
                if callable(self.audit_logger):
                    await _maybe_await(self.audit_logger(audit_event))
                    return

                for method_name in ("log", "write", "record"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        await _maybe_await(method(audit_event))
                        return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                await _maybe_await(log_audit(audit_event))
                return

            self.logger.info("real_world_context_audit=%s", audit_event)

        except Exception:
            self.logger.debug("Failed to log RealWorldContext audit event.", exc_info=True)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured successful result."""

        return {
            "success": error is None,
            "message": message,
            "data": dict(data or {}),
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "version": self.version,
                "timestamp": _now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured failed result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": str(error) if error is not None else "unknown_error",
            "metadata": {
                "agent": self.agent_name,
                "version": self.version,
                "timestamp": _now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Local handlers
    # -------------------------------------------------------------------------

    def _install_default_local_handlers(self) -> None:
        """Install safe import-ready local handlers."""

        self.local_handlers.setdefault(RealWorldIntent.DESCRIBE_SCENE.value, self._handle_describe_scene)
        self.local_handlers.setdefault(RealWorldIntent.SAFETY_ALERT.value, self._handle_safety_alert)
        self.local_handlers.setdefault(RealWorldIntent.OVERLAY_INFO.value, self._handle_overlay_info)
        self.local_handlers.setdefault(RealWorldIntent.RECORD_CONTEXT.value, self._handle_record_context)
        self.local_handlers.setdefault(RealWorldIntent.UNKNOWN.value, self._handle_unknown)

    def _install_optional_hologram_components(self) -> None:
        """Instantiate optional hologram components only when available."""

        optional_components = {
            "spatial_mapper": SpatialMapper,
            "ar_overlay": AROverlay,
            "overlay": AROverlay,
            "gesture_bridge": GestureBridge,
            "object_recognizer": ObjectRecognizer,
            "navigation_overlay": NavigationOverlay,
            "notification_overlay": NotificationOverlay,
            "device_bridge": DeviceBridge,
            "hologram_memory": HologramMemory,
        }

        for name, cls in optional_components.items():
            if cls is None:
                continue
            try:
                self.route_registry[name] = cls()
            except Exception:
                self.logger.debug("Could not instantiate optional hologram component: %s", name, exc_info=True)

    def _handle_describe_scene(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Dict[str, Any]:
        """Safe local scene summary handler."""

        objects = [
            {
                "label": obj.label,
                "confidence": obj.confidence,
                "category": obj.category,
            }
            for obj in observation.objects[:10]
        ]

        return self._safe_result(
            message="Scene described from available real-world context.",
            data={
                "summary": interpretation.summary,
                "environment_type": observation.environment_type.value,
                "scene_labels": list(observation.scene_labels),
                "objects": objects,
                "hazards": _redact_sensitive(list(observation.hazards)),
                "safety_notes": list(interpretation.safety_notes),
            },
        )

    def _handle_safety_alert(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Dict[str, Any]:
        """
        Safe local safety alert handler.

        It does not call emergency services or control devices. It only prepares
        an alert payload for approved overlay/notification systems.
        """

        return self._safe_result(
            message="Safety alert context prepared. User confirmation and Security Agent approval may be required for external actions.",
            data={
                "alert_level": interpretation.risk_level.value,
                "safety_notes": list(interpretation.safety_notes),
                "hazards": _redact_sensitive(list(observation.hazards)),
                "recommended_action": interpretation.recommended_action,
                "external_action_taken": False,
            },
        )

    def _handle_overlay_info(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Dict[str, Any]:
        """Prepare a safe AR overlay payload without rendering directly."""

        return self._safe_result(
            message="AR overlay payload prepared.",
            data={
                "overlay": {
                    "type": "context_card",
                    "title": "Real-World Context",
                    "body": interpretation.summary,
                    "labels": list(observation.scene_labels[:5]),
                    "objects": [
                        {"label": obj.label, "confidence": obj.confidence}
                        for obj in observation.objects[:5]
                    ],
                    "safety_notes": list(interpretation.safety_notes),
                },
                "rendered": False,
            },
        )

    def _handle_record_context(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Dict[str, Any]:
        """Prepare memory-safe context record without directly persisting."""

        return self._safe_result(
            message="Memory-safe real-world context record prepared.",
            data={
                "memory_ready": True,
                "summary": interpretation.summary,
                "environment_type": observation.environment_type.value,
                "scene_labels": list(observation.scene_labels[:10]),
                "objects": [
                    {"label": obj.label, "confidence": obj.confidence}
                    for obj in observation.objects[:10]
                ],
            },
        )

    def _handle_unknown(
        self,
        *,
        instruction: str,
        observation: SpatialObservation,
        interpretation: RealWorldInterpretation,
        context: RealWorldTaskContext,
        route: RouteTarget,
    ) -> Dict[str, Any]:
        """Safe fallback handler for unclear real-world tasks."""

        return self._safe_result(
            message="Real-world context was received, but intent is unclear. Safe summary returned.",
            data={
                "summary": interpretation.summary,
                "intent": interpretation.intent.value,
                "confidence": interpretation.confidence,
                "executed_external_action": False,
            },
        )

    # -------------------------------------------------------------------------
    # Result normalization and metadata
    # -------------------------------------------------------------------------

    def _normalize_target_result(self, raw_result: Any) -> Dict[str, Any]:
        """Normalize arbitrary route target result into William/Jarvis shape."""

        if isinstance(raw_result, Mapping):
            result = dict(raw_result)
            if "success" not in result:
                result["success"] = result.get("error") in (None, "", False)

            result.setdefault("message", "Real-world route target returned a result.")
            result.setdefault("data", {})
            result.setdefault("error", None if result.get("success") else "route_failed")
            result.setdefault("metadata", {})

            if not isinstance(result["data"], Mapping):
                result["data"] = {"value": result["data"]}

            if not isinstance(result["metadata"], Mapping):
                result["metadata"] = {"value": result["metadata"]}

            return {
                "success": bool(result["success"]),
                "message": str(result["message"]),
                "data": _redact_sensitive(dict(result["data"])),
                "error": None if result["success"] else str(result.get("error") or "route_failed"),
                "metadata": _redact_sensitive(dict(result["metadata"])),
            }

        return {
            "success": True,
            "message": "Real-world route target completed.",
            "data": {"value": _redact_sensitive(raw_result)},
            "error": None,
            "metadata": {},
        }

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        """Normalize Security Agent response."""

        if isinstance(response, Mapping):
            result = dict(response)
            approved = bool(result.get("approved") if "approved" in result else result.get("success", False))

            if approved:
                return self._safe_result(
                    message=str(result.get("message") or "Security Agent approved real-world action."),
                    data={"approved": True, "security_result": _redact_sensitive(result)},
                )

            return self._error_result(
                message=str(result.get("message") or "Security Agent denied real-world action."),
                error=result.get("error") or "security_approval_denied",
                data={"approved": False, "security_result": _redact_sensitive(result)},
            )

        if response is True:
            return self._safe_result(
                message="Security Agent approved real-world action.",
                data={"approved": True},
            )

        return self._error_result(
            message="Security Agent denied real-world action.",
            error="security_approval_denied",
            data={"approved": False, "security_result": _redact_sensitive(response)},
        )

    def _result_metadata(
        self,
        context: RealWorldTaskContext,
        record: RealWorldExecutionRecord,
    ) -> Dict[str, Any]:
        """Common metadata for route results."""

        return {
            "request_id": context.request_id,
            "session_id": context.session_id,
            "device_id": context.device_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "record_id": record.record_id,
            "intent": record.intent,
            "route_kind": record.route_kind,
            "route_name": record.route_name,
            "status": record.status.value,
            "duration_ms": record.duration_ms,
            "security_required": record.security_required,
            "security_approved": record.security_approved,
        }

    def _remember_record(self, record: RealWorldExecutionRecord) -> None:
        """Keep bounded local execution history."""

        self._execution_history.append(record)
        if len(self._execution_history) > 1000:
            self._execution_history = self._execution_history[-1000:]

    def _normalize_name(self, value: Any) -> str:
        """Normalize registry names."""

        return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


# =============================================================================
# Factory helper
# =============================================================================

def create_real_world_context(
    *,
    route_registry: Optional[Mapping[str, Any]] = None,
    agent_registry: Optional[Mapping[str, Any]] = None,
    security_agent: Optional[Any] = None,
    verification_agent: Optional[Any] = None,
    memory_agent: Optional[Any] = None,
    audit_logger: Optional[Any] = None,
    event_emitter: Optional[Any] = None,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> RealWorldContext:
    """
    Factory helper for Agent Loader, Agent Registry, FastAPI dependency
    injection, dashboard/API bootstrapping, and tests.
    """

    return RealWorldContext(
        route_registry=route_registry,
        agent_registry=agent_registry,
        security_agent=security_agent,
        verification_agent=verification_agent,
        memory_agent=memory_agent,
        audit_logger=audit_logger,
        event_emitter=event_emitter,
        confidence_threshold=confidence_threshold,
        default_timeout_seconds=default_timeout_seconds,
    )


# =============================================================================
# Manual smoke test
# =============================================================================

async def _smoke_test() -> Dict[str, Any]:
    """
    Import-safe smoke test.

    Run:
        python agents/super_agents/hologram_agent/real_world_context.py

    This does not perform real device, browser, message, financial, or
    destructive actions.
    """

    real_world_context = RealWorldContext()

    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "session_id": "test_session",
        "device_id": "test_ar_device",
        "permissions": ["hologram:read_context"],
        "metadata": {"trusted_internal_route": True},
    }

    observation = {
        "environment_type": "office",
        "scene_labels": ["desk", "laptop", "chair"],
        "objects": [
            {"label": "laptop", "confidence": 0.94, "category": "electronics"},
            {"label": "chair", "confidence": 0.88, "category": "furniture"},
        ],
        "confidence": 0.9,
    }

    return await real_world_context.handle_real_world_request(
        instruction="Describe what I am looking at",
        observation=observation,
        context=context,
        dry_run=False,
    )


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    result = asyncio.run(_smoke_test())
    print(result)