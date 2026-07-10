"""
agents/super_agents/hologram_agent/ar_overlay.py

Purpose:
    Displays floating UI cards, notifications, instructions, and real-world overlays
    for the William / Jarvis Hologram Agent.

Architecture:
    - Safe import even if the rest of William/Jarvis is not generated yet.
    - SaaS tenant isolation through user_id and workspace_id.
    - Structured JSON/dict results for API/dashboard integration.
    - Security Agent compatible approval hooks for sensitive visual overlays.
    - Verification Agent payloads after overlay creation/update/removal.
    - Memory Agent payloads for useful user/workspace overlay preferences.
    - Event and audit hooks for Master Agent, Agent Router, Registry, and Dashboard.

Important:
    This file does NOT directly control real AR glasses, browsers, cameras,
    operating system overlays, or external hardware. It generates safe overlay
    scene/render payloads that can be consumed later by device_bridge.py,
    navigation_overlay.py, notification_overlay.py, dashboard APIs, WebXR clients,
    mobile apps, or hologram runtimes.
"""

from __future__ import annotations

import asyncio
import copy
import html
import json
import logging
import math
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# =============================================================================
# Safe optional BaseAgent import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe before the full William/Jarvis codebase
        exists. The real BaseAgent can replace this automatically when available.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__)
            self.logger = logging.getLogger(self.__class__.__name__)


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums
# =============================================================================

class OverlayAction(str, Enum):
    """Supported AR overlay actions."""

    CREATE_CARD = "create_card"
    CREATE_NOTIFICATION = "create_notification"
    CREATE_INSTRUCTION = "create_instruction"
    CREATE_REAL_WORLD_OVERLAY = "create_real_world_overlay"
    UPDATE_OVERLAY = "update_overlay"
    REMOVE_OVERLAY = "remove_overlay"
    CLEAR_SESSION = "clear_session"
    GET_OVERLAY = "get_overlay"
    LIST_OVERLAYS = "list_overlays"
    BUILD_SCENE = "build_scene"
    VALIDATE_RENDER_PAYLOAD = "validate_render_payload"


class OverlayType(str, Enum):
    """Types of overlays supported by this file."""

    CARD = "card"
    NOTIFICATION = "notification"
    INSTRUCTION = "instruction"
    REAL_WORLD = "real_world"
    LABEL = "label"
    WARNING = "warning"
    SUCCESS = "success"
    ERROR = "error"
    MENU = "menu"
    TOOLTIP = "tooltip"
    HUD = "hud"


class OverlayPriority(str, Enum):
    """Overlay priority for sorting and rendering."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class AnchorType(str, Enum):
    """Where/how an overlay should be anchored."""

    SCREEN = "screen"
    WORLD = "world"
    OBJECT = "object"
    PERSON = "person"
    SURFACE = "surface"
    GPS = "gps"
    HAND = "hand"
    GAZE = "gaze"


class OverlayPlacement(str, Enum):
    """Common placement hints."""

    TOP_LEFT = "top_left"
    TOP_CENTER = "top_center"
    TOP_RIGHT = "top_right"
    CENTER_LEFT = "center_left"
    CENTER = "center"
    CENTER_RIGHT = "center_right"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_CENTER = "bottom_center"
    BOTTOM_RIGHT = "bottom_right"
    NEAR_OBJECT = "near_object"
    ABOVE_OBJECT = "above_object"
    BELOW_OBJECT = "below_object"
    FOLLOW_GAZE = "follow_gaze"
    WORLD_LOCKED = "world_locked"


class OverlayVisibility(str, Enum):
    """Visibility state."""

    VISIBLE = "visible"
    HIDDEN = "hidden"
    FADED = "faded"
    DISMISSED = "dismissed"


class InteractionMode(str, Enum):
    """Supported interaction modes."""

    NONE = "none"
    GAZE = "gaze"
    GESTURE = "gesture"
    VOICE = "voice"
    TOUCH = "touch"
    CONTROLLER = "controller"
    MIXED = "mixed"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class TaskContext:
    """
    Required SaaS task context.

    user_id and workspace_id are mandatory for all user/workspace scoped actions.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    subscription_id: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    source: str = "hologram_agent"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TaskContext":
        """Create TaskContext from dict-like value."""
        return cls(
            user_id=str(value.get("user_id") or "").strip(),
            workspace_id=str(value.get("workspace_id") or "").strip(),
            role=value.get("role"),
            request_id=value.get("request_id"),
            session_id=value.get("session_id"),
            subscription_id=value.get("subscription_id"),
            permissions=list(value.get("permissions") or []),
            source=str(value.get("source") or "hologram_agent"),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass
class Vector2:
    """2D position/size."""

    x: float = 0.0
    y: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {"x": float(self.x), "y": float(self.y)}


@dataclass
class Vector3:
    """3D world position/rotation/scale."""

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {"x": float(self.x), "y": float(self.y), "z": float(self.z)}


@dataclass
class OverlayStyle:
    """Visual style for AR overlays."""

    theme: str = "jarvis_dark"
    background_color: str = "rgba(16,16,16,0.82)"
    foreground_color: str = "#FFFFFF"
    accent_color: str = "#6400B3"
    border_color: str = "rgba(255,255,255,0.14)"
    border_radius: int = 18
    opacity: float = 1.0
    blur: float = 18.0
    shadow: str = "0 18px 60px rgba(0,0,0,0.35)"
    font_family: str = "Inter, system-ui, sans-serif"
    font_size: int = 15
    title_size: int = 18
    icon: Optional[str] = None
    animation: str = "float_in"
    animation_ms: int = 260
    glass_effect: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OverlayAnchor:
    """Anchor definition for an overlay."""

    anchor_type: OverlayAnchorType = None  # type: ignore
    target_id: Optional[str] = None
    target_label: Optional[str] = None
    placement: OverlayPlacement = OverlayPlacement.CENTER
    screen_position: Vector2 = field(default_factory=Vector2)
    world_position: Vector3 = field(default_factory=Vector3)
    world_rotation: Vector3 = field(default_factory=Vector3)
    world_scale: Vector3 = field(default_factory=lambda: Vector3(1.0, 1.0, 1.0))
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    distance_meters: Optional[float] = None
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if self.anchor_type is None:
            self.anchor_type = AnchorType.SCREEN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anchor_type": str(self.anchor_type.value if isinstance(self.anchor_type, AnchorType) else self.anchor_type),
            "target_id": self.target_id,
            "target_label": self.target_label,
            "placement": str(self.placement.value if isinstance(self.placement, OverlayPlacement) else self.placement),
            "screen_position": self.screen_position.to_dict(),
            "world_position": self.world_position.to_dict(),
            "world_rotation": self.world_rotation.to_dict(),
            "world_scale": self.world_scale.to_dict(),
            "gps_latitude": self.gps_latitude,
            "gps_longitude": self.gps_longitude,
            "distance_meters": self.distance_meters,
            "confidence": float(self.confidence),
        }


@dataclass
class OverlayInteraction:
    """Interaction config for an overlay."""

    mode: InteractionMode = InteractionMode.NONE
    dismissible: bool = True
    selectable: bool = False
    voice_commands: List[str] = field(default_factory=list)
    gesture_commands: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": str(self.mode.value if isinstance(self.mode, InteractionMode) else self.mode),
            "dismissible": bool(self.dismissible),
            "selectable": bool(self.selectable),
            "voice_commands": list(self.voice_commands),
            "gesture_commands": list(self.gesture_commands),
            "actions": copy.deepcopy(self.actions),
        }


@dataclass
class OverlayConfig:
    """Runtime config for AROverlay."""

    max_overlays_per_session: int = 100
    max_text_length: int = 4000
    max_title_length: int = 180
    default_ttl_seconds: int = 30
    max_ttl_seconds: int = 3600
    allow_sensitive_real_world_labels: bool = False
    require_security_for_real_world_overlays: bool = True
    require_security_for_critical_notifications: bool = True
    enable_in_memory_store: bool = True
    enable_html_sanitization: bool = True
    default_language: str = "en"
    default_depth_meters: float = 1.6
    scene_format_version: str = "william-ar-scene-v1"
    request_id_prefix: str = "william_ar"


@dataclass
class OverlayPayload:
    """Internal overlay record."""

    overlay_id: str
    overlay_type: OverlayType
    title: str
    body: str
    context: TaskContext
    anchor: OverlayAnchor = field(default_factory=OverlayAnchor)
    style: OverlayStyle = field(default_factory=OverlayStyle)
    interaction: OverlayInteraction = field(default_factory=OverlayInteraction)
    priority: OverlayPriority = OverlayPriority.NORMAL
    visibility: OverlayVisibility = OverlayVisibility.VISIBLE
    ttl_seconds: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""
    expires_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    render_data: Dict[str, Any] = field(default_factory=dict)

    def to_render_dict(self) -> Dict[str, Any]:
        """Return client/device renderable overlay payload."""
        return {
            "overlay_id": self.overlay_id,
            "type": str(self.overlay_type.value if isinstance(self.overlay_type, OverlayType) else self.overlay_type),
            "title": self.title,
            "body": self.body,
            "anchor": self.anchor.to_dict(),
            "style": self.style.to_dict(),
            "interaction": self.interaction.to_dict(),
            "priority": str(self.priority.value if isinstance(self.priority, OverlayPriority) else self.priority),
            "visibility": str(self.visibility.value if isinstance(self.visibility, OverlayVisibility) else self.visibility),
            "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "metadata": copy.deepcopy(self.metadata),
            "render_data": copy.deepcopy(self.render_data),
        }


# Backward-safe alias correction for dataclass annotation
OverlayAnchorType = AnchorType


# =============================================================================
# Main class
# =============================================================================

class AROverlay(BaseAgent):
    """
    Hologram Agent overlay manager.

    Responsibilities:
        - Build AR/HUD render payloads.
        - Store session overlays safely in memory when enabled.
        - Create cards, notifications, instructions, and world/object overlays.
        - Prepare scene payloads for WebXR/mobile/device bridge.
        - Validate and sanitize overlay content.
        - Protect sensitive overlays through Security Agent hooks.
        - Prepare Verification and Memory Agent payloads.
    """

    agent_name = "hologram_agent.ar_overlay"
    agent_version = "1.0.0"

    SENSITIVE_ACTIONS = {
        OverlayAction.CREATE_REAL_WORLD_OVERLAY,
        OverlayAction.UPDATE_OVERLAY,
        OverlayAction.REMOVE_OVERLAY,
        OverlayAction.CLEAR_SESSION,
    }

    CRITICAL_ACTIONS = {
        OverlayAction.CREATE_NOTIFICATION,
        OverlayAction.CREATE_REAL_WORLD_OVERLAY,
    }

    def __init__(
        self,
        config: Optional[Union[OverlayConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        renderer: Optional[Callable[[Mapping[str, Any]], Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)

        if isinstance(config, OverlayConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = OverlayConfig(**dict(config))
        else:
            self.config = OverlayConfig()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.renderer = renderer
        self.logger = logger_instance or logging.getLogger(self.__class__.__name__)

        self._store: Dict[str, Dict[str, OverlayPayload]] = {}

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> Tuple[bool, Optional[TaskContext], Optional[str]]:
        """Validate SaaS user/workspace context."""
        if context is None:
            return False, None, "Missing task context. user_id and workspace_id are required."

        if isinstance(context, TaskContext):
            task_context = context
        elif isinstance(context, Mapping):
            task_context = TaskContext.from_mapping(context)
        else:
            return False, None, "Invalid task context type. Expected TaskContext or dict."

        if not task_context.user_id:
            return False, None, "Missing user_id in task context."

        if not task_context.workspace_id:
            return False, None, "Missing workspace_id in task context."

        if not task_context.request_id:
            task_context.request_id = self._new_request_id()

        if not task_context.session_id:
            task_context.session_id = f"ar_session_{task_context.workspace_id}_{task_context.user_id}"

        return True, task_context, None

    def _requires_security_check(
        self,
        action: Union[OverlayAction, str],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Return True when overlay action requires Security Agent approval."""
        try:
            normalized = OverlayAction(action)
        except Exception:
            return True

        payload = payload or {}
        priority = str(payload.get("priority") or "").lower()
        overlay_type = str(payload.get("overlay_type") or payload.get("type") or "").lower()
        anchor_type = str(payload.get("anchor_type") or "").lower()

        if normalized == OverlayAction.CREATE_REAL_WORLD_OVERLAY and self.config.require_security_for_real_world_overlays:
            return True

        if (
            normalized == OverlayAction.CREATE_NOTIFICATION
            and self.config.require_security_for_critical_notifications
            and priority == OverlayPriority.CRITICAL.value
        ):
            return True

        if overlay_type in {"warning", "error"} and priority == OverlayPriority.CRITICAL.value:
            return True

        if anchor_type in {"person", "object", "gps"} and not self.config.allow_sensitive_real_world_labels:
            return True

        return normalized in self.SENSITIVE_ACTIONS

    async def _request_security_approval(
        self,
        action: Union[OverlayAction, str],
        context: TaskContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Fallback rule:
            If no Security Agent exists, sensitive action requires one of:
            hologram:admin, ar:admin, hologram:<action>, ar:<action>.
        """
        action_value = str(action.value if isinstance(action, OverlayAction) else action)

        if not self._requires_security_check(action_value, payload):
            return {
                "approved": True,
                "reason": "Security approval not required for this overlay action.",
                "source": "ar_overlay",
            }

        approval_payload = {
            "agent": self.agent_name,
            "action": action_value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "payload": self._redact_sensitive(dict(payload or {})),
            "timestamp": self._utc_now(),
        }

        if self.security_agent is not None:
            try:
                for method_name in ("approve_action", "request_approval", "validate", "authorize"):
                    if hasattr(self.security_agent, method_name):
                        response = getattr(self.security_agent, method_name)(approval_payload)
                        if asyncio.iscoroutine(response):
                            response = await response
                        return self._normalize_security_response(response)
            except Exception as exc:
                self.logger.exception("Security approval failed.")
                return {
                    "approved": False,
                    "reason": f"Security Agent error: {exc}",
                    "source": "security_agent",
                }

        allowed_permissions = {
            "hologram:admin",
            "ar:admin",
            f"hologram:{action_value}",
            f"ar:{action_value}",
        }

        if set(context.permissions).intersection(allowed_permissions):
            return {
                "approved": True,
                "reason": "Approved by context permission fallback.",
                "source": "context_permissions",
            }

        return {
            "approved": False,
            "reason": (
                "Sensitive AR overlay action requires Security Agent approval or "
                "hologram/ar admin permissions."
            ),
            "source": "fallback_guard",
        }

    def _prepare_verification_payload(
        self,
        action: Union[OverlayAction, str],
        context: TaskContext,
        result: Mapping[str, Any],
        target: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""
        action_value = str(action.value if isinstance(action, OverlayAction) else action)
        return {
            "verification_type": "hologram_ar_overlay_action",
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "action": action_value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "target": dict(target or {}),
            "data_summary": self._summarize_for_event(result.get("data")),
            "error": result.get("error"),
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        action: Union[OverlayAction, str],
        context: TaskContext,
        result: Mapping[str, Any],
        memory_type: str = "hologram_ar_overlay_context",
    ) -> Dict[str, Any]:
        """Prepare Memory Agent compatible payload."""
        action_value = str(action.value if isinstance(action, OverlayAction) else action)
        return {
            "memory_type": memory_type,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "action": action_value,
            "summary": result.get("message"),
            "data": self._summarize_for_event(result.get("data")),
            "timestamp": self._utc_now(),
            "metadata": {
                "source": "ar_overlay",
                "success": bool(result.get("success")),
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: Optional[TaskContext],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Emit dashboard/API/agent event. Best-effort only."""
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "session_id": context.session_id if context else None,
            "request_id": context.request_id if context else None,
            "payload": self._redact_sensitive(dict(payload or {})),
            "timestamp": self._utc_now(),
        }

        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit"):
                    response = self.event_bus.emit(event_name, event)
                    self._run_maybe_async(response)
                elif callable(self.event_bus):
                    response = self.event_bus(event)
                    self._run_maybe_async(response)

            self.logger.debug("AR overlay event emitted: %s", event)
        except Exception:
            self.logger.exception("Failed to emit AR overlay event.")

    def _log_audit_event(
        self,
        action: Union[OverlayAction, str],
        context: Optional[TaskContext],
        success: bool,
        message: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Write sanitized audit event. Best-effort only."""
        action_value = str(action.value if isinstance(action, OverlayAction) else action)
        record = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action_value,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "session_id": context.session_id if context else None,
            "request_id": context.request_id if context else None,
            "success": bool(success),
            "message": message,
            "payload": self._redact_sensitive(dict(payload or {})),
            "timestamp": self._utc_now(),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    response = self.audit_logger.log(record)
                    self._run_maybe_async(response)
                elif callable(self.audit_logger):
                    response = self.audit_logger(record)
                    self._run_maybe_async(response)

            self.logger.info("AR overlay audit: %s", record)
        except Exception:
            self.logger.exception("Failed to write AR overlay audit event.")

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Any = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis result."""
        return {
            "success": bool(success),
            "message": str(message),
            "data": data,
            "error": dict(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": self._utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        code: str = "ar_overlay_error",
        details: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error result."""
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error={
                "code": code,
                "details": self._redact_sensitive(details) if isinstance(details, Mapping) else details,
            },
            metadata=metadata,
        )

    # =========================================================================
    # Public methods
    # =========================================================================

    async def create_card(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        title: str,
        body: str,
        placement: Union[OverlayPlacement, str] = OverlayPlacement.CENTER_RIGHT,
        actions: Optional[List[Mapping[str, Any]]] = None,
        style: Optional[Union[OverlayStyle, Mapping[str, Any]]] = None,
        ttl_seconds: Optional[int] = None,
        priority: Union[OverlayPriority, str] = OverlayPriority.NORMAL,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a floating UI card overlay."""
        anchor = OverlayAnchor(
            anchor_type=AnchorType.SCREEN,
            placement=self._normalize_enum(placement, OverlayPlacement, OverlayPlacement.CENTER_RIGHT),
        )
        interaction = OverlayInteraction(
            mode=InteractionMode.MIXED if actions else InteractionMode.NONE,
            dismissible=True,
            selectable=bool(actions),
            actions=[dict(item) for item in (actions or [])],
        )

        return await self._create_overlay(
            action=OverlayAction.CREATE_CARD,
            context=context,
            overlay_type=OverlayType.CARD,
            title=title,
            body=body,
            anchor=anchor,
            style=style,
            interaction=interaction,
            ttl_seconds=ttl_seconds,
            priority=priority,
            metadata=metadata,
        )

    async def create_notification(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        title: str,
        body: str,
        notification_type: Union[OverlayType, str] = OverlayType.NOTIFICATION,
        priority: Union[OverlayPriority, str] = OverlayPriority.NORMAL,
        ttl_seconds: Optional[int] = None,
        placement: Union[OverlayPlacement, str] = OverlayPlacement.TOP_RIGHT,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a floating notification overlay."""
        overlay_type = self._normalize_enum(notification_type, OverlayType, OverlayType.NOTIFICATION)

        if overlay_type not in {
            OverlayType.NOTIFICATION,
            OverlayType.WARNING,
            OverlayType.SUCCESS,
            OverlayType.ERROR,
        }:
            overlay_type = OverlayType.NOTIFICATION

        style = self._style_for_notification_type(overlay_type)

        anchor = OverlayAnchor(
            anchor_type=AnchorType.SCREEN,
            placement=self._normalize_enum(placement, OverlayPlacement, OverlayPlacement.TOP_RIGHT),
        )

        return await self._create_overlay(
            action=OverlayAction.CREATE_NOTIFICATION,
            context=context,
            overlay_type=overlay_type,
            title=title,
            body=body,
            anchor=anchor,
            style=style,
            interaction=OverlayInteraction(mode=InteractionMode.GAZE, dismissible=True),
            ttl_seconds=ttl_seconds or self.config.default_ttl_seconds,
            priority=priority,
            metadata=metadata,
        )

    async def create_instruction(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        instruction: str,
        step_number: Optional[int] = None,
        total_steps: Optional[int] = None,
        title: Optional[str] = None,
        anchor_type: Union[AnchorType, str] = AnchorType.SCREEN,
        target_id: Optional[str] = None,
        placement: Union[OverlayPlacement, str] = OverlayPlacement.BOTTOM_CENTER,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an instruction overlay for guided workflows."""
        computed_title = title or "Instruction"
        render_data = {
            "step_number": step_number,
            "total_steps": total_steps,
            "progress": self._safe_progress(step_number, total_steps),
        }

        anchor = OverlayAnchor(
            anchor_type=self._normalize_enum(anchor_type, AnchorType, AnchorType.SCREEN),
            target_id=target_id,
            placement=self._normalize_enum(placement, OverlayPlacement, OverlayPlacement.BOTTOM_CENTER),
        )

        merged_metadata = {
            **dict(metadata or {}),
            "instruction_step": step_number,
            "instruction_total_steps": total_steps,
        }

        return await self._create_overlay(
            action=OverlayAction.CREATE_INSTRUCTION,
            context=context,
            overlay_type=OverlayType.INSTRUCTION,
            title=computed_title,
            body=instruction,
            anchor=anchor,
            style=OverlayStyle(
                theme="jarvis_instruction",
                accent_color="#6400B3",
                icon="route",
                animation="slide_up",
            ),
            interaction=OverlayInteraction(
                mode=InteractionMode.MIXED,
                dismissible=True,
                selectable=True,
                voice_commands=["next", "repeat", "dismiss"],
                gesture_commands=["swipe_next", "tap_dismiss"],
                actions=[
                    {"id": "repeat", "label": "Repeat", "type": "instruction_repeat"},
                    {"id": "next", "label": "Next", "type": "instruction_next"},
                    {"id": "dismiss", "label": "Dismiss", "type": "dismiss"},
                ],
            ),
            ttl_seconds=ttl_seconds,
            priority=OverlayPriority.HIGH,
            metadata=merged_metadata,
            render_data=render_data,
        )

    async def create_real_world_overlay(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        title: str,
        body: str,
        target_id: Optional[str] = None,
        target_label: Optional[str] = None,
        anchor_type: Union[AnchorType, str] = AnchorType.OBJECT,
        world_position: Optional[Union[Vector3, Mapping[str, Any]]] = None,
        gps_latitude: Optional[float] = None,
        gps_longitude: Optional[float] = None,
        distance_meters: Optional[float] = None,
        placement: Union[OverlayPlacement, str] = OverlayPlacement.NEAR_OBJECT,
        confidence: float = 1.0,
        priority: Union[OverlayPriority, str] = OverlayPriority.NORMAL,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create an overlay anchored to a real-world object, person, GPS point,
        surface, hand, or gaze target.

        This creates a render payload only. Actual device/hardware rendering
        should happen through device_bridge.py.
        """
        position = self._parse_vector3(world_position) if world_position else Vector3(0.0, 0.0, self.config.default_depth_meters)

        anchor = OverlayAnchor(
            anchor_type=self._normalize_enum(anchor_type, AnchorType, AnchorType.OBJECT),
            target_id=target_id,
            target_label=target_label,
            placement=self._normalize_enum(placement, OverlayPlacement, OverlayPlacement.NEAR_OBJECT),
            world_position=position,
            gps_latitude=gps_latitude,
            gps_longitude=gps_longitude,
            distance_meters=distance_meters,
            confidence=max(0.0, min(float(confidence), 1.0)),
        )

        return await self._create_overlay(
            action=OverlayAction.CREATE_REAL_WORLD_OVERLAY,
            context=context,
            overlay_type=OverlayType.REAL_WORLD,
            title=title,
            body=body,
            anchor=anchor,
            style=OverlayStyle(
                theme="jarvis_world_label",
                icon="scan",
                animation="world_pin",
                background_color="rgba(16,16,16,0.74)",
            ),
            interaction=OverlayInteraction(
                mode=InteractionMode.MIXED,
                dismissible=True,
                selectable=True,
                voice_commands=["open", "more info", "hide"],
                gesture_commands=["pinch_select", "tap_hide"],
            ),
            ttl_seconds=ttl_seconds,
            priority=priority,
            metadata=metadata,
            render_data={
                "real_world": True,
                "target_id": target_id,
                "target_label": target_label,
            },
        )

    async def update_overlay(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        overlay_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update an existing overlay in the current user/workspace/session."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not overlay_id:
            return self._error_result("overlay_id is required.", "missing_overlay_id")

        if not isinstance(updates, Mapping):
            return self._error_result("updates must be a mapping.", "invalid_updates")

        security = await self._request_security_approval(
            OverlayAction.UPDATE_OVERLAY,
            ctx,
            {"overlay_id": overlay_id, "updates": dict(updates)},
        )
        if not security.get("approved"):
            return self._security_denied_result(OverlayAction.UPDATE_OVERLAY, ctx, security)

        overlay = self._get_overlay_record(ctx, overlay_id)
        if overlay is None:
            return self._error_result(
                "Overlay not found in this user/workspace/session.",
                "overlay_not_found",
                metadata=self._context_metadata(ctx),
            )

        allowed_fields = {
            "title",
            "body",
            "visibility",
            "priority",
            "ttl_seconds",
            "metadata",
            "render_data",
            "style",
            "interaction",
            "anchor",
        }

        invalid_fields = set(updates.keys()) - allowed_fields
        if invalid_fields:
            return self._error_result(
                f"Invalid overlay update fields: {sorted(invalid_fields)}",
                "invalid_update_fields",
                metadata=self._context_metadata(ctx),
            )

        if "title" in updates:
            title_result = self._validate_text(str(updates["title"]), "title", self.config.max_title_length)
            if title_result is not None:
                return title_result
            overlay.title = self._sanitize_text(str(updates["title"]))

        if "body" in updates:
            body_result = self._validate_text(str(updates["body"]), "body", self.config.max_text_length)
            if body_result is not None:
                return body_result
            overlay.body = self._sanitize_text(str(updates["body"]))

        if "visibility" in updates:
            overlay.visibility = self._normalize_enum(updates["visibility"], OverlayVisibility, OverlayVisibility.VISIBLE)

        if "priority" in updates:
            overlay.priority = self._normalize_enum(updates["priority"], OverlayPriority, OverlayPriority.NORMAL)

        if "ttl_seconds" in updates:
            overlay.ttl_seconds = self._normalize_ttl(updates.get("ttl_seconds"))
            overlay.expires_at = self._calculate_expiry(overlay.ttl_seconds)

        if "metadata" in updates:
            overlay.metadata.update(self._safe_metadata(dict(updates.get("metadata") or {})))

        if "render_data" in updates:
            overlay.render_data.update(self._safe_metadata(dict(updates.get("render_data") or {})))

        if "style" in updates:
            overlay.style = self._parse_style(updates["style"])

        if "interaction" in updates:
            overlay.interaction = self._parse_interaction(updates["interaction"])

        if "anchor" in updates:
            overlay.anchor = self._parse_anchor(updates["anchor"])

        overlay.updated_at = self._utc_now()
        self._put_overlay_record(ctx, overlay)

        result = self._safe_result(
            True,
            "AR overlay updated successfully.",
            data=overlay.to_render_dict(),
            metadata=self._context_metadata(ctx, {"overlay_id": overlay_id}),
        )

        await self._post_action_side_effects(OverlayAction.UPDATE_OVERLAY, ctx, result, {"overlay_id": overlay_id})
        self._log_audit_event(OverlayAction.UPDATE_OVERLAY, ctx, True, result["message"], {"overlay_id": overlay_id})
        self._emit_agent_event("hologram.ar_overlay.updated", ctx, result)

        return result

    async def remove_overlay(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        overlay_id: str,
    ) -> Dict[str, Any]:
        """Remove an overlay from current user/workspace/session."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not overlay_id:
            return self._error_result("overlay_id is required.", "missing_overlay_id")

        security = await self._request_security_approval(
            OverlayAction.REMOVE_OVERLAY,
            ctx,
            {"overlay_id": overlay_id},
        )
        if not security.get("approved"):
            return self._security_denied_result(OverlayAction.REMOVE_OVERLAY, ctx, security)

        store_key = self._store_key(ctx)
        session_store = self._store.get(store_key, {})

        if overlay_id not in session_store:
            return self._error_result(
                "Overlay not found in this user/workspace/session.",
                "overlay_not_found",
                metadata=self._context_metadata(ctx),
            )

        removed = session_store.pop(overlay_id)
        self._store[store_key] = session_store

        result = self._safe_result(
            True,
            "AR overlay removed successfully.",
            data={"overlay_id": overlay_id, "removed": True},
            metadata=self._context_metadata(ctx, {"overlay_id": overlay_id}),
        )

        await self._post_action_side_effects(
            OverlayAction.REMOVE_OVERLAY,
            ctx,
            result,
            {"overlay_id": overlay_id, "overlay_type": removed.overlay_type.value},
        )
        self._log_audit_event(OverlayAction.REMOVE_OVERLAY, ctx, True, result["message"], {"overlay_id": overlay_id})
        self._emit_agent_event("hologram.ar_overlay.removed", ctx, result)

        return result

    async def clear_session(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Clear all overlays for the current user/workspace/session only."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        security = await self._request_security_approval(
            OverlayAction.CLEAR_SESSION,
            ctx,
            {"session_id": ctx.session_id},
        )
        if not security.get("approved"):
            return self._security_denied_result(OverlayAction.CLEAR_SESSION, ctx, security)

        store_key = self._store_key(ctx)
        count = len(self._store.get(store_key, {}))
        self._store[store_key] = {}

        result = self._safe_result(
            True,
            "AR overlay session cleared successfully.",
            data={"cleared_count": count, "session_id": ctx.session_id},
            metadata=self._context_metadata(ctx),
        )

        await self._post_action_side_effects(OverlayAction.CLEAR_SESSION, ctx, result)
        self._log_audit_event(OverlayAction.CLEAR_SESSION, ctx, True, result["message"], {"cleared_count": count})
        self._emit_agent_event("hologram.ar_overlay.session_cleared", ctx, result)

        return result

    async def get_overlay(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        overlay_id: str,
    ) -> Dict[str, Any]:
        """Get one overlay from current user/workspace/session."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        overlay = self._get_overlay_record(ctx, overlay_id)
        if overlay is None:
            return self._error_result(
                "Overlay not found in this user/workspace/session.",
                "overlay_not_found",
                metadata=self._context_metadata(ctx),
            )

        return self._safe_result(
            True,
            "AR overlay retrieved successfully.",
            data=overlay.to_render_dict(),
            metadata=self._context_metadata(ctx, {"overlay_id": overlay_id}),
        )

    async def list_overlays(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        overlay_type: Optional[Union[OverlayType, str]] = None,
        include_expired: bool = False,
        visible_only: bool = False,
    ) -> Dict[str, Any]:
        """List overlays from current user/workspace/session only."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        self._purge_expired(ctx)
        overlays = list(self._store.get(self._store_key(ctx), {}).values())

        if overlay_type is not None:
            normalized_type = self._normalize_enum(overlay_type, OverlayType, OverlayType.CARD)
            overlays = [item for item in overlays if item.overlay_type == normalized_type]

        if not include_expired:
            overlays = [item for item in overlays if not self._is_expired(item)]

        if visible_only:
            overlays = [item for item in overlays if item.visibility == OverlayVisibility.VISIBLE]

        overlays.sort(key=self._priority_sort_key, reverse=True)

        return self._safe_result(
            True,
            "AR overlays listed successfully.",
            data=[item.to_render_dict() for item in overlays],
            metadata=self._context_metadata(ctx, {"count": len(overlays)}),
        )

    async def build_scene(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        device_profile: Optional[Mapping[str, Any]] = None,
        include_hidden: bool = False,
    ) -> Dict[str, Any]:
        """
        Build a full AR scene payload.

        This can be returned to WebXR, mobile apps, dashboard preview, or
        device_bridge.py. No hardware call is executed here.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        self._purge_expired(ctx)
        overlays = list(self._store.get(self._store_key(ctx), {}).values())

        if not include_hidden:
            overlays = [
                item for item in overlays
                if item.visibility in {OverlayVisibility.VISIBLE, OverlayVisibility.FADED}
            ]

        overlays.sort(key=self._priority_sort_key, reverse=True)

        scene = {
            "format": self.config.scene_format_version,
            "scene_id": f"scene_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "session_id": ctx.session_id,
            "request_id": ctx.request_id,
            "created_at": self._utc_now(),
            "device_profile": self._safe_metadata(dict(device_profile or {})),
            "rendering": {
                "coordinate_system": "right_handed_y_up",
                "units": "meters",
                "safe_area": True,
                "depth_default_meters": self.config.default_depth_meters,
            },
            "overlays": [item.to_render_dict() for item in overlays],
        }

        validation = self.validate_render_payload(scene)
        if not validation["success"]:
            return validation

        if self.renderer is not None:
            try:
                render_response = self.renderer(scene)
                if asyncio.iscoroutine(render_response):
                    render_response = await render_response
                scene["renderer_response"] = self._redact_sensitive(render_response)
            except Exception as exc:
                self.logger.exception("Renderer callback failed.")
                return self._error_result(
                    f"Renderer callback failed: {exc}",
                    "renderer_callback_failed",
                    metadata=self._context_metadata(ctx),
                )

        result = self._safe_result(
            True,
            "AR scene payload built successfully.",
            data=scene,
            metadata=self._context_metadata(ctx, {"overlay_count": len(overlays)}),
        )

        self._emit_agent_event("hologram.ar_overlay.scene_built", ctx, result)
        self._log_audit_event(OverlayAction.BUILD_SCENE, ctx, True, result["message"], {"overlay_count": len(overlays)})

        return result

    def validate_render_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate render payload shape for downstream clients."""
        if not isinstance(payload, Mapping):
            return self._error_result("Render payload must be a mapping.", "invalid_render_payload")

        if "overlays" not in payload:
            return self._error_result("Render payload missing overlays list.", "missing_overlays")

        if not isinstance(payload.get("overlays"), list):
            return self._error_result("Render payload overlays must be a list.", "invalid_overlays")

        for index, overlay in enumerate(payload.get("overlays") or []):
            if not isinstance(overlay, Mapping):
                return self._error_result(f"Overlay at index {index} must be a mapping.", "invalid_overlay_item")

            for required_key in ("overlay_id", "type", "title", "body", "anchor", "style", "visibility"):
                if required_key not in overlay:
                    return self._error_result(
                        f"Overlay at index {index} missing required key: {required_key}",
                        "invalid_overlay_schema",
                    )

        return self._safe_result(
            True,
            "AR render payload is valid.",
            data={"valid": True, "overlay_count": len(payload.get("overlays") or [])},
        )

    # =========================================================================
    # Sync wrappers
    # =========================================================================

    def create_card_sync(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Sync wrapper for create_card."""
        return self._run_sync(self.create_card(*args, **kwargs))

    def create_notification_sync(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Sync wrapper for create_notification."""
        return self._run_sync(self.create_notification(*args, **kwargs))

    def create_instruction_sync(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Sync wrapper for create_instruction."""
        return self._run_sync(self.create_instruction(*args, **kwargs))

    def create_real_world_overlay_sync(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Sync wrapper for create_real_world_overlay."""
        return self._run_sync(self.create_real_world_overlay(*args, **kwargs))

    def build_scene_sync(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Sync wrapper for build_scene."""
        return self._run_sync(self.build_scene(*args, **kwargs))

    # =========================================================================
    # Internal overlay creation
    # =========================================================================

    async def _create_overlay(
        self,
        action: OverlayAction,
        context: Union[TaskContext, Mapping[str, Any]],
        overlay_type: OverlayType,
        title: str,
        body: str,
        anchor: Optional[OverlayAnchor] = None,
        style: Optional[Union[OverlayStyle, Mapping[str, Any]]] = None,
        interaction: Optional[OverlayInteraction] = None,
        ttl_seconds: Optional[int] = None,
        priority: Union[OverlayPriority, str] = OverlayPriority.NORMAL,
        metadata: Optional[Mapping[str, Any]] = None,
        render_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Shared overlay creation pipeline."""
        start = time.time()

        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        title_validation = self._validate_text(title, "title", self.config.max_title_length)
        if title_validation is not None:
            return title_validation

        body_validation = self._validate_text(body, "body", self.config.max_text_length)
        if body_validation is not None:
            return body_validation

        if self.config.enable_in_memory_store:
            count = len(self._store.get(self._store_key(ctx), {}))
            if count >= self.config.max_overlays_per_session:
                return self._error_result(
                    "Maximum overlays per session reached.",
                    "max_overlays_reached",
                    metadata=self._context_metadata(ctx, {"max_overlays": self.config.max_overlays_per_session}),
                )

        normalized_priority = self._normalize_enum(priority, OverlayPriority, OverlayPriority.NORMAL)
        normalized_ttl = self._normalize_ttl(ttl_seconds)
        safe_anchor = anchor or OverlayAnchor()
        safe_style = self._parse_style(style) if style is not None else OverlayStyle()
        safe_interaction = interaction or OverlayInteraction()
        safe_metadata = self._safe_metadata(dict(metadata or {}))
        safe_render_data = self._safe_metadata(dict(render_data or {}))

        security_payload = {
            "overlay_type": overlay_type.value,
            "priority": normalized_priority.value,
            "anchor_type": safe_anchor.anchor_type.value if isinstance(safe_anchor.anchor_type, AnchorType) else str(safe_anchor.anchor_type),
            "title": title,
            "metadata": safe_metadata,
        }

        security = await self._request_security_approval(action, ctx, security_payload)
        if not security.get("approved"):
            return self._security_denied_result(action, ctx, security)

        now = self._utc_now()
        overlay = OverlayPayload(
            overlay_id=f"ovr_{uuid.uuid4().hex}",
            overlay_type=overlay_type,
            title=self._sanitize_text(title),
            body=self._sanitize_text(body),
            context=ctx,
            anchor=safe_anchor,
            style=safe_style,
            interaction=safe_interaction,
            priority=normalized_priority,
            visibility=OverlayVisibility.VISIBLE,
            ttl_seconds=normalized_ttl,
            created_at=now,
            updated_at=now,
            expires_at=self._calculate_expiry(normalized_ttl),
            metadata={
                **safe_metadata,
                "managed_by": self.agent_name,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "session_id": ctx.session_id,
            },
            render_data=safe_render_data,
        )

        self._put_overlay_record(ctx, overlay)

        result = self._safe_result(
            True,
            f"AR {overlay_type.value} overlay created successfully.",
            data=overlay.to_render_dict(),
            metadata=self._context_metadata(
                ctx,
                {
                    "overlay_id": overlay.overlay_id,
                    "overlay_type": overlay_type.value,
                    "duration_ms": int((time.time() - start) * 1000),
                },
            ),
        )

        await self._post_action_side_effects(action, ctx, result, {"overlay_id": overlay.overlay_id})
        self._log_audit_event(action, ctx, True, result["message"], {"overlay_id": overlay.overlay_id})
        self._emit_agent_event(f"hologram.ar_overlay.{overlay_type.value}.created", ctx, result)

        return result

    async def _post_action_side_effects(
        self,
        action: OverlayAction,
        context: TaskContext,
        result: Mapping[str, Any],
        target: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Send best-effort Verification and Memory Agent payloads."""
        verification_payload = self._prepare_verification_payload(action, context, result, target)
        memory_payload = self._prepare_memory_payload(action, context, result)

        if self.verification_agent is not None:
            try:
                for method_name in ("submit", "verify", "record"):
                    if hasattr(self.verification_agent, method_name):
                        response = getattr(self.verification_agent, method_name)(verification_payload)
                        if asyncio.iscoroutine(response):
                            await response
                        break
            except Exception:
                self.logger.exception("Failed to submit AR overlay verification payload.")

        if self.memory_agent is not None and result.get("success"):
            try:
                for method_name in ("store", "remember", "save"):
                    if hasattr(self.memory_agent, method_name):
                        response = getattr(self.memory_agent, method_name)(memory_payload)
                        if asyncio.iscoroutine(response):
                            await response
                        break
            except Exception:
                self.logger.exception("Failed to submit AR overlay memory payload.")

    # =========================================================================
    # Store helpers
    # =========================================================================

    def _store_key(self, context: TaskContext) -> str:
        """Tenant-safe store key."""
        return f"{context.workspace_id}:{context.user_id}:{context.session_id}"

    def _put_overlay_record(self, context: TaskContext, overlay: OverlayPayload) -> None:
        """Store overlay in current tenant/session."""
        if not self.config.enable_in_memory_store:
            return

        key = self._store_key(context)
        self._store.setdefault(key, {})
        self._store[key][overlay.overlay_id] = overlay

    def _get_overlay_record(self, context: TaskContext, overlay_id: str) -> Optional[OverlayPayload]:
        """Get overlay from current tenant/session."""
        if not self.config.enable_in_memory_store:
            return None
        return self._store.get(self._store_key(context), {}).get(overlay_id)

    def _purge_expired(self, context: TaskContext) -> None:
        """Remove expired overlays from current tenant/session."""
        key = self._store_key(context)
        session_store = self._store.get(key, {})
        expired_ids = [
            overlay_id for overlay_id, overlay in session_store.items()
            if self._is_expired(overlay)
        ]
        for overlay_id in expired_ids:
            session_store.pop(overlay_id, None)
        self._store[key] = session_store

    def _is_expired(self, overlay: OverlayPayload) -> bool:
        """Check TTL expiry."""
        if not overlay.expires_at:
            return False

        try:
            expires = datetime.fromisoformat(overlay.expires_at)
            return datetime.now(timezone.utc) >= expires
        except Exception:
            return False

    # =========================================================================
    # Parsers and validators
    # =========================================================================

    def _get_valid_context_or_error(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> Union[TaskContext, Dict[str, Any]]:
        """Return valid context or structured error result."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(error or "Invalid task context.", "invalid_task_context")
        return ctx

    def _validate_text(self, value: str, field_name: str, max_length: int) -> Optional[Dict[str, Any]]:
        """Validate overlay text."""
        if value is None or not str(value).strip():
            return self._error_result(f"{field_name} is required.", f"missing_{field_name}")

        if len(str(value)) > max_length:
            return self._error_result(
                f"{field_name} is too long. Maximum length is {max_length}.",
                f"{field_name}_too_long",
            )

        return None

    def _sanitize_text(self, value: str) -> str:
        """Sanitize overlay text for safe UI rendering."""
        text = str(value).strip()
        if self.config.enable_html_sanitization:
            return html.escape(text, quote=True)
        return text

    def _normalize_ttl(self, ttl_seconds: Optional[Any]) -> Optional[int]:
        """Normalize TTL seconds."""
        if ttl_seconds is None:
            return None

        try:
            ttl = int(ttl_seconds)
        except Exception:
            ttl = self.config.default_ttl_seconds

        ttl = max(1, min(ttl, self.config.max_ttl_seconds))
        return ttl

    def _calculate_expiry(self, ttl_seconds: Optional[int]) -> Optional[str]:
        """Calculate ISO expiry timestamp from TTL."""
        if ttl_seconds is None:
            return None
        expires = datetime.now(timezone.utc).timestamp() + ttl_seconds
        return datetime.fromtimestamp(expires, timezone.utc).isoformat()

    def _parse_style(self, style: Union[OverlayStyle, Mapping[str, Any]]) -> OverlayStyle:
        """Parse style from dataclass or mapping."""
        if isinstance(style, OverlayStyle):
            return style

        if not isinstance(style, Mapping):
            return OverlayStyle()

        base = OverlayStyle()
        data = asdict(base)
        for key, value in style.items():
            if key in data:
                data[key] = value

        data["opacity"] = max(0.0, min(float(data.get("opacity", 1.0)), 1.0))
        data["border_radius"] = max(0, int(data.get("border_radius", 18)))
        data["font_size"] = max(8, min(int(data.get("font_size", 15)), 96))
        data["title_size"] = max(8, min(int(data.get("title_size", 18)), 120))
        data["animation_ms"] = max(0, min(int(data.get("animation_ms", 260)), 10000))
        return OverlayStyle(**data)

    def _parse_interaction(self, interaction: Union[OverlayInteraction, Mapping[str, Any]]) -> OverlayInteraction:
        """Parse interaction config."""
        if isinstance(interaction, OverlayInteraction):
            return interaction

        if not isinstance(interaction, Mapping):
            return OverlayInteraction()

        return OverlayInteraction(
            mode=self._normalize_enum(interaction.get("mode"), InteractionMode, InteractionMode.NONE),
            dismissible=bool(interaction.get("dismissible", True)),
            selectable=bool(interaction.get("selectable", False)),
            voice_commands=[str(item) for item in interaction.get("voice_commands", [])],
            gesture_commands=[str(item) for item in interaction.get("gesture_commands", [])],
            actions=[dict(item) for item in interaction.get("actions", []) if isinstance(item, Mapping)],
        )

    def _parse_anchor(self, anchor: Union[OverlayAnchor, Mapping[str, Any]]) -> OverlayAnchor:
        """Parse anchor config."""
        if isinstance(anchor, OverlayAnchor):
            return anchor

        if not isinstance(anchor, Mapping):
            return OverlayAnchor()

        return OverlayAnchor(
            anchor_type=self._normalize_enum(anchor.get("anchor_type"), AnchorType, AnchorType.SCREEN),
            target_id=anchor.get("target_id"),
            target_label=anchor.get("target_label"),
            placement=self._normalize_enum(anchor.get("placement"), OverlayPlacement, OverlayPlacement.CENTER),
            screen_position=self._parse_vector2(anchor.get("screen_position")),
            world_position=self._parse_vector3(anchor.get("world_position")),
            world_rotation=self._parse_vector3(anchor.get("world_rotation")),
            world_scale=self._parse_vector3(anchor.get("world_scale"), default=Vector3(1.0, 1.0, 1.0)),
            gps_latitude=self._safe_float_or_none(anchor.get("gps_latitude")),
            gps_longitude=self._safe_float_or_none(anchor.get("gps_longitude")),
            distance_meters=self._safe_float_or_none(anchor.get("distance_meters")),
            confidence=max(0.0, min(float(anchor.get("confidence", 1.0)), 1.0)),
        )

    def _parse_vector2(self, value: Optional[Any], default: Optional[Vector2] = None) -> Vector2:
        """Parse Vector2."""
        if isinstance(value, Vector2):
            return value

        if default is None:
            default = Vector2()

        if isinstance(value, Mapping):
            return Vector2(
                x=self._safe_float(value.get("x"), default.x),
                y=self._safe_float(value.get("y"), default.y),
            )

        if isinstance(value, (list, tuple)) and len(value) >= 2:
            return Vector2(
                x=self._safe_float(value[0], default.x),
                y=self._safe_float(value[1], default.y),
            )

        return default

    def _parse_vector3(self, value: Optional[Any], default: Optional[Vector3] = None) -> Vector3:
        """Parse Vector3."""
        if isinstance(value, Vector3):
            return value

        if default is None:
            default = Vector3()

        if isinstance(value, Mapping):
            return Vector3(
                x=self._safe_float(value.get("x"), default.x),
                y=self._safe_float(value.get("y"), default.y),
                z=self._safe_float(value.get("z"), default.z),
            )

        if isinstance(value, (list, tuple)) and len(value) >= 3:
            return Vector3(
                x=self._safe_float(value[0], default.x),
                y=self._safe_float(value[1], default.y),
                z=self._safe_float(value[2], default.z),
            )

        return default

    def _normalize_enum(self, value: Any, enum_cls: Any, default: Any) -> Any:
        """Normalize enum value safely."""
        if isinstance(value, enum_cls):
            return value

        try:
            return enum_cls(str(value))
        except Exception:
            return default

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Parse finite float."""
        try:
            parsed = float(value)
            if math.isfinite(parsed):
                return parsed
        except Exception:
            pass
        return float(default)

    def _safe_float_or_none(self, value: Any) -> Optional[float]:
        """Parse optional finite float."""
        if value is None:
            return None
        try:
            parsed = float(value)
            return parsed if math.isfinite(parsed) else None
        except Exception:
            return None

    def _safe_progress(self, step_number: Optional[int], total_steps: Optional[int]) -> Optional[float]:
        """Calculate instruction progress."""
        if not step_number or not total_steps or total_steps <= 0:
            return None
        return max(0.0, min(float(step_number) / float(total_steps), 1.0))

    def _safe_metadata(self, value: Mapping[str, Any]) -> Dict[str, Any]:
        """Return JSON-safe redacted metadata."""
        redacted = self._redact_sensitive(dict(value or {}))
        try:
            json.dumps(redacted, default=str)
            return copy.deepcopy(redacted)
        except Exception:
            return {"raw": str(redacted)}

    def _style_for_notification_type(self, overlay_type: OverlayType) -> OverlayStyle:
        """Create default style for notification variants."""
        if overlay_type == OverlayType.SUCCESS:
            return OverlayStyle(theme="jarvis_success", accent_color="#22C55E", icon="check_circle", animation="toast_in")
        if overlay_type == OverlayType.WARNING:
            return OverlayStyle(theme="jarvis_warning", accent_color="#F59E0B", icon="warning", animation="toast_in")
        if overlay_type == OverlayType.ERROR:
            return OverlayStyle(theme="jarvis_error", accent_color="#EF4444", icon="error", animation="toast_in")
        return OverlayStyle(theme="jarvis_notification", accent_color="#6400B3", icon="bell", animation="toast_in")

    # =========================================================================
    # Security / event helpers
    # =========================================================================

    def _security_denied_result(
        self,
        action: OverlayAction,
        context: TaskContext,
        security: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Return security denied result."""
        result = self._error_result(
            f"Security approval denied for AR overlay action '{action.value}'.",
            "security_denied",
            details=dict(security),
            metadata=self._context_metadata(context),
        )
        self._log_audit_event(action, context, False, result["message"], security)
        self._emit_agent_event("hologram.ar_overlay.security_denied", context, result)
        return result

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        """Normalize Security Agent response."""
        if isinstance(response, Mapping):
            approved = bool(
                response.get("approved")
                or response.get("allowed")
                or response.get("success")
                or response.get("is_allowed")
            )
            return {
                "approved": approved,
                "reason": response.get("reason") or response.get("message") or "Security response received.",
                "source": response.get("source") or "security_agent",
                "raw": self._redact_sensitive(dict(response)),
            }

        if isinstance(response, bool):
            return {
                "approved": response,
                "reason": "Boolean Security Agent response.",
                "source": "security_agent",
            }

        return {
            "approved": False,
            "reason": "Unrecognized Security Agent response.",
            "source": "security_agent",
            "raw": str(response),
        }

    def _redact_sensitive(self, value: Any) -> Any:
        """Redact secrets and sensitive tokens recursively."""
        sensitive_keys = {
            "api_key",
            "apikey",
            "authorization",
            "password",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "credential",
            "credentials",
            "cookie",
            "set-cookie",
            "private_key",
            "device_token",
        }

        if isinstance(value, Mapping):
            output = {}
            for key, item in value.items():
                key_str = str(key).lower()
                if key_str in sensitive_keys or any(part in key_str for part in ("secret", "token", "password", "private")):
                    output[key] = "***REDACTED***"
                else:
                    output[key] = self._redact_sensitive(item)
            return output

        if isinstance(value, list):
            return [self._redact_sensitive(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive(item) for item in value)

        return value

    def _summarize_for_event(self, data: Any) -> Any:
        """Create compact event/memory summary."""
        data = self._redact_sensitive(data)

        if data is None:
            return None

        if isinstance(data, Mapping):
            summary: Dict[str, Any] = {}
            for key in (
                "overlay_id",
                "type",
                "title",
                "priority",
                "visibility",
                "ttl_seconds",
                "expires_at",
                "session_id",
                "cleared_count",
                "overlay_count",
            ):
                if key in data:
                    summary[key] = data[key]

            if "overlays" in data and isinstance(data.get("overlays"), list):
                summary["overlay_count"] = len(data.get("overlays") or [])

            if not summary:
                summary["keys"] = list(data.keys())[:15]

            return summary

        if isinstance(data, list):
            return {
                "items_count": len(data),
                "first_item_summary": self._summarize_for_event(data[0]) if data else None,
            }

        return data

    def _context_metadata(
        self,
        context: TaskContext,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard metadata scoped to user/workspace/session."""
        return {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
            "request_id": context.request_id,
            **dict(extra or {}),
        }

    def _priority_sort_key(self, overlay: OverlayPayload) -> int:
        """Sort priority mapping."""
        order = {
            OverlayPriority.LOW: 1,
            OverlayPriority.NORMAL: 2,
            OverlayPriority.HIGH: 3,
            OverlayPriority.CRITICAL: 4,
        }
        return order.get(overlay.priority, 2)

    def _new_request_id(self) -> str:
        """Create request id."""
        return f"{self.config.request_id_prefix}_{uuid.uuid4().hex}"

    def _utc_now(self) -> str:
        """Current UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def _run_maybe_async(self, response: Any) -> None:
        """Safely execute coroutine response from sync hook."""
        if not asyncio.iscoroutine(response):
            return

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(response)
        except RuntimeError:
            asyncio.run(response)

    def _run_sync(self, coroutine: Any) -> Dict[str, Any]:
        """Run async method from sync environment."""
        try:
            asyncio.get_running_loop()
            return self._error_result(
                "Cannot use sync wrapper inside a running event loop. Use the async method instead.",
                "event_loop_already_running",
            )
        except RuntimeError:
            return asyncio.run(coroutine)

    # =========================================================================
    # Registry / loader metadata
    # =========================================================================

    def get_capabilities(self) -> Dict[str, Any]:
        """Expose capabilities for Agent Registry, Agent Loader, Dashboard, API."""
        return {
            "agent": self.agent_name,
            "version": self.agent_version,
            "class": self.__class__.__name__,
            "module": "Hologram Agent",
            "capabilities": [
                "create_floating_ui_card",
                "create_notification_overlay",
                "create_instruction_overlay",
                "create_real_world_overlay",
                "update_overlay",
                "remove_overlay",
                "clear_session_overlays",
                "list_session_overlays",
                "get_overlay",
                "build_ar_scene_payload",
                "validate_render_payload",
            ],
            "safety": {
                "requires_user_workspace_context": True,
                "does_not_control_real_hardware_directly": True,
                "requires_security_for_real_world_overlays": self.config.require_security_for_real_world_overlays,
                "requires_security_for_critical_notifications": self.config.require_security_for_critical_notifications,
                "sensitive_real_world_labels_allowed": self.config.allow_sensitive_real_world_labels,
            },
            "rendering": {
                "scene_format_version": self.config.scene_format_version,
                "default_depth_meters": self.config.default_depth_meters,
                "max_overlays_per_session": self.config.max_overlays_per_session,
            },
        }


# =============================================================================
# Factory helpers
# =============================================================================

def create_ar_overlay(
    config: Optional[Union[OverlayConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> AROverlay:
    """
    Factory helper for Agent Loader / Registry / FastAPI dependency injection.
    """
    return AROverlay(config=config, **kwargs)


def get_default_ar_overlay() -> AROverlay:
    """
    Create a default AROverlay instance with safe defaults.
    """
    return AROverlay()


__all__ = [
    "OverlayAction",
    "OverlayType",
    "OverlayPriority",
    "AnchorType",
    "OverlayPlacement",
    "OverlayVisibility",
    "InteractionMode",
    "TaskContext",
    "Vector2",
    "Vector3",
    "OverlayStyle",
    "OverlayAnchor",
    "OverlayInteraction",
    "OverlayConfig",
    "OverlayPayload",
    "AROverlay",
    "create_ar_overlay",
    "get_default_ar_overlay",
]