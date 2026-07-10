"""
agents/super_agents/hologram_agent/config.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    AR device settings, privacy flags, gesture settings, and overlay limits.

This file provides the production-ready configuration layer for the Hologram Agent.
It is import-safe, SaaS-aware, dashboard/API-ready, and compatible with Master Agent,
Agent Registry, Agent Loader, Security Agent, Memory Agent, and Verification Agent
patterns used across the William/Jarvis architecture.

Main Responsibilities:
    - Store and validate AR/hologram device settings.
    - Manage privacy flags for camera, microphone, spatial mapping, location,
      face recognition, object recognition, recording, and cloud processing.
    - Manage gesture detection configuration.
    - Manage overlay limits and notification limits.
    - Provide safe defaults for AR glasses/mobile/desktop/simulator modes.
    - Expose structured JSON-style result helpers.
    - Prepare verification and memory payloads for config changes.
    - Emit audit/event hooks for dashboard/API integration.
    - Remain safe to import even if other William/Jarvis modules are not ready.

Safety Principles:
    - Privacy-first defaults.
    - No hardcoded secrets.
    - No real device actions are executed here.
    - Every user/workspace scoped operation validates SaaS context.
    - Sensitive privacy changes can be routed through Security Agent approval.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


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
        exists. The production BaseAgent can later provide registry hooks,
        shared permission checks, logging, telemetry, and lifecycle methods.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "hologram_config"
DEFAULT_CONFIG_VERSION = "1.0.0"

MIN_OVERLAY_OPACITY = 0.05
MAX_OVERLAY_OPACITY = 1.0
MIN_OVERLAY_SCALE = 0.25
MAX_OVERLAY_SCALE = 4.0
MIN_GESTURE_CONFIDENCE = 0.1
MAX_GESTURE_CONFIDENCE = 1.0
MIN_REFRESH_RATE_HZ = 15
MAX_REFRESH_RATE_HZ = 144
MIN_FOV_DEGREES = 20
MAX_FOV_DEGREES = 140
MIN_BRIGHTNESS = 0.05
MAX_BRIGHTNESS = 1.0

DEFAULT_MAX_ACTIVE_OVERLAYS = 8
DEFAULT_MAX_NOTIFICATIONS = 5
DEFAULT_MAX_ANCHORS = 50
DEFAULT_MAX_SPATIAL_OBJECTS = 300
DEFAULT_SESSION_TIMEOUT_SECONDS = 1800


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC datetime in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse environment-style boolean values safely."""

    if value is None:
        return default

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


def parse_int(value: Optional[str], default: int) -> int:
    """Parse int safely."""

    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def parse_float(value: Optional[str], default: float) -> float:
    """Parse float safely."""

    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def clamp(value: Union[int, float], minimum: Union[int, float], maximum: Union[int, float]) -> Union[int, float]:
    """Clamp a numeric value."""

    return max(minimum, min(maximum, value))


def safe_json_dumps(value: Any) -> str:
    """Serialize values safely for logs/fingerprints."""

    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def deep_merge_dict(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge dictionaries.

    Values from updates override base values. Nested dictionaries are merged.
    """

    merged = copy.deepcopy(base)

    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge_dict(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)

    return merged


def dataclass_to_dict(value: Any) -> Dict[str, Any]:
    """
    Convert dataclass to dict with Enum values normalized.
    """

    def normalize(item: Any) -> Any:
        if isinstance(item, Enum):
            return item.value
        if is_dataclass(item):
            return {k: normalize(v) for k, v in asdict(item).items()}
        if isinstance(item, dict):
            return {k: normalize(v) for k, v in item.items()}
        if isinstance(item, (list, tuple, set)):
            return [normalize(v) for v in item]
        return item

    if is_dataclass(value):
        return normalize(value)
    if isinstance(value, dict):
        return normalize(value)
    return {"value": normalize(value)}


def result_metadata(context: Optional["HologramTaskContext"] = None, **extra: Any) -> Dict[str, Any]:
    """Build common structured metadata."""

    metadata: Dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "agent": DEFAULT_AGENT_NAME,
        "config_version": DEFAULT_CONFIG_VERSION,
    }

    if context is not None:
        metadata.update(
            {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "task_id": context.task_id,
                "source": context.source,
            }
        )

    metadata.update(extra)
    return metadata


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class HologramDeviceType(str, Enum):
    """Supported hologram/AR device categories."""

    AR_GLASSES = "ar_glasses"
    MIXED_REALITY_HEADSET = "mixed_reality_headset"
    MOBILE_AR = "mobile_ar"
    DESKTOP_SIMULATOR = "desktop_simulator"
    WEBXR = "webxr"
    UNKNOWN = "unknown"


class HologramRuntimeMode(str, Enum):
    """Runtime modes for Hologram Agent."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"
    SIMULATION = "simulation"
    TEST = "test"


class OverlayRenderMode(str, Enum):
    """Overlay rendering behavior."""

    WORLD_LOCKED = "world_locked"
    HEAD_LOCKED = "head_locked"
    SCREEN_LOCKED = "screen_locked"
    ANCHORED_TO_OBJECT = "anchored_to_object"
    ANCHORED_TO_SURFACE = "anchored_to_surface"


class OverlayPriority(str, Enum):
    """Overlay priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class GestureMode(str, Enum):
    """Gesture recognition mode."""

    DISABLED = "disabled"
    BASIC = "basic"
    ADVANCED = "advanced"
    CUSTOM = "custom"


class PrivacyMode(str, Enum):
    """Privacy strictness levels."""

    STRICT = "strict"
    BALANCED = "balanced"
    FLEXIBLE = "flexible"
    CUSTOM = "custom"


class SpatialMappingMode(str, Enum):
    """Spatial mapping behavior."""

    DISABLED = "disabled"
    LOCAL_ONLY = "local_only"
    SESSION_ONLY = "session_only"
    PERSISTENT_LOCAL = "persistent_local"
    CLOUD_SYNC = "cloud_sync"


class HologramPermissionScope(str, Enum):
    """Permission scopes used by Security Agent / Agent Router."""

    READ_CONFIG = "hologram.config.read"
    UPDATE_CONFIG = "hologram.config.update"
    UPDATE_PRIVACY = "hologram.config.update_privacy"
    UPDATE_DEVICE = "hologram.config.update_device"
    UPDATE_GESTURES = "hologram.config.update_gestures"
    UPDATE_OVERLAYS = "hologram.config.update_overlays"
    RESET_CONFIG = "hologram.config.reset"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HologramTaskContext:
    """
    SaaS task context.

    Every user/workspace-specific config read/update should include this context
    to prevent cross-user and cross-workspace leakage.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    agent_id: str = DEFAULT_AGENT_NAME
    source: str = "hologram_agent"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ARDeviceSettings:
    """
    Device-level settings for AR glasses/headsets/mobile AR/simulator.

    This config does not connect to hardware directly. DeviceBridge can consume
    these settings later after Security Agent approval.
    """

    device_type: HologramDeviceType = HologramDeviceType.DESKTOP_SIMULATOR
    device_name: str = "William Hologram Simulator"
    device_id: Optional[str] = None
    runtime_mode: HologramRuntimeMode = HologramRuntimeMode.DEVELOPMENT

    enable_device_bridge: bool = False
    enable_webxr: bool = False
    enable_camera_stream: bool = False
    enable_microphone_stream: bool = False
    enable_depth_sensor: bool = False
    enable_eye_tracking: bool = False
    enable_hand_tracking: bool = True
    enable_head_tracking: bool = True
    enable_location_services: bool = False

    refresh_rate_hz: int = 60
    field_of_view_degrees: int = 70
    brightness: float = 0.75
    adaptive_brightness: bool = True
    low_power_mode: bool = True

    session_timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS
    auto_pause_when_removed: bool = True
    auto_dim_in_private_spaces: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HologramPrivacyFlags:
    """
    Privacy flags for AR/hologram operations.

    Privacy-first defaults are used. Sensitive capabilities are disabled unless
    explicitly enabled through approved config updates.
    """

    privacy_mode: PrivacyMode = PrivacyMode.STRICT

    allow_camera_access: bool = False
    allow_microphone_access: bool = False
    allow_screen_capture: bool = False
    allow_recording: bool = False
    allow_cloud_processing: bool = False
    allow_location_access: bool = False
    allow_face_recognition: bool = False
    allow_biometric_tracking: bool = False
    allow_eye_tracking: bool = False
    allow_object_recognition: bool = False
    allow_people_detection: bool = False
    allow_text_recognition: bool = False
    allow_spatial_mapping: bool = False
    allow_persistent_spatial_map: bool = False
    allow_cross_session_memory: bool = False

    anonymize_faces: bool = True
    blur_sensitive_surfaces: bool = True
    redact_detected_text: bool = True
    local_processing_preferred: bool = True
    require_visible_privacy_indicator: bool = True
    require_user_presence: bool = True
    require_workspace_boundary: bool = True

    data_retention_seconds: int = 0
    spatial_map_retention_seconds: int = 0
    event_log_retention_days: int = 30

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GestureSettings:
    """
    Gesture detection settings.

    GestureBridge can consume these values to decide which gestures are allowed
    and how confident detections must be before triggering an action.
    """

    mode: GestureMode = GestureMode.BASIC
    enabled: bool = True

    allow_air_tap: bool = True
    allow_pinch: bool = True
    allow_swipe: bool = True
    allow_grab: bool = False
    allow_point: bool = True
    allow_palm_open: bool = True
    allow_palm_close: bool = False
    allow_two_hand_zoom: bool = False
    allow_custom_gestures: bool = False

    confidence_threshold: float = 0.72
    debounce_ms: int = 350
    hold_duration_ms: int = 700
    max_gestures_per_minute: int = 60

    require_confirmation_for_sensitive_actions: bool = True
    disable_gestures_while_moving_fast: bool = True
    disable_gestures_in_private_mode: bool = True

    custom_gesture_map: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OverlayLimits:
    """
    Overlay display and safety limits.

    AROverlay, NavigationOverlay, NotificationOverlay, and HologramAgent can
    consume these limits to avoid overwhelming the user.
    """

    max_active_overlays: int = DEFAULT_MAX_ACTIVE_OVERLAYS
    max_notifications: int = DEFAULT_MAX_NOTIFICATIONS
    max_critical_overlays: int = 2
    max_overlay_text_chars: int = 700
    max_overlay_width_px: int = 720
    max_overlay_height_px: int = 480
    max_overlay_distance_meters: float = 12.0
    min_overlay_distance_meters: float = 0.35

    default_render_mode: OverlayRenderMode = OverlayRenderMode.WORLD_LOCKED
    default_priority: OverlayPriority = OverlayPriority.NORMAL
    default_opacity: float = 0.92
    default_scale: float = 1.0

    enable_animation: bool = True
    enable_depth_occlusion: bool = False
    enable_collision_avoidance: bool = True
    enable_safe_zone: bool = True
    enable_auto_hide: bool = True

    auto_hide_seconds: int = 12
    critical_overlay_timeout_seconds: int = 60
    notification_timeout_seconds: int = 8

    suppress_noncritical_while_navigating: bool = True
    suppress_noncritical_in_focus_mode: bool = True
    suppress_noncritical_in_private_mode: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpatialSettings:
    """
    Spatial mapping and world understanding limits.

    SpatialMapper and RealWorldContext can consume these settings.
    """

    mapping_mode: SpatialMappingMode = SpatialMappingMode.LOCAL_ONLY
    enabled: bool = False

    max_anchors: int = DEFAULT_MAX_ANCHORS
    max_spatial_objects: int = DEFAULT_MAX_SPATIAL_OBJECTS
    max_room_size_square_meters: float = 200.0
    max_mapping_duration_seconds: int = 300

    allow_floor_detection: bool = True
    allow_wall_detection: bool = True
    allow_surface_detection: bool = True
    allow_object_anchors: bool = True
    allow_people_anchors: bool = False
    allow_private_zone_detection: bool = True

    persist_anchors: bool = False
    encrypt_local_spatial_cache: bool = True
    clear_map_on_session_end: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecognitionSettings:
    """
    Object/text/context recognition settings.

    ObjectRecognizer and RealWorldContext can consume these values.
    """

    enable_object_recognition: bool = False
    enable_text_recognition: bool = False
    enable_scene_understanding: bool = False
    enable_people_detection: bool = False
    enable_face_recognition: bool = False
    enable_sensitive_content_filter: bool = True

    recognition_confidence_threshold: float = 0.78
    max_recognitions_per_frame: int = 12
    max_recognition_fps: int = 5

    allow_cloud_recognition: bool = False
    redact_text_before_memory: bool = True
    anonymize_people_before_memory: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationSettings:
    """
    Notification overlay settings.

    NotificationOverlay can consume these values.
    """

    enabled: bool = True
    allow_sound: bool = False
    allow_haptics: bool = True
    allow_priority_interruptions: bool = True

    max_visible_notifications: int = DEFAULT_MAX_NOTIFICATIONS
    default_timeout_seconds: int = 8
    critical_timeout_seconds: int = 45

    quiet_mode_enabled: bool = False
    quiet_mode_suppress_low_priority: bool = True
    show_sender_identity: bool = True
    redact_sensitive_notification_text: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NavigationSettings:
    """
    Navigation overlay settings.

    NavigationOverlay can consume these values.
    """

    enabled: bool = True
    allow_location_based_navigation: bool = False
    allow_indoor_navigation: bool = True
    allow_outdoor_navigation: bool = False

    max_waypoints: int = 20
    show_distance_labels: bool = True
    show_direction_arrows: bool = True
    show_safety_warnings: bool = True
    avoid_private_areas: bool = True
    suppress_ads_or_promotional_overlays: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HologramAgentSettings:
    """
    Full Hologram Agent configuration object.

    This object can be serialized for dashboard/API responses and consumed by
    the Hologram Agent runtime.
    """

    config_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    config_version: str = DEFAULT_CONFIG_VERSION
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    device: ARDeviceSettings = field(default_factory=ARDeviceSettings)
    privacy: HologramPrivacyFlags = field(default_factory=HologramPrivacyFlags)
    gestures: GestureSettings = field(default_factory=GestureSettings)
    overlays: OverlayLimits = field(default_factory=OverlayLimits)
    spatial: SpatialSettings = field(default_factory=SpatialSettings)
    recognition: RecognitionSettings = field(default_factory=RecognitionSettings)
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    navigation: NavigationSettings = field(default_factory=NavigationSettings)

    workspace_defaults_enabled: bool = True
    user_overrides_enabled: bool = True
    security_required_for_privacy_changes: bool = True
    security_required_for_device_streams: bool = True
    security_required_for_cloud_processing: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main config class
# ---------------------------------------------------------------------------

class HologramConfig(BaseAgent):
    """
    Configuration manager for the Hologram Agent.

    This class manages AR device settings, privacy flags, gesture settings,
    overlay limits, spatial settings, recognition settings, notification settings,
    and navigation settings.

    It does not execute real AR hardware actions. DeviceBridge and related files
    can consume this config after Security Agent approval.

    Public methods:
        - get_config()
        - get_config_dict()
        - update_config()
        - update_device_settings()
        - update_privacy_flags()
        - update_gesture_settings()
        - update_overlay_limits()
        - update_spatial_settings()
        - update_recognition_settings()
        - update_notification_settings()
        - update_navigation_settings()
        - reset_to_defaults()
        - validate_config()
        - load_from_env()
        - get_registry_metadata()
    """

    def __init__(
        self,
        initial_settings: Optional[HologramAgentSettings] = None,
        *,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        agent_name: str = DEFAULT_AGENT_NAME,
    ) -> None:
        """
        Initialize HologramConfig.

        Args:
            initial_settings:
                Optional initial HologramAgentSettings instance.
            security_approval_callback:
                Optional callback for Security Agent approval.
            event_callback:
                Optional event bus/dashboard callback.
            audit_callback:
                Optional audit log callback.
            agent_name:
                Agent registry name.
        """

        try:
            super().__init__(agent_name=agent_name)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self._settings = copy.deepcopy(initial_settings) if initial_settings else self.load_from_env()
        self._revision = 1
        self._last_validation: Optional[Dict[str, Any]] = None

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def get_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return current configuration as structured result.

        Master Agent, Dashboard/API, and HologramAgent can use this method to
        retrieve safe current settings.
        """

        context = HologramTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        permission = self._check_permission(context, HologramPermissionScope.READ_CONFIG)
        if not permission["success"]:
            return permission

        config_dict = self._safe_config_dict()

        return self._safe_result(
            success=True,
            message="Hologram configuration retrieved successfully.",
            data={
                "config": config_dict,
                "revision": self._revision,
            },
            context=context,
            metadata={"operation": "get_config"},
        )

    def get_config_dict(self) -> Dict[str, Any]:
        """
        Return a plain dict copy of the current config.

        This method is intentionally context-free for internal imports/tests.
        Use get_config() when responding to user/workspace requests.
        """

        return self._safe_config_dict()

    def update_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Update multiple sections of Hologram configuration.

        Allowed top-level update sections:
            - device
            - privacy
            - gestures
            - overlays
            - spatial
            - recognition
            - notifications
            - navigation
            - workspace_defaults_enabled
            - user_overrides_enabled
            - security_required_for_privacy_changes
            - security_required_for_device_streams
            - security_required_for_cloud_processing
            - metadata
        """

        context = HologramTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, HologramPermissionScope.UPDATE_CONFIG)
            if not permission["success"]:
                return permission

            if not isinstance(updates, Mapping):
                return self._error_result(
                    "Config updates must be a mapping/dict.",
                    context=context,
                    error=None,
                    code="invalid_config_updates",
                )

            requested_updates = copy.deepcopy(dict(updates))
            security_needed = (
                bool(require_security_approval)
                if require_security_approval is not None
                else self._requires_security_check(requested_updates)
            )

            if security_needed:
                approval = self._request_security_approval(
                    context=context,
                    action="update_hologram_config",
                    updates=requested_updates,
                )
                if not approval.get("approved"):
                    return self._safe_result(
                        success=False,
                        message="Hologram config update blocked by Security Agent approval gate.",
                        data={"approval": approval},
                        error={
                            "code": "security_approval_denied",
                            "reason": approval.get("reason", "Not approved."),
                        },
                        context=context,
                        metadata={"operation": "update_config"},
                    )

            old_config = self._safe_config_dict()
            next_settings = self._apply_updates_to_copy(self._settings, requested_updates)
            validation_result = self.validate_config_object(next_settings)

            if not validation_result["success"]:
                return self._safe_result(
                    success=False,
                    message="Hologram config update failed validation.",
                    data=validation_result.get("data", {}),
                    error=validation_result.get("error"),
                    context=context,
                    metadata={"operation": "update_config"},
                )

            next_settings.updated_at = utc_now_iso()
            self._settings = next_settings
            self._revision += 1

            new_config = self._safe_config_dict()
            diff = self._config_diff(old_config, new_config)

            verification_payload = self._prepare_verification_payload(
                context=context,
                action="update_config",
                before=old_config,
                after=new_config,
                diff=diff,
            )

            memory_payload = self._prepare_memory_payload(
                context=context,
                action="update_config",
                diff=diff,
            )

            self._emit_agent_event(
                event_type="hologram.config.updated",
                context=context,
                data={
                    "revision": self._revision,
                    "changed_keys": list(diff.keys()),
                },
            )

            self._log_audit_event(
                event_type="hologram_config_updated",
                context=context,
                data={
                    "revision": self._revision,
                    "changed_keys": list(diff.keys()),
                    "sensitive_change": self._contains_sensitive_update(requested_updates),
                },
            )

            return self._safe_result(
                success=True,
                message="Hologram configuration updated successfully.",
                data={
                    "config": new_config,
                    "revision": self._revision,
                    "diff": diff,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                context=context,
                metadata={"operation": "update_config"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to update Hologram configuration.",
                error=exc,
                context=context,
                code="hologram_config_update_failed",
            )

    def update_device_settings(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update AR device settings."""

        return self._update_section(
            section="device",
            scope=HologramPermissionScope.UPDATE_DEVICE,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_privacy_flags(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update privacy flags."""

        return self._update_section(
            section="privacy",
            scope=HologramPermissionScope.UPDATE_PRIVACY,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_gesture_settings(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update gesture settings."""

        return self._update_section(
            section="gestures",
            scope=HologramPermissionScope.UPDATE_GESTURES,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_overlay_limits(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update overlay limits."""

        return self._update_section(
            section="overlays",
            scope=HologramPermissionScope.UPDATE_OVERLAYS,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_spatial_settings(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update spatial mapping settings."""

        return self._update_section(
            section="spatial",
            scope=HologramPermissionScope.UPDATE_CONFIG,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_recognition_settings(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update object/text/context recognition settings."""

        return self._update_section(
            section="recognition",
            scope=HologramPermissionScope.UPDATE_CONFIG,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_notification_settings(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update notification overlay settings."""

        return self._update_section(
            section="notifications",
            scope=HologramPermissionScope.UPDATE_OVERLAYS,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def update_navigation_settings(
        self,
        *,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update navigation overlay settings."""

        return self._update_section(
            section="navigation",
            scope=HologramPermissionScope.UPDATE_OVERLAYS,
            user_id=user_id,
            workspace_id=workspace_id,
            updates=updates,
            role=role,
            task_id=task_id,
            metadata=metadata,
        )

    def reset_to_defaults(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Reset config to privacy-first defaults.
        """

        context = HologramTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, HologramPermissionScope.RESET_CONFIG)
            if not permission["success"]:
                return permission

            if require_security_approval:
                approval = self._request_security_approval(
                    context=context,
                    action="reset_hologram_config",
                    updates={"reset_to_defaults": True},
                )
                if not approval.get("approved"):
                    return self._safe_result(
                        success=False,
                        message="Hologram config reset blocked by Security Agent approval gate.",
                        data={"approval": approval},
                        error={
                            "code": "security_approval_denied",
                            "reason": approval.get("reason", "Not approved."),
                        },
                        context=context,
                        metadata={"operation": "reset_to_defaults"},
                    )

            old_config = self._safe_config_dict()
            self._settings = HologramAgentSettings()
            self._revision += 1
            new_config = self._safe_config_dict()
            diff = self._config_diff(old_config, new_config)

            verification_payload = self._prepare_verification_payload(
                context=context,
                action="reset_to_defaults",
                before=old_config,
                after=new_config,
                diff=diff,
            )

            memory_payload = self._prepare_memory_payload(
                context=context,
                action="reset_to_defaults",
                diff=diff,
            )

            self._emit_agent_event(
                event_type="hologram.config.reset",
                context=context,
                data={"revision": self._revision},
            )

            self._log_audit_event(
                event_type="hologram_config_reset",
                context=context,
                data={"revision": self._revision},
            )

            return self._safe_result(
                success=True,
                message="Hologram configuration reset to privacy-first defaults.",
                data={
                    "config": new_config,
                    "revision": self._revision,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                context=context,
                metadata={"operation": "reset_to_defaults"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to reset Hologram configuration.",
                error=exc,
                context=context,
                code="hologram_config_reset_failed",
            )

    def validate_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate current Hologram configuration.
        """

        context = HologramTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        permission = self._check_permission(context, HologramPermissionScope.READ_CONFIG)
        if not permission["success"]:
            return permission

        result = self.validate_config_object(self._settings)
        self._last_validation = result

        return self._safe_result(
            success=result["success"],
            message=result["message"],
            data=result.get("data", {}),
            error=result.get("error"),
            context=context,
            metadata={"operation": "validate_config"},
        )

    def validate_config_object(self, settings: HologramAgentSettings) -> Dict[str, Any]:
        """
        Validate a HologramAgentSettings object without requiring user context.

        Useful for tests, loaders, and config preview before saving updates.
        """

        issues: List[str] = []
        warnings: List[str] = []

        try:
            if not isinstance(settings, HologramAgentSettings):
                return {
                    "success": False,
                    "message": "Invalid Hologram configuration object.",
                    "data": {},
                    "error": {
                        "code": "invalid_config_object",
                        "expected": "HologramAgentSettings",
                        "received": type(settings).__name__,
                    },
                    "metadata": result_metadata(),
                }

            device = settings.device
            privacy = settings.privacy
            gestures = settings.gestures
            overlays = settings.overlays
            spatial = settings.spatial
            recognition = settings.recognition
            notifications = settings.notifications
            navigation = settings.navigation

            if device.refresh_rate_hz < MIN_REFRESH_RATE_HZ or device.refresh_rate_hz > MAX_REFRESH_RATE_HZ:
                issues.append(f"device.refresh_rate_hz must be between {MIN_REFRESH_RATE_HZ} and {MAX_REFRESH_RATE_HZ}.")

            if device.field_of_view_degrees < MIN_FOV_DEGREES or device.field_of_view_degrees > MAX_FOV_DEGREES:
                issues.append(f"device.field_of_view_degrees must be between {MIN_FOV_DEGREES} and {MAX_FOV_DEGREES}.")

            if device.brightness < MIN_BRIGHTNESS or device.brightness > MAX_BRIGHTNESS:
                issues.append(f"device.brightness must be between {MIN_BRIGHTNESS} and {MAX_BRIGHTNESS}.")

            if device.session_timeout_seconds < 60:
                issues.append("device.session_timeout_seconds must be at least 60 seconds.")

            if overlays.max_active_overlays < 1:
                issues.append("overlays.max_active_overlays must be at least 1.")

            if overlays.max_notifications < 0:
                issues.append("overlays.max_notifications cannot be negative.")

            if overlays.default_opacity < MIN_OVERLAY_OPACITY or overlays.default_opacity > MAX_OVERLAY_OPACITY:
                issues.append(f"overlays.default_opacity must be between {MIN_OVERLAY_OPACITY} and {MAX_OVERLAY_OPACITY}.")

            if overlays.default_scale < MIN_OVERLAY_SCALE or overlays.default_scale > MAX_OVERLAY_SCALE:
                issues.append(f"overlays.default_scale must be between {MIN_OVERLAY_SCALE} and {MAX_OVERLAY_SCALE}.")

            if overlays.min_overlay_distance_meters <= 0:
                issues.append("overlays.min_overlay_distance_meters must be greater than 0.")

            if overlays.max_overlay_distance_meters <= overlays.min_overlay_distance_meters:
                issues.append("overlays.max_overlay_distance_meters must be greater than min_overlay_distance_meters.")

            if gestures.confidence_threshold < MIN_GESTURE_CONFIDENCE or gestures.confidence_threshold > MAX_GESTURE_CONFIDENCE:
                issues.append(
                    f"gestures.confidence_threshold must be between "
                    f"{MIN_GESTURE_CONFIDENCE} and {MAX_GESTURE_CONFIDENCE}."
                )

            if gestures.debounce_ms < 0:
                issues.append("gestures.debounce_ms cannot be negative.")

            if gestures.max_gestures_per_minute < 1:
                issues.append("gestures.max_gestures_per_minute must be at least 1.")

            if spatial.max_anchors < 0:
                issues.append("spatial.max_anchors cannot be negative.")

            if spatial.max_spatial_objects < 0:
                issues.append("spatial.max_spatial_objects cannot be negative.")

            if recognition.recognition_confidence_threshold < MIN_GESTURE_CONFIDENCE or recognition.recognition_confidence_threshold > MAX_GESTURE_CONFIDENCE:
                issues.append("recognition.recognition_confidence_threshold must be between 0.1 and 1.0.")

            if recognition.max_recognitions_per_frame < 0:
                issues.append("recognition.max_recognitions_per_frame cannot be negative.")

            if recognition.max_recognition_fps < 0:
                issues.append("recognition.max_recognition_fps cannot be negative.")

            if notifications.max_visible_notifications < 0:
                issues.append("notifications.max_visible_notifications cannot be negative.")

            if navigation.max_waypoints < 0:
                issues.append("navigation.max_waypoints cannot be negative.")

            privacy_warnings = self._validate_privacy_consistency(settings)
            warnings.extend(privacy_warnings)

            if issues:
                return {
                    "success": False,
                    "message": "Hologram configuration has validation errors.",
                    "data": {
                        "issues": issues,
                        "warnings": warnings,
                    },
                    "error": {
                        "code": "hologram_config_validation_failed",
                        "issues": issues,
                    },
                    "metadata": result_metadata(),
                }

            return {
                "success": True,
                "message": "Hologram configuration is valid.",
                "data": {
                    "issues": [],
                    "warnings": warnings,
                    "privacy_mode": privacy.privacy_mode.value,
                    "device_type": device.device_type.value,
                    "runtime_mode": device.runtime_mode.value,
                },
                "error": None,
                "metadata": result_metadata(),
            }

        except Exception as exc:
            return {
                "success": False,
                "message": "Failed to validate Hologram configuration.",
                "data": {},
                "error": {
                    "code": "hologram_config_validation_exception",
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                },
                "metadata": result_metadata(),
            }

    @classmethod
    def load_from_env(cls) -> HologramAgentSettings:
        """
        Load safe config from environment variables.

        Supported examples:
            WILLIAM_HOLOGRAM_RUNTIME_MODE=development
            WILLIAM_HOLOGRAM_DEVICE_TYPE=desktop_simulator
            WILLIAM_HOLOGRAM_ENABLE_CAMERA=false
            WILLIAM_HOLOGRAM_ENABLE_MICROPHONE=false
            WILLIAM_HOLOGRAM_PRIVACY_MODE=strict
            WILLIAM_HOLOGRAM_MAX_ACTIVE_OVERLAYS=8
            WILLIAM_HOLOGRAM_MAX_NOTIFICATIONS=5
            WILLIAM_HOLOGRAM_GESTURE_MODE=basic
            WILLIAM_HOLOGRAM_ENABLE_SPATIAL_MAPPING=false
            WILLIAM_HOLOGRAM_ENABLE_OBJECT_RECOGNITION=false
            WILLIAM_HOLOGRAM_ENABLE_WEBXR=false
        """

        device_type = cls._enum_from_env(
            "WILLIAM_HOLOGRAM_DEVICE_TYPE",
            HologramDeviceType,
            HologramDeviceType.DESKTOP_SIMULATOR,
        )
        runtime_mode = cls._enum_from_env(
            "WILLIAM_HOLOGRAM_RUNTIME_MODE",
            HologramRuntimeMode,
            HologramRuntimeMode.DEVELOPMENT,
        )
        privacy_mode = cls._enum_from_env(
            "WILLIAM_HOLOGRAM_PRIVACY_MODE",
            PrivacyMode,
            PrivacyMode.STRICT,
        )
        gesture_mode = cls._enum_from_env(
            "WILLIAM_HOLOGRAM_GESTURE_MODE",
            GestureMode,
            GestureMode.BASIC,
        )

        enable_camera = parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_CAMERA"), False)
        enable_microphone = parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_MICROPHONE"), False)
        enable_spatial_mapping = parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_SPATIAL_MAPPING"), False)
        enable_object_recognition = parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_OBJECT_RECOGNITION"), False)
        enable_webxr = parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_WEBXR"), False)
        allow_cloud_processing = parse_bool(os.getenv("WILLIAM_HOLOGRAM_ALLOW_CLOUD_PROCESSING"), False)

        settings = HologramAgentSettings(
            device=ARDeviceSettings(
                device_type=device_type,
                device_name=os.getenv("WILLIAM_HOLOGRAM_DEVICE_NAME", "William Hologram Simulator"),
                device_id=os.getenv("WILLIAM_HOLOGRAM_DEVICE_ID") or None,
                runtime_mode=runtime_mode,
                enable_device_bridge=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_DEVICE_BRIDGE"), False),
                enable_webxr=enable_webxr,
                enable_camera_stream=enable_camera,
                enable_microphone_stream=enable_microphone,
                enable_depth_sensor=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_DEPTH_SENSOR"), False),
                enable_eye_tracking=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_EYE_TRACKING"), False),
                enable_hand_tracking=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_HAND_TRACKING"), True),
                enable_head_tracking=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_HEAD_TRACKING"), True),
                enable_location_services=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_LOCATION"), False),
                refresh_rate_hz=parse_int(os.getenv("WILLIAM_HOLOGRAM_REFRESH_RATE_HZ"), 60),
                field_of_view_degrees=parse_int(os.getenv("WILLIAM_HOLOGRAM_FOV_DEGREES"), 70),
                brightness=parse_float(os.getenv("WILLIAM_HOLOGRAM_BRIGHTNESS"), 0.75),
                low_power_mode=parse_bool(os.getenv("WILLIAM_HOLOGRAM_LOW_POWER_MODE"), True),
            ),
            privacy=HologramPrivacyFlags(
                privacy_mode=privacy_mode,
                allow_camera_access=enable_camera,
                allow_microphone_access=enable_microphone,
                allow_cloud_processing=allow_cloud_processing,
                allow_location_access=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ALLOW_LOCATION"), False),
                allow_object_recognition=enable_object_recognition,
                allow_text_recognition=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ALLOW_TEXT_RECOGNITION"), False),
                allow_spatial_mapping=enable_spatial_mapping,
                allow_persistent_spatial_map=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ALLOW_PERSISTENT_SPATIAL_MAP"), False),
                local_processing_preferred=parse_bool(os.getenv("WILLIAM_HOLOGRAM_LOCAL_PROCESSING_PREFERRED"), True),
            ),
            gestures=GestureSettings(
                mode=gesture_mode,
                enabled=parse_bool(os.getenv("WILLIAM_HOLOGRAM_GESTURES_ENABLED"), True),
                confidence_threshold=parse_float(os.getenv("WILLIAM_HOLOGRAM_GESTURE_CONFIDENCE"), 0.72),
            ),
            overlays=OverlayLimits(
                max_active_overlays=parse_int(os.getenv("WILLIAM_HOLOGRAM_MAX_ACTIVE_OVERLAYS"), DEFAULT_MAX_ACTIVE_OVERLAYS),
                max_notifications=parse_int(os.getenv("WILLIAM_HOLOGRAM_MAX_NOTIFICATIONS"), DEFAULT_MAX_NOTIFICATIONS),
                default_opacity=parse_float(os.getenv("WILLIAM_HOLOGRAM_OVERLAY_OPACITY"), 0.92),
                default_scale=parse_float(os.getenv("WILLIAM_HOLOGRAM_OVERLAY_SCALE"), 1.0),
            ),
            spatial=SpatialSettings(
                enabled=enable_spatial_mapping,
                mapping_mode=SpatialMappingMode.LOCAL_ONLY if enable_spatial_mapping else SpatialMappingMode.DISABLED,
            ),
            recognition=RecognitionSettings(
                enable_object_recognition=enable_object_recognition,
                enable_text_recognition=parse_bool(os.getenv("WILLIAM_HOLOGRAM_ENABLE_TEXT_RECOGNITION"), False),
                allow_cloud_recognition=allow_cloud_processing,
            ),
        )

        cls._sanitize_settings_in_place(settings)
        return settings

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return registry metadata for Agent Loader / Agent Registry / Master Agent.
        """

        return {
            "agent_name": DEFAULT_AGENT_NAME,
            "class_name": self.__class__.__name__,
            "module": "agents.super_agents.hologram_agent.config",
            "file": "config.py",
            "agent_module": "Hologram Agent",
            "purpose": "AR device settings, privacy flags, gesture settings, overlay limits.",
            "config_version": DEFAULT_CONFIG_VERSION,
            "safe_to_import": True,
            "supports_user_workspace_isolation": True,
            "supports_security_approval": True,
            "supports_memory_payload": True,
            "supports_verification_payload": True,
            "public_methods": [
                "get_config",
                "get_config_dict",
                "update_config",
                "update_device_settings",
                "update_privacy_flags",
                "update_gesture_settings",
                "update_overlay_limits",
                "update_spatial_settings",
                "update_recognition_settings",
                "update_notification_settings",
                "update_navigation_settings",
                "reset_to_defaults",
                "validate_config",
                "load_from_env",
                "get_registry_metadata",
            ],
            "permissions": [scope.value for scope in HologramPermissionScope],
            "privacy_default": PrivacyMode.STRICT.value,
            "runtime_mode": self._settings.device.runtime_mode.value,
            "device_type": self._settings.device.device_type.value,
            "revision": self._revision,
        }

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: HologramTaskContext) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Required by William/Jarvis architecture.
        """

        missing: List[str] = []

        if not getattr(context, "user_id", None):
            missing.append("user_id")

        if not getattr(context, "workspace_id", None):
            missing.append("workspace_id")

        if missing:
            return self._safe_result(
                success=False,
                message="Missing required SaaS execution context.",
                data={"missing": missing},
                error={
                    "code": "missing_task_context",
                    "missing": missing,
                },
                context=context,
                metadata={"operation": "validate_task_context"},
            )

        return self._safe_result(
            success=True,
            message="Task context is valid.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
            },
            context=context,
            metadata={"operation": "validate_task_context"},
        )

    def _requires_security_check(self, updates: Mapping[str, Any]) -> bool:
        """
        Determine whether updates require Security Agent approval.

        Required by William/Jarvis architecture.
        """

        return self._contains_sensitive_update(updates)

    def _request_security_approval(
        self,
        *,
        context: HologramTaskContext,
        action: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Required by William/Jarvis architecture.

        If no callback is connected yet, a conservative local fallback is used.
        Sensitive enabling changes are denied in production unless an external
        callback approves them.
        """

        approval_payload = {
            "action": action,
            "agent": DEFAULT_AGENT_NAME,
            "permission_scope": self._permission_scope_for_updates(updates).value,
            "risk_level": self._risk_level_for_updates(updates),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "updates": self._safe_metadata(dict(updates)),
            "timestamp": utc_now_iso(),
        }

        try:
            if self.security_approval_callback:
                response = self.security_approval_callback(approval_payload)
                if not isinstance(response, dict):
                    return {
                        "approved": False,
                        "reason": "Security callback returned invalid response.",
                        "data": {"callback_response": str(response)},
                    }

                approved = bool(response.get("approved") or response.get("success"))
                return {
                    "approved": approved,
                    "reason": response.get("reason") or response.get("message") or "Security callback processed request.",
                    "data": response,
                }

            return self._local_security_fallback(context=context, action=action, updates=updates)

        except Exception as exc:
            return {
                "approved": False,
                "reason": "Security approval failed with exception.",
                "error": {
                    "code": "security_approval_exception",
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                },
            }

    def _prepare_verification_payload(
        self,
        *,
        context: HologramTaskContext,
        action: str,
        before: Dict[str, Any],
        after: Dict[str, Any],
        diff: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Required by William/Jarvis architecture.
        """

        return {
            "verification_type": "hologram_config_change",
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "revision": self._revision,
            "changed_keys": list(diff.keys()),
            "sensitive_change": self._contains_sensitive_update(diff),
            "before_fingerprint": self._config_fingerprint(before),
            "after_fingerprint": self._config_fingerprint(after),
            "timestamp": utc_now_iso(),
            "metadata": {
                "config_version": DEFAULT_CONFIG_VERSION,
                "source": context.source,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: HologramTaskContext,
        action: str,
        diff: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        Required by William/Jarvis architecture.

        Sensitive content is not stored. This stores only a high-level summary of
        which settings changed.
        """

        changed_keys = list(diff.keys())

        return {
            "memory_type": "hologram_config_activity",
            "agent": DEFAULT_AGENT_NAME,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "summary": (
                f"Hologram configuration action '{action}' changed "
                f"{len(changed_keys)} top-level setting group(s)."
            ),
            "safe_context": {
                "action": action,
                "changed_keys": changed_keys,
                "revision": self._revision,
                "sensitive_change": self._contains_sensitive_update(diff),
            },
            "timestamp": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        context: HologramTaskContext,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/event-bus compatible agent event.

        Required by William/Jarvis architecture.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "source": context.source,
            "data": data or {},
            "timestamp": utc_now_iso(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
            else:
                self.logger.debug("Hologram config event emitted: %s", safe_json_dumps(event))
        except Exception as exc:
            self.logger.warning("Failed to emit Hologram config event: %s", exc)

    def _log_audit_event(
        self,
        *,
        event_type: str,
        context: HologramTaskContext,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Required by William/Jarvis architecture.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "source": context.source,
            "ip_address": context.ip_address,
            "user_agent": context.user_agent,
            "data": self._safe_metadata(data or {}),
            "timestamp": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit_event)
            else:
                self.logger.info("Hologram config audit event: %s", safe_json_dumps(audit_event))
        except Exception as exc:
            self.logger.warning("Failed to log Hologram config audit event: %s", exc)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        context: Optional[HologramTaskContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return structured dict/JSON-style result.

        Required by William/Jarvis architecture.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": result_metadata(context, **(metadata or {})),
        }

    def _error_result(
        self,
        message: str,
        *,
        error: Optional[Any],
        context: Optional[HologramTaskContext] = None,
        code: str = "hologram_config_error",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return structured error result.

        Required by William/Jarvis architecture.
        """

        if isinstance(error, Exception):
            error_payload: Any = {
                "code": code,
                "type": error.__class__.__name__,
                "message": str(error),
            }
        elif isinstance(error, dict):
            error_payload = {"code": code, **error}
        elif error is None:
            error_payload = {
                "code": code,
                "message": message,
            }
        else:
            error_payload = {
                "code": code,
                "message": str(error),
            }

        self.logger.error("%s | error=%s", message, safe_json_dumps(error_payload))

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            context=context,
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Internal update helpers
    # -----------------------------------------------------------------------

    def _update_section(
        self,
        *,
        section: str,
        scope: HologramPermissionScope,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        role: Optional[str],
        task_id: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Shared update helper for a single config section.
        """

        context = HologramTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, scope)
            if not permission["success"]:
                return permission

            if not isinstance(updates, Mapping):
                return self._error_result(
                    f"Hologram {section} updates must be a mapping/dict.",
                    context=context,
                    error=None,
                    code="invalid_section_updates",
                )

            return self.update_config(
                user_id=user_id,
                workspace_id=workspace_id,
                updates={section: dict(updates)},
                role=role,
                task_id=task_id,
                metadata=metadata,
            )

        except Exception as exc:
            return self._error_result(
                f"Failed to update Hologram {section} settings.",
                error=exc,
                context=context,
                code=f"hologram_{section}_update_failed",
            )

    def _apply_updates_to_copy(
        self,
        settings: HologramAgentSettings,
        updates: Mapping[str, Any],
    ) -> HologramAgentSettings:
        """
        Apply dict updates to a copied HologramAgentSettings object.
        """

        next_settings = copy.deepcopy(settings)

        allowed_top_level = {
            "device",
            "privacy",
            "gestures",
            "overlays",
            "spatial",
            "recognition",
            "notifications",
            "navigation",
            "workspace_defaults_enabled",
            "user_overrides_enabled",
            "security_required_for_privacy_changes",
            "security_required_for_device_streams",
            "security_required_for_cloud_processing",
            "metadata",
        }

        for key, value in updates.items():
            if key not in allowed_top_level:
                raise ValueError(f"Unsupported Hologram config section: {key}")

            if key in {
                "workspace_defaults_enabled",
                "user_overrides_enabled",
                "security_required_for_privacy_changes",
                "security_required_for_device_streams",
                "security_required_for_cloud_processing",
            }:
                setattr(next_settings, key, bool(value))
                continue

            if key == "metadata":
                if not isinstance(value, Mapping):
                    raise ValueError("metadata must be a dict.")
                next_settings.metadata = deep_merge_dict(next_settings.metadata, dict(value))
                continue

            section_obj = getattr(next_settings, key)
            if not isinstance(value, Mapping):
                raise ValueError(f"{key} updates must be a dict.")

            self._apply_dataclass_section_updates(section_obj, dict(value), section_name=key)

        self._sanitize_settings_in_place(next_settings)
        return next_settings

    def _apply_dataclass_section_updates(
        self,
        section_obj: Any,
        updates: Dict[str, Any],
        *,
        section_name: str,
    ) -> None:
        """
        Apply updates to a dataclass section safely.
        """

        if not is_dataclass(section_obj):
            raise ValueError(f"{section_name} is not a dataclass section.")

        valid_fields = {field_obj.name: field_obj for field_obj in fields(section_obj)}

        for key, value in updates.items():
            if key not in valid_fields:
                raise ValueError(f"Unsupported setting '{section_name}.{key}'.")

            current_value = getattr(section_obj, key)

            if isinstance(current_value, Enum):
                enum_cls = current_value.__class__
                setattr(section_obj, key, self._coerce_enum(value, enum_cls, current_value))
            elif isinstance(current_value, bool):
                setattr(section_obj, key, bool(value))
            elif isinstance(current_value, int) and not isinstance(current_value, bool):
                setattr(section_obj, key, int(value))
            elif isinstance(current_value, float):
                setattr(section_obj, key, float(value))
            elif isinstance(current_value, dict):
                if not isinstance(value, Mapping):
                    raise ValueError(f"{section_name}.{key} must be a dict.")
                setattr(section_obj, key, deep_merge_dict(current_value, dict(value)))
            elif isinstance(current_value, tuple):
                if isinstance(value, (list, tuple)):
                    setattr(section_obj, key, tuple(value))
                else:
                    raise ValueError(f"{section_name}.{key} must be a list or tuple.")
            else:
                setattr(section_obj, key, value)

    # -----------------------------------------------------------------------
    # Validation and security helpers
    # -----------------------------------------------------------------------

    def _check_permission(
        self,
        context: HologramTaskContext,
        scope: HologramPermissionScope,
    ) -> Dict[str, Any]:
        """
        Local permission fallback.

        The production Security Agent/user permission service can replace this
        through callbacks or BaseAgent methods later.
        """

        if not context.user_id or not context.workspace_id:
            return self._safe_result(
                success=False,
                message="Permission denied because user/workspace context is missing.",
                data={"scope": scope.value},
                error={
                    "code": "permission_context_missing",
                    "scope": scope.value,
                },
                context=context,
                metadata={"operation": "check_permission"},
            )

        return self._safe_result(
            success=True,
            message="Permission check passed.",
            data={
                "scope": scope.value,
                "allowed": True,
            },
            context=context,
            metadata={"operation": "check_permission"},
        )

    def _local_security_fallback(
        self,
        *,
        context: HologramTaskContext,
        action: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Conservative local security fallback.

        Without a real Security Agent callback:
            - Strict/privacy-preserving changes are allowed.
            - Enabling camera/mic/cloud/biometric/persistent mapping in production
              is denied.
            - Non-sensitive display limit changes are allowed.
        """

        if not context.user_id or not context.workspace_id:
            return {
                "approved": False,
                "reason": "Missing SaaS user/workspace context.",
            }

        sensitive = self._contains_sensitive_update(updates)
        production = self._settings.device.runtime_mode == HologramRuntimeMode.PRODUCTION

        if sensitive and production:
            return {
                "approved": False,
                "reason": "Sensitive Hologram config changes in production require Security Agent approval callback.",
            }

        dangerous_enables = self._contains_sensitive_enable(updates)
        if dangerous_enables:
            return {
                "approved": False,
                "reason": "Enabling camera, microphone, biometrics, cloud processing, location, or persistent spatial memory requires Security Agent approval callback.",
            }

        return {
            "approved": True,
            "reason": "Local fallback approved non-sensitive or privacy-preserving Hologram config change.",
        }

    def _contains_sensitive_update(self, updates: Mapping[str, Any]) -> bool:
        """
        Detect whether updates touch sensitive AR/privacy settings.
        """

        sensitive_top_level = {
            "privacy",
            "recognition",
            "spatial",
        }

        sensitive_device_keys = {
            "enable_camera_stream",
            "enable_microphone_stream",
            "enable_depth_sensor",
            "enable_eye_tracking",
            "enable_location_services",
            "enable_device_bridge",
        }

        sensitive_privacy_keys = {
            "allow_camera_access",
            "allow_microphone_access",
            "allow_screen_capture",
            "allow_recording",
            "allow_cloud_processing",
            "allow_location_access",
            "allow_face_recognition",
            "allow_biometric_tracking",
            "allow_eye_tracking",
            "allow_object_recognition",
            "allow_people_detection",
            "allow_text_recognition",
            "allow_spatial_mapping",
            "allow_persistent_spatial_map",
            "allow_cross_session_memory",
            "data_retention_seconds",
            "spatial_map_retention_seconds",
        }

        for top_key, value in updates.items():
            if top_key in sensitive_top_level:
                return True

            if top_key == "device" and isinstance(value, Mapping):
                if any(key in sensitive_device_keys for key in value.keys()):
                    return True

            if top_key == "privacy" and isinstance(value, Mapping):
                if any(key in sensitive_privacy_keys for key in value.keys()):
                    return True

            if top_key in {
                "security_required_for_privacy_changes",
                "security_required_for_device_streams",
                "security_required_for_cloud_processing",
            }:
                return True

        return False

    def _contains_sensitive_enable(self, updates: Mapping[str, Any]) -> bool:
        """
        Detect whether updates enable sensitive capabilities.
        """

        sensitive_true_paths = {
            ("device", "enable_camera_stream"),
            ("device", "enable_microphone_stream"),
            ("device", "enable_depth_sensor"),
            ("device", "enable_eye_tracking"),
            ("device", "enable_location_services"),
            ("device", "enable_device_bridge"),
            ("privacy", "allow_camera_access"),
            ("privacy", "allow_microphone_access"),
            ("privacy", "allow_screen_capture"),
            ("privacy", "allow_recording"),
            ("privacy", "allow_cloud_processing"),
            ("privacy", "allow_location_access"),
            ("privacy", "allow_face_recognition"),
            ("privacy", "allow_biometric_tracking"),
            ("privacy", "allow_eye_tracking"),
            ("privacy", "allow_object_recognition"),
            ("privacy", "allow_people_detection"),
            ("privacy", "allow_text_recognition"),
            ("privacy", "allow_spatial_mapping"),
            ("privacy", "allow_persistent_spatial_map"),
            ("privacy", "allow_cross_session_memory"),
            ("recognition", "enable_object_recognition"),
            ("recognition", "enable_text_recognition"),
            ("recognition", "enable_scene_understanding"),
            ("recognition", "enable_people_detection"),
            ("recognition", "enable_face_recognition"),
            ("recognition", "allow_cloud_recognition"),
            ("spatial", "enabled"),
            ("spatial", "persist_anchors"),
        }

        for section, key in sensitive_true_paths:
            section_updates = updates.get(section)
            if isinstance(section_updates, Mapping) and bool(section_updates.get(key)) is True:
                return True

        return False

    def _permission_scope_for_updates(self, updates: Mapping[str, Any]) -> HologramPermissionScope:
        """Resolve best permission scope for update payload."""

        if "privacy" in updates:
            return HologramPermissionScope.UPDATE_PRIVACY
        if "device" in updates:
            return HologramPermissionScope.UPDATE_DEVICE
        if "gestures" in updates:
            return HologramPermissionScope.UPDATE_GESTURES
        if "overlays" in updates or "notifications" in updates or "navigation" in updates:
            return HologramPermissionScope.UPDATE_OVERLAYS
        return HologramPermissionScope.UPDATE_CONFIG

    def _risk_level_for_updates(self, updates: Mapping[str, Any]) -> str:
        """Calculate simple risk level for Security Agent."""

        if self._contains_sensitive_enable(updates):
            return "high"
        if self._contains_sensitive_update(updates):
            return "medium"
        return "low"

    def _validate_privacy_consistency(self, settings: HologramAgentSettings) -> List[str]:
        """
        Return warnings for privacy consistency conflicts.
        """

        warnings: List[str] = []
        device = settings.device
        privacy = settings.privacy
        spatial = settings.spatial
        recognition = settings.recognition

        if device.enable_camera_stream and not privacy.allow_camera_access:
            warnings.append("device.enable_camera_stream is true, but privacy.allow_camera_access is false.")

        if device.enable_microphone_stream and not privacy.allow_microphone_access:
            warnings.append("device.enable_microphone_stream is true, but privacy.allow_microphone_access is false.")

        if device.enable_location_services and not privacy.allow_location_access:
            warnings.append("device.enable_location_services is true, but privacy.allow_location_access is false.")

        if recognition.enable_object_recognition and not privacy.allow_object_recognition:
            warnings.append("recognition.enable_object_recognition is true, but privacy.allow_object_recognition is false.")

        if recognition.enable_text_recognition and not privacy.allow_text_recognition:
            warnings.append("recognition.enable_text_recognition is true, but privacy.allow_text_recognition is false.")

        if recognition.enable_face_recognition and not privacy.allow_face_recognition:
            warnings.append("recognition.enable_face_recognition is true, but privacy.allow_face_recognition is false.")

        if spatial.enabled and not privacy.allow_spatial_mapping:
            warnings.append("spatial.enabled is true, but privacy.allow_spatial_mapping is false.")

        if spatial.persist_anchors and not privacy.allow_persistent_spatial_map:
            warnings.append("spatial.persist_anchors is true, but privacy.allow_persistent_spatial_map is false.")

        if privacy.privacy_mode == PrivacyMode.STRICT:
            strict_sensitive_flags = [
                privacy.allow_cloud_processing,
                privacy.allow_recording,
                privacy.allow_face_recognition,
                privacy.allow_biometric_tracking,
                privacy.allow_cross_session_memory,
            ]
            if any(strict_sensitive_flags):
                warnings.append("Privacy mode is strict, but one or more high-risk privacy flags are enabled.")

        return warnings

    # -----------------------------------------------------------------------
    # Config serialization/sanitization
    # -----------------------------------------------------------------------

    def _safe_config_dict(self) -> Dict[str, Any]:
        """Return safe current config dict."""

        config = dataclass_to_dict(self._settings)
        return self._safe_metadata(config)

    @classmethod
    def _sanitize_settings_in_place(cls, settings: HologramAgentSettings) -> None:
        """
        Clamp numeric values and normalize dependent privacy-safe settings.
        """

        settings.device.refresh_rate_hz = int(clamp(settings.device.refresh_rate_hz, MIN_REFRESH_RATE_HZ, MAX_REFRESH_RATE_HZ))
        settings.device.field_of_view_degrees = int(clamp(settings.device.field_of_view_degrees, MIN_FOV_DEGREES, MAX_FOV_DEGREES))
        settings.device.brightness = float(clamp(settings.device.brightness, MIN_BRIGHTNESS, MAX_BRIGHTNESS))
        settings.device.session_timeout_seconds = max(60, int(settings.device.session_timeout_seconds))

        settings.gestures.confidence_threshold = float(
            clamp(settings.gestures.confidence_threshold, MIN_GESTURE_CONFIDENCE, MAX_GESTURE_CONFIDENCE)
        )
        settings.gestures.debounce_ms = max(0, int(settings.gestures.debounce_ms))
        settings.gestures.hold_duration_ms = max(0, int(settings.gestures.hold_duration_ms))
        settings.gestures.max_gestures_per_minute = max(1, int(settings.gestures.max_gestures_per_minute))

        settings.overlays.max_active_overlays = max(1, int(settings.overlays.max_active_overlays))
        settings.overlays.max_notifications = max(0, int(settings.overlays.max_notifications))
        settings.overlays.max_critical_overlays = max(0, int(settings.overlays.max_critical_overlays))
        settings.overlays.max_overlay_text_chars = max(1, int(settings.overlays.max_overlay_text_chars))
        settings.overlays.default_opacity = float(clamp(settings.overlays.default_opacity, MIN_OVERLAY_OPACITY, MAX_OVERLAY_OPACITY))
        settings.overlays.default_scale = float(clamp(settings.overlays.default_scale, MIN_OVERLAY_SCALE, MAX_OVERLAY_SCALE))
        settings.overlays.min_overlay_distance_meters = max(0.05, float(settings.overlays.min_overlay_distance_meters))
        settings.overlays.max_overlay_distance_meters = max(
            settings.overlays.min_overlay_distance_meters + 0.1,
            float(settings.overlays.max_overlay_distance_meters),
        )

        settings.spatial.max_anchors = max(0, int(settings.spatial.max_anchors))
        settings.spatial.max_spatial_objects = max(0, int(settings.spatial.max_spatial_objects))
        settings.spatial.max_room_size_square_meters = max(1.0, float(settings.spatial.max_room_size_square_meters))
        settings.spatial.max_mapping_duration_seconds = max(1, int(settings.spatial.max_mapping_duration_seconds))

        settings.recognition.recognition_confidence_threshold = float(
            clamp(settings.recognition.recognition_confidence_threshold, MIN_GESTURE_CONFIDENCE, MAX_GESTURE_CONFIDENCE)
        )
        settings.recognition.max_recognitions_per_frame = max(0, int(settings.recognition.max_recognitions_per_frame))
        settings.recognition.max_recognition_fps = max(0, int(settings.recognition.max_recognition_fps))

        settings.notifications.max_visible_notifications = max(0, int(settings.notifications.max_visible_notifications))
        settings.notifications.default_timeout_seconds = max(1, int(settings.notifications.default_timeout_seconds))
        settings.notifications.critical_timeout_seconds = max(1, int(settings.notifications.critical_timeout_seconds))

        settings.navigation.max_waypoints = max(0, int(settings.navigation.max_waypoints))

        if settings.privacy.privacy_mode == PrivacyMode.STRICT:
            settings.privacy.local_processing_preferred = True
            settings.privacy.require_visible_privacy_indicator = True
            settings.privacy.require_user_presence = True
            settings.privacy.require_workspace_boundary = True

        if not settings.privacy.allow_spatial_mapping:
            settings.spatial.enabled = False
            settings.spatial.mapping_mode = SpatialMappingMode.DISABLED

        if not settings.privacy.allow_persistent_spatial_map:
            settings.spatial.persist_anchors = False
            settings.spatial.clear_map_on_session_end = True

        if not settings.privacy.allow_object_recognition:
            settings.recognition.enable_object_recognition = False

        if not settings.privacy.allow_text_recognition:
            settings.recognition.enable_text_recognition = False

        if not settings.privacy.allow_people_detection:
            settings.recognition.enable_people_detection = False

        if not settings.privacy.allow_face_recognition:
            settings.recognition.enable_face_recognition = False

        if not settings.privacy.allow_cloud_processing:
            settings.recognition.allow_cloud_recognition = False

    def _safe_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact secrets or sensitive identifiers from dicts.

        Config should not contain secrets, but dashboard/API logs should still
        protect accidental sensitive metadata.
        """

        sensitive_key_parts = {
            "token",
            "secret",
            "password",
            "api_key",
            "apikey",
            "authorization",
            "credential",
            "private_key",
        }

        redacted: Dict[str, Any] = {}

        for key, value in data.items():
            lower_key = str(key).lower()

            if any(part in lower_key for part in sensitive_key_parts):
                redacted[key] = "***redacted***"
            elif isinstance(value, dict):
                redacted[key] = self._safe_metadata(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._safe_metadata(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value

        return redacted

    def _config_diff(self, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return top-level diff between two config dicts.
        """

        diff: Dict[str, Any] = {}

        all_keys = set(before.keys()) | set(after.keys())

        for key in sorted(all_keys):
            old_value = before.get(key)
            new_value = after.get(key)
            if old_value != new_value:
                diff[key] = {
                    "before": old_value,
                    "after": new_value,
                }

        return diff

    def _config_fingerprint(self, config: Dict[str, Any]) -> str:
        """
        Return stable non-cryptographic-style fingerprint using UUID5.

        Avoids adding hashlib import just for this file while still giving
        Verification Agent a stable change marker.
        """

        serialized = safe_json_dumps(config)
        return str(uuid.uuid5(uuid.NAMESPACE_URL, serialized))

    # -----------------------------------------------------------------------
    # Enum helpers
    # -----------------------------------------------------------------------

    @classmethod
    def _enum_from_env(
        cls,
        env_name: str,
        enum_cls: Any,
        default: Enum,
    ) -> Enum:
        """Read enum from environment variable safely."""

        value = os.getenv(env_name)
        if value is None:
            return default

        return cls._coerce_enum(value, enum_cls, default)

    @staticmethod
    def _coerce_enum(value: Any, enum_cls: Any, default: Enum) -> Enum:
        """Coerce string/enum value into target enum."""

        if isinstance(value, enum_cls):
            return value

        try:
            return enum_cls(str(value).strip().lower())
        except Exception:
            return default


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_hologram_config(
    initial_settings: Optional[HologramAgentSettings] = None,
    **kwargs: Any,
) -> HologramConfig:
    """
    Factory for Agent Loader / Registry / FastAPI dependency injection.
    """

    return HologramConfig(initial_settings=initial_settings, **kwargs)


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "HologramConfig",
    "HologramAgentSettings",
    "HologramTaskContext",
    "ARDeviceSettings",
    "HologramPrivacyFlags",
    "GestureSettings",
    "OverlayLimits",
    "SpatialSettings",
    "RecognitionSettings",
    "NotificationSettings",
    "NavigationSettings",
    "HologramDeviceType",
    "HologramRuntimeMode",
    "OverlayRenderMode",
    "OverlayPriority",
    "GestureMode",
    "PrivacyMode",
    "SpatialMappingMode",
    "HologramPermissionScope",
    "create_hologram_config",
]


# ---------------------------------------------------------------------------
# Lightweight manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    config = HologramConfig()

    print("Registry metadata:")
    print(json.dumps(config.get_registry_metadata(), indent=2, default=str))

    print("\nCurrent config:")
    current = config.get_config(
        user_id="test_user",
        workspace_id="test_workspace",
    )
    print(json.dumps(current, indent=2, default=str))

    print("\nUpdate overlay limits:")
    updated = config.update_overlay_limits(
        user_id="test_user",
        workspace_id="test_workspace",
        updates={
            "max_active_overlays": 6,
            "default_opacity": 0.85,
            "auto_hide_seconds": 10,
        },
    )
    print(json.dumps(updated, indent=2, default=str))

    print("\nValidate config:")
    validation = config.validate_config(
        user_id="test_user",
        workspace_id="test_workspace",
    )
    print(json.dumps(validation, indent=2, default=str))