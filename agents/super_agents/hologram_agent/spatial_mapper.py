"""
agents/super_agents/hologram_agent/spatial_mapper.py

Spatial Mapper for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Maps physical spaces, objects, anchors, zones, and coordinates for AR
    interactions used by the Hologram Agent.

This module is intentionally import-safe:
    - It can be imported even if the rest of the William/Jarvis system is not
      generated yet.
    - It does not directly access cameras, glasses, AR devices, sensors, files,
      browsers, calls, payments, or system-level hardware.
    - It only validates, normalizes, stores in-memory map definitions, performs
      coordinate math, prepares structured payloads, and returns JSON-style
      results for later integration.

Architecture Connections:
    Master Agent:
        Can route AR spatial mapping tasks here through public methods such as
        create_spatial_map(), add_anchor(), add_object(), map_coordinate(),
        hit_test(), export_spatial_map(), and describe_capabilities().

    Hologram Agent:
        Uses this module as the spatial foundation for overlays, object
        placement, navigation overlays, notifications, and gesture interaction.

    Security Agent:
        Spatial data may include sensitive real-world context. This module
        detects sensitive operations such as persistent mapping, private-space
        tagging, restricted-zone mapping, and human/person object mapping.
        It prepares approval payloads but never bypasses approval.

    Memory Agent:
        Can store safe, tenant-scoped spatial map summaries and anchor metadata
        using _prepare_memory_payload(). This file avoids storing raw images,
        biometrics, or secrets.

    Verification Agent:
        Receives structured verification payloads for map consistency, tenant
        isolation, coordinate bounds, anchor/object counts, and risk level.

    Dashboard/API:
        All public methods return:
            success, message, data, error, metadata

    Registry/Loader/Router:
        Includes registry-friendly class metadata and safe BaseAgent fallback.

SaaS Isolation:
    Every user-specific operation requires user_id and workspace_id. Spatial
    maps are kept tenant-scoped by user_id + workspace_id + map_id.

Author:
    Digital Promotix / William-Jarvis System
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    try:
        from agents.super_agents.base_agent import BaseAgent  # type: ignore
    except Exception:  # pragma: no cover
        class BaseAgent:  # type: ignore
            """
            Fallback BaseAgent.

            This keeps spatial_mapper.py import-safe while the wider William /
            Jarvis project is still being generated.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
                self.logger = logging.getLogger(self.agent_name)

            def emit_event(self, event_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {
                    "success": True,
                    "message": "Fallback event emitted locally.",
                    "data": {
                        "event_name": event_name,
                        "payload": payload,
                    },
                    "error": None,
                    "metadata": {
                        "fallback": True,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.HologramAgent.SpatialMapper")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "spatial_mapper"
AGENT_MODULE = "Hologram Agent"
DEFAULT_VERSION = "1.0.0"

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]{1,160}$")
SAFE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:. /()[\]{}@+#,&|]{1,180}$")

MAX_MAPS_PER_INSTANCE = 500
MAX_ANCHORS_PER_MAP = 2_000
MAX_OBJECTS_PER_MAP = 5_000
MAX_ZONES_PER_MAP = 1_000
MAX_NOTES_LENGTH = 2_000
MAX_TAGS = 50

DEFAULT_UNIT = "meter"
DEFAULT_COORDINATE_SYSTEM = "right_handed_y_up"
DEFAULT_CONFIDENCE = 0.75
DEFAULT_HIT_RADIUS_METERS = 0.35

SUPPORTED_UNITS = {"meter", "centimeter", "millimeter", "inch", "foot"}
SUPPORTED_COORDINATE_SYSTEMS = {
    "right_handed_y_up",
    "right_handed_z_up",
    "left_handed_y_up",
    "left_handed_z_up",
    "screen_space_2d",
    "device_local",
    "world",
}

SENSITIVE_SPACE_TYPES = {
    "bedroom",
    "bathroom",
    "medical_room",
    "child_room",
    "private_office",
    "restricted_area",
    "security_room",
    "financial_office",
    "server_room",
    "warehouse_restricted",
}

SENSITIVE_OBJECT_TYPES = {
    "person",
    "face",
    "child",
    "id_card",
    "passport",
    "credit_card",
    "bank_document",
    "medical_document",
    "password_note",
    "computer_screen",
    "license_plate",
    "security_camera",
    "weapon",
}

DESTRUCTIVE_OR_CONTROL_ACTIONS = {
    "move_robot",
    "unlock_door",
    "lock_door",
    "open_door",
    "close_door",
    "disable_device",
    "enable_device",
    "change_safety_zone",
    "delete_persistent_map",
}

PRIVATE_DATA_OPERATIONS = {
    "persist_map",
    "share_map",
    "export_map",
    "record_environment",
    "map_private_space",
    "track_person",
    "store_object_identity",
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def safe_str(value: Any, max_length: int = 2_000) -> str:
    """Convert a value into a bounded clean string."""

    text = "" if value is None else str(value)
    text = text.strip()
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def is_non_empty_string(value: Any) -> bool:
    """Return True when value is a non-empty string."""

    return isinstance(value, str) and bool(value.strip())


def deep_copy_jsonable(value: Any) -> Any:
    """Safely copy JSON-like values."""

    try:
        return copy.deepcopy(value)
    except Exception:
        try:
            return json.loads(json.dumps(value, default=str))
        except Exception:
            return str(value)


def stable_hash(value: Any) -> str:
    """Return stable SHA256 hash for JSON-like data."""

    serialized = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def slugify(value: str, default: str = "item") -> str:
    """Create a safe slug."""

    cleaned = re.sub(r"[^a-zA-Z0-9_\-]+", "-", value.strip().lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-_")
    return cleaned or default


def sanitize_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    Sanitize metadata and redact secret-like keys.

    This prevents accidental storage of tokens, credentials, or private keys in
    spatial map metadata.
    """

    if not metadata:
        return {}

    secret_fragments = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "auth",
        "credential",
        "session",
        "cookie",
    )

    sanitized: Dict[str, Any] = {}
    for key, value in metadata.items():
        key_str = safe_str(key, 120)
        if any(fragment in key_str.lower() for fragment in secret_fragments):
            sanitized[key_str] = "[REDACTED]"
        else:
            sanitized[key_str] = deep_copy_jsonable(value)
    return sanitized


def clamp_float(value: Any, default: float, min_value: float, max_value: float) -> float:
    """Convert to float and clamp."""

    try:
        number = float(value)
    except Exception:
        number = default
    return max(min_value, min(max_value, number))


# ---------------------------------------------------------------------------
# Enums and dataclasses
# ---------------------------------------------------------------------------

class SpatialRiskLevel(str, Enum):
    """Risk level for spatial mapping operations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SpatialMapStatus(str, Enum):
    """Lifecycle status for spatial maps."""

    DRAFT = "draft"
    ACTIVE = "active"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    ARCHIVED = "archived"


class AnchorType(str, Enum):
    """Common AR anchor types."""

    WORLD = "world"
    PLANE = "plane"
    IMAGE = "image"
    OBJECT = "object"
    FACE = "face"
    GEO = "geo"
    DEVICE = "device"
    MANUAL = "manual"


class ZoneType(str, Enum):
    """Zone type for AR interaction and safety boundaries."""

    INTERACTION = "interaction"
    SAFE = "safe"
    RESTRICTED = "restricted"
    PRIVATE = "private"
    NAVIGATION = "navigation"
    OVERLAY = "overlay"
    NO_OVERLAY = "no_overlay"


@dataclass
class Vector3:
    """3D vector in map units."""

    x: float
    y: float
    z: float

    def to_dict(self) -> Dict[str, float]:
        return {"x": self.x, "y": self.y, "z": self.z}


@dataclass
class Quaternion:
    """Quaternion orientation."""

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    w: float = 1.0

    def normalized(self) -> "Quaternion":
        length = math.sqrt(self.x * self.x + self.y * self.y + self.z * self.z + self.w * self.w)
        if length <= 0:
            return Quaternion()
        return Quaternion(
            x=self.x / length,
            y=self.y / length,
            z=self.z / length,
            w=self.w / length,
        )

    def to_dict(self) -> Dict[str, float]:
        q = self.normalized()
        return {"x": q.x, "y": q.y, "z": q.z, "w": q.w}


@dataclass
class Transform3D:
    """Position, rotation, and scale for spatial objects."""

    position: Vector3
    rotation: Quaternion = field(default_factory=Quaternion)
    scale: Vector3 = field(default_factory=lambda: Vector3(1.0, 1.0, 1.0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "position": self.position.to_dict(),
            "rotation": self.rotation.to_dict(),
            "scale": self.scale.to_dict(),
        }


@dataclass
class SpatialContext:
    """
    SaaS tenant context.

    user_id and workspace_id are mandatory for every map operation to prevent
    mixing spatial maps across users/workspaces.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "spatial_mapper"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationIssue:
    """Validation issue used by dashboard/API and Verification Agent."""

    code: str
    message: str
    severity: str = "error"
    field: Optional[str] = None
    item_id: Optional[str] = None
    hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SpatialStats:
    """Spatial map statistics."""

    anchors: int = 0
    objects: int = 0
    zones: int = 0
    sensitive_objects: int = 0
    sensitive_zones: int = 0
    persistent_items: int = 0
    restricted_zones: int = 0
    private_zones: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


# ---------------------------------------------------------------------------
# SpatialMapper
# ---------------------------------------------------------------------------

class SpatialMapper(BaseAgent):
    """
    Maps physical spaces, anchors, objects, coordinates, and zones for AR use.

    Public methods:
        - describe_capabilities()
        - create_spatial_map()
        - import_spatial_map()
        - export_spatial_map()
        - validate_spatial_map()
        - add_anchor()
        - update_anchor()
        - remove_anchor()
        - add_object()
        - update_object()
        - remove_object()
        - add_zone()
        - update_zone()
        - remove_zone()
        - map_coordinate()
        - transform_coordinate()
        - distance_between()
        - hit_test()
        - find_nearest_objects()
        - get_map()
        - list_maps()
        - archive_map()

    Important:
        This file does not operate real AR hardware. It is a safe data and math
        layer for future AR glasses/device_bridge integration.
    """

    agent_name = "SpatialMapper"
    agent_module = AGENT_MODULE
    file_name = "spatial_mapper.py"
    version = DEFAULT_VERSION

    def __init__(
        self,
        agent_id: str = "spatial_mapper",
        logger: Optional[logging.Logger] = None,
        enable_local_events: bool = True,
        allow_persistent_maps_without_security: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Initialize SpatialMapper.

        Args:
            agent_id:
                Agent registry id.
            logger:
                Optional logger.
            enable_local_events:
                If True, returns local event payloads through fallback emit.
            allow_persistent_maps_without_security:
                Safe default is False. Persistent spatial maps may reveal private
                spaces and should normally go through Security Agent.
            **kwargs:
                Future BaseAgent-compatible arguments.
        """

        try:
            super().__init__(agent_name=self.agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_id = agent_id
        self.logger = logger or LOGGER
        self.enable_local_events = enable_local_events
        self.allow_persistent_maps_without_security = allow_persistent_maps_without_security
        self._maps: Dict[str, Dict[str, Any]] = {}

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def describe_capabilities(self) -> Dict[str, Any]:
        """
        Return static registry/dashboard capabilities.

        This method does not require user_id/workspace_id because it exposes no
        tenant data.
        """

        return self._safe_result(
            message="SpatialMapper capabilities loaded.",
            data={
                "agent": self.agent_name,
                "module": self.agent_module,
                "file": self.file_name,
                "version": self.version,
                "responsibilities": [
                    "Create tenant-scoped spatial maps",
                    "Manage AR anchors",
                    "Manage mapped physical objects",
                    "Manage safe, restricted, private, and overlay zones",
                    "Transform coordinates across supported coordinate systems",
                    "Perform AR hit-testing against anchors, objects, and zones",
                    "Find nearest spatial objects",
                    "Prepare Security Agent approval payloads",
                    "Prepare Verification Agent payloads",
                    "Prepare Memory Agent-safe map summaries",
                    "Export/import dashboard-ready spatial map JSON",
                ],
                "public_methods": [
                    "describe_capabilities",
                    "create_spatial_map",
                    "import_spatial_map",
                    "export_spatial_map",
                    "validate_spatial_map",
                    "add_anchor",
                    "update_anchor",
                    "remove_anchor",
                    "add_object",
                    "update_object",
                    "remove_object",
                    "add_zone",
                    "update_zone",
                    "remove_zone",
                    "map_coordinate",
                    "transform_coordinate",
                    "distance_between",
                    "hit_test",
                    "find_nearest_objects",
                    "get_map",
                    "list_maps",
                    "archive_map",
                ],
                "supported_units": sorted(SUPPORTED_UNITS),
                "supported_coordinate_systems": sorted(SUPPORTED_COORDINATE_SYSTEMS),
                "sensitive_space_types": sorted(SENSITIVE_SPACE_TYPES),
                "sensitive_object_types": sorted(SENSITIVE_OBJECT_TYPES),
            },
            metadata={
                "import_safe": True,
                "executes_hardware_actions": False,
                "requires_context_for_map_operations": True,
            },
        )

    def create_spatial_map(
        self,
        *,
        user_id: str,
        workspace_id: str,
        name: str,
        space_type: str = "workspace",
        description: str = "",
        unit: str = DEFAULT_UNIT,
        coordinate_system: str = DEFAULT_COORDINATE_SYSTEM,
        dimensions: Optional[Mapping[str, Any]] = None,
        origin: Optional[Mapping[str, Any]] = None,
        anchors: Optional[Sequence[Mapping[str, Any]]] = None,
        objects: Optional[Sequence[Mapping[str, Any]]] = None,
        zones: Optional[Sequence[Mapping[str, Any]]] = None,
        tags: Optional[Sequence[str]] = None,
        persistent: bool = False,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        requested_by_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new tenant-scoped spatial map.

        A spatial map is disabled for sensitive persistence until Security Agent
        approval payload is reviewed by the wider system.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        if len(self._maps) >= MAX_MAPS_PER_INSTANCE:
            return self._error_result(
                message="Spatial map limit reached for this mapper instance.",
                error={
                    "code": "map_limit_reached",
                    "max_maps": MAX_MAPS_PER_INSTANCE,
                },
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        context = SpatialContext(
            user_id=user_id.strip(),
            workspace_id=workspace_id.strip(),
            role=role,
            subscription_tier=subscription_tier,
            source=requested_by_agent or self.agent_name,
            metadata=sanitize_metadata(metadata),
        )

        try:
            map_id = f"spmap_{slugify(name, 'space')}_{uuid.uuid4().hex[:12]}"
            normalized_unit = self._normalize_unit(unit)
            normalized_coordinate_system = self._normalize_coordinate_system(coordinate_system)

            spatial_map: Dict[str, Any] = {
                "map_id": map_id,
                "name": self._normalize_name(name, "Spatial Map"),
                "description": safe_str(description, MAX_NOTES_LENGTH),
                "space_type": slugify(space_type, "workspace").replace("-", "_"),
                "status": SpatialMapStatus.DRAFT.value,
                "persistent": bool(persistent),
                "unit": normalized_unit,
                "coordinate_system": normalized_coordinate_system,
                "origin": self._normalize_transform(origin or {}),
                "dimensions": self._normalize_dimensions(dimensions or {}),
                "tenant": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
                "ownership": {
                    "created_by_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "requested_by_agent": requested_by_agent or self.agent_name,
                },
                "anchors": {},
                "objects": {},
                "zones": {},
                "tags": self._normalize_tags(tags),
                "metadata": sanitize_metadata(metadata),
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
                "policies": {
                    "security": {
                        "requires_approval": False,
                        "approval_status": "not_required",
                        "approval_id": None,
                    },
                    "privacy": {
                        "store_raw_camera_frames": False,
                        "store_biometrics": False,
                        "store_precise_people_tracking": False,
                        "safe_summary_only_for_memory": True,
                    },
                    "interaction": {
                        "allow_overlays": True,
                        "allow_gesture_targets": True,
                        "allow_device_control": False,
                    },
                },
            }

            for anchor in anchors or []:
                normalized_anchor = self._normalize_anchor(anchor, spatial_map)
                spatial_map["anchors"][normalized_anchor["anchor_id"]] = normalized_anchor

            for obj in objects or []:
                normalized_object = self._normalize_object(obj, spatial_map)
                spatial_map["objects"][normalized_object["object_id"]] = normalized_object

            for zone in zones or []:
                normalized_zone = self._normalize_zone(zone, spatial_map)
                spatial_map["zones"][normalized_zone["zone_id"]] = normalized_zone

            stats = self._calculate_stats(spatial_map)
            risk_level = self._calculate_risk_level(spatial_map, stats)
            validation = self._validate_spatial_map_object(spatial_map)

            security_required = self._requires_security_check(
                operation="create_spatial_map",
                spatial_map=spatial_map,
                stats=stats,
                risk_level=risk_level,
            )

            approval_payload = None
            if security_required:
                spatial_map["status"] = SpatialMapStatus.SECURITY_REVIEW_REQUIRED.value
                approval_payload = self._request_security_approval(
                    context=context,
                    operation="create_spatial_map",
                    spatial_map=spatial_map,
                    stats=stats,
                    risk_level=risk_level,
                    reason="Spatial map contains persistent, private, restricted, or sensitive real-world context.",
                )
                spatial_map["policies"]["security"] = {
                    "requires_approval": True,
                    "approval_status": "pending",
                    "approval_id": approval_payload["data"]["approval_id"],
                }
            else:
                spatial_map["status"] = SpatialMapStatus.ACTIVE.value

            spatial_map["integrity"] = {
                "map_hash": stable_hash(
                    {
                        "tenant": spatial_map["tenant"],
                        "map_id": spatial_map["map_id"],
                        "anchors": spatial_map["anchors"],
                        "objects": spatial_map["objects"],
                        "zones": spatial_map["zones"],
                    }
                ),
                "builder": self.agent_name,
                "builder_version": self.version,
            }

            self._maps[self._tenant_map_key(context.user_id, context.workspace_id, map_id)] = spatial_map

            verification_payload = self._prepare_verification_payload(
                context=context,
                operation="create_spatial_map",
                spatial_map=spatial_map,
                validation_result=validation,
                stats=stats,
                risk_level=risk_level,
            )
            memory_payload = self._prepare_memory_payload(
                context=context,
                spatial_map=spatial_map,
                stats=stats,
                risk_level=risk_level,
            )
            audit_event = self._log_audit_event(
                context=context,
                event_type="spatial_map_created",
                operation="create_spatial_map",
                spatial_map=spatial_map,
                risk_level=risk_level,
                stats=stats,
                success=validation["success"],
            )
            agent_event = self._emit_agent_event(
                event_name="hologram.spatial.map_created",
                context=context,
                payload={
                    "map_id": map_id,
                    "name": spatial_map["name"],
                    "risk_level": risk_level.value,
                    "status": spatial_map["status"],
                    "stats": stats.to_dict(),
                },
            )

            return self._safe_result(
                message="Spatial map created successfully."
                if not security_required
                else "Spatial map created and requires Security Agent approval before sensitive use.",
                data={
                    "spatial_map": spatial_map,
                    "validation": validation["data"],
                    "security_approval": approval_payload["data"] if approval_payload else None,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "audit_event": audit_event,
                    "agent_event": agent_event,
                },
                metadata={
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "map_id": map_id,
                    "risk_level": risk_level.value,
                    "status": spatial_map["status"],
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to create spatial map.")
            return self._error_result(
                message="Unexpected error while creating spatial map.",
                error={"code": "create_spatial_map_exception", "detail": str(exc)},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def import_spatial_map(
        self,
        *,
        user_id: str,
        workspace_id: str,
        spatial_map: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Import an existing spatial map after tenant validation and normalization.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        raw = deep_copy_jsonable(dict(spatial_map))
        tenant = raw.get("tenant", {})

        if tenant and (
            tenant.get("user_id") not in {None, user_id}
            or tenant.get("workspace_id") not in {None, workspace_id}
        ):
            return self._error_result(
                message="Cannot import spatial map from a different tenant.",
                error={
                    "code": "tenant_mismatch",
                    "map_user_id": tenant.get("user_id"),
                    "map_workspace_id": tenant.get("workspace_id"),
                },
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        return self.create_spatial_map(
            user_id=user_id,
            workspace_id=workspace_id,
            name=raw.get("name", "Imported Spatial Map"),
            space_type=raw.get("space_type", "workspace"),
            description=raw.get("description", ""),
            unit=raw.get("unit", DEFAULT_UNIT),
            coordinate_system=raw.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM),
            dimensions=raw.get("dimensions", {}),
            origin=raw.get("origin", {}),
            anchors=list((raw.get("anchors") or {}).values()) if isinstance(raw.get("anchors"), dict) else raw.get("anchors", []),
            objects=list((raw.get("objects") or {}).values()) if isinstance(raw.get("objects"), dict) else raw.get("objects", []),
            zones=list((raw.get("zones") or {}).values()) if isinstance(raw.get("zones"), dict) else raw.get("zones", []),
            tags=raw.get("tags", []),
            persistent=bool(raw.get("persistent", False)),
            role=role,
            subscription_tier=subscription_tier,
            metadata={
                **sanitize_metadata(metadata),
                "imported": True,
                "source_map_hash": stable_hash(raw),
            },
            requested_by_agent="spatial_map_import",
        )

    def export_spatial_map(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        include_objects: bool = True,
        include_anchors: bool = True,
        include_zones: bool = True,
        safe_summary_only: bool = False,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export a tenant-scoped spatial map.

        Exporting persistent/private maps can require Security Agent approval.
        This method returns the export payload but does not send it externally.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        map_result = self.get_map(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not map_result["success"]:
            return map_result

        spatial_map = deep_copy_jsonable(map_result["data"]["spatial_map"])
        context = SpatialContext(
            user_id=user_id.strip(),
            workspace_id=workspace_id.strip(),
            role=role,
            subscription_tier=subscription_tier,
            source=self.agent_name,
            metadata=sanitize_metadata(metadata),
        )

        stats = self._calculate_stats(spatial_map)
        risk_level = self._calculate_risk_level(spatial_map, stats)
        security_required = self._requires_security_check(
            operation="export_map",
            spatial_map=spatial_map,
            stats=stats,
            risk_level=risk_level,
        )

        if safe_summary_only:
            exported = self._safe_map_summary(spatial_map, stats, risk_level)
        else:
            exported = deep_copy_jsonable(spatial_map)
            if not include_objects:
                exported["objects"] = {}
            if not include_anchors:
                exported["anchors"] = {}
            if not include_zones:
                exported["zones"] = {}

        approval_payload = None
        if security_required and not safe_summary_only:
            approval_payload = self._request_security_approval(
                context=context,
                operation="export_map",
                spatial_map=spatial_map,
                stats=stats,
                risk_level=risk_level,
                reason="Exporting spatial maps may expose private physical layout or sensitive object context.",
            )

        audit_event = self._log_audit_event(
            context=context,
            event_type="spatial_map_export_prepared",
            operation="export_map",
            spatial_map=spatial_map,
            risk_level=risk_level,
            stats=stats,
            success=True,
        )

        return self._safe_result(
            message="Spatial map export prepared."
            if not approval_payload
            else "Spatial map export prepared with Security Agent approval payload.",
            data={
                "export": exported,
                "export_hash": stable_hash(exported),
                "safe_summary_only": safe_summary_only,
                "security_approval": approval_payload["data"] if approval_payload else None,
                "audit_event": audit_event,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "map_id": map_id,
                "risk_level": risk_level.value,
                "requires_security_approval": bool(approval_payload),
            },
        )

    def validate_spatial_map(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: Optional[str] = None,
        spatial_map: Optional[Mapping[str, Any]] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate an existing map by id or a supplied map object."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        if spatial_map is None:
            if not map_id:
                return self._error_result(
                    message="map_id or spatial_map is required.",
                    error={"code": "missing_map_reference"},
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )
            map_result = self.get_map(
                user_id=user_id,
                workspace_id=workspace_id,
                map_id=map_id,
                role=role,
                subscription_tier=subscription_tier,
                metadata=metadata,
            )
            if not map_result["success"]:
                return map_result
            target_map = map_result["data"]["spatial_map"]
        else:
            target_map = deep_copy_jsonable(dict(spatial_map))

        tenant = target_map.get("tenant", {})
        issues: List[ValidationIssue] = []

        if tenant.get("user_id") and tenant.get("user_id") != user_id:
            issues.append(
                ValidationIssue(
                    code="tenant_user_mismatch",
                    message="Map user_id does not match request context.",
                    severity="error",
                    field="tenant.user_id",
                )
            )

        if tenant.get("workspace_id") and tenant.get("workspace_id") != workspace_id:
            issues.append(
                ValidationIssue(
                    code="tenant_workspace_mismatch",
                    message="Map workspace_id does not match request context.",
                    severity="error",
                    field="tenant.workspace_id",
                )
            )

        validation = self._validate_spatial_map_object(target_map)
        for item in validation["data"].get("issues", []):
            issues.append(
                ValidationIssue(
                    code=item.get("code", "validation_issue"),
                    message=item.get("message", "Validation issue."),
                    severity=item.get("severity", "error"),
                    field=item.get("field"),
                    item_id=item.get("item_id"),
                    hint=item.get("hint"),
                )
            )

        stats = self._calculate_stats(target_map)
        risk_level = self._calculate_risk_level(target_map, stats)
        has_errors = any(issue.severity == "error" for issue in issues)

        return self._safe_result(
            message="Spatial map validation completed."
            if not has_errors
            else "Spatial map validation completed with errors.",
            data={
                "valid": not has_errors,
                "issues": [issue.to_dict() for issue in issues],
                "stats": stats.to_dict(),
                "risk_level": risk_level.value,
                "requires_security_approval": self._requires_security_check(
                    operation="validate_spatial_map",
                    spatial_map=target_map,
                    stats=stats,
                    risk_level=risk_level,
                ),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "map_id": target_map.get("map_id"),
                "issue_count": len(issues),
            },
        )

    def add_anchor(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        name: str,
        anchor_type: str = AnchorType.MANUAL.value,
        transform: Optional[Mapping[str, Any]] = None,
        confidence: float = DEFAULT_CONFIDENCE,
        persistent: bool = False,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add an AR anchor to a spatial map."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="anchors",
            item_kind="anchor",
            action="add",
            payload={
                "name": name,
                "anchor_type": anchor_type,
                "transform": transform or {},
                "confidence": confidence,
                "persistent": persistent,
                "tags": tags or [],
                "metadata": metadata or {},
            },
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def update_anchor(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        anchor_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update an existing anchor."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="anchors",
            item_kind="anchor",
            action="update",
            item_id=anchor_id,
            payload=updates,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def remove_anchor(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        anchor_id: str,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remove an anchor."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="anchors",
            item_kind="anchor",
            action="remove",
            item_id=anchor_id,
            payload={},
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def add_object(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        name: str,
        object_type: str = "object",
        transform: Optional[Mapping[str, Any]] = None,
        dimensions: Optional[Mapping[str, Any]] = None,
        confidence: float = DEFAULT_CONFIDENCE,
        anchor_id: Optional[str] = None,
        persistent: bool = False,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a mapped physical object to a spatial map."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="objects",
            item_kind="object",
            action="add",
            payload={
                "name": name,
                "object_type": object_type,
                "transform": transform or {},
                "dimensions": dimensions or {},
                "confidence": confidence,
                "anchor_id": anchor_id,
                "persistent": persistent,
                "tags": tags or [],
                "metadata": metadata or {},
            },
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def update_object(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        object_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update an existing mapped object."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="objects",
            item_kind="object",
            action="update",
            item_id=object_id,
            payload=updates,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def remove_object(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        object_id: str,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remove an object."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="objects",
            item_kind="object",
            action="remove",
            item_id=object_id,
            payload={},
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def add_zone(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        name: str,
        zone_type: str = ZoneType.INTERACTION.value,
        center: Optional[Mapping[str, Any]] = None,
        size: Optional[Mapping[str, Any]] = None,
        radius: Optional[float] = None,
        polygon: Optional[Sequence[Mapping[str, Any]]] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add an interaction/safety/private/restricted zone."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="zones",
            item_kind="zone",
            action="add",
            payload={
                "name": name,
                "zone_type": zone_type,
                "center": center or {"x": 0, "y": 0, "z": 0},
                "size": size or {},
                "radius": radius,
                "polygon": list(polygon or []),
                "tags": tags or [],
                "metadata": metadata or {},
            },
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def update_zone(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        zone_id: str,
        updates: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a zone."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="zones",
            item_kind="zone",
            action="update",
            item_id=zone_id,
            payload=updates,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def remove_zone(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        zone_id: str,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remove a zone."""

        return self._mutate_map_item(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            collection="zones",
            item_kind="zone",
            action="remove",
            item_id=zone_id,
            payload={},
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def map_coordinate(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        coordinate: Mapping[str, Any],
        from_system: str = "device_local",
        to_system: str = "world",
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Map a coordinate between coordinate systems.

        This uses safe deterministic transformations. Future device_bridge.py may
        replace this with real device pose transforms.
        """

        return self.transform_coordinate(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            coordinate=coordinate,
            from_system=from_system,
            to_system=to_system,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )

    def transform_coordinate(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        coordinate: Mapping[str, Any],
        from_system: str,
        to_system: str,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Transform coordinate from one supported coordinate system to another."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        map_result = self.get_map(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not map_result["success"]:
            return map_result

        if from_system not in SUPPORTED_COORDINATE_SYSTEMS:
            return self._error_result(
                message="Unsupported source coordinate system.",
                error={"code": "unsupported_from_system", "from_system": from_system},
                metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
            )

        if to_system not in SUPPORTED_COORDINATE_SYSTEMS:
            return self._error_result(
                message="Unsupported target coordinate system.",
                error={"code": "unsupported_to_system", "to_system": to_system},
                metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
            )

        source = self._normalize_vector3(coordinate)
        target = self._convert_coordinate(
            source=source,
            from_system=from_system,
            to_system=to_system,
            spatial_map=map_result["data"]["spatial_map"],
        )

        return self._safe_result(
            message="Coordinate transformed successfully.",
            data={
                "input": {
                    "coordinate": source.to_dict(),
                    "coordinate_system": from_system,
                },
                "output": {
                    "coordinate": target.to_dict(),
                    "coordinate_system": to_system,
                },
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
        )

    def distance_between(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        point_a: Mapping[str, Any],
        point_b: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Calculate Euclidean distance between two points in map units."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        map_result = self.get_map(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not map_result["success"]:
            return map_result

        a = self._normalize_vector3(point_a)
        b = self._normalize_vector3(point_b)
        distance = self._distance(a, b)

        return self._safe_result(
            message="Distance calculated successfully.",
            data={
                "point_a": a.to_dict(),
                "point_b": b.to_dict(),
                "distance": distance,
                "unit": map_result["data"]["spatial_map"].get("unit", DEFAULT_UNIT),
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
        )

    def hit_test(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        point: Mapping[str, Any],
        radius: float = DEFAULT_HIT_RADIUS_METERS,
        include_anchors: bool = True,
        include_objects: bool = True,
        include_zones: bool = True,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Perform a safe hit test against anchors, objects, and zones.

        Useful for AR cursor, gesture targets, overlay placement, and hologram
        interaction selection.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        map_result = self.get_map(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not map_result["success"]:
            return map_result

        spatial_map = map_result["data"]["spatial_map"]
        query = self._normalize_vector3(point)
        hit_radius = clamp_float(radius, DEFAULT_HIT_RADIUS_METERS, 0.001, 1000.0)
        hits: List[Dict[str, Any]] = []

        if include_anchors:
            for anchor in spatial_map.get("anchors", {}).values():
                position = self._extract_item_position(anchor)
                distance = self._distance(query, position)
                if distance <= hit_radius:
                    hits.append(
                        {
                            "item_type": "anchor",
                            "item_id": anchor.get("anchor_id"),
                            "name": anchor.get("name"),
                            "distance": distance,
                            "risk_level": anchor.get("risk_level", SpatialRiskLevel.LOW.value),
                            "hit": True,
                        }
                    )

        if include_objects:
            for obj in spatial_map.get("objects", {}).values():
                position = self._extract_item_position(obj)
                object_radius = self._object_hit_radius(obj, hit_radius)
                distance = self._distance(query, position)
                if distance <= object_radius:
                    hits.append(
                        {
                            "item_type": "object",
                            "item_id": obj.get("object_id"),
                            "name": obj.get("name"),
                            "object_type": obj.get("object_type"),
                            "distance": distance,
                            "risk_level": obj.get("risk_level", SpatialRiskLevel.LOW.value),
                            "hit": True,
                        }
                    )

        if include_zones:
            for zone in spatial_map.get("zones", {}).values():
                zone_hit = self._point_in_zone(query, zone)
                if zone_hit:
                    center = self._normalize_vector3(zone.get("center", {}))
                    hits.append(
                        {
                            "item_type": "zone",
                            "item_id": zone.get("zone_id"),
                            "name": zone.get("name"),
                            "zone_type": zone.get("zone_type"),
                            "distance": self._distance(query, center),
                            "risk_level": zone.get("risk_level", SpatialRiskLevel.LOW.value),
                            "hit": True,
                        }
                    )

        hits.sort(key=lambda item: item["distance"])

        return self._safe_result(
            message="Hit test completed.",
            data={
                "query_point": query.to_dict(),
                "radius": hit_radius,
                "hits": hits,
                "hit_count": len(hits),
                "nearest_hit": hits[0] if hits else None,
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
        )

    def find_nearest_objects(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        point: Mapping[str, Any],
        limit: int = 10,
        object_type: Optional[str] = None,
        max_distance: Optional[float] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Find nearest mapped objects to a point."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        map_result = self.get_map(
            user_id=user_id,
            workspace_id=workspace_id,
            map_id=map_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not map_result["success"]:
            return map_result

        spatial_map = map_result["data"]["spatial_map"]
        query = self._normalize_vector3(point)
        normalized_type = slugify(object_type, "object").replace("-", "_") if object_type else None
        max_dist_value = float(max_distance) if max_distance is not None else None
        limit_value = int(clamp_float(limit, 10, 1, 100))

        matches: List[Dict[str, Any]] = []
        for obj in spatial_map.get("objects", {}).values():
            if normalized_type and obj.get("object_type") != normalized_type:
                continue

            position = self._extract_item_position(obj)
            distance = self._distance(query, position)
            if max_dist_value is not None and distance > max_dist_value:
                continue

            matches.append(
                {
                    "object_id": obj.get("object_id"),
                    "name": obj.get("name"),
                    "object_type": obj.get("object_type"),
                    "position": position.to_dict(),
                    "distance": distance,
                    "confidence": obj.get("confidence", DEFAULT_CONFIDENCE),
                    "risk_level": obj.get("risk_level", SpatialRiskLevel.LOW.value),
                }
            )

        matches.sort(key=lambda item: item["distance"])

        return self._safe_result(
            message="Nearest objects found.",
            data={
                "query_point": query.to_dict(),
                "objects": matches[:limit_value],
                "count": min(len(matches), limit_value),
                "total_matches": len(matches),
                "unit": spatial_map.get("unit", DEFAULT_UNIT),
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
        )

    def get_map(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a tenant-scoped spatial map by id."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        if not is_non_empty_string(map_id) or not SAFE_ID_PATTERN.match(map_id):
            return self._error_result(
                message="Invalid map_id.",
                error={"code": "invalid_map_id"},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        key = self._tenant_map_key(user_id.strip(), workspace_id.strip(), map_id)
        spatial_map = self._maps.get(key)
        if not spatial_map:
            return self._error_result(
                message="Spatial map not found for this user/workspace.",
                error={"code": "map_not_found", "map_id": map_id},
                metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
            )

        return self._safe_result(
            message="Spatial map loaded.",
            data={"spatial_map": deep_copy_jsonable(spatial_map)},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
        )

    def list_maps(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """List map summaries for a tenant."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        summaries: List[Dict[str, Any]] = []
        prefix = self._tenant_key_prefix(user_id.strip(), workspace_id.strip())
        for key, spatial_map in self._maps.items():
            if not key.startswith(prefix):
                continue
            if status and spatial_map.get("status") != status:
                continue
            stats = self._calculate_stats(spatial_map)
            risk_level = self._calculate_risk_level(spatial_map, stats)
            summaries.append(self._safe_map_summary(spatial_map, stats, risk_level))

        summaries.sort(key=lambda item: item.get("updated_at", ""), reverse=True)

        return self._safe_result(
            message="Spatial maps listed.",
            data={"maps": summaries, "count": len(summaries)},
            metadata={"user_id": user_id, "workspace_id": workspace_id},
        )

    def archive_map(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Archive a tenant-scoped spatial map. This does not delete it."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        key = self._tenant_map_key(user_id.strip(), workspace_id.strip(), map_id)
        spatial_map = self._maps.get(key)
        if not spatial_map:
            return self._error_result(
                message="Spatial map not found.",
                error={"code": "map_not_found", "map_id": map_id},
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        spatial_map["status"] = SpatialMapStatus.ARCHIVED.value
        spatial_map["updated_at"] = utc_now_iso()
        spatial_map["integrity"] = {
            "map_hash": stable_hash(spatial_map),
            "builder": self.agent_name,
            "builder_version": self.version,
        }

        context = SpatialContext(
            user_id=user_id.strip(),
            workspace_id=workspace_id.strip(),
            role=role,
            subscription_tier=subscription_tier,
            source=self.agent_name,
            metadata=sanitize_metadata(metadata),
        )

        stats = self._calculate_stats(spatial_map)
        risk_level = self._calculate_risk_level(spatial_map, stats)
        audit_event = self._log_audit_event(
            context=context,
            event_type="spatial_map_archived",
            operation="archive_map",
            spatial_map=spatial_map,
            risk_level=risk_level,
            stats=stats,
            success=True,
        )

        return self._safe_result(
            message="Spatial map archived.",
            data={"spatial_map": deep_copy_jsonable(spatial_map), "audit_event": audit_event},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
        )

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate SaaS user/workspace context."""

        issues: List[ValidationIssue] = []

        if not is_non_empty_string(user_id):
            issues.append(
                ValidationIssue(
                    code="missing_user_id",
                    message="user_id is required for spatial mapping operations.",
                    severity="error",
                    field="user_id",
                )
            )
        elif not SAFE_ID_PATTERN.match(str(user_id).strip()):
            issues.append(
                ValidationIssue(
                    code="invalid_user_id",
                    message="user_id contains unsupported characters.",
                    severity="error",
                    field="user_id",
                )
            )

        if not is_non_empty_string(workspace_id):
            issues.append(
                ValidationIssue(
                    code="missing_workspace_id",
                    message="workspace_id is required for spatial mapping operations.",
                    severity="error",
                    field="workspace_id",
                )
            )
        elif not SAFE_ID_PATTERN.match(str(workspace_id).strip()):
            issues.append(
                ValidationIssue(
                    code="invalid_workspace_id",
                    message="workspace_id contains unsupported characters.",
                    severity="error",
                    field="workspace_id",
                )
            )

        if role is not None and not is_non_empty_string(role):
            issues.append(
                ValidationIssue(
                    code="invalid_role",
                    message="role must be a non-empty string when provided.",
                    severity="warning",
                    field="role",
                )
            )

        if subscription_tier is not None and not is_non_empty_string(subscription_tier):
            issues.append(
                ValidationIssue(
                    code="invalid_subscription_tier",
                    message="subscription_tier must be a non-empty string when provided.",
                    severity="warning",
                    field="subscription_tier",
                )
            )

        has_errors = any(issue.severity == "error" for issue in issues)
        if has_errors:
            return self._error_result(
                message="Invalid spatial mapping task context.",
                error={
                    "code": "invalid_task_context",
                    "issues": [issue.to_dict() for issue in issues],
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    **sanitize_metadata(metadata),
                },
            )

        return self._safe_result(
            message="Spatial mapping task context validated.",
            data={
                "user_id": str(user_id).strip(),
                "workspace_id": str(workspace_id).strip(),
                "role": role,
                "subscription_tier": subscription_tier,
                "issues": [issue.to_dict() for issue in issues],
            },
            metadata=sanitize_metadata(metadata),
        )

    def _requires_security_check(
        self,
        *,
        operation: str,
        spatial_map: Optional[Mapping[str, Any]] = None,
        item: Optional[Mapping[str, Any]] = None,
        stats: Optional[SpatialStats] = None,
        risk_level: Optional[SpatialRiskLevel] = None,
    ) -> bool:
        """Return True if Security Agent approval should be required."""

        op = slugify(operation, "operation").replace("-", "_")

        if op in DESTRUCTIVE_OR_CONTROL_ACTIONS:
            return True

        if op in PRIVATE_DATA_OPERATIONS:
            return True

        if risk_level in {SpatialRiskLevel.HIGH, SpatialRiskLevel.CRITICAL}:
            return True

        if spatial_map:
            if spatial_map.get("persistent") and not self.allow_persistent_maps_without_security:
                return True

            space_type = spatial_map.get("space_type")
            if space_type in SENSITIVE_SPACE_TYPES:
                return True

        if stats:
            if stats.sensitive_objects > 0 or stats.private_zones > 0 or stats.restricted_zones > 0:
                return True

        if item:
            item_type = item.get("object_type") or item.get("zone_type") or item.get("anchor_type")
            if item_type in SENSITIVE_OBJECT_TYPES or item_type in {"private", "restricted"}:
                return True
            if item.get("persistent") and not self.allow_persistent_maps_without_security:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        context: SpatialContext,
        operation: str,
        spatial_map: Mapping[str, Any],
        stats: SpatialStats,
        risk_level: SpatialRiskLevel,
        reason: str,
        item: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Security Agent approval payload."""

        approval_id = f"spatial_sec_{uuid.uuid4().hex}"
        payload = {
            "approval_id": approval_id,
            "approval_type": "hologram_spatial_mapping_security_review",
            "status": "pending",
            "requested_at": utc_now_iso(),
            "requested_by": self.agent_name,
            "target_agent": "SecurityAgent",
            "operation": operation,
            "reason": reason,
            "context": asdict(context),
            "spatial_map": {
                "map_id": spatial_map.get("map_id"),
                "name": spatial_map.get("name"),
                "space_type": spatial_map.get("space_type"),
                "status": spatial_map.get("status"),
                "persistent": spatial_map.get("persistent", False),
            },
            "item": deep_copy_jsonable(item) if item else None,
            "risk": {
                "risk_level": risk_level.value,
                "stats": stats.to_dict(),
                "sensitive_space_type": spatial_map.get("space_type") in SENSITIVE_SPACE_TYPES,
            },
            "privacy_policy": spatial_map.get("policies", {}).get("privacy", {}),
            "required_decision": {
                "allowed_decisions": ["approve", "reject", "request_changes"],
                "activation_allowed_without_approval": False,
            },
        }

        return self._safe_result(
            message="Spatial mapping security approval payload prepared.",
            data=payload,
            metadata={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "map_id": spatial_map.get("map_id"),
                "approval_id": approval_id,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        context: SpatialContext,
        operation: str,
        spatial_map: Mapping[str, Any],
        validation_result: Mapping[str, Any],
        stats: SpatialStats,
        risk_level: SpatialRiskLevel,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""

        return {
            "verification_type": "hologram_spatial_map_verification",
            "target_agent": "VerificationAgent",
            "prepared_by": self.agent_name,
            "prepared_at": utc_now_iso(),
            "operation": operation,
            "context": asdict(context),
            "spatial_map": {
                "map_id": spatial_map.get("map_id"),
                "name": spatial_map.get("name"),
                "space_type": spatial_map.get("space_type"),
                "status": spatial_map.get("status"),
                "unit": spatial_map.get("unit"),
                "coordinate_system": spatial_map.get("coordinate_system"),
            },
            "stats": stats.to_dict(),
            "risk_level": risk_level.value,
            "validation": deep_copy_jsonable(validation_result.get("data", {})),
            "integrity": spatial_map.get("integrity", {}),
            "checks_requested": [
                "tenant_isolation",
                "coordinate_schema",
                "anchor_integrity",
                "object_integrity",
                "zone_integrity",
                "privacy_policy",
                "security_policy",
                "map_hash_consistency",
            ],
        }

    def _prepare_memory_payload(
        self,
        *,
        context: SpatialContext,
        spatial_map: Mapping[str, Any],
        stats: SpatialStats,
        risk_level: SpatialRiskLevel,
    ) -> Dict[str, Any]:
        """Prepare safe Memory Agent payload."""

        return {
            "memory_type": "hologram_spatial_map_summary",
            "target_agent": "MemoryAgent",
            "prepared_by": self.agent_name,
            "prepared_at": utc_now_iso(),
            "safe_to_store": True,
            "tenant": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "spatial_map": {
                "map_id": spatial_map.get("map_id"),
                "name": spatial_map.get("name"),
                "description": spatial_map.get("description"),
                "space_type": spatial_map.get("space_type"),
                "status": spatial_map.get("status"),
                "unit": spatial_map.get("unit"),
                "coordinate_system": spatial_map.get("coordinate_system"),
                "tags": spatial_map.get("tags", []),
                "persistent": spatial_map.get("persistent", False),
            },
            "summary": self._summarize_map(spatial_map, stats, risk_level),
            "stats": stats.to_dict(),
            "risk_level": risk_level.value,
            "privacy_note": "Stores safe spatial summary only. No raw images, biometrics, or camera frames.",
            "retention_hint": "workspace_scoped_hologram_spatial_context",
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        context: SpatialContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Emit or prepare a local agent event."""

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_name": event_name,
            "emitted_by": self.agent_name,
            "emitted_at": utc_now_iso(),
            "context": asdict(context),
            "payload": deep_copy_jsonable(payload),
        }

        if not self.enable_local_events:
            return {
                "success": True,
                "message": "Agent event prepared; local emission disabled.",
                "data": event,
                "error": None,
                "metadata": {"local_emit": False},
            }

        try:
            if hasattr(super(), "emit_event"):
                emitted = super().emit_event(event_name, event)  # type: ignore[misc]
                if isinstance(emitted, dict):
                    return emitted
        except Exception:
            self.logger.debug("BaseAgent event emission unavailable; returning local event.")

        return {
            "success": True,
            "message": "Agent event prepared locally.",
            "data": event,
            "error": None,
            "metadata": {"local_emit": True},
        }

    def _log_audit_event(
        self,
        *,
        context: SpatialContext,
        event_type: str,
        operation: str,
        spatial_map: Mapping[str, Any],
        risk_level: SpatialRiskLevel,
        stats: SpatialStats,
        success: bool,
    ) -> Dict[str, Any]:
        """Prepare audit log event."""

        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "event_type": event_type,
            "operation": operation,
            "agent": self.agent_name,
            "module": MODULE_NAME,
            "timestamp": utc_now_iso(),
            "success": bool(success),
            "tenant": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "request": {
                "request_id": context.request_id,
                "correlation_id": context.correlation_id,
                "source": context.source,
            },
            "spatial_map": {
                "map_id": spatial_map.get("map_id"),
                "name": spatial_map.get("name"),
                "status": spatial_map.get("status"),
                "persistent": spatial_map.get("persistent", False),
                "map_hash": spatial_map.get("integrity", {}).get("map_hash"),
            },
            "risk": {
                "risk_level": risk_level.value,
                "stats": stats.to_dict(),
                "requires_security_approval": spatial_map.get("policies", {})
                .get("security", {})
                .get("requires_approval", False),
            },
        }

        self.logger.info(
            "SpatialMapper audit event prepared: %s",
            json.dumps(
                {
                    "audit_id": audit_event["audit_id"],
                    "event_type": event_type,
                    "operation": operation,
                    "map_id": spatial_map.get("map_id"),
                    "success": success,
                    "risk_level": risk_level.value,
                },
                default=str,
            ),
        )

        return audit_event

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis success result."""

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": MODULE_NAME,
                "timestamp": utc_now_iso(),
                **sanitize_metadata(metadata),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": error if error is not None else {"code": "unknown_error"},
            "metadata": {
                "agent": self.agent_name,
                "module": MODULE_NAME,
                "timestamp": utc_now_iso(),
                **sanitize_metadata(metadata),
            },
        }

    # -----------------------------------------------------------------------
    # Internal mutation and normalization helpers
    # -----------------------------------------------------------------------

    def _mutate_map_item(
        self,
        *,
        user_id: str,
        workspace_id: str,
        map_id: str,
        collection: str,
        item_kind: str,
        action: str,
        payload: Mapping[str, Any],
        item_id: Optional[str] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Shared add/update/remove logic for anchors, objects, and zones."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        key = self._tenant_map_key(user_id.strip(), workspace_id.strip(), map_id)
        spatial_map = self._maps.get(key)
        if not spatial_map:
            return self._error_result(
                message="Spatial map not found.",
                error={"code": "map_not_found", "map_id": map_id},
                metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
            )

        if collection not in {"anchors", "objects", "zones"}:
            return self._error_result(
                message="Invalid spatial collection.",
                error={"code": "invalid_collection", "collection": collection},
                metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
            )

        try:
            if action == "add":
                if collection == "anchors" and len(spatial_map["anchors"]) >= MAX_ANCHORS_PER_MAP:
                    return self._error_result(
                        message="Anchor limit reached for this map.",
                        error={"code": "anchor_limit_reached", "max": MAX_ANCHORS_PER_MAP},
                        metadata={"map_id": map_id},
                    )
                if collection == "objects" and len(spatial_map["objects"]) >= MAX_OBJECTS_PER_MAP:
                    return self._error_result(
                        message="Object limit reached for this map.",
                        error={"code": "object_limit_reached", "max": MAX_OBJECTS_PER_MAP},
                        metadata={"map_id": map_id},
                    )
                if collection == "zones" and len(spatial_map["zones"]) >= MAX_ZONES_PER_MAP:
                    return self._error_result(
                        message="Zone limit reached for this map.",
                        error={"code": "zone_limit_reached", "max": MAX_ZONES_PER_MAP},
                        metadata={"map_id": map_id},
                    )

                if collection == "anchors":
                    item = self._normalize_anchor(payload, spatial_map)
                    real_id = item["anchor_id"]
                elif collection == "objects":
                    item = self._normalize_object(payload, spatial_map)
                    real_id = item["object_id"]
                else:
                    item = self._normalize_zone(payload, spatial_map)
                    real_id = item["zone_id"]

                spatial_map[collection][real_id] = item
                message = f"{item_kind.title()} added successfully."

            elif action == "update":
                if not item_id or item_id not in spatial_map[collection]:
                    return self._error_result(
                        message=f"{item_kind.title()} not found.",
                        error={"code": f"{item_kind}_not_found", "item_id": item_id},
                        metadata={"map_id": map_id},
                    )

                existing = deep_copy_jsonable(spatial_map[collection][item_id])
                merged = {**existing, **sanitize_metadata(payload)}

                if collection == "anchors":
                    item = self._normalize_anchor(merged, spatial_map, existing_id=item_id)
                    real_id = item["anchor_id"]
                elif collection == "objects":
                    item = self._normalize_object(merged, spatial_map, existing_id=item_id)
                    real_id = item["object_id"]
                else:
                    item = self._normalize_zone(merged, spatial_map, existing_id=item_id)
                    real_id = item["zone_id"]

                spatial_map[collection][real_id] = item
                message = f"{item_kind.title()} updated successfully."

            elif action == "remove":
                if not item_id or item_id not in spatial_map[collection]:
                    return self._error_result(
                        message=f"{item_kind.title()} not found.",
                        error={"code": f"{item_kind}_not_found", "item_id": item_id},
                        metadata={"map_id": map_id},
                    )

                item = spatial_map[collection].pop(item_id)
                real_id = item_id
                message = f"{item_kind.title()} removed successfully."

            else:
                return self._error_result(
                    message="Unsupported map mutation action.",
                    error={"code": "unsupported_mutation_action", "action": action},
                    metadata={"map_id": map_id},
                )

            spatial_map["updated_at"] = utc_now_iso()
            stats = self._calculate_stats(spatial_map)
            risk_level = self._calculate_risk_level(spatial_map, stats)

            security_required = self._requires_security_check(
                operation=f"{action}_{item_kind}",
                spatial_map=spatial_map,
                item=item if action in {"add", "update"} else None,
                stats=stats,
                risk_level=risk_level,
            )

            approval_payload = None
            if security_required:
                approval_payload = self._request_security_approval(
                    context=SpatialContext(
                        user_id=user_id.strip(),
                        workspace_id=workspace_id.strip(),
                        role=role,
                        subscription_tier=subscription_tier,
                        source=self.agent_name,
                        metadata=sanitize_metadata(metadata),
                    ),
                    operation=f"{action}_{item_kind}",
                    spatial_map=spatial_map,
                    item=item,
                    stats=stats,
                    risk_level=risk_level,
                    reason=f"Spatial {item_kind} mutation may involve persistent, restricted, private, or sensitive real-world context.",
                )

            spatial_map["integrity"] = {
                "map_hash": stable_hash(spatial_map),
                "builder": self.agent_name,
                "builder_version": self.version,
            }

            validation = self._validate_spatial_map_object(spatial_map)
            self._maps[key] = spatial_map

            return self._safe_result(
                message=message,
                data={
                    item_kind: item,
                    "spatial_map": deep_copy_jsonable(spatial_map),
                    "validation": validation["data"],
                    "security_approval": approval_payload["data"] if approval_payload else None,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "map_id": map_id,
                    "item_id": real_id,
                    "action": action,
                    "risk_level": risk_level.value,
                    "requires_security_approval": bool(approval_payload),
                },
            )

        except Exception as exc:
            self.logger.exception("Spatial map mutation failed.")
            return self._error_result(
                message="Unexpected error while mutating spatial map.",
                error={"code": "spatial_map_mutation_exception", "detail": str(exc)},
                metadata={"user_id": user_id, "workspace_id": workspace_id, "map_id": map_id},
            )

    def _normalize_anchor(
        self,
        raw: Mapping[str, Any],
        spatial_map: Mapping[str, Any],
        existing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Normalize an anchor."""

        anchor_type = slugify(str(raw.get("anchor_type") or raw.get("type") or AnchorType.MANUAL.value), "manual").replace("-", "_")
        anchor_id = existing_id or raw.get("anchor_id") or raw.get("id") or f"anchor_{anchor_type}_{uuid.uuid4().hex[:10]}"
        anchor_id = self._safe_id(anchor_id, f"anchor_{uuid.uuid4().hex[:10]}")

        transform = self._normalize_transform(raw.get("transform") or raw)
        confidence = clamp_float(raw.get("confidence", DEFAULT_CONFIDENCE), DEFAULT_CONFIDENCE, 0.0, 1.0)
        persistent = bool(raw.get("persistent", False))

        risk_level = SpatialRiskLevel.HIGH if anchor_type in {"face", "geo"} or persistent else SpatialRiskLevel.LOW

        return {
            "anchor_id": anchor_id,
            "name": self._normalize_name(raw.get("name") or anchor_type, "Anchor"),
            "anchor_type": anchor_type,
            "transform": transform,
            "confidence": confidence,
            "persistent": persistent,
            "coordinate_system": spatial_map.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM),
            "unit": spatial_map.get("unit", DEFAULT_UNIT),
            "tags": self._normalize_tags(raw.get("tags", [])),
            "metadata": sanitize_metadata(raw.get("metadata", {})),
            "risk_level": risk_level.value,
            "created_at": raw.get("created_at") or utc_now_iso(),
            "updated_at": utc_now_iso(),
        }

    def _normalize_object(
        self,
        raw: Mapping[str, Any],
        spatial_map: Mapping[str, Any],
        existing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Normalize mapped object."""

        object_type = slugify(str(raw.get("object_type") or raw.get("type") or "object"), "object").replace("-", "_")
        object_id = existing_id or raw.get("object_id") or raw.get("id") or f"object_{object_type}_{uuid.uuid4().hex[:10]}"
        object_id = self._safe_id(object_id, f"object_{uuid.uuid4().hex[:10]}")

        persistent = bool(raw.get("persistent", False))
        confidence = clamp_float(raw.get("confidence", DEFAULT_CONFIDENCE), DEFAULT_CONFIDENCE, 0.0, 1.0)
        risk_level = self._object_risk_level(object_type, persistent)

        anchor_id = raw.get("anchor_id")
        if anchor_id and anchor_id not in spatial_map.get("anchors", {}):
            anchor_id = None

        return {
            "object_id": object_id,
            "name": self._normalize_name(raw.get("name") or object_type, "Object"),
            "object_type": object_type,
            "transform": self._normalize_transform(raw.get("transform") or raw),
            "dimensions": self._normalize_dimensions(raw.get("dimensions", {})),
            "confidence": confidence,
            "anchor_id": anchor_id,
            "persistent": persistent,
            "coordinate_system": spatial_map.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM),
            "unit": spatial_map.get("unit", DEFAULT_UNIT),
            "tags": self._normalize_tags(raw.get("tags", [])),
            "metadata": sanitize_metadata(raw.get("metadata", {})),
            "risk_level": risk_level.value,
            "created_at": raw.get("created_at") or utc_now_iso(),
            "updated_at": utc_now_iso(),
        }

    def _normalize_zone(
        self,
        raw: Mapping[str, Any],
        spatial_map: Mapping[str, Any],
        existing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Normalize a spatial zone."""

        zone_type = slugify(str(raw.get("zone_type") or raw.get("type") or ZoneType.INTERACTION.value), "interaction").replace("-", "_")
        zone_id = existing_id or raw.get("zone_id") or raw.get("id") or f"zone_{zone_type}_{uuid.uuid4().hex[:10]}"
        zone_id = self._safe_id(zone_id, f"zone_{uuid.uuid4().hex[:10]}")

        center = self._normalize_vector3(raw.get("center", {"x": 0, "y": 0, "z": 0}))
        size = self._normalize_dimensions(raw.get("size") or raw.get("dimensions") or {})
        radius = raw.get("radius")
        radius_value = None if radius is None else clamp_float(radius, 1.0, 0.001, 10_000.0)

        polygon = []
        for point in raw.get("polygon", []) or []:
            polygon.append(self._normalize_vector3(point).to_dict())

        risk_level = self._zone_risk_level(zone_type)

        return {
            "zone_id": zone_id,
            "name": self._normalize_name(raw.get("name") or zone_type, "Zone"),
            "zone_type": zone_type,
            "center": center.to_dict(),
            "size": size,
            "radius": radius_value,
            "polygon": polygon,
            "coordinate_system": spatial_map.get("coordinate_system", DEFAULT_COORDINATE_SYSTEM),
            "unit": spatial_map.get("unit", DEFAULT_UNIT),
            "tags": self._normalize_tags(raw.get("tags", [])),
            "metadata": sanitize_metadata(raw.get("metadata", {})),
            "risk_level": risk_level.value,
            "created_at": raw.get("created_at") or utc_now_iso(),
            "updated_at": utc_now_iso(),
        }

    def _normalize_transform(self, raw: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize transform from flexible input."""

        if "position" in raw:
            position = self._normalize_vector3(raw.get("position", {}))
        else:
            position = self._normalize_vector3(raw)

        rotation_raw = raw.get("rotation", {})
        rotation = Quaternion(
            x=clamp_float(rotation_raw.get("x", 0.0), 0.0, -1.0, 1.0) if isinstance(rotation_raw, Mapping) else 0.0,
            y=clamp_float(rotation_raw.get("y", 0.0), 0.0, -1.0, 1.0) if isinstance(rotation_raw, Mapping) else 0.0,
            z=clamp_float(rotation_raw.get("z", 0.0), 0.0, -1.0, 1.0) if isinstance(rotation_raw, Mapping) else 0.0,
            w=clamp_float(rotation_raw.get("w", 1.0), 1.0, -1.0, 1.0) if isinstance(rotation_raw, Mapping) else 1.0,
        )

        scale_raw = raw.get("scale", {"x": 1, "y": 1, "z": 1})
        scale = self._normalize_vector3(scale_raw, default=1.0, min_value=0.0001, max_value=10_000.0)

        return Transform3D(position=position, rotation=rotation, scale=scale).to_dict()

    def _normalize_vector3(
        self,
        raw: Mapping[str, Any],
        default: float = 0.0,
        min_value: float = -1_000_000.0,
        max_value: float = 1_000_000.0,
    ) -> Vector3:
        """Normalize a Vector3."""

        if not isinstance(raw, Mapping):
            raw = {}

        return Vector3(
            x=clamp_float(raw.get("x", default), default, min_value, max_value),
            y=clamp_float(raw.get("y", default), default, min_value, max_value),
            z=clamp_float(raw.get("z", default), default, min_value, max_value),
        )

    def _normalize_dimensions(self, raw: Mapping[str, Any]) -> Dict[str, float]:
        """Normalize dimensions."""

        if not isinstance(raw, Mapping):
            raw = {}

        width = raw.get("width", raw.get("x", 0.0))
        height = raw.get("height", raw.get("y", 0.0))
        depth = raw.get("depth", raw.get("z", 0.0))

        return {
            "width": clamp_float(width, 0.0, 0.0, 1_000_000.0),
            "height": clamp_float(height, 0.0, 0.0, 1_000_000.0),
            "depth": clamp_float(depth, 0.0, 0.0, 1_000_000.0),
        }

    def _normalize_unit(self, unit: str) -> str:
        """Normalize unit."""

        normalized = slugify(unit, DEFAULT_UNIT).replace("-", "_")
        return normalized if normalized in SUPPORTED_UNITS else DEFAULT_UNIT

    def _normalize_coordinate_system(self, coordinate_system: str) -> str:
        """Normalize coordinate system."""

        normalized = slugify(coordinate_system, DEFAULT_COORDINATE_SYSTEM).replace("-", "_")
        return normalized if normalized in SUPPORTED_COORDINATE_SYSTEMS else DEFAULT_COORDINATE_SYSTEM

    def _normalize_name(self, name: Any, default: str) -> str:
        """Normalize safe display name."""

        if not is_non_empty_string(name):
            return default
        text = safe_str(name, 180)
        if not SAFE_NAME_PATTERN.match(text):
            text = re.sub(r"[^a-zA-Z0-9_\-:. /()[\]{}@+#,&|]", "", text).strip()
        return text or default

    def _normalize_tags(self, tags: Optional[Sequence[str]]) -> List[str]:
        """Normalize tags."""

        result: List[str] = []
        for tag in tags or []:
            if not is_non_empty_string(tag):
                continue
            clean = slugify(str(tag), "tag")
            if clean not in result:
                result.append(clean)
            if len(result) >= MAX_TAGS:
                break
        return result

    def _safe_id(self, value: Any, default: str) -> str:
        """Return safe id."""

        candidate = safe_str(value, 160)
        if candidate and SAFE_ID_PATTERN.match(candidate):
            return candidate
        return default

    # -----------------------------------------------------------------------
    # Validation, stats, and risk
    # -----------------------------------------------------------------------

    def _validate_spatial_map_object(self, spatial_map: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate a spatial map object."""

        issues: List[ValidationIssue] = []

        if not is_non_empty_string(spatial_map.get("map_id")):
            issues.append(
                ValidationIssue(
                    code="missing_map_id",
                    message="map_id is required.",
                    severity="error",
                    field="map_id",
                )
            )

        if not is_non_empty_string(spatial_map.get("name")):
            issues.append(
                ValidationIssue(
                    code="missing_map_name",
                    message="Spatial map name is required.",
                    severity="error",
                    field="name",
                )
            )

        tenant = spatial_map.get("tenant", {})
        if not tenant.get("user_id"):
            issues.append(
                ValidationIssue(
                    code="missing_tenant_user_id",
                    message="tenant.user_id is required.",
                    severity="error",
                    field="tenant.user_id",
                )
            )

        if not tenant.get("workspace_id"):
            issues.append(
                ValidationIssue(
                    code="missing_tenant_workspace_id",
                    message="tenant.workspace_id is required.",
                    severity="error",
                    field="tenant.workspace_id",
                )
            )

        if spatial_map.get("unit") not in SUPPORTED_UNITS:
            issues.append(
                ValidationIssue(
                    code="unsupported_unit",
                    message="Spatial map unit is unsupported.",
                    severity="error",
                    field="unit",
                    hint=f"Supported units: {sorted(SUPPORTED_UNITS)}",
                )
            )

        if spatial_map.get("coordinate_system") not in SUPPORTED_COORDINATE_SYSTEMS:
            issues.append(
                ValidationIssue(
                    code="unsupported_coordinate_system",
                    message="Spatial map coordinate system is unsupported.",
                    severity="error",
                    field="coordinate_system",
                    hint=f"Supported coordinate systems: {sorted(SUPPORTED_COORDINATE_SYSTEMS)}",
                )
            )

        anchors = spatial_map.get("anchors", {})
        objects = spatial_map.get("objects", {})
        zones = spatial_map.get("zones", {})

        if not isinstance(anchors, dict):
            issues.append(
                ValidationIssue(
                    code="invalid_anchors",
                    message="anchors must be a dictionary.",
                    severity="error",
                    field="anchors",
                )
            )
            anchors = {}

        if not isinstance(objects, dict):
            issues.append(
                ValidationIssue(
                    code="invalid_objects",
                    message="objects must be a dictionary.",
                    severity="error",
                    field="objects",
                )
            )
            objects = {}

        if not isinstance(zones, dict):
            issues.append(
                ValidationIssue(
                    code="invalid_zones",
                    message="zones must be a dictionary.",
                    severity="error",
                    field="zones",
                )
            )
            zones = {}

        if len(anchors) > MAX_ANCHORS_PER_MAP:
            issues.append(
                ValidationIssue(
                    code="too_many_anchors",
                    message=f"Map exceeds max anchors: {MAX_ANCHORS_PER_MAP}.",
                    severity="error",
                    field="anchors",
                )
            )

        if len(objects) > MAX_OBJECTS_PER_MAP:
            issues.append(
                ValidationIssue(
                    code="too_many_objects",
                    message=f"Map exceeds max objects: {MAX_OBJECTS_PER_MAP}.",
                    severity="error",
                    field="objects",
                )
            )

        if len(zones) > MAX_ZONES_PER_MAP:
            issues.append(
                ValidationIssue(
                    code="too_many_zones",
                    message=f"Map exceeds max zones: {MAX_ZONES_PER_MAP}.",
                    severity="error",
                    field="zones",
                )
            )

        for anchor_id, anchor in anchors.items():
            if anchor.get("anchor_id") != anchor_id:
                issues.append(
                    ValidationIssue(
                        code="anchor_id_key_mismatch",
                        message="Anchor dictionary key does not match anchor_id.",
                        severity="warning",
                        field="anchors",
                        item_id=anchor_id,
                    )
                )

        for object_id, obj in objects.items():
            if obj.get("object_id") != object_id:
                issues.append(
                    ValidationIssue(
                        code="object_id_key_mismatch",
                        message="Object dictionary key does not match object_id.",
                        severity="warning",
                        field="objects",
                        item_id=object_id,
                    )
                )

            anchor_id = obj.get("anchor_id")
            if anchor_id and anchor_id not in anchors:
                issues.append(
                    ValidationIssue(
                        code="object_anchor_missing",
                        message="Object references a missing anchor.",
                        severity="warning",
                        field="objects.anchor_id",
                        item_id=object_id,
                    )
                )

        for zone_id, zone in zones.items():
            if zone.get("zone_id") != zone_id:
                issues.append(
                    ValidationIssue(
                        code="zone_id_key_mismatch",
                        message="Zone dictionary key does not match zone_id.",
                        severity="warning",
                        field="zones",
                        item_id=zone_id,
                    )
                )

            has_radius = zone.get("radius") is not None
            has_size = any(float(v or 0) > 0 for v in zone.get("size", {}).values())
            has_polygon = bool(zone.get("polygon"))
            if not (has_radius or has_size or has_polygon):
                issues.append(
                    ValidationIssue(
                        code="zone_no_boundary",
                        message="Zone should define radius, size, or polygon boundary.",
                        severity="warning",
                        field="zones.boundary",
                        item_id=zone_id,
                    )
                )

        has_errors = any(issue.severity == "error" for issue in issues)

        return self._safe_result(
            message="Spatial map object validation completed.",
            data={
                "valid": not has_errors,
                "issues": [issue.to_dict() for issue in issues],
                "issue_count": len(issues),
                "error_count": sum(1 for issue in issues if issue.severity == "error"),
                "warning_count": sum(1 for issue in issues if issue.severity == "warning"),
            },
            metadata={"map_id": spatial_map.get("map_id")},
        )

    def _calculate_stats(self, spatial_map: Mapping[str, Any]) -> SpatialStats:
        """Calculate map statistics."""

        anchors = spatial_map.get("anchors", {}) or {}
        objects = spatial_map.get("objects", {}) or {}
        zones = spatial_map.get("zones", {}) or {}

        stats = SpatialStats(
            anchors=len(anchors),
            objects=len(objects),
            zones=len(zones),
        )

        for anchor in anchors.values():
            if anchor.get("persistent"):
                stats.persistent_items += 1

        for obj in objects.values():
            if obj.get("object_type") in SENSITIVE_OBJECT_TYPES:
                stats.sensitive_objects += 1
            if obj.get("persistent"):
                stats.persistent_items += 1

        for zone in zones.values():
            zone_type = zone.get("zone_type")
            if zone_type in {"private", "restricted"}:
                stats.sensitive_zones += 1
            if zone_type == "private":
                stats.private_zones += 1
            if zone_type == "restricted":
                stats.restricted_zones += 1

        return stats

    def _calculate_risk_level(
        self,
        spatial_map: Mapping[str, Any],
        stats: SpatialStats,
    ) -> SpatialRiskLevel:
        """Calculate map risk level."""

        if spatial_map.get("space_type") in {"bathroom", "child_room", "medical_room"}:
            return SpatialRiskLevel.CRITICAL

        if stats.sensitive_objects > 0:
            return SpatialRiskLevel.CRITICAL

        if stats.private_zones > 0 or stats.restricted_zones > 0:
            return SpatialRiskLevel.HIGH

        if spatial_map.get("space_type") in SENSITIVE_SPACE_TYPES:
            return SpatialRiskLevel.HIGH

        if spatial_map.get("persistent") or stats.persistent_items > 0:
            return SpatialRiskLevel.MEDIUM

        if stats.objects > 100 or stats.anchors > 100:
            return SpatialRiskLevel.MEDIUM

        return SpatialRiskLevel.LOW

    def _object_risk_level(self, object_type: str, persistent: bool) -> SpatialRiskLevel:
        """Risk for object type."""

        if object_type in SENSITIVE_OBJECT_TYPES:
            return SpatialRiskLevel.CRITICAL
        if persistent:
            return SpatialRiskLevel.MEDIUM
        return SpatialRiskLevel.LOW

    def _zone_risk_level(self, zone_type: str) -> SpatialRiskLevel:
        """Risk for zone type."""

        if zone_type == "restricted":
            return SpatialRiskLevel.HIGH
        if zone_type == "private":
            return SpatialRiskLevel.HIGH
        return SpatialRiskLevel.LOW

    # -----------------------------------------------------------------------
    # Spatial math
    # -----------------------------------------------------------------------

    def _convert_coordinate(
        self,
        *,
        source: Vector3,
        from_system: str,
        to_system: str,
        spatial_map: Mapping[str, Any],
    ) -> Vector3:
        """
        Convert coordinate between common coordinate systems.

        This is intentionally deterministic and does not depend on device APIs.
        """

        if from_system == to_system:
            return source

        origin = self._normalize_transform(spatial_map.get("origin", {}))
        origin_pos = self._normalize_vector3(origin.get("position", {}))

        world = source

        if from_system == "device_local":
            world = Vector3(
                x=source.x + origin_pos.x,
                y=source.y + origin_pos.y,
                z=source.z + origin_pos.z,
            )
        elif from_system == "screen_space_2d":
            world = Vector3(
                x=source.x,
                y=source.y,
                z=0.0,
            )
        elif from_system == "right_handed_z_up":
            world = Vector3(x=source.x, y=source.z, z=source.y)
        elif from_system == "left_handed_y_up":
            world = Vector3(x=-source.x, y=source.y, z=source.z)
        elif from_system == "left_handed_z_up":
            world = Vector3(x=-source.x, y=source.z, z=source.y)

        if to_system == "world" or to_system == spatial_map.get("coordinate_system"):
            return world

        if to_system == "device_local":
            return Vector3(
                x=world.x - origin_pos.x,
                y=world.y - origin_pos.y,
                z=world.z - origin_pos.z,
            )
        if to_system == "screen_space_2d":
            return Vector3(x=world.x, y=world.y, z=0.0)
        if to_system == "right_handed_z_up":
            return Vector3(x=world.x, y=world.z, z=world.y)
        if to_system == "left_handed_y_up":
            return Vector3(x=-world.x, y=world.y, z=world.z)
        if to_system == "left_handed_z_up":
            return Vector3(x=-world.x, y=world.z, z=world.y)

        return world

    def _distance(self, a: Vector3, b: Vector3) -> float:
        """Euclidean distance."""

        return math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2)

    def _extract_item_position(self, item: Mapping[str, Any]) -> Vector3:
        """Extract item transform position."""

        transform = item.get("transform", {})
        if isinstance(transform, Mapping) and "position" in transform:
            return self._normalize_vector3(transform.get("position", {}))
        if "center" in item:
            return self._normalize_vector3(item.get("center", {}))
        return self._normalize_vector3(item)

    def _object_hit_radius(self, obj: Mapping[str, Any], default_radius: float) -> float:
        """Estimate object hit radius from dimensions."""

        dimensions = obj.get("dimensions", {}) or {}
        width = float(dimensions.get("width", 0.0) or 0.0)
        height = float(dimensions.get("height", 0.0) or 0.0)
        depth = float(dimensions.get("depth", 0.0) or 0.0)

        if width <= 0 and height <= 0 and depth <= 0:
            return default_radius

        return max(default_radius, math.sqrt(width * width + height * height + depth * depth) / 2.0)

    def _point_in_zone(self, point: Vector3, zone: Mapping[str, Any]) -> bool:
        """Check if point is inside zone using radius, box, or polygon fallback."""

        center = self._normalize_vector3(zone.get("center", {}))
        radius = zone.get("radius")

        if radius is not None:
            return self._distance(point, center) <= float(radius)

        size = zone.get("size", {}) or {}
        width = float(size.get("width", 0.0) or 0.0)
        height = float(size.get("height", 0.0) or 0.0)
        depth = float(size.get("depth", 0.0) or 0.0)

        if width > 0 or height > 0 or depth > 0:
            return (
                abs(point.x - center.x) <= max(width / 2.0, 0.0001)
                and abs(point.y - center.y) <= max(height / 2.0, 0.0001)
                and abs(point.z - center.z) <= max(depth / 2.0, 0.0001)
            )

        polygon = zone.get("polygon", []) or []
        if polygon:
            return self._point_in_polygon_2d(point, polygon)

        return False

    def _point_in_polygon_2d(self, point: Vector3, polygon: Sequence[Mapping[str, Any]]) -> bool:
        """Ray-casting point-in-polygon test using x/z plane."""

        if len(polygon) < 3:
            return False

        x = point.x
        z = point.z
        inside = False
        j = len(polygon) - 1

        for i in range(len(polygon)):
            pi = self._normalize_vector3(polygon[i])
            pj = self._normalize_vector3(polygon[j])

            intersects = ((pi.z > z) != (pj.z > z)) and (
                x < (pj.x - pi.x) * (z - pi.z) / ((pj.z - pi.z) or 1e-12) + pi.x
            )
            if intersects:
                inside = not inside
            j = i

        return inside

    # -----------------------------------------------------------------------
    # Summary and keys
    # -----------------------------------------------------------------------

    def _tenant_key_prefix(self, user_id: str, workspace_id: str) -> str:
        """Tenant prefix for in-memory map isolation."""

        return f"{user_id}:{workspace_id}:"

    def _tenant_map_key(self, user_id: str, workspace_id: str, map_id: str) -> str:
        """Tenant-scoped map key."""

        return f"{self._tenant_key_prefix(user_id, workspace_id)}{map_id}"

    def _safe_map_summary(
        self,
        spatial_map: Mapping[str, Any],
        stats: SpatialStats,
        risk_level: SpatialRiskLevel,
    ) -> Dict[str, Any]:
        """Return safe map summary without raw object geometry details."""

        return {
            "map_id": spatial_map.get("map_id"),
            "name": spatial_map.get("name"),
            "description": spatial_map.get("description"),
            "space_type": spatial_map.get("space_type"),
            "status": spatial_map.get("status"),
            "persistent": spatial_map.get("persistent", False),
            "unit": spatial_map.get("unit"),
            "coordinate_system": spatial_map.get("coordinate_system"),
            "tags": spatial_map.get("tags", []),
            "stats": stats.to_dict(),
            "risk_level": risk_level.value,
            "created_at": spatial_map.get("created_at"),
            "updated_at": spatial_map.get("updated_at"),
            "integrity": spatial_map.get("integrity", {}),
        }

    def _summarize_map(
        self,
        spatial_map: Mapping[str, Any],
        stats: SpatialStats,
        risk_level: SpatialRiskLevel,
    ) -> str:
        """Human-readable map summary."""

        return (
            f"Spatial map '{spatial_map.get('name')}' contains "
            f"{stats.anchors} anchors, {stats.objects} objects, and {stats.zones} zones "
            f"in {spatial_map.get('unit', DEFAULT_UNIT)} units using "
            f"{spatial_map.get('coordinate_system', DEFAULT_COORDINATE_SYSTEM)} coordinates. "
            f"Risk level: {risk_level.value}."
        )


# ---------------------------------------------------------------------------
# Standalone smoke test helper
# ---------------------------------------------------------------------------

def _smoke_test() -> Dict[str, Any]:
    """
    Minimal import-safe smoke test.

    This function is not executed on import.
    """

    mapper = SpatialMapper()
    created = mapper.create_spatial_map(
        user_id="user_demo",
        workspace_id="workspace_demo",
        name="Demo Office",
        space_type="workspace",
        dimensions={"width": 5, "height": 3, "depth": 7},
        anchors=[
            {
                "name": "Desk Anchor",
                "anchor_type": "manual",
                "transform": {"position": {"x": 1, "y": 0, "z": 2}},
            }
        ],
        objects=[
            {
                "name": "Desk",
                "object_type": "furniture",
                "transform": {"position": {"x": 1.2, "y": 0, "z": 2.1}},
                "dimensions": {"width": 1.5, "height": 0.8, "depth": 0.7},
            }
        ],
        zones=[
            {
                "name": "Overlay Zone",
                "zone_type": "overlay",
                "center": {"x": 1, "y": 1.5, "z": 2},
                "size": {"width": 2, "height": 2, "depth": 2},
            }
        ],
    )
    return created


__all__ = [
    "SpatialMapper",
    "SpatialContext",
    "SpatialStats",
    "SpatialRiskLevel",
    "SpatialMapStatus",
    "AnchorType",
    "ZoneType",
    "Vector3",
    "Quaternion",
    "Transform3D",
    "ValidationIssue",
]